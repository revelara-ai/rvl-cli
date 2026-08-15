//! The spec cache: the asset that compounds.
//!
//! A spec answers a question about an API or a config type, not about a call
//! site. `net/http.Client.Do blocks, and a context or client config can bound
//! it` is true in every repository that imports it, so specs earned once pay
//! forever. Per-site labels are worth nothing to the next repo.
//!
//! This inverts the cost model that made the per-site scanner unaffordable. On
//! the reference Go repo, 1525 call sites reduced to 76 spec questions (23x), and the spec
//! answers reproduced a per-site finding at roughly 1/40th the cost: seven APIs
//! judged non-blocking removed 285 sites, 18.7% of the corpus, which matched
//! the 14-19% not-applicable rate the per-site panel measured over two runs.
//!
//! It also changes the risk profile, and the change is not benign. A wrong spec
//! is applied to every site using that API at once, so spec error is
//! MULTIPLIED where per-site error is isolated. Hence the confidence floor
//! below, and hence `depends` never collapsing to `yes`.

use rvl_core::{RepoConfig, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A spec below this confidence does not decide anything; the site abstains.
/// Set by the multiplier, not by ordinary caution.
pub const MIN_CONFIDENCE: f64 = 0.6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blocking {
    Yes,
    No,
    /// Conditional on the call, so the spec alone cannot settle it.
    Depends,
    Unknown,
}

/// Where a bound can come from. Only mechanisms the spec lists are searched for,
/// which is what keeps propagation from inventing bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    CallArg,
    Context,
    ClientConfig,
    ServerConfig,
    /// A decorator or annotation on the enclosing function bounds the call.
    /// Python's dominant idiom -- @shared_task(time_limit=120) bounds every
    /// call inside the task -- and it had no representation at all until the
    /// fixture gold set scored app/reports.py wrong.
    Decorator,
    None,
}

/// What the LIBRARY itself does when the caller passes no explicit bound
/// (po-av01j.175).
///
/// This is the one fact the engine can never derive from the user's code, and
/// without it the scanner was asserting it anyway: every completed search with
/// no bound printed "it can hang indefinitely", which is true of `requests`
/// (whose timeout defaults to `None`) and FALSE of every SDK that ships a
/// default — openai 3.1.0 and anthropic 0.122.0 both carry
/// `DEFAULT_TIMEOUT = Timeout(connect=5.0, read=600, write=600, pool=600)`.
///
/// Three states, deliberately distinct, because "we do not know" and "there is
/// no default" are different claims and only one of them licenses the strong
/// sentence:
///   - [`DefaultBound::Unknown`] — nobody established it. Say only what the
///     search verified about the user's code.
///   - [`DefaultBound::None`] — the library applies no default. The strong
///     claim is now EVIDENCED and may be made.
///   - [`DefaultBound::Seconds`] — the library applies its own default, which
///     is a finding of its own shape: a 600s fallback in a request path
///     exhausts workers long before it returns.
///
/// Absent from a cache means `Unknown`, so every spec authored before this
/// field existed keeps the honest wording rather than silently inheriting a
/// claim about a library nobody checked.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefaultBound {
    #[default]
    Unknown,
    None,
    Seconds {
        seconds: f64,
    },
}

/// WHY a call blocks: because bounding it was forgotten, or because waiting
/// IS the job (po-av01j.180).
///
/// `blocking = yes` plus `bounded_by = [none]` conflates two situations a
/// reader needs kept apart, and the corpus proves it: `requests.post` (an
/// actionable defect — I/O that should carry a timeout and does not) and
/// `uvicorn.run` (the server main loop, which blocks until the process is
/// killed, by design) carried the SAME two fields and so rendered the same
/// complaint. On the open-webui demo the by-design classes produced 4 of ~14
/// advisory rows, each asking for a deadline that would be meaningless.
///
/// The model answered accurately every time; the vocabulary had no way to
/// record the difference. This is that vocabulary.
///
/// TWO STATES, NOT THREE — deliberately unlike [`DefaultBound`], where
/// "unknown" and "none" license DIFFERENT sentences and so both had to exist.
/// Here "nobody asked" and "asked, and it is not by design" license the same
/// output: surface the finding exactly as today. A third state would be a
/// distinction the renderer could not honor, and every state that is not
/// `ByDesign` must fail safe to surfacing anyway — because a wrong by-design
/// marker HIDES a real defect, which is strictly worse than the noise it
/// removes. So the default is the safe one and the payload rides the one
/// variant that changes behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockingIntent {
    /// The call is MEANT to block indefinitely. There is no deadline to add,
    /// so there is no remediation to ask for.
    ///
    /// `role` is serde-defaulted so a `{"kind":"by_design"}` with no role
    /// degrades to [`DesignRole::Unrecognized`] — which suppresses nothing —
    /// instead of failing `SpecCache::load` for the whole artifact. The
    /// publish guard rejects that shape at authoring time; this is what
    /// happens if one reaches a binary anyway.
    ByDesign {
        #[serde(default)]
        role: DesignRole,
    },
    /// Blocking is a means to an end here: the call waits because it is doing
    /// I/O, and a bound belongs on it. The ordinary case, the serde default,
    /// and what an absent field means — so every cache authored before this
    /// existed behaves EXACTLY as it does today.
    ///
    /// `#[serde(other)]` as well as `#[default]`: a future `kind` this binary
    /// has never heard of lands here rather than failing `SpecCache::load` for
    /// the whole artifact, and lands on the side that still reports the
    /// finding. Forward compatibility that fails safe in the same direction.
    /// (Serde requires the catch-all to be the LAST variant, which is why the
    /// default is written second.)
    #[default]
    #[serde(other)]
    Incidental,
}

/// The closed vocabulary of reasons a call legitimately blocks forever.
///
/// Closed on purpose. An open string would let the authoring model invent a
/// category and let anything be marked by-design, and the publish guard could
/// not validate it. Extending this list is a deliberate code change with the
/// same review as any other spec semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesignRole {
    /// A server's own main loop: `uvicorn.run`, `app.run`, `srv.Serve`. It
    /// returns when the process is shut down and not before.
    ServerMainLoop,
    /// An event/scheduler loop run to completion: `loop.run_forever`.
    EventLoop,
    /// A blocking take from a queue or channel, where waiting for the next
    /// item IS the contract.
    BlockingQueue,
    /// A write to a process stream (`sys.stdout.write`, `sys.stderr.write`).
    /// It can technically block on a full pipe; a timeout is not the remedy
    /// and a finding on every log line is noise, not signal.
    StreamWrite,
    /// A role this binary does not recognize — only reachable by reading a
    /// NEWER corpus than the binary. Treated as not-by-design everywhere, so
    /// an unknown role reports the finding exactly as today: an old binary may
    /// print noise, but it may never hide a defect. The publish guard rejects
    /// this spelling at authoring time, so it cannot be chosen deliberately.
    #[serde(other)]
    Unrecognized,
}

/// The DEFAULT role is the unrecognized one, which is the only defensible
/// choice: a role that was never stated must not be filled in with a guess
/// that suppresses a finding. Every unstated, unreadable or future value lands
/// on "report it as before".
impl Default for DesignRole {
    fn default() -> Self {
        DesignRole::Unrecognized
    }
}

/// Marker that opens the propagation reason for a by-design site. The
/// propagation layer's reason strings are a consumed CONTRACT (coverage
/// bucketing string-matches them), so the format is defined here, next to the
/// [`by_design_label`] that reads it back, rather than spelled twice.
pub const BY_DESIGN_PREFIX: &str = "blocks by design: ";

/// Separates the class label from the explanation inside a by-design reason.
const BY_DESIGN_SEP: &str = " \u{2014} ";

impl DesignRole {
    /// How the role reads in a sentence.
    pub fn label(self) -> &'static str {
        match self {
            DesignRole::ServerMainLoop => "server main loop",
            DesignRole::EventLoop => "event loop",
            DesignRole::BlockingQueue => "blocking queue wait",
            DesignRole::StreamWrite => "stream write",
            DesignRole::Unrecognized => "unrecognized",
        }
    }
}

impl BlockingIntent {
    /// The role when this spec declares the call blocks by design, and the
    /// binary recognizes the role. `Unrecognized` answers `None` — the whole
    /// point of the fallback variant is that it must not suppress anything.
    pub fn by_design_role(self) -> Option<DesignRole> {
        match self {
            BlockingIntent::ByDesign { role } if role != DesignRole::Unrecognized => Some(role),
            _ => None,
        }
    }
}

/// The `<class> (<role>)` label out of a by-design reason, or None if the
/// reason is not one. The inverse of the format `spec_gate` writes, kept
/// beside it so the two cannot drift.
pub fn by_design_label(reason: &str) -> Option<&str> {
    let rest = reason.strip_prefix(BY_DESIGN_PREFIX)?;
    Some(rest.split(BY_DESIGN_SEP).next().unwrap_or(rest))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    pub method: String,
    pub blocking: Blocking,
    #[serde(default)]
    pub bounded_by: Vec<Mechanism>,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub site_count: u32,
    /// Which site kinds this spec governs (G3, po-av01j.4). Empty — every
    /// spec authored before site kinds existed — means the classic G1 client
    /// call site only (`Site::site_kind == ""`), so no existing spec silently
    /// widens onto job-registration sites. A spec that re-applies timeout/
    /// retry judgment at job altitude declares `["background_job"]`; one
    /// governing both altitudes lists both `""` and `"background_job"`.
    #[serde(default)]
    pub site_kinds: Vec<String>,
    /// Values of THIS API's call-argument timeout that mean "no bound"
    /// (po-av01j.25). Library knowledge, so it lives in the spec and never in
    /// propagation: `requests.get(timeout=None)` blocks forever,
    /// `socket.settimeout(0)` is non-blocking rather than bounded,
    /// `CURLOPT_TIMEOUT 0` never times out, JDBC's `setQueryTimeout(0)` means
    /// no limit. Which token carries that meaning differs per API, so the
    /// answer belongs to the API's own spec.
    ///
    /// Empty — every spec authored before this field existed — leaves the
    /// call-arg mechanism exactly as it was: a named timeout argument credits
    /// a whole-call bound. Declaring values makes the mechanism VALUE-AWARE
    /// (see the propagation arm), which is the only way a resolved sentinel
    /// stops reading as a bound.
    ///
    /// Values are the packet's canonical source-level rendering (`"0"`,
    /// `"None"`, `"-1"`, `"DateTime.MaxValue"`), string-compared like
    /// [`ConfigExpect::Equals`].
    #[serde(default)]
    pub unbounded_sentinels: Vec<String>,
    /// What this API does with NO explicit bound from the caller
    /// (po-av01j.175). Serde-defaulted to [`DefaultBound::Unknown`]: every
    /// cache predating the field parses unchanged, and a cache carrying the
    /// field loads in a pre-.175 binary with the field ignored — additive in
    /// both directions, so the envelope schema version does not move.
    ///
    /// It is DISPLAY knowledge, not verdict knowledge. Propagation still
    /// resolves a call with no bound in user code exactly as it did; what
    /// changes is that the sentence describing it can no longer claim a
    /// library behaviour nobody verified.
    #[serde(default)]
    pub default_bound: DefaultBound,
    /// Whether blocking here is the POINT of the call (po-av01j.180).
    /// Serde-defaulted to [`BlockingIntent::Incidental`]: every cache
    /// predating the field parses unchanged and keeps reporting exactly what
    /// it reports today, and a cache carrying the field loads in a pre-.180
    /// binary with the field ignored — additive in both directions, so the
    /// envelope schema version does not move.
    ///
    /// Unlike [`ApiSpec::default_bound`] this IS verdict knowledge: a
    /// by-design call is not-applicable to the deadline control, the same way
    /// a non-blocking call is, because there is no bound to add. The
    /// suppression is one-directional by construction — only an explicit,
    /// recognized `ByDesign` removes a row, so the failure mode of every
    /// missing, malformed or future value is the noise this field exists to
    /// remove, never a hidden defect.
    #[serde(default)]
    pub blocking_intent: BlockingIntent,
}

impl ApiSpec {
    /// Whether `value` is a declared unbounded sentinel for this API.
    ///
    /// Comparison is trimmed and ASCII-case-insensitive, deliberately more
    /// forgiving than exact equality: a loose match errs toward NOT crediting
    /// a bound, and on a safety property that is the only direction it is safe
    /// to be wrong in. A spec that declares nothing matches nothing, so the
    /// pre-sentinel behaviour is unchanged rather than merely similar.
    pub fn is_unbounded_sentinel(&self, value: &str) -> bool {
        let v = value.trim();
        self.unbounded_sentinels
            .iter()
            .any(|s| s.trim().eq_ignore_ascii_case(v))
    }

    /// Whether this spec governs a site of `site_kind`. The applicability
    /// mechanism for job-altitude re-application: the JUDGMENT machinery is
    /// unchanged, a spec merely declares which altitudes it covers.
    pub fn applies_to(&self, site_kind: &str) -> bool {
        if self.site_kinds.is_empty() {
            return site_kind.is_empty();
        }
        self.site_kinds.iter().any(|k| k == site_kind)
    }
}

/// What a config field actually bounds. The distinction is load-bearing: a
/// transport setting only dial and TLS-handshake timeouts bounds the connection
/// phase and leaves the response read unbounded, so calling it "bounded" is a
/// false pass. `net/http.Server` specced phase_only for the same reason:
/// WriteTimeout deadlines the connection write and never cancels the request
/// context, so the handler goroutine and its query keep running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bounds {
    WholeCall,
    PhaseOnly,
    Unrelated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ThisClient,
    ServedRequests,
    None,
}

/// A coarse client-I/O family. It scopes a repo-level client-config bound to
/// the calls it can plausibly govern: a DB pool's `query_timeout` bounds DB
/// queries, never an image tool's `taskTimeoutMillis` (measured on immich).
///
/// Classified mechanically from the type name (like `scope_of`), and
/// deliberately CONSERVATIVE: only strong, well-known markers classify; an
/// unrecognised type returns `None` and never borrows another family's bound —
/// a finding is left for a human rather than risk a cross-family false pass.
/// (The more general design is an authorer-assigned family tag on the spec;
/// this keyword classifier is the sound interim — see po-3t3oj.34.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    Database,
    Http,
    Cache,
    Rpc,
    MessageQueue,
}

/// Classify a client type into an I/O family, or `None` if unrecognised.
pub fn client_family(type_name: &str) -> Option<Family> {
    let t = type_name.to_ascii_lowercase();
    let has = |ks: &[&str]| ks.iter().any(|k| t.contains(k));
    // Database: ORMs, query builders, drivers, pools. Strong markers only —
    // bare "pool"/"pg" are excluded because a non-DB connection pool must not
    // borrow a DB timeout (false-negative risk the soundness pin forbids).
    if has(&[
        "typeorm",
        "kysely",
        "sequelize",
        "prisma",
        "mongoose",
        "mongodb",
        "datasource",
        "queryrunner",
        "pgxpool",
        "pgpool",
        "database/sql",
        "sqlplugin",
        "gocql",
        "xorm",
        "postgres",
        "mysql",
        "sqlite",
        "mssql",
        "cassandra",
        "clickhouse",
        "dynamodb",
    ]) {
        return Some(Family::Database);
    }
    if has(&["redis", "memcache", "ioredis", "valkey"]) {
        return Some(Family::Cache);
    }
    if has(&["grpc", "twirp", "thrift"]) {
        return Some(Family::Rpc);
    }
    if has(&[
        "amqp", "kafka", "rabbitmq", "sqs", "bullmq", "pubsub", "nats",
    ]) {
        return Some(Family::MessageQueue);
    }
    if has(&[
        "http",
        "axios",
        "gaxios",
        "got",
        "undici",
        "node-fetch",
        "httpclient",
        "restclient",
    ]) {
        return Some(Family::Http);
    }
    None
}

/// A G4 emission spec (po-av01j.5): what a matched emission aggregate MEANS
/// for an observability control. Like every spec, this is library/judgment
/// knowledge kept out of the retrievers: the emitter reports "17 slog.Logger
/// log calls in this function" and only a spec says that counts as error
/// monitoring, tracing, or neither.
///
/// `role` is what a match implies for the control:
///   - `"satisfies"`: presence of this emission shape is evidence the control
///     is implemented (a sentry capture for RC-027, an otel span for RC-046).
///   - `"violates"`: presence of this shape is evidence of a gap (an
///     `except_handler`/`catch_clause`/`recover_block` aggregate — an error
///     path that swallows with no capture or log emission).
///   - `"anchor"`: this CLIENT type marks a G1 call site the control governs
///     (RC-061: the LLM SDK call whose surroundings must emit telemetry).
///
/// A role this consumer does not recognize matches nothing — additive
/// degradation, mirroring `ConstArg::how`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionSpec {
    /// The identity the emitter stamped: a telemetry framework
    /// (`log/slog.Logger`, `winston.Logger`, `logging.Logger`), an
    /// error-path construct (`except_handler`), or — for `role: "anchor"` —
    /// a G1 client type (`openai.OpenAI`).
    #[serde(rename = "type")]
    pub type_name: String,
    /// The emission category the aggregate carries (`log` | `trace` |
    /// `error_capture`); empty for `anchor` specs, which match call sites.
    #[serde(default)]
    pub category: String,
    /// The control this spec serves: RC-027, RC-046, or RC-061.
    pub control: String,
    /// `satisfies` | `violates` | `anchor` — see the type docs.
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    pub bounds: Bounds,
    pub scope: Scope,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
    /// True when this spec is a repo-local `.revelara.yaml` bound declaration
    /// rather than a factory-authored spec. Runtime-only overlay state: never
    /// emitted by the factory, skipped on serialization, and used to carry the
    /// policy provenance into the finding's reason.
    #[serde(default, skip_serializing)]
    pub declared: bool,
}

/// Whether the control governs a scope at all. Judged once per scope class,
/// not per site: five answers cover every repository.
///
/// The canon these encode was corrected by human adjudication and is narrower
/// than it first looks. A migration may relax statement_timeout for DDL and
/// still needs SOME bound, so "no bound of any kind" is a finding. A backfill
/// is not exempt for being a backfill: it can saturate the database it reads,
/// and a hang is expensive when the work is not retryable or rollbackable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSpec {
    pub scope: String,
    /// False means the control does not apply here and the site satisfies by
    /// non-applicability.
    pub applies: bool,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
}

/// What satisfies a config-key spec. This is the factory's authoring grammar
/// for the G6 config lane, deliberately small and enumerable: every variant is
/// auditable by reading it, and there is no user-supplied regex to reason
/// about. Patterns are NAMED and resolved by the scanner (see the config
/// lane's pattern table); a name this binary does not know yields an
/// abstention, never a guess — that is how a spec authored for a newer scanner
/// degrades safely on an older one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConfigExpect {
    /// An EXPLICIT setting must be present in the repo. A platform default
    /// governing the key does not count: the control asks for an authored
    /// bound, and "the platform picked one for you" is the finding.
    Present,
    /// The resolved value must equal `value` (string-compared on the packet's
    /// canonical rendering).
    Equals { value: String },
    /// The resolved value must be one of `values`.
    OneOf { values: Vec<String> },
    /// The resolved value must match the NAMED pattern (e.g. "sha40" = a full
    /// 40-hex-char commit SHA, the action-pinning control).
    Pattern { name: String },
    /// The resolved value, parsed as a number, must be >= `value`
    /// (po-av01j.129).
    ///
    /// WHY THIS EXISTS RATHER THAN one_of. "replicas >= 2" was previously
    /// unstatable: `equals("1")` is backwards, since an expectation flags what
    /// does NOT match and would fire on every correctly-sized workload, and
    /// `one_of(["2","3",...])` breaks at any count outside the list. Authoring
    /// the class anyway produced the po-av01j.44 inversion, where a presence
    /// check on a PodDisruptionBudget PASSED the exact configuration that pins
    /// disruptionsAllowed at 0 and blocks node drain forever.
    ///
    /// A value that does not parse as a number ABSTAINS rather than failing:
    /// an unresolved template or an unexpected unit is not evidence of a
    /// violation.
    AtLeast { value: f64 },
    /// The resolved value, parsed as a number, must be <= `value`.
    AtMost { value: f64 },
}

/// A spec about one config key in one config format — the G6 analog of
/// [`ApiSpec`]. It answers a question about the FORMAT ("a GitHub Actions job
/// without an explicit timeout-minutes runs under the 6h platform default"),
/// never about a repository, so it is earned once and applies everywhere.
///
/// Unlike the call-site lane, where class judgment (severity/fix) lives in a
/// separate judgment file, a config-key spec IS its finding class: one spec is
/// one reader-facing class, so severity and fix ride on the spec. Empty means
/// unjudged, and unjudged findings surface as advisory, never blocking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigKeySpec {
    /// The config format id, e.g. "github-actions", "gitlab-ci".
    pub format: String,
    /// The canonical key identity within the format, e.g. "job.timeout-minutes".
    pub key: String,
    pub expect: ConfigExpect,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
    /// The control this key evidences (e.g. "RC-013"), empty if unmapped.
    #[serde(default)]
    pub control: String,
    /// Judged severity: high | medium | low | "" (unjudged).
    #[serde(default)]
    pub severity: String,
    /// Suggested fix for the explain view.
    #[serde(default)]
    pub fix: String,
}

/// The `kind` of a [`ServerSpec`]: route paths that count as a health-check
/// endpoint (RC-020).
pub const SERVER_KIND_HEALTH_PATH: &str = "health_path";
/// The `kind` of a [`ServerSpec`]: middleware/handler identities that
/// rate-limit (RC-069).
pub const SERVER_KIND_RATE_LIMIT: &str = "rate_limit_middleware";
/// The `kind` of a [`ServerSpec`]: middleware/handler identities that provide
/// a degraded-response path (RC-018, the G2 half).
pub const SERVER_KIND_DEGRADED_RESPONSE: &str = "degraded_response";

/// A spec for a control that rides the G2 server-entry lane (po-av01j.3).
///
/// Unlike an [`ApiSpec`] (a question about one API), a server spec carries the
/// JUDGEMENT patterns the server-entry evaluator matches against the
/// inventoried registrations: which route paths count as a health endpoint,
/// which middleware identities rate-limit, which provide degraded responses.
/// The retrievers stay neutral — they inventory registrations; what a path or
/// identity MEANS lives here, factory-authored like every other spec.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerSpec {
    /// Control code this spec serves ("RC-020" | "RC-069" | "RC-018").
    pub control: String,
    /// What the patterns match (`SERVER_KIND_*`). A string, not an enum, so a
    /// future factory adding a kind degrades to an ignored spec rather than a
    /// cache-wide parse failure.
    #[serde(default)]
    pub kind: String,
    /// Case-insensitive match targets: route paths for `health_path`,
    /// identity substrings for the middleware kinds.
    #[serde(default)]
    pub patterns: Vec<String>,

    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpecFile {
    #[serde(default)]
    pub apis: Vec<ApiSpec>,
    #[serde(default)]
    pub configs: Vec<ConfigSpec>,
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
    /// G6 config-lane specs. Serde-defaulted: caches predating the lane parse
    /// unchanged, and an old binary ignores the section (serde skips unknown
    /// fields), so the envelope schema version does not move.
    #[serde(default)]
    pub config_keys: Vec<ConfigKeySpec>,
    /// G2 server-entry control specs. Defaults empty: every cache predating
    /// the lane still loads, and the evaluator abstains without specs.
    #[serde(default)]
    pub server: Vec<ServerSpec>,
    /// G4 emission specs. Additive with a carrying default: every pre-G4
    /// cache loads with an empty list, and a cache carrying entries loads in
    /// a pre-G4 consumer with the field ignored — compatible both ways.
    #[serde(default)]
    pub emissions: Vec<EmissionSpec>,
}

/// What repo-level config imposes on served requests, if anything.
#[derive(Debug, Clone, PartialEq)]
pub enum ServedBound {
    /// Every applicable spec agrees.
    Agreed(Bounds),
    /// Specs disagree. Not resolved by picking a winner: taking the strongest
    /// is optimistic, and for a safety property optimism is the one bias you
    /// cannot afford. The affected sites abstain and a human decides.
    Conflict(Vec<String>),
    None,
}

#[derive(Debug, Default)]
pub struct SpecCache {
    apis: HashMap<(String, String), ApiSpec>,
    configs: HashMap<String, ConfigSpec>,
    scopes: HashMap<String, ScopeSpec>,
    config_keys: HashMap<(String, String), ConfigKeySpec>,
    server: Vec<ServerSpec>,
    emissions: Vec<EmissionSpec>,
}

impl SpecCache {
    pub fn load(text: &str) -> anyhow::Result<Self> {
        let f: SpecFile = serde_json::from_str(text)?;
        Ok(Self::from_file(f))
    }

    pub fn from_file(f: SpecFile) -> Self {
        let mut c = SpecCache::default();
        for a in f.apis {
            c.apis.insert((a.type_name.clone(), a.method.clone()), a);
        }
        for s in f.configs {
            c.configs.insert(s.type_name.clone(), s);
        }
        for s in f.scopes {
            c.scopes.insert(s.scope.clone(), s);
        }
        for s in f.config_keys {
            c.config_keys.insert((s.format.clone(), s.key.clone()), s);
        }
        c.server = f.server;
        c.emissions = f.emissions;
        c
    }

    /// The usable G2 server-entry specs: everything at or above the
    /// confidence floor. A shaky server spec is ignored entirely — it applies
    /// to every registration in the repo at once, the same multiplier that
    /// set [`MIN_CONFIDENCE`].
    pub fn server_specs(&self) -> impl Iterator<Item = &ServerSpec> {
        self.server
            .iter()
            .filter(|s| s.confidence >= MIN_CONFIDENCE)
    }

    /// True when the control does not govern this scope. Absent or
    /// low-confidence scope specs default to APPLYING: silently exempting a
    /// scope is how a real violation disappears, and three of five overturned
    /// verdicts in adjudication came from exemptions that were too broad.
    pub fn scope_exempt(&self, scope: &str) -> Option<&ScopeSpec> {
        self.scopes
            .get(scope)
            .filter(|s| !s.applies && s.confidence >= MIN_CONFIDENCE)
    }

    pub fn api(&self, key: &(String, String)) -> Option<&ApiSpec> {
        self.apis.get(key)
    }
    pub fn config(&self, type_name: &str) -> Option<&ConfigSpec> {
        self.configs.get(type_name)
    }
    /// The G6 config-lane lookup: the spec for one (format, key) identity.
    pub fn config_key(&self, format: &str, key: &str) -> Option<&ConfigKeySpec> {
        self.config_keys.get(&(format.to_string(), key.to_string()))
    }
    /// The G4 emission specs, for the emission lane's evaluator. A slice, not
    /// a keyed lookup: the lane's matches are (type, category, control, role)
    /// combinations and the corpus is small (tens of entries).
    pub fn emission_specs(&self) -> &[EmissionSpec] {
        &self.emissions
    }
    pub fn len(&self) -> usize {
        self.apis.len()
            + self.configs.len()
            + self.scopes.len()
            + self.config_keys.len()
            + self.server.len()
            + self.emissions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge another cache in, preferring the higher-confidence spec. This is
    /// what lets a shipped baseline cache be extended by locally-inferred specs
    /// without a human resolving every overlap.
    pub fn merge(&mut self, other: SpecCache) {
        for (k, v) in other.apis {
            match self.apis.get(&k) {
                Some(existing) if existing.confidence >= v.confidence => {}
                _ => {
                    self.apis.insert(k, v);
                }
            }
        }
        for (k, v) in other.configs {
            match self.configs.get(&k) {
                Some(existing) if existing.confidence >= v.confidence => {}
                _ => {
                    self.configs.insert(k, v);
                }
            }
        }
        for (k, v) in other.config_keys {
            match self.config_keys.get(&k) {
                Some(existing) if existing.confidence >= v.confidence => {}
                _ => {
                    self.config_keys.insert(k, v);
                }
            }
        }
        for v in other.server {
            match self
                .server
                .iter_mut()
                .find(|s| s.control == v.control && s.kind == v.kind)
            {
                Some(existing) if existing.confidence >= v.confidence => {}
                Some(existing) => *existing = v,
                None => self.server.push(v),
            }
        }
        // Emission specs merge on (type, category, control), preferring the
        // higher-confidence entry — same policy as apis/configs.
        for v in other.emissions {
            match self.emissions.iter_mut().find(|e| {
                e.type_name == v.type_name && e.category == v.category && e.control == v.control
            }) {
                Some(existing) if existing.confidence >= v.confidence => {}
                Some(existing) => *existing = v,
                None => self.emissions.push(v),
            }
        }
    }

    /// What the repo's own construction sites impose on served requests.
    pub fn served_bound(&self, cfg: &RepoConfig) -> ServedBound {
        let mut seen: Vec<(String, Bounds)> = Vec::new();
        for c in &cfg.constructions {
            let Some(spec) = self.config(&c.type_name) else {
                continue;
            };
            if spec.scope != Scope::ServedRequests || spec.confidence < MIN_CONFIDENCE {
                continue;
            }
            if matches!(spec.bounds, Bounds::WholeCall | Bounds::PhaseOnly)
                && !seen.iter().any(|(t, _)| t == &c.type_name)
            {
                seen.push((c.type_name.clone(), spec.bounds));
            }
        }
        match seen.len() {
            0 => ServedBound::None,
            _ => {
                let first = seen[0].1;
                if seen.iter().all(|(_, b)| *b == first) {
                    ServedBound::Agreed(first)
                } else {
                    ServedBound::Conflict(seen.iter().map(|(t, b)| format!("{t}={b:?}")).collect())
                }
            }
        }
    }

    /// What the repo's construction sites impose on calls made THROUGH their
    /// own clients (`this_client` scope) — the analog of `served_bound` for
    /// client config. A DB pool constructed with a whole-call `query_timeout`
    /// bounds every query issued on it, but for a DI-injected pool that
    /// construction is nowhere near the call site, so per-site retrieval can
    /// never see it. This is the repo-level fact that closes the gap.
    ///
    /// Deliberately conservative (soundness pin, po-3t3oj.30): `Agreed` only
    /// when every `this_client` whole/phase config in the repo agrees. If they
    /// conflict, this returns `Conflict` and the caller abstains rather than
    /// guessing which config governs a call — a false pass on a reliability
    /// property is the one error we refuse. `Agreed` is what licenses the
    /// guarded broadening to related DB-family calls; exact-type matches do not
    /// need it.
    /// Group the repo's `this_client` config constructions BY I/O family and
    /// resolve each family's bound independently. A DB pool's whole-call
    /// timeout governs the Database family; an image tool's timeout governs no
    /// recognised family and is dropped. A call is later broadened only by its
    /// OWN family's bound, so one client's timeout can never mask another's
    /// unbounded calls. Within a family: `Agreed` iff every construction agrees,
    /// else `Conflict` (abstain). Constructions whose type has no family are
    /// skipped — never a basis for broadening.
    pub fn client_bound_by_family(&self, cfg: &RepoConfig) -> HashMap<Family, ServedBound> {
        let mut by_family: HashMap<Family, Vec<(String, Bounds)>> = HashMap::new();
        for c in &cfg.constructions {
            let Some(spec) = self.config(&c.type_name) else {
                continue;
            };
            if spec.scope != Scope::ThisClient || spec.confidence < MIN_CONFIDENCE {
                continue;
            }
            if !matches!(spec.bounds, Bounds::WholeCall | Bounds::PhaseOnly) {
                continue;
            }
            let Some(fam) = client_family(&c.type_name) else {
                continue;
            };
            let seen = by_family.entry(fam).or_default();
            if !seen.iter().any(|(t, _)| t == &c.type_name) {
                seen.push((c.type_name.clone(), spec.bounds));
            }
        }
        by_family
            .into_iter()
            .map(|(fam, seen)| {
                let first = seen[0].1;
                let bound = if seen.iter().all(|(_, b)| *b == first) {
                    ServedBound::Agreed(first)
                } else {
                    ServedBound::Conflict(seen.iter().map(|(t, b)| format!("{t}={b:?}")).collect())
                };
                (fam, bound)
            })
            .collect()
    }
}

/// The verdict a spec forces on its own, before any evidence is searched.
/// Returns `None` when the site still has to be decided from evidence.
pub fn spec_gate(spec: Option<&ApiSpec>) -> Option<(Verdict, String)> {
    let Some(s) = spec else {
        return Some((Verdict::Abstain, "no spec for this API".into()));
    };
    match s.blocking {
        Blocking::No => Some((
            Verdict::NotApplicable,
            format!("spec: {} does not block", s.method),
        )),
        Blocking::Unknown => Some((Verdict::Abstain, "spec: API unrecognised".into())),
        // `depends` is not `yes`. sync.Once.Do blocks only if another goroutine
        // is running the wrapped function and inherits whatever that function
        // does; collapsing that to blocking produced a false violates on a site
        // a human confirmed was not applicable.
        Blocking::Depends => Some((
            Verdict::Abstain,
            "spec: blocking depends on the call; needs per-site judgement".into(),
        )),
        Blocking::Yes if s.confidence < MIN_CONFIDENCE => Some((
            Verdict::Abstain,
            format!("spec confidence {:.2} below {MIN_CONFIDENCE}", s.confidence),
        )),
        // The call blocks, and blocking is the POINT of it (po-av01j.180).
        // Resolved as NotApplicable for the same reason `Blocking::No` is:
        // there is no bound to look for, so searching for one and then
        // reporting its absence describes nothing the reader can act on.
        // `uvicorn.run` returns when the process is killed; a deadline on it
        // is not a fix, it is a shorter outage.
        //
        // Placed AFTER the confidence floor deliberately: a spec too shaky to
        // decide that the call blocks is too shaky to decide why it blocks,
        // and abstaining routes it to an author instead of silently removing
        // it from the report.
        Blocking::Yes => s.blocking_intent.by_design_role().map(|role| {
            (
                Verdict::NotApplicable,
                format!(
                    "{BY_DESIGN_PREFIX}{}.{} ({}){BY_DESIGN_SEP}waiting is the contract here, \
                     so no deadline is expected",
                    s.type_name,
                    s.method,
                    role.label(),
                ),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_core::ConfigFact;

    fn api(blocking: Blocking, confidence: f64) -> ApiSpec {
        ApiSpec {
            type_name: "t".into(),
            method: "Do".into(),
            blocking,
            bounded_by: vec![Mechanism::Context],
            confidence,
            rationale: String::new(),
            site_count: 1,
            site_kinds: vec![],
            unbounded_sentinels: vec![],
            default_bound: DefaultBound::Unknown,
            blocking_intent: BlockingIntent::Incidental,
        }
    }

    #[test]
    fn depends_routes_to_judgement_rather_than_asserting() {
        let (v, why) = spec_gate(Some(&api(Blocking::Depends, 0.9))).unwrap();
        assert_eq!(v, Verdict::Abstain);
        assert!(why.contains("depends"));
    }

    #[test]
    fn low_confidence_blocking_spec_abstains() {
        let (v, _) = spec_gate(Some(&api(Blocking::Yes, 0.55))).unwrap();
        assert_eq!(
            v,
            Verdict::Abstain,
            "a shaky spec applies to every site at once"
        );
        assert!(spec_gate(Some(&api(Blocking::Yes, 0.9))).is_none());
    }

    #[test]
    fn non_blocking_is_not_applicable_not_satisfies() {
        let (v, _) = spec_gate(Some(&api(Blocking::No, 0.9))).unwrap();
        assert_eq!(v, Verdict::NotApplicable);
    }

    #[test]
    fn missing_spec_abstains() {
        assert_eq!(spec_gate(None).unwrap().0, Verdict::Abstain);
    }

    fn cache(specs: Vec<(&str, Bounds, Scope, f64)>) -> SpecCache {
        SpecCache::from_file(SpecFile {
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
            apis: vec![],
            configs: specs
                .into_iter()
                .map(|(t, b, s, c)| ConfigSpec {
                    type_name: t.into(),
                    bounds: b,
                    scope: s,
                    confidence: c,
                    rationale: String::new(),
                    declared: false,
                })
                .collect(),
        })
    }

    fn repo(types: &[&str]) -> RepoConfig {
        RepoConfig {
            snapshot_id: "r".into(),
            constructions: types
                .iter()
                .map(|t| ConfigFact {
                    type_name: (*t).into(),
                    fields: vec!["Timeout".into()],
                    ..Default::default()
                })
                .collect(),
        }
    }

    #[test]
    fn conflicting_server_specs_are_not_resolved_by_taking_the_strongest() {
        // The real case: internal/config.ServerConfig merely HOLDS timeout
        // values and was specced whole_call, while net/http.Server actually
        // enforces them and was specced phase_only. Taking the max silently
        // turned "not really bounded" into a false pass.
        let c = cache(vec![
            (
                "cfg.ServerConfig",
                Bounds::WholeCall,
                Scope::ServedRequests,
                0.9,
            ),
            (
                "net/http.Server",
                Bounds::PhaseOnly,
                Scope::ServedRequests,
                0.9,
            ),
        ]);
        match c.served_bound(&repo(&["cfg.ServerConfig", "net/http.Server"])) {
            ServedBound::Conflict(v) => assert_eq!(v.len(), 2),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn agreeing_server_specs_are_used() {
        let c = cache(vec![(
            "net/http.Server",
            Bounds::PhaseOnly,
            Scope::ServedRequests,
            0.9,
        )]);
        assert_eq!(
            c.served_bound(&repo(&["net/http.Server"])),
            ServedBound::Agreed(Bounds::PhaseOnly)
        );
    }

    #[test]
    fn low_confidence_config_specs_are_ignored_entirely() {
        let c = cache(vec![(
            "net/http.Server",
            Bounds::WholeCall,
            Scope::ServedRequests,
            0.3,
        )]);
        assert_eq!(
            c.served_bound(&repo(&["net/http.Server"])),
            ServedBound::None
        );
    }

    #[test]
    fn merge_prefers_higher_confidence() {
        let mut base = SpecCache::from_file(SpecFile {
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
            apis: vec![api(Blocking::Yes, 0.7)],
            configs: vec![],
        });
        let mut better = api(Blocking::No, 0.95);
        better.rationale = "local".into();
        base.merge(SpecCache::from_file(SpecFile {
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
            apis: vec![better],
            configs: vec![],
        }));
        let got = base.api(&("t".into(), "Do".into())).unwrap();
        assert_eq!(got.blocking, Blocking::No);
        assert_eq!(got.rationale, "local");
    }
    #[test]
    fn config_key_specs_parse_from_a_spec_file_and_are_looked_up() {
        // The G6 lane's spec kind rides the SAME SpecFile the signed cache
        // carries. `config_keys` is serde-defaulted so every existing cache
        // (which lacks the section) still parses — the envelope schema does
        // not change.
        let text = r#"{
            "apis": [],
            "configs": [],
            "scopes": [],
            "config_keys": [
                {"format": "github-actions", "key": "job.timeout-minutes",
                 "expect": {"kind": "present"},
                 "confidence": 0.9, "control": "RC-013",
                 "rationale": "a job without an explicit timeout runs 6h"}
            ]
        }"#;
        let cache = SpecCache::load(text).unwrap();
        let spec = cache
            .config_key("github-actions", "job.timeout-minutes")
            .expect("the config-key spec is retrievable by (format, key)");
        assert_eq!(spec.control, "RC-013");
        assert!(matches!(spec.expect, ConfigExpect::Present));
        assert!(cache
            .config_key("github-actions", "job.concurrency")
            .is_none());
        // Counted in len() so the scan's "specs N" line reflects the lane.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn spec_file_without_config_keys_section_still_parses() {
        // Backward compatibility: the shipped 2026 caches have no config_keys.
        let cache = SpecCache::load(r#"{"apis": [], "configs": [], "scopes": []}"#).unwrap();
        assert!(cache
            .config_key("github-actions", "job.timeout-minutes")
            .is_none());
    }

    #[test]
    fn config_key_merge_prefers_higher_confidence() {
        let mk = |confidence: f64, rationale: &str| SpecFile {
            config_keys: vec![ConfigKeySpec {
                format: "github-actions".into(),
                key: "job.timeout-minutes".into(),
                expect: ConfigExpect::Present,
                confidence,
                rationale: rationale.into(),
                control: String::new(),
                severity: String::new(),
                fix: String::new(),
            }],
            ..Default::default()
        };
        let mut base = SpecCache::from_file(mk(0.7, "base"));
        base.merge(SpecCache::from_file(mk(0.95, "better")));
        assert_eq!(
            base.config_key("github-actions", "job.timeout-minutes")
                .unwrap()
                .rationale,
            "better"
        );
        base.merge(SpecCache::from_file(mk(0.5, "worse")));
        assert_eq!(
            base.config_key("github-actions", "job.timeout-minutes")
                .unwrap()
                .rationale,
            "better",
            "a lower-confidence spec never displaces a higher one"
        );
    }

    #[test]
    fn a_pre_sentinel_cache_parses_and_declares_nothing() {
        // Compatibility (po-av01j.25): every cache in production predates the
        // field. It must parse, and the resulting spec must match NO value --
        // not "match leniently", not "match zero" -- so propagation's call-arg
        // mechanism is bit-for-bit what it was.
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"requests","method":"get","blocking":"yes",
                 "bounded_by":["call_arg"],"confidence":0.9}],"configs":[]}"#,
        )
        .expect("a cache without the section must still parse");
        let spec = cache.api(&("requests".into(), "get".into())).unwrap();
        assert!(spec.unbounded_sentinels.is_empty());
        for v in ["0", "None", "-1", ""] {
            assert!(
                !spec.is_unbounded_sentinel(v),
                "an undeclared spec must match nothing, including {v:?}"
            );
        }
    }

    // --- default bounds: the library's own fallback (po-av01j.175) ---

    #[test]
    fn a_cache_without_the_default_bound_field_reads_as_unknown() {
        // Compatibility, direction one: every cache in production predates the
        // field. It must parse, and the resulting spec must claim NOTHING
        // about the library -- Unknown is what makes the renderer stop at the
        // half the search actually verified.
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"requests","method":"get","blocking":"yes",
                 "bounded_by":["call_arg"],"confidence":0.9}],"configs":[]}"#,
        )
        .expect("a cache without the field must still parse");
        let spec = cache.api(&("requests".into(), "get".into())).unwrap();
        assert_eq!(spec.default_bound, DefaultBound::Unknown);
    }

    #[test]
    fn the_three_default_bound_states_are_distinguishable_on_the_wire() {
        let cache = SpecCache::load(
            r#"{"apis":[
                 {"type":"requests","method":"get","blocking":"yes","confidence":0.9,
                  "default_bound":{"kind":"none"}},
                 {"type":"openai.OpenAI","method":"create","blocking":"yes","confidence":0.9,
                  "default_bound":{"kind":"seconds","seconds":600.0}},
                 {"type":"mystery","method":"call","blocking":"yes","confidence":0.9}
               ],"configs":[]}"#,
        )
        .unwrap();
        assert_eq!(
            cache
                .api(&("requests".into(), "get".into()))
                .unwrap()
                .default_bound,
            DefaultBound::None,
            "requests really does default to None; the spec must be able to say so"
        );
        assert_eq!(
            cache
                .api(&("openai.OpenAI".into(), "create".into()))
                .unwrap()
                .default_bound,
            DefaultBound::Seconds { seconds: 600.0 },
            "openai 3.1.0 ships DEFAULT_TIMEOUT read=600"
        );
        assert_eq!(
            cache
                .api(&("mystery".into(), "call".into()))
                .unwrap()
                .default_bound,
            DefaultBound::Unknown
        );
    }

    #[test]
    fn a_cache_carrying_default_bounds_still_loads_where_the_field_is_unknown() {
        // Compatibility, direction two: a NEW cache read by an OLD binary.
        // Serde skips unknown fields, so the section is inert rather than a
        // parse failure -- which is why the envelope schema version does not
        // move for this change. Simulated by parsing a spec that also carries
        // a field this binary has never heard of.
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"requests","method":"get","blocking":"yes","confidence":0.9,
                 "default_bound":{"kind":"none"},"some_future_field":{"a":1}}],
               "configs":[],"some_future_section":[{"x":1}]}"#,
        )
        .expect("unknown fields and sections must be ignored, not rejected");
        let spec = cache.api(&("requests".into(), "get".into())).unwrap();
        assert_eq!(spec.default_bound, DefaultBound::None);
    }

    #[test]
    fn merge_carries_the_winning_specs_default_bound() {
        // The default bound rides the api entry, so the existing merge policy
        // decides it: a stale spec must not leave its (possibly wrong) library
        // claim behind on the winner.
        let mk = |confidence: f64, db: DefaultBound| SpecFile {
            apis: vec![ApiSpec {
                default_bound: db,
                ..api(Blocking::Yes, confidence)
            }],
            ..Default::default()
        };
        let mut base = SpecCache::from_file(mk(0.7, DefaultBound::None));
        base.merge(SpecCache::from_file(mk(
            0.95,
            DefaultBound::Seconds { seconds: 600.0 },
        )));
        assert_eq!(
            base.api(&("t".into(), "Do".into())).unwrap().default_bound,
            DefaultBound::Seconds { seconds: 600.0 }
        );
        base.merge(SpecCache::from_file(mk(0.5, DefaultBound::Unknown)));
        assert_eq!(
            base.api(&("t".into(), "Do".into())).unwrap().default_bound,
            DefaultBound::Seconds { seconds: 600.0 },
            "a lower-confidence spec never displaces the winner's default bound"
        );
    }

    // --- blocking intent: waiting as the contract (po-av01j.180) ---

    /// Compatibility, direction one. Every cache in the fleet predates this
    /// field; each must parse and behave EXACTLY as it does today, which for
    /// this field means "surface the finding".
    #[test]
    fn a_cache_without_blocking_intent_reads_as_incidental() {
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"uvicorn","method":"run","blocking":"yes",
                 "bounded_by":["none"],"confidence":1.0}],"configs":[]}"#,
        )
        .expect("a cache without the field must still parse");
        let spec = cache.api(&("uvicorn".into(), "run".into())).unwrap();
        assert_eq!(spec.blocking_intent, BlockingIntent::Incidental);
        assert_eq!(
            spec.blocking_intent.by_design_role(),
            None,
            "absence must never suppress"
        );
        assert_eq!(
            spec_gate(Some(spec)),
            None,
            "and the site is still decided from evidence, exactly as before"
        );
    }

    /// Compatibility, direction two: a NEW cache in an OLD binary. Serde skips
    /// unknown fields, so the section is inert rather than a parse failure —
    /// which is why the envelope schema version does not move.
    #[test]
    fn an_unknown_field_alongside_blocking_intent_is_ignored_not_rejected() {
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"uvicorn","method":"run","blocking":"yes","confidence":1.0,
                 "blocking_intent":{"kind":"by_design","role":"server_main_loop"},
                 "some_future_field":{"a":1}}],
               "configs":[],"some_future_section":[{"x":1}]}"#,
        )
        .expect("unknown fields and sections must be ignored, not rejected");
        assert_eq!(
            cache
                .api(&("uvicorn".into(), "run".into()))
                .unwrap()
                .blocking_intent,
            BlockingIntent::ByDesign {
                role: DesignRole::ServerMainLoop
            }
        );
    }

    #[test]
    fn the_declared_roles_parse_and_read_as_english() {
        let cache = SpecCache::load(
            r#"{"apis":[
                 {"type":"uvicorn","method":"run","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"by_design","role":"server_main_loop"}},
                 {"type":"asyncio.AbstractEventLoop","method":"run_forever","blocking":"yes",
                  "confidence":1.0,"blocking_intent":{"kind":"by_design","role":"event_loop"}},
                 {"type":"queue.Queue","method":"get","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"by_design","role":"blocking_queue"}},
                 {"type":"sys.stdout","method":"write","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"by_design","role":"stream_write"}}
               ],"configs":[]}"#,
        )
        .unwrap();
        for (t, m, role, label) in [
            (
                "uvicorn",
                "run",
                DesignRole::ServerMainLoop,
                "server main loop",
            ),
            (
                "asyncio.AbstractEventLoop",
                "run_forever",
                DesignRole::EventLoop,
                "event loop",
            ),
            (
                "queue.Queue",
                "get",
                DesignRole::BlockingQueue,
                "blocking queue wait",
            ),
            (
                "sys.stdout",
                "write",
                DesignRole::StreamWrite,
                "stream write",
            ),
        ] {
            let spec = cache.api(&(t.into(), m.into())).unwrap();
            assert_eq!(spec.blocking_intent.by_design_role(), Some(role), "{t}.{m}");
            assert_eq!(role.label(), label);
        }
    }

    /// THE FIX. A by-design call resolves as not-applicable to the deadline
    /// control, the same way a non-blocking call does — so it never becomes a
    /// violation and never asks for a timeout that would be meaningless.
    #[test]
    fn a_by_design_spec_resolves_as_not_applicable_rather_than_violating() {
        let mut s = api(Blocking::Yes, 1.0);
        s.type_name = "uvicorn".into();
        s.method = "run".into();
        s.blocking_intent = BlockingIntent::ByDesign {
            role: DesignRole::ServerMainLoop,
        };
        let (v, why) = spec_gate(Some(&s)).expect("a by-design spec decides on its own");
        assert_eq!(v, Verdict::NotApplicable);
        assert!(v.is_resolved(), "and it is a CONCLUSION, not an abstention");
        assert!(why.starts_with(BY_DESIGN_PREFIX), "{why}");
        assert_eq!(
            by_design_label(&why),
            Some("uvicorn.run (server main loop)")
        );
        assert!(why.contains("waiting is the contract"), "{why}");
    }

    /// The regression that matters most: the genuine defects must be
    /// untouched. `requests` and `subprocess` carry no intent in the corpus,
    /// so they must still fall through to the evidence search.
    #[test]
    fn the_genuine_defect_classes_still_reach_the_evidence_search() {
        let cache = SpecCache::load(
            r#"{"apis":[
                 {"type":"requests","method":"post","blocking":"yes","bounded_by":["call_arg"],
                  "confidence":1.0,"default_bound":{"kind":"none"}},
                 {"type":"subprocess","method":"run","blocking":"yes","bounded_by":["call_arg"],
                  "confidence":1.0,"default_bound":{"kind":"none"}}
               ],"configs":[]}"#,
        )
        .unwrap();
        for (t, m) in [("requests", "post"), ("subprocess", "run")] {
            let spec = cache.api(&(t.into(), m.into())).unwrap();
            assert_eq!(spec.blocking_intent, BlockingIntent::Incidental);
            assert_eq!(
                spec_gate(Some(spec)),
                None,
                "{t}.{m} must still be decided from the evidence in the user's code"
            );
        }
    }

    /// Forward compatibility, and it fails in the SAFE direction. A newer
    /// corpus can carry a kind or a role this binary has never heard of; both
    /// must load, and both must leave the finding standing. An old binary may
    /// print noise; it may never hide a defect.
    #[test]
    fn an_unreadable_intent_never_suppresses_and_never_fails_the_artifact() {
        let cache = SpecCache::load(
            r#"{"apis":[
                 {"type":"a","method":"x","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"some_future_kind"}},
                 {"type":"b","method":"x","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"by_design","role":"some_future_role"}},
                 {"type":"c","method":"x","blocking":"yes","confidence":1.0,
                  "blocking_intent":{"kind":"by_design"}}
               ],"configs":[]}"#,
        )
        .expect("a future value must not take down the whole artifact");
        for t in ["a", "b", "c"] {
            let spec = cache.api(&(t.into(), "x".into())).unwrap();
            assert_eq!(
                spec.blocking_intent.by_design_role(),
                None,
                "{t}: an intent this binary cannot read must not suppress anything"
            );
            assert_eq!(spec_gate(Some(spec)), None, "{t}");
        }
    }

    /// A spec too shaky to decide that the call blocks is too shaky to decide
    /// WHY it blocks: it abstains and routes to an author, rather than
    /// silently removing the class from the report.
    #[test]
    fn a_low_confidence_by_design_spec_abstains_rather_than_suppressing() {
        let mut s = api(Blocking::Yes, 0.4);
        s.blocking_intent = BlockingIntent::ByDesign {
            role: DesignRole::ServerMainLoop,
        };
        let (v, why) = spec_gate(Some(&s)).unwrap();
        assert_eq!(v, Verdict::Abstain);
        assert_eq!(by_design_label(&why), None);
    }

    #[test]
    fn merge_carries_the_winning_specs_blocking_intent() {
        let mk = |confidence: f64, bi: BlockingIntent| SpecFile {
            apis: vec![ApiSpec {
                blocking_intent: bi,
                ..api(Blocking::Yes, confidence)
            }],
            ..Default::default()
        };
        let by_design = BlockingIntent::ByDesign {
            role: DesignRole::ServerMainLoop,
        };
        let mut base = SpecCache::from_file(mk(0.7, BlockingIntent::Incidental));
        base.merge(SpecCache::from_file(mk(0.95, by_design)));
        assert_eq!(
            base.api(&("t".into(), "Do".into()))
                .unwrap()
                .blocking_intent,
            by_design
        );
        base.merge(SpecCache::from_file(mk(0.5, BlockingIntent::Incidental)));
        assert_eq!(
            base.api(&("t".into(), "Do".into()))
                .unwrap()
                .blocking_intent,
            by_design,
            "a lower-confidence spec never displaces the winner's intent"
        );
    }

    /// The reason string is a consumed contract (coverage bucketing reads it),
    /// so the parser and the formatter are tested against each other.
    #[test]
    fn by_design_label_reads_back_only_a_by_design_reason() {
        assert_eq!(
            by_design_label("blocks by design: sys.stdout.write (stream write) \u{2014} waiting is the contract here, so no deadline is expected"),
            Some("sys.stdout.write (stream write)")
        );
        assert_eq!(
            by_design_label("no bound anywhere and the search was complete"),
            None
        );
        assert_eq!(by_design_label("spec: run does not block"), None);
    }

    #[test]
    fn declared_sentinels_parse_and_match_on_the_canonical_rendering() {
        let cache = SpecCache::load(
            r#"{"apis":[{"type":"requests","method":"get","blocking":"yes",
                 "bounded_by":["call_arg"],"confidence":0.9,
                 "unbounded_sentinels":["None","0"]}],"configs":[]}"#,
        )
        .unwrap();
        let spec = cache.api(&("requests".into(), "get".into())).unwrap();
        assert!(spec.is_unbounded_sentinel("None"));
        assert!(spec.is_unbounded_sentinel("0"));
        // Trimmed and case-insensitive on purpose: a loose match errs toward
        // NOT crediting a bound, the only safe direction on this property.
        assert!(spec.is_unbounded_sentinel(" none "));
        // A real timeout is still a real timeout.
        assert!(!spec.is_unbounded_sentinel("5"));
        assert!(!spec.is_unbounded_sentinel("None()"));
    }

    #[test]
    fn merge_carries_the_winning_specs_sentinels() {
        // Sentinels ride the api entry, so the merge policy that already
        // decides which spec wins decides which sentinel list is in effect --
        // a stale spec must not leave its knowledge behind on the winner.
        let mk = |confidence: f64, sentinels: Vec<String>| SpecFile {
            apis: vec![ApiSpec {
                unbounded_sentinels: sentinels,
                ..api(Blocking::Yes, confidence)
            }],
            ..Default::default()
        };
        let mut base = SpecCache::from_file(mk(0.7, vec![]));
        base.merge(SpecCache::from_file(mk(0.95, vec!["0".into()])));
        assert!(base
            .api(&("t".into(), "Do".into()))
            .unwrap()
            .is_unbounded_sentinel("0"));
        base.merge(SpecCache::from_file(mk(0.5, vec!["-1".into()])));
        let got = base.api(&("t".into(), "Do".into())).unwrap();
        assert!(
            got.is_unbounded_sentinel("0") && !got.is_unbounded_sentinel("-1"),
            "a lower-confidence spec never displaces the winner's sentinels"
        );
    }

    #[test]
    fn spec_applicability_defaults_to_classic_call_sites_only() {
        // G3 (po-av01j.4): every existing spec was authored against G1 client
        // call sites. An undeclared site_kinds list must therefore keep the
        // spec scoped to classic sites — silently re-applying a call-site spec
        // to a background-job registration would multiply an unreviewed
        // judgment across a surface it never covered.
        let s = api(Blocking::Yes, 0.9);
        assert!(s.applies_to(""), "default specs govern classic call sites");
        assert!(
            !s.applies_to("background_job"),
            "a spec that never declared job-altitude applicability must not decide job sites"
        );
    }

    #[test]
    fn emission_specs_merge_on_identity_preferring_confidence() {
        let e = |conf: f64, rationale: &str| EmissionSpec {
            type_name: "log/slog.Logger".into(),
            category: "log".into(),
            control: "RC-061".into(),
            role: "satisfies".into(),
            confidence: conf,
            rationale: rationale.into(),
        };
        let mut base = SpecCache::from_file(SpecFile {
            apis: vec![],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![e(0.7, "base")],
        });
        base.merge(SpecCache::from_file(SpecFile {
            apis: vec![],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![
                e(0.9, "better"),
                EmissionSpec {
                    type_name: "except_handler".into(),
                    category: "error_capture".into(),
                    control: "RC-027".into(),
                    role: "violates".into(),
                    confidence: 0.9,
                    rationale: "new".into(),
                },
            ],
        }));
        let specs = base.emission_specs();
        assert_eq!(specs.len(), 2, "same identity merges, new identity appends");
        let slog = specs
            .iter()
            .find(|s| s.type_name == "log/slog.Logger")
            .unwrap();
        assert_eq!(slog.rationale, "better", "higher confidence wins");
    }

    #[test]
    fn emission_specs_load_from_the_spec_file() {
        // G4 (po-av01j.5): the spec file gains an additive `emissions` list.
        // Old caches (no field) load with an empty list; a cache carrying
        // entries exposes them through the accessor and counts them in len().
        let text = r#"{
            "apis": [],
            "configs": [],
            "emissions": [
                {"type": "log/slog.Logger", "category": "log", "control": "RC-027",
                 "role": "satisfies", "confidence": 0.9, "rationale": "structured log emission"},
                {"type": "except_handler", "category": "error_capture", "control": "RC-027",
                 "role": "violates", "confidence": 0.9,
                 "rationale": "an error path with no emission swallows the failure"}
            ]
        }"#;
        let cache = SpecCache::load(text).expect("emissions must parse");
        assert_eq!(cache.len(), 2, "emission specs count toward the cache size");
        let specs = cache.emission_specs();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].type_name, "log/slog.Logger");
        assert_eq!(specs[0].role, "satisfies");
        assert_eq!(specs[1].role, "violates");

        let empty = SpecCache::load(r#"{"apis":[],"configs":[]}"#).unwrap();
        assert!(
            empty.emission_specs().is_empty(),
            "a pre-G4 cache has no emission specs"
        );
    }

    #[test]
    fn config_expect_serde_round_trips_every_variant() {
        // The expect grammar is the factory's authoring contract; a variant
        // that cannot round-trip would corrupt the signed cache silently.
        let variants = vec![
            ConfigExpect::Present,
            ConfigExpect::Equals {
                value: "false".into(),
            },
            ConfigExpect::OneOf {
                values: vec!["a".into(), "b".into()],
            },
            ConfigExpect::Pattern {
                name: "sha40".into(),
            },
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ConfigExpect = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back, "{json}");
        }
    }

    #[test]
    fn declared_site_kinds_scope_the_spec_exactly() {
        let mut job_only = api(Blocking::Yes, 0.9);
        job_only.site_kinds = vec!["background_job".into()];
        assert!(job_only.applies_to("background_job"));
        assert!(
            !job_only.applies_to(""),
            "a job-altitude spec must not leak onto classic call sites"
        );

        // Both altitudes, declared explicitly: "" is the classic call site.
        let mut both = api(Blocking::Yes, 0.9);
        both.site_kinds = vec![String::new(), "background_job".into()];
        assert!(both.applies_to("") && both.applies_to("background_job"));
        assert!(
            !both.applies_to("server_entry"),
            "undeclared kinds stay out"
        );
    }

    #[test]
    fn server_specs_ride_the_spec_file_and_low_confidence_ones_are_ignored() {
        // G2 (po-av01j.3): the controls that ride the server-entry lane
        // (RC-020 health checks, RC-069 rate limiting, RC-018 degraded
        // response) are spec-driven like everything else. A spec below the
        // confidence floor decides nothing — spec error is multiplied.
        let text = r#"{
            "apis": [], "configs": [],
            "server": [
                {"control":"RC-020","kind":"health_path",
                 "patterns":["/healthz","/health"],
                 "confidence":0.9,"rationale":"seed"},
                {"control":"RC-069","kind":"rate_limit_middleware",
                 "patterns":["ratelimit"],
                 "confidence":0.3,"rationale":"too shaky to apply"}
            ]
        }"#;
        let cache = SpecCache::load(text).unwrap();
        let usable: Vec<_> = cache.server_specs().collect();
        assert_eq!(usable.len(), 1, "the 0.3-confidence spec must be ignored");
        assert_eq!(usable[0].control, "RC-020");
        assert_eq!(usable[0].kind, SERVER_KIND_HEALTH_PATH);
        assert_eq!(usable[0].patterns, vec!["/healthz", "/health"]);
    }

    #[test]
    fn a_spec_file_without_a_server_section_still_loads() {
        // Every production cache today predates the section; it must default.
        let cache = SpecCache::load(r#"{"apis":[],"configs":[]}"#).unwrap();
        assert_eq!(cache.server_specs().count(), 0);
    }

    #[test]

    fn client_family_classifies_the_real_corpus_types() {
        use super::{client_family, Family};
        // DB configs + calls (twenty/immich): must classify Database.
        for t in [
            "typeorm.QueryRunner",
            "typeorm.Repository",
            "typeorm.DataSource",
            "GlobalWorkspaceDataSource",
            "kysely.RawBuilder",
            "kysely.SelectQueryBuilder",
            "github.com/jackc/pgx/v5/pgxpool.Pool",
            "database/sql.Tx",
        ] {
            assert_eq!(client_family(t), Some(Family::Database), "{t}");
        }
        // Non-DB clients that carry timeouts (immich/twenty) must NOT be Database.
        for t in [
            "ExifTool",
            "PendingEvents",
            "imapflow.ImapFlow",
            "E2BDriver",
            "sharp.Sharp",
        ] {
            assert_ne!(client_family(t), Some(Family::Database), "{t}");
        }
        assert_eq!(client_family("axios.AxiosInstance"), Some(Family::Http));
        assert_eq!(client_family("ioredis.Redis"), Some(Family::Cache));
    }
}
