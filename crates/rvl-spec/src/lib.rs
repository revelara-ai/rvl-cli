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
}

impl ApiSpec {
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpecFile {
    #[serde(default)]
    pub apis: Vec<ApiSpec>,
    #[serde(default)]
    pub configs: Vec<ConfigSpec>,
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
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
        c
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
    pub fn len(&self) -> usize {
        self.apis.len() + self.configs.len() + self.scopes.len()
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
        Blocking::Yes => None,
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
            apis: vec![api(Blocking::Yes, 0.7)],
            configs: vec![],
        });
        let mut better = api(Blocking::No, 0.95);
        better.rationale = "local".into();
        base.merge(SpecCache::from_file(SpecFile {
            scopes: vec![],
            apis: vec![better],
            configs: vec![],
        }));
        let got = base.api(&("t".into(), "Do".into())).unwrap();
        assert_eq!(got.blocking, Blocking::No);
        assert_eq!(got.rationale, "local");
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
