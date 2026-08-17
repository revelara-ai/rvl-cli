//! Shared types for the reliability scanner.
//!
//! These mirror the JSON contract the per-language retrievers already emit
//! (`tools/goindex`, `tools/pyindex`), deliberately field-for-field. The
//! contract is the boundary that keeps the architecture honest: retrievers emit
//! SOURCE and structural facts, never verdicts, so adding a language costs
//! compiler-frontend work and no reliability judgement. That rule was violated
//! twice in the Python prototype and both times produced a matcher that failed
//! its own sanity check.

pub mod flag;

use serde::{Deserialize, Serialize};

/// Semver comparison shared by every surface that reports version drift:
/// plugin content (`rvl-skills`) and the CLI update nag (`rvl-data`). It
/// lives in this leaf crate for the same reason [`BIN`] does — so both can
/// reach it without one depending on the other, and so the two surfaces can
/// never disagree about what "newer" means.
pub mod semver;

/// The binary name used in user-facing hints ("run 'rvl login'").
/// Flipped from "rvlscan" to "rvl" at the v1.0.0 cutover (po-av01j.154).
///
/// It lives in this leaf crate, not in `rvl-data`, so that every crate that
/// prints a hint can reach it without taking a dependency on the data
/// commands. `rvl_data::BIN` re-exports it, so the ~57 existing call sites
/// are unaffected. Never hardcode the name at a call site: a hardcoded name
/// is what made the rename a 341-site sweep instead of a one-line change.
pub const BIN: &str = "rvl";

/// The packet contract version this consumer understands. It MUST agree with
/// the emitters' constants (goindex `PacketSchema`, pyindex `PACKET_SCHEMA`,
/// tsindex `PACKET_SCHEMA`); each helper prints its version via
/// `--packet-schema` so a consumer can negotiate before paying for a load.
///
/// v2 adds `const_args` (constant-valued arguments at the call site) and
/// `macro_expansion` (per-site macro flag; C/C++ mechanical, other languages
/// false/absent). v2 is a strict superset of v1: every v1 record parses as v2
/// with the new fields defaulted, so v1 streams remain readable.
///
/// `site_kind` (G4, po-av01j.5) rides the v2 train WITHOUT a version bump: v2
/// is unreleased, and the field is additive with a carrying default (absent =
/// classic G1 call site), so every existing stream parses unchanged.
pub const PACKET_SCHEMA: u32 = 2;

/// The `site_kind` value stamped on emission-point packets (G4): log
/// statements, span/trace instrumentation, and error-handling sites. An empty
/// `site_kind` remains the classic G1 client-call site.
pub const SITE_KIND_EMISSION: &str = "emission_point";

/// The `const_args` entry name carrying an emission aggregate's category
/// (`log` | `trace` | `error_capture`). Emission packets are AGGREGATES — one
/// per (enclosing function, framework, category), never one per log line —
/// and the category and count ride `const_args` (with `how: "aggregate"`)
/// rather than new fields, keeping the addition to the v2 train minimal.
pub const CONST_ARG_EMISSION_CATEGORY: &str = "emission_category";

/// The `const_args` entry name carrying how many emission calls the aggregate
/// stands for. Log statements are the highest-volume site class in any
/// codebase; the count is the volume-control contract (a large backend repo
/// must not produce tens of thousands of emission Sites).
pub const CONST_ARG_EMISSION_COUNT: &str = "emission_count";

/// Go marshals a nil slice as JSON `null`, not `[]`, and serde's `default`
/// attribute only covers a MISSING field, not a present-but-null one. Without
/// this, 821 of 1525 real production records failed to parse and the scanner
/// silently examined 46% of the repository. The same nil-slice trap cost a
/// wrong headline number once already in the Python prototype; here the
/// unparseable-line count in the harness caught it immediately.
fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// A verdict about one call site.
///
/// `NotApplicable` is not a flavour of `Satisfies`. A site that performs no
/// blocking I/O was never a candidate, and folding the two together teaches
/// downstream that in-memory lookups are compliant I/O. Kept separate, its rate
/// measures the candidate extractor's precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Violates,
    Satisfies,
    Abstain,
    NotApplicable,
}

impl Verdict {
    /// Whether this verdict carries a usable label. Abstentions are scanner
    /// input, not training rows; NotApplicable belongs in the extractor's
    /// precision report.
    pub fn is_decided(self) -> bool {
        matches!(self, Verdict::Violates | Verdict::Satisfies)
    }
    /// Whether the scanner reached a conclusion for this site: a bounded or
    /// unbounded blocking call, OR a non-blocking one (`NotApplicable`). This is
    /// the human-facing "resolved" notion, broader than `is_decided` (which is
    /// blocking-only for the eval/precision report). A non-blocking call the
    /// spec resolved is handled, not an abstention, so it belongs here.
    pub fn is_resolved(self) -> bool {
        matches!(
            self,
            Verdict::Violates | Verdict::Satisfies | Verdict::NotApplicable
        )
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Violates => "violates",
            Verdict::Satisfies => "satisfies",
            Verdict::Abstain => "abstain",
            Verdict::NotApplicable => "not_applicable",
        }
    }
}

/// A constant-valued argument observed at a call site (schema v2).
///
/// This is RETRIEVAL: the emitter reports that an argument's value is knowable
/// without running the program, and how it was determined. What the value MEANS
/// (CURLOPT_TIMEOUT vs CURLOPT_URL, timeout=0 as "no timeout") is library
/// knowledge and belongs to the spec layer. Emitters resolve only literals and
/// cheaply-resolvable named constants — no deep constant propagation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstArg {
    /// Zero-based position of the argument at the call site as written.
    #[serde(default)]
    pub index: u32,
    /// Keyword/parameter name when the language surface provides one
    /// (`timeout=5` in Python), `""` for purely positional arguments.
    #[serde(default)]
    pub name: String,
    /// Source-level rendering of the resolved value (language-specific:
    /// `"5"`, `"'x'"`, `"2000000000"` for a folded Go constant expression).
    #[serde(default)]
    pub value: String,
    /// How the value was determined: `"literal"` for a literal token at the
    /// call, `"named_constant"` for a resolved constant reference or folded
    /// constant expression. A string, not an enum, so a future emitter adding
    /// a mechanism degrades to an unrecognized label rather than a parse
    /// failure.
    #[serde(default)]
    pub how: String,
}

/// A piece of retrieved source with enough provenance to cite it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snippet {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub source: String,
}

/// A function the upward walk stopped at because nothing in the repository
/// calls it. Whether that makes it a genuine program entrypoint is a JUDGEMENT
/// and belongs downstream; these are the structural facts it needs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RootFact {
    #[serde(default)]
    pub symbol: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub exported: bool,
    #[serde(default)]
    pub in_package_main: bool,
    #[serde(default)]
    pub referenced_as_value: u32,
    /// Python's dominant indirect-invocation idiom. Raw source, unclassified.
    #[serde(default, deserialize_with = "null_as_default")]
    pub decorators: Vec<String>,
}

/// What the retriever looked at and what it had to leave out. Metadata about
/// the SEARCH, never a claim about the code. This is what licenses reasoning
/// from absence: a complete walk that found no deadline is evidence, a
/// truncated one is not.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default)]
    pub callers_total: u32,
    #[serde(default)]
    pub callers_included: u32,
    #[serde(default)]
    pub callees_total: u32,
    #[serde(default)]
    pub callees_included: u32,
    #[serde(default)]
    pub ancestry_depth_searched: u32,
    #[serde(default, deserialize_with = "null_as_default")]
    pub chain_roots: Vec<RootFact>,
    #[serde(default)]
    pub hit_depth_cap: bool,
    #[serde(default)]
    pub hit_caller_budget: bool,
    #[serde(default)]
    pub client_type_resolved: bool,
    /// Python only: how many definitions the callee name matched. Ambiguity is
    /// the normal case without static types, so it is reported rather than
    /// silently inherited.
    #[serde(default)]
    pub callee_candidates: u32,

    /// The context question, counted over the WHOLE traced ancestry rather than
    /// the budget-limited slice that gets emitted. How many callers were shown
    /// is an artefact of the byte budget; how many establish a deadline is the
    /// evidence, and 12 of 25 human adjudications came down to exactly this.
    #[serde(default)]
    pub ancestors_traced: u32,
    #[serde(default)]
    pub ancestors_with_deadline: u32,
    #[serde(default)]
    pub enclosing_takes_context: bool,
    /// Direct callers resolved by DATAFLOW: how many pass a ctx traced to a
    /// context.WithTimeout, out of how many were checked. Unlike
    /// ancestors_with_deadline, this asks whether the ctx ARRIVING here is
    /// bounded rather than whether the caller's body mentions a deadline
    /// anywhere, which main() does in almost every Go program.
    #[serde(default)]
    pub direct_callers: u32,
    #[serde(default)]
    pub direct_callers_passing_bounded_ctx: u32,
}

/// What the traced ancestry says about the context reaching a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxEvidence {
    /// Every traced path establishes a deadline first.
    AllBounded,
    /// Some paths do and some do not: the unbounded ones are real exposure.
    Mixed { bounded: u32, total: u32 },
    /// No traced path establishes one.
    NoneBounded,
    /// Nothing was traced, so the ancestry says nothing either way.
    Unknown,
}

impl Provenance {
    /// True when the search ended by exhausting the graph rather than by
    /// running out of budget. Only then does "no bound found" mean "no bound".
    pub fn complete(&self) -> bool {
        !self.hit_depth_cap && !self.hit_caller_budget
    }

    /// What DATAFLOW says about the ctx arriving at this call. Uses the direct
    /// callers only: tracing a ctx through many frames needs interprocedural
    /// summaries, whereas one hop is where the evidence is and is sound.
    pub fn ctx_evidence(&self) -> CtxEvidence {
        if self.direct_callers == 0 {
            return CtxEvidence::Unknown;
        }
        if self.direct_callers_passing_bounded_ctx == 0 {
            CtxEvidence::NoneBounded
        } else if self.direct_callers_passing_bounded_ctx == self.direct_callers {
            CtxEvidence::AllBounded
        } else {
            CtxEvidence::Mixed {
                bounded: self.direct_callers_passing_bounded_ctx,
                total: self.direct_callers,
            }
        }
    }
}

/// One call site plus every piece of source bearing on it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Site {
    #[serde(default)]
    pub snapshot_id: String,
    #[serde(default)]
    pub file_path: String,
    #[serde(default)]
    pub line_number: u32,
    #[serde(default)]
    pub symbol: String,
    #[serde(rename = "func", default)]
    pub method: String,
    #[serde(default)]
    pub receiver: String,
    #[serde(default)]
    pub client_type: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub enclosing_function_body: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub callers: Vec<Snippet>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub callees: Vec<Snippet>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub client_construction: Vec<Snippet>,
    #[serde(default)]
    pub provenance: Provenance,
    #[serde(default)]
    pub lang: String,
    /// Present on the repo-scoped record that rides in the same stream.
    /// Skipped when absent so a Site serialized by an in-workspace emitter
    /// (rustindex) matches the sibling helpers' wire shape exactly — G1
    /// records carry no `kind` field at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The contract version the emitter stamped on this record (0 when the
    /// stream predates stamping). `parse_stream` refuses records stamped with
    /// a version newer than [`PACKET_SCHEMA`].
    #[serde(default)]
    pub packet_schema: u32,
    /// Schema v2: constant-valued arguments observed at this call site.
    /// Evidence, never a verdict — the libcurl/POSIX discrimination lives in
    /// enum constants like CURLOPT_TIMEOUT, and the TS pool-timeout precision
    /// fix needed exactly this shape.
    #[serde(default, deserialize_with = "null_as_default")]
    pub const_args: Vec<ConstArg>,
    /// Schema v2: whether this site sits inside a macro expansion. Mechanical
    /// for C/C++ (expansion locations); other languages emit false/absent.
    #[serde(default)]
    pub macro_expansion: bool,
    /// Which KIND of site this record inventories. Empty (the default) is the
    /// classic G1 client-call site every existing emitter produces, so v1/v2
    /// G1 streams parse unchanged — an additive default-carrying field within
    /// the v2 train, deliberately NOT a schema bump. G2+ emitters stamp their
    /// own kind: [`SITE_KIND_SERVER_ENTRY`] for HTTP handler/route/middleware
    /// registrations (po-av01j.3), `"background_job"` for G3 scheduler/cron
    /// registrations, queue worker handlers, and dispatcher/worker-loop sites
    /// (po-av01j.4), [`SITE_KIND_EMISSION`] for G4 emission points
    /// (po-av01j.5). Retrieval only: the retriever reports WHERE the site is;
    /// whether a control governs that kind is spec knowledge
    /// (`ApiSpec::site_kinds`), and each kind is judged by its own lane so G1
    /// specs never fire on a server-entry site or vice versa.
    #[serde(default)]
    pub site_kind: String,
    /// Scope assigned from REPO EVIDENCE rather than from the path alone: a
    /// declaration in the project's own manifest (a hatchling build hook named
    /// by `pyproject.toml`), or a layout fact no path substring can express (a
    /// root-level script nothing in the repo references). Set by the scan
    /// pipeline before propagation; `None` means "no evidence was found, so
    /// the path decides" and is the only state a retriever ever emits.
    ///
    /// Read through [`Site::scope`], never directly: every consumer must get
    /// the same answer, and half of them only hold a `Site` (po-av01j.173).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_override: Option<ScopeClass>,
}

/// The `site_kind` a G2 server-entry record carries: an HTTP handler, route,
/// or middleware-chain registration inventoried by a typed retriever.
pub const SITE_KIND_SERVER_ENTRY: &str = "server_entry";

impl Site {
    pub fn id(&self) -> String {
        format!("{}:{}", self.file_path, self.line_number)
    }
    /// A classic G1 client-call site (empty `site_kind`, the pre-G4 default).
    pub fn is_call_site(&self) -> bool {
        self.site_kind.is_empty()
    }
    /// A G4 emission-point aggregate (log/trace/error-capture inventory).
    pub fn is_emission_point(&self) -> bool {
        self.site_kind == SITE_KIND_EMISSION
    }
    /// The emission aggregate's category (`log` | `trace` | `error_capture`),
    /// read from the [`CONST_ARG_EMISSION_CATEGORY`] const-args entry. `None`
    /// on call sites and on malformed emission packets — the caller abstains
    /// rather than guessing a category.
    pub fn emission_category(&self) -> Option<&str> {
        self.const_args
            .iter()
            .find(|a| a.name == CONST_ARG_EMISSION_CATEGORY)
            .map(|a| a.value.as_str())
    }
    /// How many emission calls this aggregate stands for, read from the
    /// [`CONST_ARG_EMISSION_COUNT`] const-args entry. Defaults to 1: an
    /// aggregate exists because at least one emission call did.
    pub fn emission_count(&self) -> u32 {
        self.const_args
            .iter()
            .find(|a| a.name == CONST_ARG_EMISSION_COUNT)
            .and_then(|a| a.value.parse().ok())
            .unwrap_or(1)
    }
    /// Unique per site: `file:line:client_type:method`. `id()` (`file:line`) is
    /// NOT unique -- chained calls (`db.selectFrom(...).select(...).execute()`)
    /// put several distinct sites on one line -- so anything that rematches a
    /// verdict back to its site (triage) must key on this, or it grabs the
    /// wrong call and mislabels the finding. Mirrors `rvl_index::site_key`.
    pub fn site_key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.file_path, self.line_number, self.client_type, self.method
        )
    }
    pub fn api_key(&self) -> (String, String) {
        let t = if self.client_type.is_empty() {
            "?".to_string()
        } else {
            self.client_type.clone()
        };
        (t, self.method.clone())
    }
    /// Where this site lives. Repo evidence first ([`Site::scope_override`]),
    /// the path second ([`scope_of`]). THE ONLY correct way to ask: reading
    /// `scope_of(&site.file_path)` directly skips the evidence and re-files a
    /// declared build hook as Runtime.
    pub fn scope(&self) -> ScopeClass {
        self.scope_override
            .unwrap_or_else(|| scope_of(&self.file_path))
    }

    /// All source in scope of this site: the enclosing function plus every
    /// retrieved caller and callee. Deadlines are established above and below.
    pub fn scope_source(&self) -> String {
        let mut s = self.enclosing_function_body.clone();
        for c in self.callers.iter().chain(self.callees.iter()) {
            s.push('\n');
            s.push_str(&c.source);
        }
        s
    }
}

/// A mechanical classification of where a site lives, derived from its path and
/// nothing else. This is RETRIEVAL: it reports an observable fact ("this path
/// contains /migrations/"), never a conclusion ("therefore exempt"). Whether a
/// scope is governed by the control is a judgement and lives in a ScopeSpec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeClass {
    Runtime,
    Migration,
    TestSupport,
    DevOnly,
    Backfill,
}

impl ScopeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeClass::Runtime => "runtime",
            ScopeClass::Migration => "migration",
            ScopeClass::TestSupport => "test_support",
            ScopeClass::DevOnly => "dev_only",
            ScopeClass::Backfill => "backfill",
        }
    }
}

/// Filenames whose meaning is fixed by a tool's SPECIFICATION, not by
/// convention or by where they sit: `setup.py` is setuptools' build script
/// (the legacy PEP 517 entry point, executed by the packaging frontend), and
/// `noxfile.py` is nox's configuration file, read only by the `nox` runner.
/// Neither is importable product code in any project that follows the spec,
/// so an unbounded `subprocess` call in one blocks a BUILD, never a request.
///
/// Deliberately short. Every name here is a name a tool DEFINES; convention
/// alone is not enough, because a false dev_only hides a real finding. Two
/// names that look like they belong and do not:
///   - `tasks.py` — invoke's default, and equally Celery's/RQ's conventional
///     task module. Demoting it would exempt production worker code, which is
///     precisely the surface an unbounded call hurts most.
///   - `hatch_build.py` — a name hatchling only honours when pyproject.toml
///     declares it (see the scan pipeline's `devscope` lane). Undeclared, it
///     is an ordinary module and stays Runtime.
///
/// (`conftest.py`, pytest's fixture module, is already routed to TestSupport.)
const DEV_TOOL_ENTRY_POINTS: &[&str] = &["setup.py", "noxfile.py"];

/// Classify by path. Deliberately crude and deliberately not a verdict: a
/// mis-classification routes a site to the wrong SPEC, where a human can see
/// and correct one answer, rather than silently deciding the site itself.
///
/// Path-only, and therefore blind to anything a manifest declares. Prefer
/// [`Site::scope`], which consults repo evidence first.
pub fn scope_of(path: &str) -> ScopeClass {
    let p = path.to_ascii_lowercase();
    let base = p.rsplit('/').next().unwrap_or(p.as_str()).to_string();
    if p.contains("/migrations/") || p.starts_with("migrations/") || p.contains("/migrate/") {
        ScopeClass::Migration
    } else if p.contains("backfill") {
        ScopeClass::Backfill
    } else if p.contains("/test")
        || p.starts_with("tests/")
        || p.ends_with("_test.go")
        || p.contains("test_")
        || p.ends_with("conftest.py")
        // Test-support packages that carry "test" mid-token, so the "/test"
        // and "test_" guards above miss them (po-x1bla sibling, found when a
        // judgment promoted `_openmetadata_testutils/…` to BLOCKING). Distinct
        // enough not to collide with "latest"/"greatest"/"attestation".
        || p.contains("testutils")
        || p.contains("test-utils")
        || p.contains("testsupport")
        || p.contains("test_support")
        || p.contains("/testing/")
        || p.starts_with("testing/")
        // Non-production support material, same severity class as test trees
        // (po-x1bla): example/sample configs, fixtures, testdata and docs ship
        // deliberate dummy credentials, so a secret finding in one is advisory,
        // never a blocking gate. Matched broadly — `examples/`, `sample_*`,
        // `/samples/`, `fixtures/`, `testdata/`, `docs/` — because the false
        // positive that motivated this was `examples/sample_configs/…`.
        || p.contains("/examples/")
        || p.starts_with("examples/")
        || p.contains("/sample")
        || p.starts_with("sample")
        || p.contains("/fixtures/")
        || p.starts_with("fixtures/")
        || p.contains("/testdata/")
        || p.starts_with("testdata/")
        || p.contains("/docs/")
        || p.starts_with("docs/")
    {
        ScopeClass::TestSupport
    } else if p.starts_with("scripts/")
        || p.contains("/scripts/")
        || p.starts_with("cmd/")
        || p.contains("/devtools/")
        // Checked LAST, after the test/example guards: a `setup.py` shipped as
        // a packaging fixture under tests/ is test material first.
        || DEV_TOOL_ENTRY_POINTS.contains(&base.as_str())
    {
        ScopeClass::DevOnly
    } else {
        ScopeClass::Runtime
    }
}

/// Repo-scoped construction facts. An `http.Server`'s WriteTimeout bounds a
/// handler but appears in no handler's caller chain, so it is carried forward
/// from here rather than dragged backward into a packet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigFact {
    #[serde(rename = "type", default)]
    pub type_name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub fields: Vec<String>,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoConfig {
    #[serde(default)]
    pub snapshot_id: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub constructions: Vec<ConfigFact>,
}

/// Parse a retriever's JSONL stream into sites plus the repo-scoped record.
/// Unparseable lines are skipped rather than fatal: a retriever bug should
/// degrade coverage, not abort a scan, and coverage is reported separately.
///
/// Version negotiation: a record stamped with a `packet_schema` newer than
/// [`PACKET_SCHEMA`] is REFUSED (counted as skipped), never parsed on the
/// guess that the shape still fits. Older stamps (and unstamped v1-era lines)
/// are accepted: v2 is a strict superset, so their fields default cleanly.
pub fn parse_stream(text: &str) -> (Vec<Site>, RepoConfig, usize) {
    let mut sites = Vec::new();
    let mut cfg = RepoConfig::default();
    let mut skipped = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if let Some(version) = v.get("packet_schema").and_then(|s| s.as_u64()) {
            if version > u64::from(PACKET_SCHEMA) {
                skipped += 1;
                continue;
            }
        }
        if let Some(kind) = v.get("kind").and_then(|k| k.as_str()) {
            // Repo-scoped records ride the same stream, tagged by `kind`.
            // Only repo_config is consumed here; any other kind (e.g. the G7
            // repo_structure record) belongs to its own consumer and must not
            // fall through into Site parsing, where every-field-defaulted
            // serde would mint a junk site out of it.
            if kind == "repo_config" {
                if let Ok(rc) = serde_json::from_value::<RepoConfig>(v) {
                    cfg = rc;
                }
            }
            continue;
        }
        match serde_json::from_value::<Site>(v) {
            Ok(s) => sites.push(s),
            Err(_) => skipped += 1,
        }
    }
    (sites, cfg, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_production_material_is_not_runtime_scoped() {
        // po-x1bla: a secret in examples/sample_configs fired HIGH + BLOCKING
        // on OpenMetadata while the identical class in tests/ was demoted to
        // medium — the classifier knew test trees but not example/sample/doc/
        // fixture material, which is equally non-production. All of it routes
        // to TestSupport so the content lane's test_support->medium demotion
        // reaches it too, and blocking stays reserved for production paths.
        for p in [
            "ingestion/examples/sample_configs/drives/sample_drive_data.yaml",
            "pkg/samples/config.yaml",
            "app/sample_drive_data.yaml",
            "docs/impersonation-design.md",
            "internal/fixtures/keys.pem",
            "src/testdata/creds.json",
            // Mid-token "test" packages the /test and test_ guards miss.
            "ingestion/src/_openmetadata_testutils/kafka/load_csv_data.py",
            "pkg/testsupport/fake.go",
            "src/testing/harness.py",
        ] {
            assert_eq!(
                scope_of(p),
                ScopeClass::TestSupport,
                "{p} must be non-production"
            );
        }
        // Production paths stay runtime — blocking must still reach a real leak.
        // "latest" contains "test" but not "/test"/"test_"/"testutils", so the
        // widening must NOT catch it. (A pre-existing narrower imprecision, out
        // of scope here: "greatest_handler" contains "test_" and so demotes —
        // noted, not fixed in this change.)
        assert_eq!(scope_of("internal/api/handler.go"), ScopeClass::Runtime);
        assert_eq!(scope_of("src/server/auth.py"), ScopeClass::Runtime);
        assert_eq!(
            scope_of("src/latestrelease/handler.go"),
            ScopeClass::Runtime
        );
    }

    #[test]
    fn specified_dev_tool_entry_points_are_dev_only() {
        // po-av01j.173. `setup.py` and `noxfile.py` are names a TOOL defines:
        // the packaging frontend runs one, the nox runner reads the other, and
        // neither is imported by product code. An unbounded call in them
        // blocks a build, not a request.
        assert_eq!(scope_of("setup.py"), ScopeClass::DevOnly);
        assert_eq!(scope_of("svc/setup.py"), ScopeClass::DevOnly);
        assert_eq!(scope_of("noxfile.py"), ScopeClass::DevOnly);
        // A packaging FIXTURE keeps its test-support class: the test guards
        // run first, so this is material for a test, not tooling for a build.
        assert_eq!(scope_of("tests/fixtures/setup.py"), ScopeClass::TestSupport);
    }

    #[test]
    fn build_tool_names_alone_never_exempt_a_file() {
        // THE CONSERVATIVE HALF. A false dev_only hides a real finding, so a
        // name is only enough when a tool's SPECIFICATION fixes its meaning.
        // These do not qualify, and the repo-evidence lane (rvl::devscope)
        // is what exempts the first one — and only when pyproject declares it.
        assert_eq!(scope_of("hatch_build.py"), ScopeClass::Runtime);
        // Celery's/RQ's conventional worker module has the same name as
        // invoke's task file. Demoting it would exempt production workers.
        assert_eq!(scope_of("tasks.py"), ScopeClass::Runtime);
        assert_eq!(scope_of("app/tasks.py"), ScopeClass::Runtime);
        assert_eq!(scope_of("manage.py"), ScopeClass::Runtime);
        // Not a suffix match: a product module whose name merely ends in one
        // of the tooling names stays runtime.
        assert_eq!(scope_of("app/prod_setup.py"), ScopeClass::Runtime);
    }

    #[test]
    fn repo_evidence_overrides_the_path_class() {
        // po-av01j.173: the scan pipeline stamps what the repo DECLARES, and
        // every consumer reads it through `Site::scope`.
        let mut s = Site {
            file_path: "hatch_build.py".into(),
            ..Default::default()
        };
        assert_eq!(s.scope(), ScopeClass::Runtime, "no evidence: path decides");
        s.scope_override = Some(ScopeClass::DevOnly);
        assert_eq!(s.scope(), ScopeClass::DevOnly);
    }

    #[test]
    fn a_scope_override_round_trips_and_is_absent_when_unset() {
        // Sites cross the packet stream and the incremental index as JSON.
        let s = Site {
            file_path: "hatch_build.py".into(),
            scope_override: Some(ScopeClass::DevOnly),
            ..Default::default()
        };
        let text = serde_json::to_string(&s).unwrap();
        assert!(text.contains("\"scope_override\":\"dev_only\""), "{text}");
        let back: Site = serde_json::from_str(&text).unwrap();
        assert_eq!(back.scope(), ScopeClass::DevOnly);
        // Unset stays off the wire: retrievers emit no such field, and their
        // records must keep matching the shape byte for byte.
        let plain = Site {
            file_path: "a.py".into(),
            ..Default::default()
        };
        assert!(!serde_json::to_string(&plain)
            .unwrap()
            .contains("scope_override"));
    }

    #[test]
    fn not_applicable_is_not_a_decided_label() {
        assert!(Verdict::Violates.is_decided());
        assert!(Verdict::Satisfies.is_decided());
        assert!(!Verdict::Abstain.is_decided());
        assert!(
            !Verdict::NotApplicable.is_decided(),
            "a rejected candidate is not a label"
        );
    }

    #[test]
    fn resolved_includes_not_applicable_but_not_abstain() {
        // "Resolved" is the human coverage notion: the scanner reached a
        // conclusion, including "this call does not block". Only Abstain is
        // unresolved.
        assert!(Verdict::Violates.is_resolved());
        assert!(Verdict::Satisfies.is_resolved());
        assert!(
            Verdict::NotApplicable.is_resolved(),
            "a non-blocking call is resolved, not an abstention"
        );
        assert!(!Verdict::Abstain.is_resolved());
    }

    #[test]
    fn provenance_complete_requires_neither_cap_hit() {
        let mut p = Provenance::default();
        assert!(p.complete());
        p.hit_caller_budget = true;
        assert!(
            !p.complete(),
            "a truncated search must not license reasoning from absence"
        );
    }

    #[test]
    fn repo_config_record_does_not_become_a_site() {
        let stream = concat!(
            r#"{"file_path":"a.go","line_number":7,"func":"Query","client_type":"db.Pool"}"#,
            "\n",
            r#"{"kind":"repo_config","snapshot_id":"x","constructions":[{"type":"net/http.Server","fields":["WriteTimeout"]}]}"#,
            "\n"
        );
        let (sites, cfg, skipped) = parse_stream(stream);
        assert_eq!(sites.len(), 1);
        assert_eq!(skipped, 0);
        assert_eq!(cfg.constructions.len(), 1);
        assert_eq!(sites[0].id(), "a.go:7");
    }

    #[test]
    fn schema_v2_fields_round_trip() {
        // A v2 record survives serialize -> parse with its constant-argument
        // evidence and macro flag intact. The contract is the boundary; losing
        // a field in transit is how evidence silently disappears.
        let s = Site {
            file_path: "a.c".into(),
            line_number: 9,
            method: "curl_easy_setopt".into(),
            packet_schema: PACKET_SCHEMA,
            const_args: vec![ConstArg {
                index: 1,
                name: String::new(),
                value: "CURLOPT_TIMEOUT".into(),
                how: "named_constant".into(),
            }],
            macro_expansion: true,
            ..Default::default()
        };
        let line = serde_json::to_string(&s).unwrap();
        let (sites, _, skipped) = parse_stream(&line);
        assert_eq!(skipped, 0);
        assert_eq!(sites.len(), 1);
        let got = &sites[0];
        assert_eq!(got.packet_schema, PACKET_SCHEMA);
        assert!(got.macro_expansion);
        assert_eq!(got.const_args.len(), 1);
        assert_eq!(got.const_args[0].index, 1);
        assert_eq!(got.const_args[0].value, "CURLOPT_TIMEOUT");
        assert_eq!(got.const_args[0].how, "named_constant");
    }

    #[test]
    fn site_kind_rides_the_stream_and_defaults_to_classic_call_site() {
        // G3 (po-av01j.4): background-job sites ride the SAME Site stream,
        // distinguished by an additive `site_kind` field. Absent means the
        // classic G1 call site, so every existing stream parses unchanged;
        // a "background_job" stamp must survive parse -> serialize intact.
        // Additive default-carrying field within the unreleased v2 train:
        // deliberately NOT a schema bump.
        let stream = concat!(
            r#"{"file_path":"a.go","line_number":7,"func":"Query","client_type":"db.Pool"}"#,
            "\n",
            r#"{"file_path":"jobs.go","line_number":12,"func":"AddFunc","client_type":"github.com/robfig/cron/v3.Cron","site_kind":"background_job"}"#,
            "\n"
        );
        let (sites, _, skipped) = parse_stream(stream);
        assert_eq!(skipped, 0, "site_kind must not break parsing");
        assert_eq!(sites.len(), 2);
        let classic = serde_json::to_value(&sites[0]).unwrap();
        let job = serde_json::to_value(&sites[1]).unwrap();
        assert_eq!(
            classic["site_kind"], "",
            "absent site_kind must default to the classic G1 call site"
        );
        assert_eq!(
            job["site_kind"], "background_job",
            "a background_job stamp must round-trip through Site"
        );
    }

    #[test]
    fn v1_records_still_parse_with_v2_defaults() {
        // v2 is a strict superset of v1: an old stream (no packet_schema, no
        // const_args, no macro_expansion) parses with defaults, and a Go-style
        // present-but-null const_args does too (the nil-slice trap).
        let stream = concat!(
            r#"{"file_path":"a.go","line_number":7,"func":"Query","client_type":"db.Pool"}"#,
            "\n",
            r#"{"packet_schema":1,"file_path":"b.go","line_number":8,"func":"Do","const_args":null}"#,
            "\n"
        );
        let (sites, _, skipped) = parse_stream(stream);
        assert_eq!(skipped, 0);
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0].packet_schema, 0);
        assert!(sites[0].const_args.is_empty());
        assert!(!sites[0].macro_expansion);
        assert_eq!(sites[1].packet_schema, 1);
        assert!(sites[1].const_args.is_empty());
    }

    #[test]
    fn unknown_newer_schema_versions_are_refused_not_guessed_at() {
        // The negotiation contract: a consumer that does not know a version
        // refuses the record rather than guessing at its shape. A v3 stamp on
        // an otherwise-parseable record must land in the skipped count, and a
        // v3 repo_config must not overwrite the config either.
        let stream = concat!(
            r#"{"packet_schema":3,"file_path":"a.go","line_number":7,"func":"Query"}"#,
            "\n",
            r#"{"packet_schema":3,"kind":"repo_config","snapshot_id":"x","constructions":[{"type":"t","fields":["Timeout"]}]}"#,
            "\n",
            r#"{"packet_schema":2,"file_path":"b.go","line_number":8,"func":"Do"}"#,
            "\n"
        );
        let (sites, cfg, skipped) = parse_stream(stream);
        assert_eq!(skipped, 2, "both v3 records must be refused");
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id(), "b.go:8");
        assert!(
            cfg.constructions.is_empty(),
            "a repo_config from an unknown schema must not be consumed"
        );
    }

    #[test]
    fn unknown_repo_scoped_record_kinds_do_not_become_sites() {
        // The stream carries repo-scoped records tagged by `kind`
        // (repo_config today, repo_structure from the G7 retriever). A kind
        // this parser does not recognize must be routed AWAY from the site
        // list, not misparsed into an all-defaults junk Site.
        let stream = concat!(
            r#"{"file_path":"a.go","line_number":7,"func":"Query","client_type":"db.Pool"}"#,
            "\n",
            r#"{"kind":"repo_structure","snapshot_id":"x","ecosystems":[]}"#,
            "\n"
        );
        let (sites, _, skipped) = parse_stream(stream);
        assert_eq!(
            sites.len(),
            1,
            "a repo-scoped record must not become an empty Site"
        );
        assert_eq!(skipped, 0, "another record kind is not a parse failure");
    }

    #[test]
    fn site_kind_survives_a_parse_serialize_round_trip() {
        // G2 (po-av01j.3): server-entry sites ride the SAME Site stream,
        // distinguished by the additive `site_kind` field. Losing it in
        // transit (parse -> index -> reload) would silently demote a
        // server-entry record back to a G1 call site.
        let line = concat!(
            r#"{"file_path":"routes.go","line_number":12,"func":"HandleFunc","#,
            r#""client_type":"net/http.ServeMux","site_kind":"server_entry"}"#
        );
        let (sites, _, skipped) = parse_stream(line);
        assert_eq!(skipped, 0);
        assert_eq!(sites.len(), 1);
        let back = serde_json::to_value(&sites[0]).unwrap();
        assert_eq!(
            back.get("site_kind").and_then(|v| v.as_str()),
            Some("server_entry"),
            "site_kind must survive the Site round trip"
        );
    }

    #[test]
    fn emission_site_kind_survives_the_round_trip() {
        // G4 (po-av01j.5): emission-point sites ride the SAME Site stream,
        // distinguished by the additive `site_kind` field. Absent = classic G1
        // call site. The field must survive parse -> serialize, or an
        // emission packet silently becomes a call site in the next pass.
        let stream = concat!(
            r#"{"packet_schema":2,"file_path":"a.go","line_number":7,"func":"Error","client_type":"log/slog.Logger","site_kind":"emission_point"}"#,
            "\n",
            r#"{"packet_schema":2,"file_path":"b.go","line_number":8,"func":"Do","client_type":"net/http.Client"}"#,
            "\n"
        );
        let (sites, _, skipped) = parse_stream(stream);
        assert_eq!(skipped, 0);
        assert_eq!(sites.len(), 2);
        let back = serde_json::to_string(&sites[0]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&back).unwrap();
        assert_eq!(
            v.get("site_kind").and_then(|k| k.as_str()),
            Some("emission_point"),
            "site_kind must survive the round trip: {back}"
        );
        let back1 = serde_json::to_string(&sites[1]).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&back1).unwrap();
        assert_eq!(
            v1.get("site_kind").and_then(|k| k.as_str()).unwrap_or(""),
            "",
            "a classic G1 site defaults to an empty site_kind"
        );
    }

    #[test]
    fn site_kind_defaults_to_the_g1_call_site() {
        // Every v1/v2 record predating the field parses as a classic G1 call
        // site: the empty default IS the G1 marker, so no schema bump is
        // needed (additive default-carrying field within the v2 train).
        let (sites, _, skipped) =
            parse_stream(r#"{"file_path":"a.go","line_number":7,"func":"Query"}"#);
        assert_eq!(skipped, 0);
        let back = serde_json::to_value(&sites[0]).unwrap();
        assert_eq!(
            back.get("site_kind").and_then(|v| v.as_str()),
            Some(""),
            "a record predating the field must parse as a G1 call site"
        );
    }

    #[test]
    fn emission_accessors_read_the_aggregate_const_args() {
        // The category and count of an emission aggregate ride const_args
        // (how: "aggregate") rather than new fields. The accessors are the one
        // shared parser for that convention.
        let s = Site {
            file_path: "svc/log.go".into(),
            line_number: 12,
            method: "Error".into(),
            client_type: "log/slog.Logger".into(),
            site_kind: SITE_KIND_EMISSION.into(),
            const_args: vec![
                ConstArg {
                    name: CONST_ARG_EMISSION_CATEGORY.into(),
                    value: "log".into(),
                    how: "aggregate".into(),
                    ..Default::default()
                },
                ConstArg {
                    name: CONST_ARG_EMISSION_COUNT.into(),
                    value: "17".into(),
                    how: "aggregate".into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(s.is_emission_point() && !s.is_call_site());
        assert_eq!(s.emission_category(), Some("log"));
        assert_eq!(s.emission_count(), 17);

        // A classic G1 site: empty kind, no category, count defaults to 1.
        let g1 = Site::default();
        assert!(g1.is_call_site() && !g1.is_emission_point());
        assert_eq!(g1.emission_category(), None);
        assert_eq!(g1.emission_count(), 1);
    }

    #[test]
    fn malformed_lines_degrade_coverage_rather_than_aborting() {
        let (sites, _, skipped) =
            parse_stream("{not json}\n{\"file_path\":\"b.go\",\"line_number\":1}\n");
        assert_eq!(sites.len(), 1);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn ctx_evidence_distinguishes_all_none_and_mixed() {
        let p = |t, d| Provenance {
            direct_callers: t,
            direct_callers_passing_bounded_ctx: d,
            ..Default::default()
        };
        assert_eq!(p(0, 0).ctx_evidence(), CtxEvidence::Unknown);
        assert_eq!(p(7, 0).ctx_evidence(), CtxEvidence::NoneBounded);
        assert_eq!(p(7, 7).ctx_evidence(), CtxEvidence::AllBounded);
        assert_eq!(
            p(7, 3).ctx_evidence(),
            CtxEvidence::Mixed {
                bounded: 3,
                total: 7
            }
        );
    }

    #[test]
    fn scope_source_spans_callers_and_callees() {
        let s = Site {
            enclosing_function_body: "body".into(),
            callers: vec![Snippet {
                source: "up".into(),
                ..Default::default()
            }],
            callees: vec![Snippet {
                source: "down".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let src = s.scope_source();
        assert!(src.contains("body") && src.contains("up") && src.contains("down"));
    }
}
