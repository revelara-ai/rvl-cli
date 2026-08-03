//! Shared types for the reliability scanner.
//!
//! These mirror the JSON contract the per-language retrievers already emit
//! (`tools/goindex`, `tools/pyindex`), deliberately field-for-field. The
//! contract is the boundary that keeps the architecture honest: retrievers emit
//! SOURCE and structural facts, never verdicts, so adding a language costs
//! compiler-frontend work and no reliability judgement. That rule was violated
//! twice in the Python prototype and both times produced a matcher that failed
//! its own sanity check.

use serde::{Deserialize, Serialize};

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
    #[serde(default)]
    pub kind: Option<String>,
}

impl Site {
    pub fn id(&self) -> String {
        format!("{}:{}", self.file_path, self.line_number)
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

/// Classify by path. Deliberately crude and deliberately not a verdict: a
/// mis-classification routes a site to the wrong SPEC, where a human can see
/// and correct one answer, rather than silently deciding the site itself.
pub fn scope_of(path: &str) -> ScopeClass {
    let p = path.to_ascii_lowercase();
    if p.contains("/migrations/") || p.starts_with("migrations/") || p.contains("/migrate/") {
        ScopeClass::Migration
    } else if p.contains("backfill") {
        ScopeClass::Backfill
    } else if p.contains("/test")
        || p.starts_with("tests/")
        || p.ends_with("_test.go")
        || p.contains("test_")
        || p.ends_with("conftest.py")
    {
        ScopeClass::TestSupport
    } else if p.starts_with("scripts/")
        || p.contains("/scripts/")
        || p.starts_with("cmd/")
        || p.contains("/devtools/")
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
        if v.get("kind").and_then(|k| k.as_str()) == Some("repo_config") {
            if let Ok(rc) = serde_json::from_value::<RepoConfig>(v) {
                cfg = rc;
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
