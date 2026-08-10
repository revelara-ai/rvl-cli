//! G7 repo-structure retriever + evaluator (po-av01j.7).
//!
//! Language-agnostic inventory of what a repository's SHAPE says about its
//! testing and dependency hygiene: test-file conventions per ecosystem,
//! coverage configuration, contract-test frameworks, dep-manifest/lockfile
//! consistency, and runbook-directory presence. The retrieval/judgement split
//! mirrors the call-site scanner: [`inventory`] reports observable facts
//! (names, counts, presence) and never a verdict; [`evaluate`] maps those
//! facts to per-control verdicts with honest abstention.
//!
//! Privacy: facts are shape-only — file names, counts, and presence booleans.
//! Content is read locally to detect markers (a `#[cfg(test)]` attribute, a
//! coverage key in a config) but no source text is ever stored in the facts.

use rvl_core::Verdict;
use serde::{Deserialize, Serialize};
use std::path::Path;

mod inventory;

pub use inventory::inventory;

/// The `kind` tag this record carries in the packet stream.
pub const RECORD_KIND: &str = "repo_structure";

/// An ecosystem with fewer source files than this is too small for "no test
/// files" to be a decidable negative; the evaluator abstains instead.
pub const MIN_SOURCES_FOR_TEST_VERDICT: u32 = 5;

fn default_kind() -> String {
    RECORD_KIND.to_string()
}

/// Per-ecosystem test-presence facts: how many source files, how many of them
/// follow the ecosystem's test-file convention, and which integration/e2e
/// conventions were seen.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcosystemFacts {
    /// "go" | "js" | "python" | "rust" | "java".
    pub name: String,
    pub source_files: u32,
    pub test_files: u32,
    /// Repo-relative paths of integration/e2e markers (dirs or config files).
    #[serde(default)]
    pub integration_markers: Vec<String>,
}

/// One dependency manifest and the lockfile state governing it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestFacts {
    /// Repo-relative manifest path (e.g. "package.json", "svc/go.mod").
    pub path: String,
    /// "npm" | "gomod" | "cargo" | "pyproject" | "requirements" | "pipfile".
    pub kind: String,
    /// Declared dependency count (rough; shape only).
    pub deps: u32,
    /// Repo-relative lockfiles governing this manifest (same dir or an
    /// ancestor, for workspace/monorepo layouts).
    #[serde(default)]
    pub lockfiles: Vec<String>,
    /// requirements-style manifests only: exact pins (`==`) seen.
    #[serde(default)]
    pub pinned: u32,
    /// requirements-style manifests only: floating specs seen.
    #[serde(default)]
    pub floating: u32,
}

/// The repo-scoped structure record. Rides the packet stream as a JSONL line
/// with `kind: "repo_structure"`, like the `repo_config` record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoStructure {
    #[serde(default = "default_kind")]
    pub kind: String,
    #[serde(default)]
    pub snapshot_id: String,
    #[serde(default)]
    pub ecosystems: Vec<EcosystemFacts>,
    /// Repo-relative paths of coverage tool configs / CI coverage invocations.
    #[serde(default)]
    pub coverage_configs: Vec<String>,
    /// Contract-test frameworks found, as "framework (manifest path)".
    #[serde(default)]
    pub contract_frameworks: Vec<String>,
    #[serde(default)]
    pub manifests: Vec<ManifestFacts>,
    /// Repo-relative runbook-convention directories present.
    #[serde(default)]
    pub runbook_dirs: Vec<String>,
    /// True when the walk exhausted the tree (no unreadable directories).
    /// Only a complete walk licenses reasoning from absence — mirrors
    /// `Provenance::complete` on call-site packets.
    #[serde(default)]
    pub walk_complete: bool,
}

impl Default for RepoStructure {
    fn default() -> Self {
        Self {
            kind: default_kind(),
            snapshot_id: String::new(),
            ecosystems: Vec::new(),
            coverage_configs: Vec::new(),
            contract_frameworks: Vec::new(),
            manifests: Vec::new(),
            runbook_dirs: Vec::new(),
            walk_complete: false,
        }
    }
}

impl RepoStructure {
    /// The JSONL line this record contributes to a packet stream.
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("RepoStructure serializes")
    }
}

/// Extract the repo-structure record from a JSONL packet stream, if one rides
/// in it. Later records win, matching the repo_config convention.
pub fn parse_record(stream: &str) -> Option<RepoStructure> {
    let mut found = None;
    for line in stream.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("kind").and_then(|k| k.as_str()) == Some(RECORD_KIND) {
            if let Ok(r) = serde_json::from_value::<RepoStructure>(v) {
                found = Some(r);
            }
        }
    }
    found
}

/// One control-mapped conclusion drawn from the structure facts. The
/// evaluator emits one per control, every time: satisfies/abstain outcomes
/// are part of the record, not silently dropped — the renderer decides what
/// to surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructureFinding {
    /// Control code, e.g. "RC-033".
    pub control: &'static str,
    /// Control name for display, e.g. "unit test coverage".
    pub control_name: &'static str,
    pub verdict: Verdict,
    pub reason: String,
    /// Repo-relative evidence paths (shape only).
    pub evidence: Vec<String>,
    /// Suggested fix (shown on violates).
    pub fix: String,
    /// Base severity when this control violates ("medium" | "low"; empty for
    /// controls that never violate).
    pub severity: &'static str,
    /// True for weak, presence-only signals (RC-006): the verdict carries
    /// low confidence by construction.
    pub weak: bool,
}

/// Map structure facts to per-control verdicts. Deterministic, no model
/// calls. Always returns one finding per control, in stable order:
/// RC-033, RC-057, RC-058, RC-034, RC-070, RC-006.
///
/// Abstention philosophy, matching the call-site scanner: an absence is a
/// decidable negative only when the walk was complete AND absence is
/// detectable in principle (coverage config, test files). Where applicability
/// itself is a judgement (contract tests for a possibly-consumer-less
/// library, runbooks that may live in a wiki), the evaluator abstains with
/// the reason rather than guessing.
pub fn evaluate(facts: &RepoStructure) -> Vec<StructureFinding> {
    vec![
        eval_unit_tests(facts),
        eval_coverage(facts),
        eval_integration(facts),
        eval_contract(facts),
        eval_manifests(facts),
        eval_runbooks(facts),
    ]
}

/// Ecosystems with any source at all — the candidates the test controls
/// judge.
fn eligible(facts: &RepoStructure) -> Vec<&EcosystemFacts> {
    facts
        .ecosystems
        .iter()
        .filter(|e| e.source_files > 0)
        .collect()
}

fn eval_unit_tests(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-033";
    let control_name = "unit test coverage";
    let severity = "medium";
    let fix =
        "add unit tests for the untested ecosystem(s) and run them in CI with a coverage threshold"
            .to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity,
        weak: false,
    };

    let eligible = eligible(facts);
    if eligible.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no recognized source ecosystems".into(),
            vec![],
        );
    }
    let untested: Vec<&&EcosystemFacts> = eligible
        .iter()
        .filter(|e| e.source_files >= MIN_SOURCES_FOR_TEST_VERDICT && e.test_files == 0)
        .collect();
    if !untested.is_empty() {
        if !facts.walk_complete {
            return mk(
                Verdict::Abstain,
                "walk truncated: absence of test files is not evidence".into(),
                vec![],
            );
        }
        let list = untested
            .iter()
            .map(|e| format!("{} ({} source files)", e.name, e.source_files))
            .collect::<Vec<_>>()
            .join(", ");
        return mk(Verdict::Violates, format!("no test files: {list}"), vec![]);
    }
    if eligible.iter().any(|e| e.test_files > 0) {
        let ratios = eligible
            .iter()
            .filter(|e| e.test_files > 0)
            .map(|e| {
                format!(
                    "{}: {}/{} test-to-source",
                    e.name, e.test_files, e.source_files
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return mk(
            Verdict::Satisfies,
            format!("test files present — {ratios}"),
            vec![],
        );
    }
    mk(
        Verdict::Abstain,
        format!(
            "fewer than {MIN_SOURCES_FOR_TEST_VERDICT} source files per ecosystem: too small to judge test presence"
        ),
        vec![],
    )
}

fn eval_coverage(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-057";
    let control_name = "test architecture standards";
    let fix = "add coverage tooling (codecov.yml, coverage.py, jest --coverage, cargo-tarpaulin) \
               and enforce a threshold in CI"
        .to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "low",
        weak: false,
    };
    if eligible(facts).is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no recognized source ecosystems".into(),
            vec![],
        );
    }
    if !facts.coverage_configs.is_empty() {
        return mk(
            Verdict::Satisfies,
            "coverage configuration present".into(),
            facts.coverage_configs.clone(),
        );
    }
    if !facts.walk_complete {
        return mk(
            Verdict::Abstain,
            "walk truncated: absence of coverage configuration is not evidence".into(),
            vec![],
        );
    }
    // State the search, not a universal negative. The recognizer reads coverage
    // config files, CI workflows, Makefiles and build scripts; a claim broader
    // than that is one the evidence cannot carry.
    mk(
        Verdict::Violates,
        "no coverage tooling found in coverage config, CI workflows, Makefiles or build scripts"
            .into(),
        vec![],
    )
}

fn eval_integration(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-058";
    let control_name = "integration and smoke tests";
    let fix = "add integration/e2e tests (tests/integration/, e2e/, playwright/cypress) and run \
               them post-deployment"
        .to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "medium",
        weak: false,
    };
    let eligible = eligible(facts);
    if eligible.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no recognized source ecosystems".into(),
            vec![],
        );
    }
    let markers: Vec<String> = facts
        .ecosystems
        .iter()
        .flat_map(|e| e.integration_markers.iter().cloned())
        .collect();
    if !markers.is_empty() {
        return mk(
            Verdict::Satisfies,
            "integration/e2e test convention present".into(),
            markers,
        );
    }
    let total_tests: u32 = eligible.iter().map(|e| e.test_files).sum();
    if total_tests > 0 {
        return mk(
            Verdict::Abstain,
            "unit tests present but no recognizable integration/e2e convention; integration \
             tests may exist under other names"
                .into(),
            vec![],
        );
    }
    let big_enough = eligible
        .iter()
        .any(|e| e.source_files >= MIN_SOURCES_FOR_TEST_VERDICT);
    if big_enough && facts.walk_complete {
        return mk(
            Verdict::Violates,
            "no test files of any kind: integration and smoke tests are absent".into(),
            vec![],
        );
    }
    mk(
        Verdict::Abstain,
        "too few source files or truncated walk: cannot judge integration test presence".into(),
        vec![],
    )
}

fn eval_contract(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-034";
    let control_name = "contract testing";
    let fix = "adopt a contract-test framework (Pact, schemathesis, buf breaking-change gate) \
               for service-to-service interfaces"
        .to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "",
        weak: false,
    };
    if !facts.contract_frameworks.is_empty() {
        return mk(
            Verdict::Satisfies,
            format!(
                "contract-test framework present: {}",
                facts.contract_frameworks.join(", ")
            ),
            facts.contract_frameworks.clone(),
        );
    }
    if facts.manifests.is_empty() && eligible(facts).is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no dependency manifests or source ecosystems".into(),
            vec![],
        );
    }
    mk(
        Verdict::Abstain,
        "no contract-test framework in any dependency manifest; whether contract tests apply \
         requires service-consumer judgement"
            .into(),
        vec![],
    )
}

fn eval_manifests(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-070";
    let control_name = "third-party dependency management";
    let fix = "commit the lockfile (package-lock.json / go.sum / Cargo.lock / poetry.lock) and \
               pin floating requirement specs"
        .to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "medium",
        weak: false,
    };
    if facts.manifests.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no dependency manifests found".into(),
            vec![],
        );
    }
    let mut missing_lock: Vec<&str> = Vec::new();
    let mut floating: Vec<String> = Vec::new();
    let mut satisfied = false;
    let mut py_unlocked: Vec<&str> = Vec::new();
    for m in &facts.manifests {
        if m.deps == 0 {
            continue;
        }
        match m.kind.as_str() {
            "npm" | "gomod" | "cargo" | "pipfile" => {
                if m.lockfiles.is_empty() {
                    missing_lock.push(&m.path);
                } else {
                    satisfied = true;
                }
            }
            "requirements" => {
                if m.floating > 0 {
                    floating.push(format!("{} ({} floating specs)", m.path, m.floating));
                } else {
                    satisfied = true;
                }
            }
            "pyproject" => {
                if m.lockfiles.is_empty() {
                    py_unlocked.push(&m.path);
                } else {
                    satisfied = true;
                }
            }
            _ => {}
        }
    }
    if !missing_lock.is_empty() || !floating.is_empty() {
        let mut parts = Vec::new();
        let mut evidence: Vec<String> = Vec::new();
        if !missing_lock.is_empty() {
            parts.push(format!(
                "manifest(s) without a lockfile: {}",
                missing_lock.join(", ")
            ));
            evidence.extend(missing_lock.iter().map(|s| s.to_string()));
        }
        if !floating.is_empty() {
            parts.push(format!(
                "floating requirement specs: {}",
                floating.join(", ")
            ));
            evidence.extend(
                floating
                    .iter()
                    .map(|s| s.split(' ').next().unwrap_or(s).to_string()),
            );
        }
        return mk(Verdict::Violates, parts.join("; "), evidence);
    }
    if satisfied {
        return mk(
            Verdict::Satisfies,
            "declared dependencies are lockfile-governed".into(),
            vec![],
        );
    }
    if !py_unlocked.is_empty() {
        return mk(
            Verdict::Abstain,
            format!(
                "pyproject without a lockfile ({}): a library legitimately omits one; \
                 application-ness is a judgement",
                py_unlocked.join(", ")
            ),
            vec![],
        );
    }
    mk(
        Verdict::NotApplicable,
        "manifests declare no dependencies".into(),
        vec![],
    )
}

fn eval_runbooks(facts: &RepoStructure) -> StructureFinding {
    let control = "RC-006";
    let control_name = "incident runbooks";
    let fix =
        "add runbooks/ with per-alert mitigation procedures and link them from alerts".to_string();
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "",
        weak: true,
    };
    if !facts.runbook_dirs.is_empty() {
        return mk(
            Verdict::Satisfies,
            "runbook directory present (weak signal: presence only)".into(),
            facts.runbook_dirs.clone(),
        );
    }
    mk(
        Verdict::Abstain,
        "no runbook directory convention found; runbooks may live outside the repo (weak signal)"
            .into(),
        vec![],
    )
}

/// Convenience: inventory + a caller-supplied snapshot id.
pub fn retrieve(root: &Path, snapshot_id: &str) -> RepoStructure {
    let mut facts = inventory(root);
    facts.snapshot_id = snapshot_id.to_string();
    facts
}
