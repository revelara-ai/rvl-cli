//! The `--out` structured scan document, schema `rvl-scan/v1`.
//!
//! The SHIPPED machine contract between the binary and any orchestrator
//! (`docs/out-contract.md` is the external spec; update it in the same change
//! as any edit here). It mirrors what the human ladder and COVERAGE block
//! say: the post-waiver findings, coverage with abstains by lever, the
//! per-site eval rows, the undecided sites, and the classes the loaded cache
//! judges in this repo. All of it is serialization of existing internals;
//! nothing here re-analyzes. Evolution within v1 is additive only; breaking
//! changes bump `schema`.
//!
//! Deterministic-engine truth ONLY: agent/lens findings never enter this
//! document. An orchestrator merges them downstream, provenance-tagged, with
//! engine rows authoritative.

use serde::Serialize;
use std::collections::BTreeSet;

use crate::render;

/// The `site_id` of every `structure` row: the lane judges the repository as
/// a whole, so a row is identified by its `class`, not by a location.
pub const STRUCTURE_SITE_ID: &str = "repo";

/// Which abstain lever closes an unresolved site. The same classification the
/// COVERAGE block buckets by; kept as one function so the rendered counts and
/// the per-site `undecided` rows can never disagree.
pub fn lever_of(reason: &str) -> &'static str {
    if reason.starts_with("no spec") {
        "no_spec"
    } else if reason.contains("truncated") {
        "bounds"
    } else if reason.contains("depends") || reason.contains("per-site") {
        "judge"
    } else {
        "other"
    }
}

#[derive(Serialize)]
pub struct OutDoc {
    pub schema: &'static str,
    /// Duplicates the process exit code so a consumer holding only this file
    /// knows whether the gate fired (0 clean, 3 blocking).
    pub exit: u8,
    pub findings: Vec<OutFinding>,
    pub coverage: OutCoverage,
    /// Every site the engine evaluated, one row per (site, verdict): the old
    /// top-level eval-rows array verbatim, one level down. The eval harness'
    /// per-site (verdict, reason) contract lives HERE; `undecided` and
    /// `covered_classes` below are projections of these rows, precomputed so
    /// an orchestrator never needs to know which verdict strings count as
    /// resolved.
    pub sites: Vec<OutSite>,
    pub undecided: Vec<OutUndecided>,
    pub covered_classes: Vec<String>,
    /// The repo-structure lane (po-av01j.28): one eval row per control
    /// (RC-033/057/058/034/070/006) with EVERY verdict, satisfies and
    /// abstain included, pre-waiver. Kept out of `sites` on purpose: these
    /// rows describe the repo, not a call site, so they must not move
    /// `coverage.resolved/total`, `undecided` or `covered_classes`. Empty
    /// when the lane did not run (`--changed-only`, or a `--retrieved`
    /// stream with no `repo_structure` record). The violations among them
    /// are also ladder rows in `findings`, post-waiver.
    pub structure: Vec<OutSite>,
    /// The hook-adjudication agent block verbatim when `--hook` ran; null
    /// otherwise. Provenance-tagged and separate, exactly as rendered.
    pub hook_agent: Option<String>,
    /// `scan --blend` status (po-av01j.205): complete or not, why, counts,
    /// and the BLEND block verbatim. Null when `--blend` was not given. A
    /// status report, not findings: engine rows above are never rewritten.
    pub blend: Option<crate::blend::BlendSummary>,
}

/// One per-site eval row. Field names match the old top-level array (and the
/// rvl-eval `run` emitter) exactly, so harness consumers migrate by reading
/// `.sites` instead of the document root, nothing else. The `structure` rows
/// reuse the shape with `site_id` fixed to [`STRUCTURE_SITE_ID`] and `class`
/// set to `repo_structure.RC-XXX`, so the one findings loader reads both.
#[derive(Clone, Debug, Serialize)]
pub struct OutSite {
    pub site_id: String,
    pub snapshot_id: String,
    pub verdict: String,
    pub reason: String,
    pub class: String,
}

/// One ladder row, post-waiver. `severity` is the SECTION the row renders in
/// (`blocking` | `advisory` | `suppressed`) derived by the same `classify` the
/// exit code uses; `base_severity` is the judgment's raw grade (high | medium
/// | low | "").
#[derive(Serialize)]
pub struct OutFinding {
    pub id: String,
    pub class: String,
    /// What the row is about, for the server's identity (po-zcqld). Without
    /// it the identity is control plus title, and two rows of one class share
    /// both.
    pub subject: OutSubject,
    pub severity: &'static str,
    pub base_severity: String,
    pub site: String,
    pub description: String,
    pub control: String,
    pub fix: String,
    pub site_count: usize,
    pub suppressed: bool,
    pub gate_exempt: bool,
}

/// The subject of a finding, in the wire shape the server reads
/// (`{"kind", "value"}`).
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct OutSubject {
    pub kind: &'static str,
    pub value: String,
}

/// The subject kind of every engine row. The server folds the case of a
/// `config_key` value and keeps the case of a `symbol` value; a class and a
/// path are both case-sensitive, so no lane sends `config_key`.
pub const SUBJECT_KIND: &str = "symbol";

/// The subject of one ladder row: the class for a row that aggregates sites,
/// and `class@path` for a row on one site, so two rows of one class at two
/// files stay two risks. The path is the waiver path of the site (no line, no
/// config unit): an edit above the site does not move the identity. A row
/// that aggregates sites cannot name one, because its primary site is only an
/// example.
pub fn subject_of(class: &str, site: &str, site_count: usize) -> OutSubject {
    let path = crate::waiver::site_path(site).trim();
    let value = if site_count == 1 && !path.is_empty() {
        format!("{class}@{path}")
    } else {
        class.to_string()
    };
    OutSubject {
        kind: SUBJECT_KIND,
        value,
    }
}

#[derive(Serialize)]
pub struct OutAbstain {
    pub no_spec: usize,
    pub bounds: usize,
    pub judge: usize,
    pub other: usize,
}

#[derive(Serialize)]
pub struct OutLang {
    pub lang: String,
    pub state: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct OutLangCoverage {
    pub lang: String,
    pub resolved: usize,
    pub total: usize,
    pub no_spec: usize,
    /// The resolved rate is ~0 and missing specs are why: the corpus, not the
    /// scanner, is the lever for this language. A hint, never a gate.
    pub corpus_gap: bool,
}

#[derive(Serialize)]
pub struct OutRetriever {
    pub lang: String,
    pub path: String,
    pub source: String,
    /// How this helper differs from the build this binary ships, when it does
    /// and a shipped sibling exists to compare against (po-8ozxg).
    pub drift: Option<String>,
}

#[derive(Serialize)]
pub struct OutDegraded {
    pub lang: String,
    pub abstained: bool,
    pub not_installed: bool,
    pub reason: String,
}

#[derive(Serialize)]
pub struct OutConfigAbstain {
    pub no_spec: usize,
    pub outside_repo: usize,
    pub other: usize,
    /// Unjudged by design (the key ledger's vocabulary-only marker): not a
    /// lever, and never part of `no_spec` or `no_spec_keys`.
    pub vocabulary_only: usize,
}

/// The config lane's verdict counts for one (format, key). The four counts
/// of every row sum to `OutConfig::total`.
#[derive(Serialize)]
pub struct OutConfigKey {
    pub format: String,
    pub key: String,
    pub violates: usize,
    pub satisfies: usize,
    pub abstain: usize,
    pub not_applicable: usize,
}

#[derive(Serialize)]
pub struct OutConfig {
    pub resolved: usize,
    pub total: usize,
    pub abstain: OutConfigAbstain,
    pub no_spec_keys: Vec<String>,
    /// Ordered by format, then key (po-av01j.133.12). Additive.
    pub by_key: Vec<OutConfigKey>,
    pub unparseable_files: usize,
}

/// The repo-structure lane's verdict counts, one control each. Mirrors the
/// COVERAGE block's `structure:` line.
#[derive(Serialize)]
pub struct OutStructureCoverage {
    pub total: usize,
    pub violates: usize,
    pub satisfies: usize,
    pub abstain: usize,
    pub not_applicable: usize,
}

#[derive(Serialize)]
pub struct OutCoverage {
    pub resolved: usize,
    pub total: usize,
    pub abstain: OutAbstain,
    pub generated_skipped: usize,
    /// Test files the retrievers skipped, summed across languages
    ///; the per-language split is in the COVERAGE block.
    pub test_files_skipped: usize,
    /// Workspaces scanned without their installed dependencies, summed
    /// across languages (po-pk3fp.15). Non-zero means those lanes resolved
    /// client types from import syntax; the per-language split is in the
    /// COVERAGE block.
    pub dependency_trees_uninstalled: usize,
    pub degraded_note: Option<String>,
    pub lang_status: Vec<OutLang>,
    /// Resolved and no-spec counts per language (po-5csvg). Additive.
    pub by_language: Vec<OutLangCoverage>,
    pub retrievers: Vec<OutRetriever>,
    pub degraded: Vec<OutDegraded>,
    pub config: Option<OutConfig>,
    /// The retrieval denominator per language (po-av01j.219): candidate call
    /// sites the extractor retrieved, out of every call the type checker
    /// resolved, plus the known I/O it did not retrieve. `resolved`/`total`
    /// is measured over the retrieved sites only, so quote them together.
    pub retrieval: Vec<rvl_core::RetrievalCensus>,
    /// Null when the structure lane did not run.
    pub structure: Option<OutStructureCoverage>,
}

/// A site the engine reached and abstained on, with the lever that closes it.
/// Together with `covered_classes` this is the abstain manifest an
/// orchestrator scopes its semantic pass with. `scope` is the path-derived
/// [`rvl_core::ScopeClass`], carried so a consumer can rank runtime abstains
/// above test scaffolding without re-deriving path heuristics: on the first
/// real dogfood, 2761 undecided read as alarming until scope showed most were
/// test_support (playwright/msw).
#[derive(Serialize)]
pub struct OutUndecided {
    pub site: String,
    pub class: String,
    pub lever: &'static str,
    pub scope: &'static str,
}

fn lang_state_str(s: render::LangState) -> String {
    match s {
        render::LangState::Scanned => "scanned",
        render::LangState::Partial => "partial",
        render::LangState::Abstained => "abstained",
        render::LangState::Failed => "failed",
        render::LangState::Unsupported => "unsupported",
        render::LangState::NotInstalled => "not_installed",
        render::LangState::Skipped => "skipped",
    }
    .to_string()
}

/// Assemble the document from the pieces `render_scan_output` already holds.
#[allow(clippy::too_many_arguments)]
pub fn build(
    ladder: &[render::Finding],
    coverage: &render::Coverage,
    config: Option<&render::ConfigCoverage>,
    propagated: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    structure: &[OutSite],
    hook_agent_block: Option<&str>,
    blend: Option<&crate::blend::BlendSummary>,
    blocked: bool,
) -> OutDoc {
    let findings = ladder
        .iter()
        .map(|f| OutFinding {
            id: f.id.clone(),
            class: f.class_rule.clone(),
            subject: subject_of(&f.class_rule, &f.site, f.site_count),
            severity: match render::classify(f) {
                render::Section::Blocking => "blocking",
                render::Section::Advisory => "advisory",
                render::Section::Suppressed => "suppressed",
            },
            base_severity: f.severity.clone(),
            site: f.site.clone(),
            description: f.description.clone(),
            control: f.control.clone(),
            fix: f.fix.clone(),
            site_count: f.site_count,
            suppressed: f.suppressed,
            gate_exempt: f.gate_exempt,
        })
        .collect();

    let mut site_rows = Vec::with_capacity(propagated.len());
    let mut undecided = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for (f, s) in propagated.iter().zip(sites.iter()) {
        let class = rvl_triage::class_key_string(s);
        site_rows.push(OutSite {
            site_id: f.site_id.clone(),
            snapshot_id: s.snapshot_id.clone(),
            verdict: f.verdict.as_str().to_string(),
            reason: f.reason.clone(),
            class: class.clone(),
        });
        if f.verdict.is_resolved() {
            covered.insert(class);
        } else {
            undecided.push(OutUndecided {
                site: format!("{}:{}", s.file_path, s.line_number),
                class,
                lever: lever_of(&f.reason),
                scope: s.scope().as_str(),
            });
        }
    }

    OutDoc {
        schema: "rvl-scan/v1",
        exit: if blocked { 3 } else { 0 },
        findings,
        coverage: OutCoverage {
            resolved: coverage.resolved,
            total: coverage.total,
            abstain: OutAbstain {
                no_spec: coverage.abstain_no_spec,
                bounds: coverage.abstain_bounds,
                judge: coverage.abstain_judge,
                other: coverage.abstain_other,
            },
            generated_skipped: coverage.generated_skipped,
            test_files_skipped: coverage.test_files_skipped.iter().map(|t| t.count).sum(),
            dependency_trees_uninstalled: coverage
                .dependencies_uninstalled
                .iter()
                .map(|d| d.count)
                .sum(),
            degraded_note: coverage.degraded_note.clone(),
            lang_status: coverage
                .lang_status
                .iter()
                .map(|s| OutLang {
                    lang: s.lang.clone(),
                    state: lang_state_str(s.state),
                    detail: s.detail.clone(),
                })
                .collect(),
            by_language: coverage
                .by_lang
                .iter()
                .map(|l| OutLangCoverage {
                    lang: l.lang.clone(),
                    resolved: l.resolved,
                    total: l.total,
                    no_spec: l.no_spec,
                    // The ladder prints no lever line under an empty corpus;
                    // the document must not say otherwise.
                    corpus_gap: !coverage.empty_api_corpus && l.corpus_is_the_lever(),
                })
                .collect(),
            retrievers: coverage
                .retrievers
                .iter()
                .map(|r| OutRetriever {
                    lang: r.lang.clone(),
                    path: r.path.clone(),
                    source: r.source.clone(),
                    drift: r.drift.clone(),
                })
                .collect(),
            degraded: coverage
                .degraded
                .iter()
                .map(|d| OutDegraded {
                    lang: d.lang.clone(),
                    abstained: d.abstained,
                    not_installed: d.not_installed,
                    reason: d.reason.clone(),
                })
                .collect(),
            config: config.filter(|c| !c.is_empty()).map(|c| OutConfig {
                resolved: c.resolved,
                total: c.total,
                abstain: OutConfigAbstain {
                    no_spec: c.abstain_no_spec,
                    outside_repo: c.abstain_outside_repo,
                    other: c.abstain_other,
                    vocabulary_only: c.vocabulary_only,
                },
                no_spec_keys: c.no_spec_keys.iter().cloned().collect(),
                by_key: c
                    .by_key
                    .iter()
                    .map(|((format, key), n)| OutConfigKey {
                        format: format.clone(),
                        key: key.clone(),
                        violates: n.violates,
                        satisfies: n.satisfies,
                        abstain: n.abstain,
                        not_applicable: n.not_applicable,
                    })
                    .collect(),
                unparseable_files: c.unparseable_files,
            }),
            retrieval: coverage.retrieval.clone(),
            structure: coverage.structure.map(|c| OutStructureCoverage {
                total: c.total(),
                violates: c.violates,
                satisfies: c.satisfies,
                abstain: c.abstain,
                not_applicable: c.not_applicable,
            }),
        },
        sites: site_rows,
        undecided,
        covered_classes: covered.into_iter().collect(),
        structure: structure.to_vec(),
        hook_agent: hook_agent_block.map(|b| b.to_string()),
        blend: blend.cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document's `exit` and its blocking rows must tell the same story
    /// the process exit code tells: derived from the same `classify`.
    #[test]
    fn exit_agrees_with_blocking_rows() {
        let f = render::Finding {
            id: "abcd".into(),
            site: "a.go:1".into(),
            description: "d".into(),
            disposition: "surface".into(),
            severity: "high".into(),
            incident_count: 0,
            critical_count: 0,
            control: "RC-019".into(),
            fix: "f".into(),
            site_count: 1,
            example_sites: vec![],
            class_rule: "t.m".into(),
            suppressed: false,
            gate_exempt: false,
        };
        let blocked = render::blocking_count(std::slice::from_ref(&f)) > 0;
        let doc = build(
            std::slice::from_ref(&f),
            &render::Coverage::default(),
            None,
            &[],
            &[],
            &[],
            None,
            None,
            blocked,
        );
        assert_eq!(doc.exit, 3);
        assert_eq!(doc.findings[0].severity, "blocking");
        assert_eq!(
            doc.findings
                .iter()
                .filter(|x| x.severity == "blocking")
                .count()
                > 0,
            doc.exit == 3
        );
    }

    /// CONTRACT LOCK (po-scnmv.16): for spec-lane findings, `class` IS the
    /// producing spec's identity — `class_rule` = `client_type.method`, the
    /// same key waivers use. The server's precision arm attributes
    /// adjudicated false positives to specs through this field, so renaming
    /// or restructuring it is a breaking change to the flywheel, not a
    /// cosmetic one. Vocabulary/structure lanes keep their fixed prefixes
    /// (`server_entry.`, `emission.`, `repo_structure.`, `config.`), which
    /// is how consumers tell the two apart.
    #[test]
    fn class_carries_spec_identity_verbatim() {
        let f = render::Finding {
            id: "abcd".into(),
            site: "a.go:1".into(),
            description: "d".into(),
            disposition: "surface".into(),
            severity: "low".into(),
            incident_count: 0,
            critical_count: 0,
            control: "RC-019".into(),
            fix: "f".into(),
            site_count: 1,
            example_sites: vec![],
            class_rule: "github.com/cli/cli/v2/api.Client.Do".into(),
            suppressed: false,
            gate_exempt: false,
        };
        let doc = build(
            std::slice::from_ref(&f),
            &render::Coverage::default(),
            None,
            &[],
            &[],
            &[],
            None,
            None,
            false,
        );
        assert_eq!(doc.findings[0].class, "github.com/cli/cli/v2/api.Client.Do");
    }

    fn row(class: &str, site: &str, site_count: usize) -> render::Finding {
        render::Finding {
            id: render::finding_id(&format!("{class}:{site}")),
            site: site.into(),
            description: "d".into(),
            disposition: "surface".into(),
            severity: "high".into(),
            incident_count: 0,
            critical_count: 0,
            control: "RC-019".into(),
            fix: "f".into(),
            site_count,
            example_sites: vec![],
            class_rule: class.into(),
            suppressed: false,
            gate_exempt: false,
        }
    }

    fn subjects(rows: &[render::Finding]) -> Vec<serde_json::Value> {
        let doc = build(
            rows,
            &render::Coverage::default(),
            None,
            &[],
            &[],
            &[],
            None,
            None,
            false,
        );
        let v = serde_json::to_value(&doc.findings).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|f| f["subject"].clone())
            .collect()
    }

    /// po-zcqld: two rows of one class and one control at two sites had one
    /// title, so the server gave both one identity and refused the second.
    /// The subject of a one-site row carries the file, so they stay apart.
    #[test]
    fn two_one_site_rows_of_one_class_get_two_subjects() {
        let got = subjects(&[
            row("secret.generic_api_key", "deploy/prod.env:3", 1),
            row("secret.generic_api_key", "tests/fixtures/keys.py:12", 1),
        ]);
        assert_eq!(
            got,
            vec![
                serde_json::json!({"kind": "symbol",
                    "value": "secret.generic_api_key@deploy/prod.env"}),
                serde_json::json!({"kind": "symbol",
                    "value": "secret.generic_api_key@tests/fixtures/keys.py"}),
            ]
        );
    }

    /// A row that aggregates sites is identified by its class alone: the
    /// primary site is only an example and changes between scans.
    #[test]
    fn a_row_that_aggregates_sites_has_the_class_as_subject() {
        let got = subjects(&[row("net/http.Client.Do", "internal/x/y.go:45", 3)]);
        assert_eq!(
            got,
            vec![serde_json::json!({"kind": "symbol", "value": "net/http.Client.Do"})]
        );
    }

    /// The line, the column and the config lane's unit are not identity: an
    /// edit above the site must not make a new risk.
    #[test]
    fn subject_of_a_one_site_row_carries_the_path_and_not_the_line() {
        assert_eq!(
            subject_of("t.m", "src/a.ts:12:7", 1).value,
            subject_of("t.m", "src/a.ts:90", 1).value
        );
        assert_eq!(
            subject_of(
                "github-actions.job.timeout-minutes",
                ".github/workflows/ci.yml (build)",
                1
            )
            .value,
            "github-actions.job.timeout-minutes@.github/workflows/ci.yml"
        );
    }

    /// A one-site row with no site to name keeps the class, never `class@`.
    #[test]
    fn subject_of_a_one_site_row_with_no_path_is_the_class() {
        assert_eq!(subject_of("t.m", "", 1).value, "t.m");
        assert_eq!(subject_of("t.m", "  ", 1).value, "t.m");
    }

    /// po-av01j.219: the retrieval denominator reaches the document beside
    /// resolved/total, so a consumer never quotes a coverage percentage
    /// without the extractor scope it was measured over.
    #[test]
    fn coverage_carries_the_retrieval_denominator() {
        let mut cov = render::Coverage::default();
        let mut unretrieved = std::collections::BTreeMap::new();
        unretrieved.insert("io.ReadAll".to_string(), 3);
        cov.retrieval = vec![rvl_core::RetrievalCensus {
            lang: "go".into(),
            calls_resolved: 4200,
            candidates: 97,
            unretrieved,
        }];
        let doc = build(&[], &cov, None, &[], &[], &[], None, None, false);
        let v = serde_json::to_value(&doc.coverage).unwrap();
        assert_eq!(v["retrieval"][0]["lang"], "go");
        assert_eq!(v["retrieval"][0]["candidates"], 97);
        assert_eq!(v["retrieval"][0]["calls_resolved"], 4200);
        assert_eq!(v["retrieval"][0]["unretrieved"]["io.ReadAll"], 3);
    }

    /// The per-language split reaches the document, with the same corpus-gap
    /// call the ladder's lever line makes (po-5csvg).
    /// po-av01j.133.12: the per-key counts are what a per-spec fire rate is
    /// computed from, so a consumer must be able to read them without the
    /// ladder, and they must account for every config setting.
    #[test]
    fn config_by_key_carries_the_counts_and_sums_to_the_total() {
        let counts = |violates, satisfies, abstain, not_applicable| render::ConfigKeyCounts {
            violates,
            satisfies,
            abstain,
            not_applicable,
        };
        let cc = render::ConfigCoverage {
            resolved: 6,
            total: 9,
            abstain_no_spec: 3,
            by_key: [
                (
                    ("kubernetes".to_string(), "workload.replicas".to_string()),
                    counts(0, 0, 3, 0),
                ),
                (
                    (
                        "github-actions".to_string(),
                        "job.timeout-minutes".to_string(),
                    ),
                    counts(2, 3, 0, 1),
                ),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let doc = build(
            &[],
            &render::Coverage::default(),
            Some(&cc),
            &[],
            &[],
            &[],
            None,
            None,
            false,
        );
        let v = serde_json::to_value(&doc).unwrap();
        let config = &v["coverage"]["config"];
        assert_eq!(
            config["by_key"],
            serde_json::json!([
                { "format": "github-actions", "key": "job.timeout-minutes",
                  "violates": 2, "satisfies": 3, "abstain": 0, "not_applicable": 1 },
                { "format": "kubernetes", "key": "workload.replicas",
                  "violates": 0, "satisfies": 0, "abstain": 3, "not_applicable": 0 },
            ]),
            "one row per (format, key), ordered by format then key"
        );
        let sum: u64 = config["by_key"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|r| ["violates", "satisfies", "abstain", "not_applicable"].map(|k| &r[k]))
            .map(|n| n.as_u64().unwrap())
            .sum();
        assert_eq!(Some(sum), config["total"].as_u64());
    }

    #[test]
    fn by_language_carries_the_split_and_the_corpus_gap() {
        let lc = |lang: &str, resolved, total, no_spec| render::LangCoverage {
            lang: lang.into(),
            resolved,
            total,
            no_spec,
        };
        let mut cov = render::Coverage {
            by_lang: vec![lc("Go", 900, 1000, 100), lc("Python", 0, 7184, 5173)],
            ..Default::default()
        };
        let doc = build(&[], &cov, None, &[], &[], &[], None, None, false);
        let v = serde_json::to_value(&doc.coverage.by_language).unwrap();
        assert_eq!(
            v,
            serde_json::json!([
                {"lang": "Go", "resolved": 900, "total": 1000, "no_spec": 100, "corpus_gap": false},
                {"lang": "Python", "resolved": 0, "total": 7184, "no_spec": 5173, "corpus_gap": true},
            ])
        );
        cov.empty_api_corpus = true;
        let doc = build(&[], &cov, None, &[], &[], &[], None, None, false);
        assert!(!doc.coverage.by_language[1].corpus_gap);
    }

    /// The structure lane rides its own array (po-av01j.28): repo-level rows
    /// must not change what the site-shaped fields mean.
    #[test]
    fn structure_rows_ride_their_own_array_and_leave_sites_alone() {
        let row = |control: &str, verdict: &str| OutSite {
            site_id: STRUCTURE_SITE_ID.into(),
            snapshot_id: "snap".into(),
            verdict: verdict.into(),
            reason: "r".into(),
            class: format!("repo_structure.{control}"),
        };
        let rows = [
            row("RC-033", "violates"),
            row("RC-057", "satisfies"),
            row("RC-034", "abstain"),
        ];
        let coverage = render::Coverage {
            structure: render::StructureCoverage::from_verdicts(
                rows.iter().map(|r| r.verdict.as_str()),
            ),
            ..Default::default()
        };
        let doc = build(&[], &coverage, None, &[], &[], &rows, None, None, false);
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["structure"].as_array().unwrap().len(), 3);
        assert_eq!(v["structure"][0]["site_id"], "repo");
        assert_eq!(v["structure"][0]["class"], "repo_structure.RC-033");
        assert_eq!(v["structure"][2]["verdict"], "abstain");
        assert_eq!(v["sites"].as_array().unwrap().len(), 0);
        assert_eq!(v["undecided"].as_array().unwrap().len(), 0);
        assert_eq!(v["covered_classes"].as_array().unwrap().len(), 0);
        assert_eq!(v["coverage"]["total"], 0);
        assert_eq!(
            v["coverage"]["structure"],
            serde_json::json!({"total": 3, "violates": 1, "satisfies": 1,
                               "abstain": 1, "not_applicable": 0})
        );
    }

    /// A scan whose structure lane did not run says so: an empty array and a
    /// null summary, never six fabricated abstains.
    #[test]
    fn no_structure_lane_is_an_empty_array_and_a_null_summary() {
        let doc = build(
            &[],
            &render::Coverage::default(),
            None,
            &[],
            &[],
            &[],
            None,
            None,
            false,
        );
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["structure"], serde_json::json!([]));
        assert!(v["coverage"]["structure"].is_null());
    }

    /// Unresolved sites land in `undecided` with the same lever the COVERAGE
    /// bucketing uses; resolved classes land in `covered_classes`.
    #[test]
    fn undecided_and_covered_partition_the_sites() {
        assert_eq!(lever_of("no spec for gcp.storage.write"), "no_spec");
        assert_eq!(lever_of("search truncated at depth 3"), "bounds");
        assert_eq!(lever_of("spec says depends"), "judge");
        assert_eq!(lever_of("mystery"), "other");
    }
}
