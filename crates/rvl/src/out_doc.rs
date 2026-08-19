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
    /// The hook-adjudication agent block verbatim when `--hook` ran; null
    /// otherwise. Provenance-tagged and separate, exactly as rendered.
    pub hook_agent: Option<String>,
}

/// One per-site eval row. Field names match the old top-level array (and the
/// rvl-eval `run` emitter) exactly, so harness consumers migrate by reading
/// `.sites` instead of the document root, nothing else.
#[derive(Serialize)]
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
pub struct OutRetriever {
    pub lang: String,
    pub path: String,
    pub source: String,
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
}

#[derive(Serialize)]
pub struct OutConfig {
    pub resolved: usize,
    pub total: usize,
    pub abstain: OutConfigAbstain,
    pub no_spec_keys: Vec<String>,
    pub unparseable_files: usize,
}

#[derive(Serialize)]
pub struct OutCoverage {
    pub resolved: usize,
    pub total: usize,
    pub abstain: OutAbstain,
    pub generated_skipped: usize,
    pub degraded_note: Option<String>,
    pub lang_status: Vec<OutLang>,
    pub retrievers: Vec<OutRetriever>,
    pub degraded: Vec<OutDegraded>,
    pub config: Option<OutConfig>,
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
        render::LangState::Abstained => "abstained",
        render::LangState::Failed => "failed",
        render::LangState::Unsupported => "unsupported",
        render::LangState::NotInstalled => "not_installed",
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
    hook_agent_block: Option<&str>,
    blocked: bool,
) -> OutDoc {
    let findings = ladder
        .iter()
        .map(|f| OutFinding {
            id: f.id.clone(),
            class: f.class_rule.clone(),
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
            retrievers: coverage
                .retrievers
                .iter()
                .map(|r| OutRetriever {
                    lang: r.lang.clone(),
                    path: r.path.clone(),
                    source: r.source.clone(),
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
                },
                no_spec_keys: c.no_spec_keys.iter().cloned().collect(),
                unparseable_files: c.unparseable_files,
            }),
        },
        sites: site_rows,
        undecided,
        covered_classes: covered.into_iter().collect(),
        hook_agent: hook_agent_block.map(|b| b.to_string()),
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
            None,
            false,
        );
        assert_eq!(doc.findings[0].class, "github.com/cli/cli/v2/api.Client.Do");
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
