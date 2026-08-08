//! Scan-side wiring of the G6 config lane: retrieve config packets from the
//! repo, run the config-spec verification lane, and shape the results for the
//! ladder.
//!
//! The lane rides the same SpecCache the code lane already loaded (one signed
//! artifact carries both), and its findings become ordinary ladder rows: a
//! config finding groups by (format, key, rule), carries the spec's control
//! and severity, and is waivable through `.revelara.yaml` under the class
//! rule `<format>.<key>` — the exact mechanics code findings use.

use crate::render;
use rvl_core::Verdict;
use std::collections::BTreeMap;
use std::path::Path;

/// Everything the config lane contributes to one scan.
#[derive(Debug, Default)]
pub struct LaneOutput {
    /// Ladder rows for violating config classes (grouped, not per-packet).
    pub findings: Vec<render::Finding>,
    pub coverage: render::ConfigCoverage,
}

/// The class rule a config finding is grouped and waived by.
fn class_rule(format: &str, key: &str) -> String {
    format!("{format}.{key}")
}

/// The rule phrase of a reason: the fixed vocabulary before any `:` detail,
/// same convention as `rvl_triage::class_of` so detail never fragments a
/// class.
fn rule_phrase(reason: &str) -> &str {
    reason.split(':').next().unwrap_or(reason).trim()
}

/// Run the config lane over `root` with the already-loaded specs.
pub fn run(root: &Path, specs: &rvl_spec::SpecCache, snapshot_id: &str) -> LaneOutput {
    let retrieval = rvl_config::retrieve_repo(root, snapshot_id);
    let findings = rvl_config::eval::evaluate_all(&retrieval.packets, specs);

    let mut coverage = render::ConfigCoverage {
        total: retrieval.packets.len(),
        unparseable_files: retrieval.unparseable_files,
        sightings: retrieval
            .sightings
            .iter()
            .map(|s| (s.format.clone(), s.file_count, s.retriever_exists))
            .collect(),
        ..Default::default()
    };

    // Group violations into classes: one (format, key, rule) is one reader-
    // facing item, however many workflows repeat it.
    struct Class {
        control: String,
        severity: String,
        fix: String,
        sites: Vec<String>,
    }
    let mut classes: BTreeMap<(String, String, String), Class> = BTreeMap::new();

    for (f, p) in findings.iter().zip(retrieval.packets.iter()) {
        if f.verdict.is_resolved() {
            coverage.resolved += 1;
        } else if f.reason.starts_with("no config spec") {
            coverage.abstain_no_spec += 1;
        } else if f.reason.contains("outside the repo") {
            coverage.abstain_outside_repo += 1;
        } else {
            coverage.abstain_other += 1;
        }
        if f.verdict != Verdict::Violates {
            continue;
        }
        let key = (
            p.format.clone(),
            p.key.clone(),
            rule_phrase(&f.reason).to_string(),
        );
        let c = classes.entry(key).or_insert_with(|| Class {
            control: f.control.clone(),
            severity: f.severity.clone(),
            fix: f.fix.clone(),
            sites: Vec::new(),
        });
        c.sites.push(format!("{} ({})", p.file_path, p.unit));
    }

    let ladder = classes
        .into_iter()
        .map(|((format, key, rule), c)| {
            let id_key = format!("{format}.{key}:{rule}");
            render::Finding {
                id: render::finding_id(&id_key),
                site: c
                    .sites
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("{} sites", c.sites.len())),
                description: format!("{format} {key} \u{2014} {rule}"),
                // A spec that carries a judged severity surfaces; one without
                // is unjudged and stays advisory — never blocking.
                disposition: if c.severity.is_empty() {
                    "unjudged".to_string()
                } else {
                    "surface".to_string()
                },
                severity: c.severity,
                incident_count: 0,
                critical_count: 0,
                control: c.control,
                fix: c.fix,
                site_count: c.sites.len(),
                example_sites: c.sites.into_iter().take(3).collect(),
                class_rule: class_rule(&format, &key),
                suppressed: false,
            }
        })
        .collect();

    LaneOutput {
        findings: ladder,
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_spec::{ConfigExpect, ConfigKeySpec, SpecCache, SpecFile};

    fn specs(severity: &str) -> SpecCache {
        SpecCache::from_file(SpecFile {
            config_keys: vec![
                ConfigKeySpec {
                    format: "github-actions".into(),
                    key: "job.timeout-minutes".into(),
                    expect: ConfigExpect::Present,
                    confidence: 0.9,
                    rationale: String::new(),
                    control: "RC-013".into(),
                    severity: severity.into(),
                    fix: "set jobs.<id>.timeout-minutes".into(),
                },
                // A specced key whose value lives outside the repo (the
                // GITHUB_TOKEN default) exercises the outside-repo lever.
                ConfigKeySpec {
                    format: "github-actions".into(),
                    key: "job.permissions".into(),
                    expect: ConfigExpect::Present,
                    confidence: 0.9,
                    rationale: String::new(),
                    control: "RC-044".into(),
                    severity: String::new(),
                    fix: String::new(),
                },
            ],
            ..Default::default()
        })
    }

    fn repo_with_workflow(yaml: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        std::fs::write(dir.path().join(".github/workflows/ci.yml"), yaml).unwrap();
        dir
    }

    #[test]
    fn violations_group_into_one_class_per_format_key_rule() {
        let dir =
            repo_with_workflow("on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    runs-on: x\n");
        let out = run(dir.path(), &specs(""), "snap");
        let timeouts: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class_rule == "github-actions.job.timeout-minutes")
            .collect();
        assert_eq!(timeouts.len(), 1, "two jobs, one class: {:?}", out.findings);
        assert_eq!(timeouts[0].site_count, 2);
        assert_eq!(timeouts[0].control, "RC-013");
        assert_eq!(
            timeouts[0].disposition, "unjudged",
            "an unjudged config class never blocks"
        );
    }

    #[test]
    fn judged_severity_surfaces_and_coverage_counts_levers() {
        let dir = repo_with_workflow("on: push\njobs:\n  a:\n    runs-on: x\n");
        let out = run(dir.path(), &specs("high"), "snap");
        let f = out
            .findings
            .iter()
            .find(|f| f.class_rule == "github-actions.job.timeout-minutes")
            .expect("a violating class");
        assert_eq!(f.disposition, "surface");
        assert_eq!(f.severity, "high");
        // Coverage: timeout resolved (violates IS a conclusion); the other
        // packets (permissions unresolvable, concurrency/continue-on-error
        // unspecced) abstain by their levers.
        assert!(out.coverage.total >= 4, "coverage: {:?}", out.coverage);
        assert!(out.coverage.resolved >= 1);
        assert!(out.coverage.abstain_no_spec >= 2);
        assert!(out.coverage.abstain_outside_repo >= 1);
    }

    #[test]
    fn empty_repo_yields_an_empty_lane() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(dir.path(), &specs("high"), "snap");
        assert!(out.findings.is_empty());
        assert!(out.coverage.is_empty());
    }
}
