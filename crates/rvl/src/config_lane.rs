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
use rvl_config::key_ledger::{self, KeyState};
use rvl_config::kubernetes::manifest::LIVENESS_HTTP_GET_PATH_KEY;
use rvl_core::Verdict;
use rvl_data::BIN;
use rvl_propagate::probe_handler::LivenessProbe;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

/// Everything the config lane contributes to one scan.
#[derive(Debug, Default)]
pub struct LaneOutput {
    /// Ladder rows for violating config classes (grouped, not per-packet).
    pub findings: Vec<render::Finding>,
    pub coverage: render::ConfigCoverage,
    /// The liveness probe `httpGet` paths in the repo's Kubernetes manifests:
    /// the manifest half of the probe-to-handler join, which the scan
    /// completes against the server-entry lane's route inventory.
    pub liveness_probes: Vec<LivenessProbe>,
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
    let findings = rvl_config::eval::evaluate_all(&retrieval.packets, &retrieval.predicates, specs);

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
        let counts = coverage
            .by_key
            .entry((p.format.clone(), p.key.clone()))
            .or_default();
        match f.verdict {
            Verdict::Violates => counts.violates += 1,
            Verdict::Satisfies => counts.satisfies += 1,
            Verdict::Abstain => counts.abstain += 1,
            Verdict::NotApplicable => counts.not_applicable += 1,
        }
        if f.verdict.is_resolved() {
            coverage.resolved += 1;
        } else if f.reason.starts_with("no config spec") {
            // No spec is a gap only where one is wanted: a vocabulary-only
            // key is unjudged by design and stays out of the authoring lever.
            let unjudged_by_design = key_ledger::lookup(&p.format, &p.key)
                .is_some_and(|e| matches!(e.intent, key_ledger::Intent::VocabularyOnly(_)));
            if unjudged_by_design {
                coverage.vocabulary_only += 1;
            } else {
                coverage.abstain_no_spec += 1;
                coverage
                    .no_spec_keys
                    .insert(format!("{} {}", p.format, p.key));
            }
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
                gate_exempt: false,
            }
        })
        .collect();

    let liveness_probes = retrieval
        .packets
        .iter()
        .filter(|p| p.format == "kubernetes" && p.key == LIVENESS_HTTP_GET_PATH_KEY)
        .filter_map(|p| {
            Some(LivenessProbe {
                file_path: p.file_path.clone(),
                unit: p.unit.clone(),
                path: p.resolved_value.clone()?,
            })
        })
        .collect();

    LaneOutput {
        findings: ladder,
        coverage,
        liveness_probes,
    }
}

/// The standing mint queue as text, for `rvl cache keys`: every key the
/// retrievers can emit, split by where it stands against the installed specs.
/// Unlike a scan's `unjudged keys` line this does not depend on what one repo
/// happens to contain, and it is never truncated.
pub fn render_key_report(q: &key_ledger::MintQueue, artifact_loaded: bool) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "config keys: {} emitted \u{00b7} {} specced \u{00b7} {} awaiting a spec \u{00b7} {} vocabulary only",
        q.emitted, q.specced, q.mint_queue, q.vocabulary_only
    );
    if !artifact_loaded {
        let _ = writeln!(
            o,
            "no spec cache installed, so every judged key reads as awaiting a spec; \
             run '{BIN} sync' or '{BIN} cache import'"
        );
    }
    for (state, heading) in [
        (KeyState::MintQueue, "awaiting a spec (the mint queue):"),
        (KeyState::VocabularyOnly, "vocabulary only, not judged:"),
        (KeyState::Specced, "specced:"),
    ] {
        let _ = writeln!(o, "\n{heading}");
        let mut any = false;
        for row in q.keys.iter().filter(|r| r.state == state) {
            any = true;
            if row.reason.is_empty() {
                let _ = writeln!(o, "  {} {}", row.format, row.key);
            } else {
                let _ = writeln!(o, "  {} {} \u{2014} {}", row.format, row.key, row.reason);
            }
        }
        if !any {
            let _ = writeln!(o, "  (none)");
        }
    }
    o
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

    // THE INVARIANT rule_phrase EXISTS FOR, pinned. A class is grouped by the
    // text before the first colon, so any VALUE appearing there fragments one
    // reader-facing class into one class per distinct value. Introduced by
    // po-av01j.129's numeric bounds ("workload.replicas = 1 is below the
    // minimum of 2" has no colon at all) and caught by reading the ladder on a
    // real repo, not by any test.
    #[test]
    fn differing_values_do_not_fragment_one_class() {
        for (a, b) in [
            (
                "below the minimum of 2: workload.replicas = 1",
                "below the minimum of 2: workload.replicas = 0",
            ),
            (
                "not one of digest, tag: dockerfile.base_image_pin = latest",
                "not one of digest, tag: dockerfile.base_image_pin = ",
            ),
            (
                "does not match sha40: step.uses.ref = v4",
                "does not match sha40: step.uses.ref = main",
            ),
            (
                "not equal to false: job.continue-on-error = true",
                "not equal to false: job.continue-on-error = yes",
            ),
        ] {
            assert_eq!(
                rule_phrase(a),
                rule_phrase(b),
                "two sites of the same rule must share a class"
            );
            assert!(
                !rule_phrase(a).contains('='),
                "a class phrase must carry no value: {:?}",
                rule_phrase(a)
            );
        }
    }

    // ...and the phrase must still SAY something. "unexpected value" was fixed
    // across sites and told the reader nothing; the expectation is equally
    // fixed and is the useful half.
    #[test]
    fn a_class_phrase_names_the_expectation() {
        for (reason, want) in [
            ("below the minimum of 2: k = 1", "below the minimum of 2"),
            (
                "not one of digest, tag: k = latest",
                "not one of digest, tag",
            ),
            ("does not match sha40: k = v4", "does not match sha40"),
        ] {
            assert_eq!(rule_phrase(reason), want);
        }
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
        // Coverage: timeout resolved (violates IS a conclusion), and since
        // po-av01j.143 the permissions packet resolves too -- `Present` asks
        // about authorship, so an unauthored key decides rather than abstaining
        // on an out-of-repo default it never needed. The unspecced packets
        // (concurrency, continue-on-error) still abstain by their lever.
        assert!(out.coverage.total >= 4, "coverage: {:?}", out.coverage);
        assert!(out.coverage.resolved >= 2, "coverage: {:?}", out.coverage);
        assert!(out.coverage.abstain_no_spec >= 2);
        let perms: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class_rule == "github-actions.job.permissions")
            .collect();
        assert_eq!(
            perms.len(),
            1,
            "an unauthored permissions block is a finding, not an abstention: {:?}",
            out.findings
        );
    }

    // The outside-repo lever still exists and must still be reachable: a
    // VALUE-BEARING expectation on the same unresolvable packet cannot decide,
    // because it genuinely needs the value `Present` never wanted.
    #[test]
    fn a_value_bearing_spec_still_abstains_on_an_out_of_repo_value() {
        let sf = SpecFile {
            config_keys: vec![ConfigKeySpec {
                format: "github-actions".into(),
                key: "job.permissions".into(),
                expect: ConfigExpect::Equals {
                    value: "contents: read".into(),
                },
                confidence: 0.9,
                rationale: String::new(),
                control: "RC-044".into(),
                severity: "medium".into(),
                fix: String::new(),
            }],
            ..Default::default()
        };
        let dir = repo_with_workflow("on: push\njobs:\n  a:\n    runs-on: x\n");
        let out = run(dir.path(), &SpecCache::from_file(sf), "snap");
        assert!(
            out.coverage.abstain_outside_repo >= 1,
            "coverage: {:?}",
            out.coverage
        );
    }

    // A vocabulary-only key has no spec BY DESIGN. Counting it under the
    // authoring lever would name a gap nobody intends to close.
    #[test]
    fn a_vocabulary_only_key_is_not_reported_as_a_missing_spec() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("main.tf"),
            "module \"vpc\" {\n  source  = \"terraform-aws-modules/vpc/aws\"\n  version = \"5.1.0\"\n}\n",
        )
        .unwrap();
        let out = run(dir.path(), &specs("high"), "snap");
        let cov = &out.coverage;
        assert_eq!(
            cov.vocabulary_only, 3,
            "module.source, module.version-pin and terraform.module-kind: {cov:?}"
        );
        assert!(
            !cov.no_spec_keys.contains("terraform module.source")
                && !cov.no_spec_keys.contains("terraform module.version-pin"),
            "{cov:?}"
        );
        assert!(
            cov.no_spec_keys.contains("terraform module.source-class"),
            "a judged key with no spec stays in the queue: {cov:?}"
        );
        assert_eq!(
            cov.resolved + cov.abstain_total(),
            cov.total,
            "every packet is accounted for: {cov:?}"
        );
    }

    // po-av01j.133.12. A per-spec fire rate is violates / (violates +
    // satisfies) of ONE key, and the ladder only ever named the violating
    // half. Every packet lands in exactly one count of exactly one key, so
    // the block sums to the lane total and to each of its halves.
    #[test]
    fn every_packet_is_counted_once_under_its_key() {
        let dir = repo_with_workflow(
            "on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    runs-on: x\n    timeout-minutes: 5\n  c:\n    runs-on: x\n",
        );
        let out = run(dir.path(), &specs("high"), "snap");
        let cov = &out.coverage;
        let key = |k: &str| {
            *cov.by_key
                .get(&("github-actions".to_string(), k.to_string()))
                .unwrap_or_else(|| panic!("no row for {k}: {:?}", cov.by_key))
        };
        assert_eq!(
            key("job.timeout-minutes"),
            render::ConfigKeyCounts {
                violates: 2,
                satisfies: 1,
                abstain: 0,
                not_applicable: 0,
            },
            "two jobs without a timeout, one with"
        );
        // A key with no spec is still a row: its packets abstain.
        let unspecced = key("workflow.concurrency");
        assert_eq!(unspecced.violates + unspecced.satisfies, 0);
        assert!(unspecced.abstain >= 1, "{unspecced:?}");

        let sum = |f: fn(&render::ConfigKeyCounts) -> usize| -> usize {
            cov.by_key.values().map(f).sum()
        };
        assert_eq!(
            sum(|c| c.violates + c.satisfies + c.abstain + c.not_applicable),
            cov.total,
            "{cov:?}"
        );
        assert_eq!(
            sum(|c| c.violates + c.satisfies + c.not_applicable),
            cov.resolved,
            "{cov:?}"
        );
        assert_eq!(sum(|c| c.abstain), cov.abstain_total(), "{cov:?}");
    }

    #[test]
    fn key_report_names_the_queue_and_separates_vocabulary_only() {
        let q = rvl_config::key_ledger::mint_queue(&specs("high"));
        let text = render_key_report(&q, true);
        let line = |needle: &str| text.lines().position(|l| l.contains(needle));
        assert!(
            text.contains(&format!(
                "config keys: {} emitted \u{00b7} 2 specced \u{00b7} {} awaiting a spec \u{00b7} {} vocabulary only",
                q.emitted, q.mint_queue, q.vocabulary_only
            )),
            "{text}"
        );
        let (queue, vocab, specced) = (
            line("awaiting a spec (the mint queue)").unwrap(),
            line("vocabulary only, not judged").unwrap(),
            line("specced:").unwrap(),
        );
        let at = |needle: &str| line(needle).unwrap_or_else(|| panic!("no {needle} in {text}"));
        assert!((queue..vocab).contains(&at("github-actions workflow.concurrency")));
        assert!((vocab..specced).contains(&at("terraform module.source ")));
        // A guard predicate is a fact a conditional spec asks about, never a
        // key awaiting a spec of its own (po-av01j.133.10).
        assert!((vocab..specced).contains(&at("github-actions workflow.triggers ")));
        assert!(at("github-actions job.timeout-minutes") > specced);
        assert!(!text.contains("no spec cache"), "{text}");
    }

    // With nothing installed the whole judged ledger reads as queued. That is
    // true, and it must not pass for a statement about the factory's backlog.
    #[test]
    fn key_report_says_when_no_artifact_was_loaded() {
        let q = rvl_config::key_ledger::mint_queue(&SpecCache::default());
        let text = render_key_report(&q, false);
        assert!(text.contains("no spec cache installed"), "{text}");
    }

    #[test]
    fn empty_repo_yields_an_empty_lane() {
        let dir = tempfile::tempdir().unwrap();
        let out = run(dir.path(), &specs("high"), "snap");
        assert!(out.findings.is_empty());
        assert!(out.coverage.is_empty());
    }

    // po-av01j.133.10. `workflow.concurrency` was REJECTED as a spec because
    // the unconditional form fires on every lint and test workflow, where two
    // overlapping runs are harmless. Restated as a conditional spec it fires
    // only where overlapping runs race to publish. Driven from the WIRE form
    // through real workflow files, so the retriever's predicates, the spec
    // grammar and the evaluator are proven to agree on the predicate key.
    #[test]
    fn the_rejected_concurrency_candidate_decides_as_a_conditional_spec() {
        let specs = SpecCache::load(
            r#"{"config_keys": [
                {"format": "github-actions", "key": "workflow.concurrency",
                 "expect": {"kind": "when",
                            "guard": {"key": "workflow.publishes_image",
                                      "any_of": ["true"]},
                            "then": {"kind": "present"}},
                 "confidence": 0.9, "control": "RC-014", "severity": "medium",
                 "fix": "set a workflow-level concurrency group"}
            ]}"#,
        )
        .unwrap();
        let publish = "    steps:\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n";

        let dir = tempfile::tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        std::fs::create_dir_all(&wf).unwrap();
        std::fs::write(
            wf.join("lint.yml"),
            "on: pull_request\njobs:\n  lint:\n    steps:\n      - run: make lint\n",
        )
        .unwrap();
        std::fs::write(
            wf.join("release.yml"),
            format!("on: push\njobs:\n  image:\n{publish}"),
        )
        .unwrap();
        std::fs::write(
            wf.join("serialized.yml"),
            format!("on: push\nconcurrency: release\njobs:\n  image:\n{publish}"),
        )
        .unwrap();

        let out = run(dir.path(), &specs, "snap");
        let class: Vec<_> = out
            .findings
            .iter()
            .filter(|f| f.class_rule == "github-actions.workflow.concurrency")
            .collect();
        assert_eq!(class.len(), 1, "{:?}", out.findings);
        assert_eq!(
            class[0].example_sites,
            vec![".github/workflows/release.yml (workflow)".to_string()],
            "only the unserialized publishing workflow violates"
        );
        assert_eq!(class[0].control, "RC-014");
        // All three concurrency packets RESOLVED: violates, not-applicable,
        // satisfies. None fell to an abstention.
        assert_eq!(out.coverage.resolved, 3, "{:?}", out.coverage);
        assert_eq!(out.coverage.abstain_other, 0, "{:?}", out.coverage);
        // A guard that does not hold is not a site that satisfied: counting
        // it there would dilute the fire rate of the conditional spec.
        assert_eq!(
            out.coverage.by_key[&(
                "github-actions".to_string(),
                "workflow.concurrency".to_string()
            )],
            render::ConfigKeyCounts {
                violates: 1,
                satisfies: 1,
                abstain: 0,
                not_applicable: 1,
            }
        );
        // And the predicates did not leak into the unjudged-keys queue.
        assert!(
            out.coverage
                .no_spec_keys
                .iter()
                .all(|k| !k.contains("triggers") && !k.contains("publishes_image")),
            "{:?}",
            out.coverage.no_spec_keys
        );
    }
}
