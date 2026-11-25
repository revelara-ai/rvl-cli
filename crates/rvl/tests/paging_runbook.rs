//! RC-006 end to end, through the binary: a paging alert rule with no
//! runbook annotation is flagged by the guarded spec form
//! (`when rule.labels.severity one_of [critical, page, p1]`, then a
//! nonempty runbook), a warning rule is not, and neither is the paging rule
//! of a repository whose Alertmanager receivers page nobody.

use std::path::{Path, PathBuf};
use std::process::Command;

const RULES: &str = "deploy/prometheus/rules.yaml";

const RULE_FILE: &str = "groups:\n- name: api\n  rules:\n  - alert: ApiDown\n    expr: up == 0\n    for: 5m\n    labels:\n      severity: critical\n    annotations:\n      summary: the API is down\n  - alert: ApiSlow\n    expr: latency > 1\n    for: 5m\n    labels:\n      severity: warning\n    annotations:\n      summary: the API is slow\n";

const SPECS: &str = r#"{"config_keys":[
    {"format":"prometheus-rules","key":"rule.annotations.runbook",
     "expect":{"kind":"when",
               "guard":{"key":"rule.labels.severity","any_of":["critical","page","p1"]},
               "then":{"kind":"pattern","name":"nonempty"}},
     "confidence":0.9,"control":"RC-006","severity":"medium",
     "fix":"link a runbook from the paging alert",
     "rationale":"test-grade seed of the guarded form"}
]}"#;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    for k in [
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

/// Scan a repository of `files` and return the verdict of the runbook row
/// of each alert, keyed by its resource.
fn runbook_verdicts(files: &[(&str, &str)]) -> Vec<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("platform");
    for (path, text) in files {
        let path = repo.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, SPECS).unwrap();
    let out_path: PathBuf = dir.path().join("out.json");
    let out = bin()
        .arg("scan")
        .arg(&repo)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvl");
    assert!(
        Path::new(&out_path).is_file(),
        "scan wrote no --out document: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = doc["config_sites"]
        .as_array()
        .unwrap_or_else(|| panic!("no config_sites array: {doc}"));
    let mut got: Vec<(String, String)> = rows
        .iter()
        .filter(|r| r["file"] == RULES && r["key"] == "rule.annotations.runbook")
        .map(|r| {
            (
                r["resource"].as_str().unwrap_or("").to_string(),
                r["verdict"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    got.sort();
    got
}

fn row(resource: &str, verdict: &str) -> (String, String) {
    (resource.to_string(), verdict.to_string())
}

#[test]
fn a_critical_rule_with_no_runbook_is_flagged_and_a_warning_rule_is_not() {
    assert_eq!(
        runbook_verdicts(&[(RULES, RULE_FILE)]),
        vec![
            row("rule:api/ApiDown", "violates"),
            row("rule:api/ApiSlow", "not_applicable"),
        ]
    );
}

#[test]
fn the_critical_rule_is_not_flagged_when_alerts_only_reach_slack() {
    let slack = "route:\n  receiver: chat\nreceivers:\n- name: chat\n  slack_configs:\n  - channel: '#alerts'\n";
    assert_eq!(
        runbook_verdicts(&[
            (RULES, RULE_FILE),
            ("deploy/alertmanager/alertmanager.yml", slack)
        ]),
        vec![
            row("rule:api/ApiDown", "abstain"),
            row("rule:api/ApiSlow", "not_applicable"),
        ]
    );
}
