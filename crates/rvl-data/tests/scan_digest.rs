//! `rvl scan digest`: the residual-scoping digest of an engine scan document.
//! The fixtures and expected lines are the ones the scan skill's own tests
//! held for the script this command replaces.

use rvl_data::scan_digest;
use serde_json::{json, Value};
use std::path::Path;

fn digest(dir: &Path, doc: &Value) -> anyhow::Result<String> {
    let path = dir.join("engine.json");
    std::fs::write(&path, serde_json::to_vec(doc).unwrap()).unwrap();
    let mut out = Vec::new();
    scan_digest::run(&path, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

fn undecided(n: usize, lever: &str, scope: &str) -> Vec<Value> {
    (0..n)
        .map(|i| {
            json!({
                "site": format!("internal/{scope}_{lever}_{i:02}.go:{}", i + 1),
                "class": "http.Client", "lever": lever, "scope": scope,
            })
        })
        .collect()
}

#[test]
fn adjudication_list_is_runtime_only_judge_then_bounds_then_no_spec_capped_at_20() {
    let dir = tempfile::tempdir().unwrap();
    // Worst input order for the ranking: lowest-priority lever first.
    let mut und = undecided(8, "no_spec", "runtime");
    und.extend(undecided(4, "judge", "test_support"));
    und.extend(undecided(9, "bounds", "runtime"));
    und.extend(undecided(3, "judge", "migration"));
    und.extend(undecided(6, "judge", "runtime"));
    let out = digest(
        dir.path(),
        &json!({
            "schema": "rvl-scan/v1", "exit": 0, "findings": [], "covered_classes": ["http.Client"],
            "coverage": {"resolved": 1, "total": 31, "abstain": 30}, "undecided": und,
        }),
    )
    .unwrap();

    let (_, list) = out
        .split_once("ADJUDICATION_LIST (20 sites, cap 20):\n")
        .unwrap_or_else(|| panic!("want a 20-site adjudication list, got:\n{out}"));
    let mut levers = Vec::new();
    for line in list.trim_end_matches('\n').split('\n') {
        let parts: Vec<&str> = line.trim().split(" · ").collect();
        assert_eq!(parts.len(), 3, "line {line:?} is not site · class · lever");
        assert!(
            parts[0].starts_with("internal/runtime_"),
            "non-runtime site {} must never enter the adjudication list",
            parts[0]
        );
        levers.push(parts[2]);
    }
    let want: Vec<&str> = [("judge", 6), ("bounds", 9), ("no_spec", 5)]
        .iter()
        .flat_map(|(l, n)| std::iter::repeat_n(*l, *n))
        .collect();
    assert_eq!(levers, want);
}

#[test]
fn digest_prints_the_lines_the_skill_reads() {
    let dir = tempfile::tempdir().unwrap();
    // Written as text: the digest shows `coverage.abstain` in the key order
    // of the file, which `json!` would sort.
    let path = dir.path().join("engine.json");
    std::fs::write(
        &path,
        r#"{
            "schema": "rvl-scan/v1", "exit": 3,
            "covered_classes": ["http.Client", "sql.DB"],
            "coverage": {"resolved": 4, "total": 9, "abstain": {"no_spec": 3, "bounds": 1, "judge": 1, "other": 0}},
            "findings": [
                {"id": "E2", "class": "retry", "site": "repo", "control": "RC-021", "fix": "add backoff", "severity": "advisory"},
                {"id": "E1", "class": "http.Client", "site": "internal/x.go:3", "control": "RC-019", "fix": "set timeout", "severity": "blocking"}
            ],
            "undecided": [
                {"site": "a.go:1", "class": "sql.DB", "lever": "no_spec", "scope": "runtime"},
                {"site": "a_test.go:2", "class": "sql.DB", "lever": "judge", "scope": "test_support"},
                {"site": "b.go:3", "class": "http.Client", "lever": "judge", "scope": "runtime"},
                {"site": "c.go:4", "class": "sql.DB", "lever": "no_spec", "scope": "runtime"}
            ]
        }"#,
    )
    .unwrap();
    let mut out = Vec::new();
    scan_digest::run(&path, &mut out).unwrap();
    let out = String::from_utf8(out).unwrap();
    let want = "\
ENGINE_DIGEST exit=3 blocking=1 advisory=1 resolved=4/9 abstain={'no_spec': 3, 'bounds': 1, 'judge': 1, 'other': 0}
  BLOCK [E1] http.Client — internal/x.go:3 · RC-019 · fix: set timeout
  ADV   [E2] retry — repo · RC-021
COVERED_CLASSES (engine-settled; lenses must NOT re-report these):
  http.Client, sql.DB
UNDECIDED total=4 by_scope={'runtime': 3, 'test_support': 1} runtime_by_lever={'no_spec': 2, 'judge': 1}
UNDECIDED_CLASS_CENSUS (runtime, top 10):
      2  sql.DB
      1  http.Client
ADJUDICATION_LIST (3 sites, cap 20):
  b.go:3 · http.Client · judge
  a.go:1 · sql.DB · no_spec
  c.go:4 · sql.DB · no_spec
";
    assert_eq!(out, want);
}

#[test]
fn a_scan_document_of_another_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = digest(dir.path(), &json!({"schema": "rvl-scan/v2"})).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("rvl-scan/v2") && msg.contains("rvl-scan/v1"),
        "{msg}"
    );
}

#[test]
fn a_document_that_lacks_a_field_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let err = digest(
        dir.path(),
        &json!({"schema": "rvl-scan/v1", "exit": 0, "findings": [], "covered_classes": [], "undecided": []}),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("coverage"), "{err:#}");
}
