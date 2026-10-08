//! `rvl scan report`: the sections of the scan report that are pure data,
//! printed from the engine scan document and the findings files.

use rvl_data::scan_report;
use serde_json::{json, Value};
use std::path::Path;

fn write(path: &Path, v: &Value) {
    std::fs::write(path, serde_json::to_vec(v).unwrap()).unwrap();
}

fn report(dir: &Path, doc: &Value, scan_dir: Option<&Path>) -> anyhow::Result<String> {
    let path = dir.join("engine.json");
    write(&path, doc);
    let mut out = Vec::new();
    scan_report::run(&path, scan_dir, &mut out)?;
    Ok(String::from_utf8(out).unwrap())
}

fn finding(id: &str, severity: &str) -> Value {
    json!({
        "id": id, "class": "http.Client", "site": "internal/x.go:3", "control": "RC-019",
        "fix": "set timeout", "description": "No client timeout", "severity": severity,
        "base_severity": "high", "site_count": 1, "suppressed": false, "gate_exempt": false,
    })
}

/// A document with a row in each section, in an order that is not the order
/// of the sections, and each flag a row can carry.
fn engine_doc() -> Value {
    let mut waived = finding("E3", "suppressed");
    waived["class"] = json!("grpc.Dial");
    waived["site"] = json!("internal/rpc.go:11");
    waived["fix"] = json!("set a deadline");
    waived["suppressed"] = json!(true);
    let mut advisory = finding("E2", "advisory");
    advisory["class"] = json!("sql.DB");
    advisory["site"] = json!("internal/db.go:7");
    advisory["control"] = json!("RC-021");
    advisory["fix"] = json!("bound the pool");
    let mut low_value = finding("E4", "suppressed");
    low_value["site"] = json!("cmd/tool.go:2");
    low_value["control"] = json!("");
    let mut exempt = finding("E5", "advisory");
    exempt["class"] = json!("repo_structure.RC-033");
    exempt["site"] = json!("repo");
    exempt["control"] = json!("RC-033");
    exempt["fix"] = json!("add a CODEOWNERS file");
    exempt["gate_exempt"] = json!(true);
    json!({
        "schema": "rvl-scan/v1", "exit": 3,
        "findings": [waived, advisory, finding("E1", "blocking"), low_value, exempt],
        "coverage": {
            "resolved": 7, "total": 9,
            "abstain": {"no_spec": 1, "bounds": 0, "judge": 1, "other": 0},
            "lang_status": [
                {"lang": "go", "state": "scanned", "detail": "1240"},
                {"lang": "c", "state": "partial", "detail": "12 sites, INCOMPLETE: a header is missing"},
                {"lang": "ruby", "state": "abstained", "detail": "no gems"},
                {"lang": "java", "state": "failed", "detail": "helper crashed"},
                {"lang": "kotlin", "state": "unsupported", "detail": "3 files"},
                {"lang": "python", "state": "not_installed", "detail": "python3 not found on PATH"},
                {"lang": "typescript", "state": "skipped", "detail": "1 file"},
            ],
        },
        "undecided": [], "covered_classes": ["http.Client"],
    })
}

const GATE_AND_COVERAGE: &str = "\
### Gate (deterministic engine) — exit 3
BLOCKING (1):
  [E1] http.Client — internal/x.go:3 · RC-019 · fix: set timeout
    waive: `rvl suppress E1 --reason=\"...\"` or a `# rvl:allow` comment on the line
ADVISORY (2):
  [E2] sql.DB — internal/db.go:7 · RC-021 · fix: bound the pool
  [E5] repo_structure.RC-033 — repo · RC-033 · fix: add a CODEOWNERS file (gate-exempt)
SUPPRESSED (2):
  [E3] grpc.Dial — internal/rpc.go:11 · RC-019 · fix: set a deadline (suppressed)
  [E4] http.Client — cmd/tool.go:2 ·  · fix: set timeout (low value)

### Coverage
Engine: 7/9 retrieved API surfaces resolved (77% of retrieved) · abstains: no_spec 1 · bounds 0 · judge 1 · other 0
Languages: go 1240 sites · c 12 sites, INCOMPLETE: a header is missing · ruby abstained · java FAILED · kotlin not supported (3 files) · python helper not installed · typescript skipped (1 file, test material only; --include-tests scans it)
";

#[test]
fn prints_the_gate_and_coverage_sections_of_the_fixture_document() {
    let dir = tempfile::tempdir().unwrap();
    let out = report(dir.path(), &engine_doc(), None).unwrap();
    assert_eq!(out, GATE_AND_COVERAGE);
}

#[test]
fn a_suppressed_row_is_shown_with_a_flag_and_no_row_is_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let doc = engine_doc();
    let out = report(dir.path(), &doc, None).unwrap();
    for x in doc["findings"].as_array().unwrap() {
        let id = format!("  [{}] ", x["id"].as_str().unwrap());
        assert_eq!(out.matches(&id).count(), 1, "row {id:?} in:\n{out}");
    }
    let (_, suppressed) = out.split_once("SUPPRESSED (2):\n").unwrap();
    let rows: Vec<&str> = suppressed.lines().take(2).collect();
    assert!(rows[0].ends_with(" (suppressed)"), "{rows:?}");
    assert!(rows[1].ends_with(" (low value)"), "{rows:?}");

    // A row of a section this command does not know has no place to go. It is
    // refused, because leaving it out would drop it.
    let mut doc = engine_doc();
    doc["findings"][1]["severity"] = json!("deferred");
    let err = report(dir.path(), &doc, None).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("finding 2") && msg.contains("deferred"),
        "{msg}"
    );
}

#[test]
fn a_document_with_no_findings_keeps_the_three_headers() {
    let dir = tempfile::tempdir().unwrap();
    let out = report(
        dir.path(),
        &json!({
            "schema": "rvl-scan/v1", "exit": 0, "findings": [],
            "coverage": {
                "resolved": 0, "total": 0,
                "abstain": {"no_spec": 0, "bounds": 0, "judge": 0, "other": 0},
                "lang_status": [],
            },
        }),
        None,
    )
    .unwrap();
    assert_eq!(
        out,
        "\
### Gate (deterministic engine) — exit 0
BLOCKING (0):
ADVISORY (0):
SUPPRESSED (0):

### Coverage
Engine: 0/0 retrieved API surfaces resolved (nothing retrieved) · abstains: no_spec 0 · bounds 0 · judge 0 · other 0
Languages: (the scan document has no language roll-call)
"
    );
}

#[test]
fn the_routing_rows_are_the_practice_controls_that_the_submitted_codes_touch() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    std::fs::create_dir(&scan_dir).unwrap();
    write(
        &scan_dir.join("03-findings-engine.json"),
        &json!({"findings": [{"title": "a", "control_codes": ["RC-019"]}]}),
    );
    write(
        &scan_dir.join("03-findings-sre-pro.json"),
        &json!({"findings": [
            {"title": "b", "control_codes": ["RC-071", "RC-029"]},
            {"title": "c", "control_codes": ["RC-003", "RC-029"]},
            {"title": "d"},
        ]}),
    );
    // Not a findings file: its codes are not submitted as findings.
    write(
        &scan_dir.join("02-control-structure.json"),
        &json!({"findings": [{"control_codes": ["RC-005"]}]}),
    );
    let out = report(dir.path(), &engine_doc(), Some(&scan_dir)).unwrap();
    let want = format!(
        "{GATE_AND_COVERAGE}
### Not Assessable From Code
These gaps touch practice controls that only the team can attest to; run the interview:
- `/rvl:assess-alert-hygiene` (RC-003, RC-029)
- `/rvl:assess-recovery-readiness` (RC-071)
"
    );
    assert_eq!(out, want);
}

#[test]
fn no_routing_section_when_no_practice_control_is_touched() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    std::fs::create_dir(&scan_dir).unwrap();
    write(
        &scan_dir.join("03-findings-engine.json"),
        &json!({"findings": [{"title": "a", "control_codes": ["RC-019"]}]}),
    );
    let out = report(dir.path(), &engine_doc(), Some(&scan_dir)).unwrap();
    assert_eq!(out, GATE_AND_COVERAGE);
}

#[test]
fn a_scan_dir_that_finalize_has_not_filled_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    std::fs::create_dir(&scan_dir).unwrap();
    let err = report(dir.path(), &engine_doc(), Some(&scan_dir)).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("03-findings-") && msg.contains("scan-parts"),
        "{msg}"
    );

    std::fs::write(scan_dir.join("03-findings-engine.json"), "{not json").unwrap();
    let err = report(dir.path(), &engine_doc(), Some(&scan_dir)).unwrap_err();
    assert!(
        format!("{err:#}").contains("03-findings-engine.json"),
        "{err:#}"
    );
}

#[test]
fn a_document_that_cannot_be_read_as_rvl_scan_v1_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.json");

    write(&path, &json!({"schema": "rvl-scan/v2", "findings": []}));
    let mut out = Vec::new();
    let err = scan_report::run(&path, None, &mut out).unwrap_err();
    assert!(
        format!("{err:#}").contains("unexpected schema rvl-scan/v2"),
        "{err:#}"
    );
    assert!(out.is_empty());

    // A field that is not there is named, never read as empty or zero.
    let mut doc = engine_doc();
    doc["coverage"]["abstain"] = json!(2);
    write(&path, &doc);
    let mut out = Vec::new();
    let err = scan_report::run(&path, None, &mut out).unwrap_err();
    assert!(format!("{err:#}").contains("no_spec"), "{err:#}");
    assert!(out.is_empty());

    let mut doc = engine_doc();
    doc["findings"][0].as_object_mut().unwrap().remove("fix");
    write(&path, &doc);
    let mut out = Vec::new();
    let err = scan_report::run(&path, None, &mut out).unwrap_err();
    assert!(format!("{err:#}").contains("\"fix\""), "{err:#}");
    assert!(out.is_empty());
}
