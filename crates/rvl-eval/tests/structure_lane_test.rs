//! The structure lane of an `rvl scan --out` document (po-av01j.28): the
//! loader picks the lane's own array, so call-site rows and repo-structure
//! rows are never scored as one population.

use rvl_eval::{load_findings, load_findings_lane, Lane};

const DOC: &str = r#"{
  "schema": "rvl-scan/v1",
  "exit": 0,
  "findings": [],
  "sites": [
    {"site_id": "a.go:1", "snapshot_id": "s", "verdict": "violates",
     "reason": "no bound anywhere", "class": "net/http.Client.Do"}
  ],
  "structure": [
    {"site_id": "repo", "snapshot_id": "s", "verdict": "violates",
     "reason": "no test files", "class": "repo_structure.RC-033"},
    {"site_id": "repo", "snapshot_id": "s", "verdict": "abstain",
     "reason": "runbooks may live in a wiki", "class": "repo_structure.RC-006"}
  ]
}"#;

fn write(name: &str, body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join(name);
    std::fs::write(&p, body).unwrap();
    (dir, p)
}

#[test]
fn a_scan_document_yields_each_lane_separately() {
    let (_d, p) = write("scan.json", DOC);
    let sites = load_findings_lane(&p, Lane::Sites).unwrap();
    assert_eq!(sites.len(), 1);
    assert_eq!(sites[0].site_id, "a.go:1");

    let structure = load_findings_lane(&p, Lane::Structure).unwrap();
    let classes: Vec<_> = structure.iter().map(|f| f.class.as_deref()).collect();
    assert_eq!(
        classes,
        [Some("repo_structure.RC-033"), Some("repo_structure.RC-006")]
    );
    // The default loader reads the call-site lane of a document.
    assert_eq!(load_findings(&p).unwrap().len(), 1);
}

#[test]
fn a_bare_findings_array_still_loads() {
    let (_d, p) = write(
        "findings.json",
        r#"[{"site_id": "a.go:1", "verdict": "satisfies"}]"#,
    );
    assert_eq!(load_findings(&p).unwrap().len(), 1);
    assert_eq!(load_findings_lane(&p, Lane::Structure).unwrap().len(), 1);
}

/// A document from an rvl that predates the structure array has no lane to
/// score. That is an error naming the missing key, never zero rows: zero rows
/// would read as "the repo has no structure verdicts".
#[test]
fn a_document_without_the_lane_is_an_error_not_an_empty_result() {
    let (_d, p) = write("old.json", r#"{"schema": "rvl-scan/v1", "sites": []}"#);
    let err = load_findings_lane(&p, Lane::Structure).unwrap_err();
    assert!(format!("{err:#}").contains("structure"), "{err:#}");
    assert!(load_findings_lane(&p, Lane::Sites).unwrap().is_empty());
}
