//! `rvl scan digest`, `rvl scan finalize` and `rvl scan report` through the
//! binary: the wiring, the exit codes, and that none of them disturbs `rvl
//! scan [PATH]`. What the commands compute is tested in `rvl-data`.

use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Output};

fn rvl(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rvl"))
        .args(args)
        .env("HOME", home)
        .env_remove("RVL_API_KEY")
        .output()
        .expect("run rvl")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write(path: &Path, v: &Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(v).unwrap()).unwrap();
}

fn engine_doc() -> Value {
    json!({
        "schema": "rvl-scan/v1", "exit": 3, "covered_classes": ["http.Client"],
        "coverage": {"resolved": 1, "total": 2, "abstain": {"no_spec": 1, "bounds": 0, "judge": 0, "other": 0}},
        "findings": [
            {"id": "E1", "class": "http.Client", "site": "internal/x.go:3", "control": "RC-019", "fix": "set timeout", "description": "No client timeout", "severity": "blocking"},
        ],
        "undecided": [{"site": "internal/y.go:9", "class": "sql.DB", "lever": "no_spec", "scope": "runtime"}],
    })
}

#[test]
fn scan_digest_prints_the_digest_and_refuses_another_schema() {
    let dir = tempfile::tempdir().unwrap();
    let doc = dir.path().join("engine.json");
    write(&doc, &engine_doc());
    let out = rvl(dir.path(), &["scan", "digest", doc.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert!(
        stdout.starts_with("ENGINE_DIGEST exit=3 blocking=1 advisory=0 resolved=1/2 abstain={"),
        "{stdout}"
    );
    assert!(
        stdout.ends_with(
            "ADJUDICATION_LIST (1 sites, cap 20):\n  internal/y.go:9 · sql.DB · no_spec\n"
        ),
        "{stdout}"
    );

    write(&doc, &json!({"schema": "rvl-scan/v2"}));
    let out = rvl(dir.path(), &["scan", "digest", doc.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "a refusal prints no digest");
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("unexpected schema rvl-scan/v2") && stderr.contains("engine.json"),
        "{stderr}"
    );
}

#[test]
fn scan_finalize_writes_one_findings_file_per_lens_and_the_engine_file() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    std::fs::create_dir(&scan_dir).unwrap();
    let doc = dir.path().join("scan-parts.engine.json");
    write(&doc, &engine_doc());
    write(
        &dir.path().join("scan-parts.lens/golang-pro.json"),
        &json!({"findings": [{"title": "Unbounded fan-out", "severity": "high", "risk_category": "capacity", "location": "internal/fanout.go:8", "control_code": "RC-019"}]}),
    );
    // A trailing separator on the directory is the same directory.
    let arg = format!("{}/", scan_dir.display());
    let out = rvl(
        dir.path(),
        &[
            "scan",
            "finalize",
            &arg,
            "--engine",
            doc.to_str().unwrap(),
            "--mode",
            "deep",
            "--crit",
            "0.5",
        ],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        "Written: 03-findings-golang-pro.json (1 findings)\n\
         Written: 03-findings-engine.json (1 findings)\n\
         LENS_DIGEST (1 findings, score desc; ref PRIO score category site [controls] title):\n  \
         golang-pro#1 HIGH 79 capacity internal/fanout.go:8 [RC-019] Unbounded fan-out\n"
    );
    let mut names: Vec<String> = std::fs::read_dir(&scan_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["03-findings-engine.json", "03-findings-golang-pro.json"]
    );
    let lens: Value = serde_json::from_slice(
        &std::fs::read(scan_dir.join("03-findings-golang-pro.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(lens["scan_mode"], json!("deep"));
    assert_eq!(lens["business_criticality"], json!(0.5));
    assert_eq!(lens["findings"][0]["provenance"], json!("agent:golang-pro"));
}

#[test]
fn scan_finalize_usage_errors_exit_2_and_a_missing_dir_exits_1() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    let arg = scan_dir.to_str().unwrap();

    let out = rvl(dir.path(), &["scan", "finalize", arg]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("is not a directory"));

    std::fs::create_dir(&scan_dir).unwrap();
    for bad in [
        vec!["scan", "finalize", arg, "--mode", "thorough"],
        vec!["scan", "finalize", arg, "--crit", "high"],
        // An empty value is never "not given": a lost patch must not pass.
        vec!["scan", "finalize", arg, "--patch="],
        vec!["scan", "finalize", arg, "--engine", ""],
        vec!["scan", "finalize", arg, "--mode="],
        vec!["scan", "finalize", arg, "--crit="],
        vec!["scan", "finalize"],
        vec!["scan", "digest"],
        // No scan flag combines with a subcommand.
        vec!["scan", "--strict", "finalize", arg],
    ] {
        let out = rvl(dir.path(), &bad);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", text(&out.stderr));
    }
}

/// `finalize` and then `report` are one pipeline: the report reads the scan
/// document for the gate and the coverage, and the findings files that
/// `finalize` wrote for the practice controls.
#[test]
fn scan_report_prints_the_data_sections_and_refuses_another_schema() {
    let dir = tempfile::tempdir().unwrap();
    let scan_dir = dir.path().join("scan-parts");
    std::fs::create_dir(&scan_dir).unwrap();
    let doc = dir.path().join("scan-parts.engine.json");
    let mut engine = engine_doc();
    engine["coverage"]["lang_status"] = json!([{"lang": "go", "state": "scanned", "detail": "2"}]);
    let mut waived = engine["findings"][0].clone();
    waived["id"] = json!("E2");
    waived["severity"] = json!("suppressed");
    waived["suppressed"] = json!(true);
    engine["findings"].as_array_mut().unwrap().push(waived);
    write(&doc, &engine);
    write(
        &dir.path().join("scan-parts.lens/sre-pro.json"),
        &json!({"findings": [{"title": "No paging policy", "severity": "high", "risk_category": "operations", "location": "deploy/alerts.yaml:1", "control_code": "RC-003"}]}),
    );
    let (dir_arg, doc_arg) = (scan_dir.to_str().unwrap(), doc.to_str().unwrap());
    let out = rvl(
        dir.path(),
        &["scan", "finalize", dir_arg, "--engine", doc_arg],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));

    let gate_and_coverage = "\
### Gate (deterministic engine) — exit 3
BLOCKING (1):
  [E1] http.Client — internal/x.go:3 · RC-019 · fix: set timeout
    waive: `rvl suppress E1 --reason=\"...\"` or a `# rvl:allow` comment on the line
ADVISORY (0):
SUPPRESSED (1):
  [E2] http.Client — internal/x.go:3 · RC-019 · fix: set timeout (suppressed)

### Coverage
Engine: 1/2 retrieved API surfaces resolved (50% of retrieved) · abstains: no_spec 1 · bounds 0 · judge 0 · other 0
Languages: go 2 sites
";
    let out = rvl(dir.path(), &["scan", "report", doc_arg]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stdout), gate_and_coverage);

    let out = rvl(
        dir.path(),
        &["scan", "report", doc_arg, "--scan-dir", dir_arg],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout),
        format!(
            "{gate_and_coverage}
### Not Assessable From Code
These gaps touch practice controls that only the team can attest to; run the interview:
- `/rvl:assess-alert-hygiene` (RC-003)
"
        )
    );

    for bad in [
        vec!["scan", "report"],
        // An empty value is never "not given": the practice-control rows
        // must not go missing without a word.
        vec!["scan", "report", doc_arg, "--scan-dir="],
        vec!["scan", "--strict", "report", doc_arg],
    ] {
        let out = rvl(dir.path(), &bad);
        assert_eq!(out.status.code(), Some(2), "{bad:?}: {}", text(&out.stderr));
    }

    write(&doc, &json!({"schema": "rvl-scan/v2"}));
    let out = rvl(dir.path(), &["scan", "report", doc_arg]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "a refusal prints no report");
    assert!(
        text(&out.stderr).contains("unexpected schema rvl-scan/v2"),
        "{}",
        text(&out.stderr)
    );
}

/// `digest`, `finalize` and `report` are subcommand names now. A path that is not one
/// of them, `force-next` included, still parses as before.
#[test]
fn scan_with_a_path_is_not_taken_for_a_subcommand() {
    let dir = tempfile::tempdir().unwrap();
    let out = rvl(dir.path(), &["scan", "--help"]);
    let help = text(&out.stdout);
    assert!(
        help.contains("digest") && help.contains("finalize") && help.contains("report"),
        "{help}"
    );
    assert!(help.contains("[PATH]"), "{help}");

    // Outside a repository `force-next` fails by its own rule, which proves
    // it reached its handler and was not read as a subcommand or scanned.
    let out = rvl(
        dir.path(),
        &[
            "scan",
            "force-next",
            "--target",
            dir.path().to_str().unwrap(),
        ],
    );
    let stderr = text(&out.stderr);
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
}
