//! THE BARE-TYPE CLIENT-CONFIG GATE (po-m2ill).
//!
//! One function, one `&http.Client{}` with no `Timeout`, one `c.Do(req)`: the
//! classic Go hang. The served corpus carried a config spec keyed on the bare
//! type `net/http.Client` (bounds `whole_call`, scope `this_client`) whose
//! rationale talked about the `Timeout` FIELD, and the propagator credited the
//! type match without ever looking at the literal. The site resolved
//! `satisfies`, reason "client config net/http.Client" twice over: a false
//! negative in the dangerous direction, presented by the JSON verdict as
//! settled.
//!
//! Pinned end to end, through the binary and the `--out` document:
//!
//!   - the repro packet under the shipped bare-type spec never satisfies;
//!   - under a spec that names `fields: ["Timeout"]`, the empty literal
//!     violates and the `Timeout`-bearing literal satisfies;
//!   - the same two outcomes hold against packets the goindex built from THIS
//!     tree emits, so the wire shape the fix reads is the one that ships.
//!
//! A declared bound in `.revelara.yaml` keeps satisfying, and it does so
//! OVER the shipped bare-type spec: the two meet in the spec-cache merge at
//! equal confidence, and the declaration must win there or it never reaches
//! the propagator (`cli.rs::declared_bound_converts_finding_to_satisfies_with_provenance`
//! covers the declaration with no served config at all).
//!
//! The hand-written packets below are shaped the way goindex emits them: a
//! construction's `symbol` is the TYPE, never a field name, and the field
//! evidence is the literal's `source`.

use std::path::{Path, PathBuf};
use std::process::Command;

const BARE_SPEC: &str = r#"{"apis":[{"type":"net/http.Client","method":"Do","site_count":1,"blocking":"yes","bounded_by":["client_config"],"confidence":0.95,"rationale":"Do blocks until the response headers arrive"}],"configs":[{"type":"net/http.Client","bounds":"whole_call","scope":"this_client","confidence":1,"rationale":"net/http.Client has a Timeout field that bounds the entire HTTP request end-to-end."}]}"#;

const FIELDS_SPEC: &str = r#"{"apis":[{"type":"net/http.Client","method":"Do","site_count":1,"blocking":"yes","bounded_by":["client_config"],"confidence":0.95,"rationale":"Do blocks until the response headers arrive"}],"configs":[{"type":"net/http.Client","bounds":"whole_call","scope":"this_client","confidence":1,"fields":["Timeout"],"rationale":"net/http.Client is bounded end-to-end only when Timeout is set."}]}"#;

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

/// The one-function repro as Go source. `literal` is the client construction.
fn go_source(literal: &str) -> String {
    format!(
        "package main\n\nimport (\n\t\"net\"\n\t\"net/http\"\n\t\"time\"\n)\n\nvar _ = time.Second\nvar _ net.Dialer\n\nfunc fetch(req *http.Request) (*http.Response, error) {{\n\tc := &{literal}\n\treturn c.Do(req)\n}}\n"
    )
}

/// The standard dialer idiom: a `Timeout` that bounds only the dial, nested
/// two literals deep. A slow body read still blocks forever.
const NESTED_DIAL_TIMEOUT: &str = "http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 30 * time.Second}).DialContext}}";

/// A packet for the repro, shaped as goindex emits it (the index hashes file
/// content, so the file it names must exist).
fn write_packet(dir: &Path, literal: &str) -> PathBuf {
    let main_go = dir.join("main.go");
    std::fs::write(&main_go, go_source(literal)).unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(
        &packets,
        format!(
            "{{\"snapshot_id\":\"fixture\",\"file_path\":{file:?},\"line_number\":12,\"func\":\"Do\",\"client_type\":\"net/http.Client\",\"snippet\":\"c.Do(req)\",\"lang\":\"go\",\"client_construction\":[{{\"file\":\"main.go\",\"line\":11,\"symbol\":\"net/http.Client\",\"source\":{literal:?}}}]}}\n",
            file = main_go.to_str().unwrap(),
        ),
    )
    .unwrap();
    packets
}

/// The `--out` rows for a scan, as `(verdict, reason)` in site order.
fn verdicts(out_path: &Path) -> Vec<(String, String)> {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_path).unwrap()).unwrap();
    doc["sites"]
        .as_array()
        .expect("sites must be a JSON array")
        .iter()
        .map(|r| {
            (
                r["verdict"].as_str().unwrap_or_default().to_string(),
                r["reason"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn scan_packets(dir: &Path, packets: &Path, spec_json: &str) -> Vec<(String, String)> {
    let specs = dir.join("specs.json");
    std::fs::write(&specs, spec_json).unwrap();
    let out_path = dir.join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(dir)
        .arg("--retrieved")
        .arg(packets)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_CACHE_DIR", dir.join("cache"))
        .output()
        .expect("failed to run rvl");
    assert!(
        out_path.is_file(),
        "scan wrote no --out document: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    verdicts(&out_path)
}

#[test]
fn an_empty_http_client_never_satisfies_under_the_shipped_bare_type_spec() {
    let dir = tempfile::tempdir().unwrap();
    let packets = write_packet(dir.path(), "http.Client{}");
    let rows = scan_packets(dir.path(), &packets, BARE_SPEC);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (verdict, reason) = &rows[0];
    assert_ne!(verdict, "satisfies", "{reason}");
    assert_eq!(verdict, "abstain", "{reason}");
    assert!(
        reason.contains("names no bounding field"),
        "the reason must say what the spec is missing: {reason}"
    );
}

#[test]
fn a_spec_naming_the_field_tells_the_empty_literal_from_the_bounded_one() {
    let dir = tempfile::tempdir().unwrap();
    let packets = write_packet(dir.path(), "http.Client{}");
    let rows = scan_packets(dir.path(), &packets, FIELDS_SPEC);
    assert_eq!(rows[0].0, "violates", "{:?}", rows[0]);

    let dir = tempfile::tempdir().unwrap();
    let packets = write_packet(dir.path(), "http.Client{Timeout: 10 * time.Second}");
    let rows = scan_packets(dir.path(), &packets, FIELDS_SPEC);
    assert_eq!(rows[0].0, "satisfies", "{:?}", rows[0]);
    assert!(
        rows[0].1.contains("Timeout"),
        "the reason must cite the field that bounds the call: {}",
        rows[0].1
    );
}

#[test]
fn a_declared_bound_closes_the_bare_type_abstain_over_the_shipped_spec() {
    let dir = tempfile::tempdir().unwrap();
    let packets = write_packet(dir.path(), "http.Client{}");
    std::fs::write(
        dir.path().join(".revelara.yaml"),
        "scanner:\n  bounds:\n    - client_type: net/http.Client\n      bounds: whole_call\n      reason: egress proxy enforces a 30s deadline on every outbound call\n",
    )
    .unwrap();
    let rows = scan_packets(dir.path(), &packets, BARE_SPEC);
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (verdict, reason) = &rows[0];
    assert_eq!(
        verdict, "satisfies",
        "the declaration must win the merge against the served bare spec: {reason}"
    );
    assert!(
        reason.contains("declared in .revelara.yaml"),
        "the reason must carry the policy provenance: {reason}"
    );
}

/// The goindex FROM THIS TREE, so the assertion is about the wire shape that
/// ships and not about whatever `goindex` is on PATH. Skips loudly when there
/// is no Go toolchain to build it with. A build FAILURE is a defect where the
/// toolchain is guaranteed (CI), and a skip on a developer machine whose Go
/// install is broken (a stale GOROOT, say): the other tests in this file do
/// not need Go, and one dead toolchain must not read as a propagator bug.
fn goindex_binary(dir: &Path) -> Option<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../helpers/goindex");
    let bin = dir.join("goindex");
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".")
        .current_dir(&src)
        .output()
    {
        Ok(out) if out.status.success() => Some(bin),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if std::env::var_os("CI").is_some() {
                panic!("goindex failed to build: {stderr}");
            }
            eprintln!("SKIP: goindex failed to build (set CI=1 to make this fatal): {stderr}");
            None
        }
        Err(e) => {
            eprintln!("SKIP: `go` not available: {e}");
            None
        }
    }
}

fn scan_module(
    dir: &Path,
    goindex: &Path,
    literal: &str,
    spec_json: &str,
) -> Vec<(String, String)> {
    std::fs::write(dir.join("go.mod"), "module repro\n\ngo 1.22\n").unwrap();
    std::fs::write(dir.join("main.go"), go_source(literal)).unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, spec_json).unwrap();
    let out_path = dir.join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(dir)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_GOINDEX", goindex)
        .env("RVL_CACHE_DIR", dir.join("cache"))
        .output()
        .expect("failed to run rvl");
    assert!(
        out_path.is_file(),
        "scan wrote no --out document: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    verdicts(&out_path)
}

#[test]
fn the_live_goindex_repro_never_satisfies_and_a_timeout_still_does() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    // Separate modules on purpose: goindex attaches every construction of a
    // TYPE in the module to every site using it, so one bounded literal
    // beside the bare one would be evidence for both.
    let bare = tempfile::tempdir().unwrap();
    let rows = scan_module(bare.path(), &goindex, "http.Client{}", BARE_SPEC);
    let (verdict, reason) = rows
        .iter()
        .find(|(_, r)| r.contains("net/http.Client"))
        .unwrap_or_else(|| panic!("no row for the Client.Do site: {rows:?}"));
    assert_eq!(verdict, "abstain", "{reason}");
    assert!(reason.contains("names no bounding field"), "{reason}");

    let bare = tempfile::tempdir().unwrap();
    let rows = scan_module(bare.path(), &goindex, "http.Client{}", FIELDS_SPEC);
    assert!(
        rows.iter().any(|(v, _)| v == "violates"),
        "an empty literal under a field-naming spec is the hang: {rows:?}"
    );
    assert!(rows.iter().all(|(v, _)| v != "satisfies"), "{rows:?}");

    let bounded = tempfile::tempdir().unwrap();
    let rows = scan_module(
        bounded.path(),
        &goindex,
        "http.Client{Timeout: 10 * time.Second}",
        FIELDS_SPEC,
    );
    assert!(
        rows.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("Timeout")),
        "a Timeout-bearing client still satisfies, citing the field: {rows:?}"
    );

    // goindex emits the whole nested literal as the construction's source,
    // so the dialer's Timeout sits in that text. It is not the client's.
    let nested = tempfile::tempdir().unwrap();
    let rows = scan_module(nested.path(), &goindex, NESTED_DIAL_TIMEOUT, FIELDS_SPEC);
    assert!(
        rows.iter().all(|(v, _)| v != "satisfies"),
        "a dial-only timeout nested in the transport must not read as the client's Timeout: {rows:?}"
    );
    assert!(
        rows.iter().any(|(v, _)| v == "violates"),
        "the nested literal leaves the call unbounded: {rows:?}"
    );
}
