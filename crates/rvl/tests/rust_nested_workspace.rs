//! The Rust lane on a POLYGLOT monorepo, end to end through the `rustindex`
//! binary (po-pk3fp.11).
//!
//! dolthub/dolt, genspark-ai/genoffice and google/osv-scanner keep their
//! crates in a subdirectory, and rustindex used to run `cargo metadata` at the
//! scan root and abstain with "could not find Cargo.toml in <repo>" — real
//! Rust, never looked at. The unit tests in `crates/rustindex/src/workspace.rs`
//! cover discovery; these cover what the FLEET sees, which is the process:
//! its stdout, and above all its EXIT CODE.
//!
//! The exit code is the whole point. rvl reads 3 as "this lane declined" and
//! 0 as "this lane was scanned". Getting that backwards on an empty stream
//! reports code that was never read as clean — the silent-success collapse
//! goindex fixed for nested `go.mod` in po-av01j.131.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The `rustindex` executable is a bin target of the `rvl` package, so cargo
/// has built it before this test runs.
fn rustindex() -> &'static str {
    env!("CARGO_BIN_EXE_rustindex")
}

/// Skip, don't fail, when the rustup component is absent: the convention the
/// goindex/tsindex fixture suites already follow.
fn rust_analyzer_available() -> bool {
    match Command::new("rust-analyzer").arg("--version").output() {
        Ok(o) if o.status.success() => true,
        _ => {
            eprintln!("SKIP rust_nested_workspace: rust-analyzer not available");
            false
        }
    }
}

fn fixture_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("rustindex")
        .join("testdata")
        .join("fixture")
}

/// Copy the offline fixture workspace, minus its build output: `target/` holds
/// a cargo lock file and megabytes that say nothing about discovery.
fn copy_fixture(dst: &Path) {
    fn rec(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        for entry in std::fs::read_dir(from).unwrap().flatten() {
            let name = entry.file_name();
            if name == "target" {
                continue;
            }
            let (src, dst) = (entry.path(), to.join(&name));
            if entry.file_type().unwrap().is_dir() {
                rec(&src, &dst);
            } else {
                std::fs::copy(&src, &dst).unwrap();
            }
        }
    }
    rec(&fixture_src(), dst);
}

fn write(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

fn retrieve(root: &Path) -> (std::process::Output, Vec<serde_json::Value>) {
    let out = Command::new(rustindex())
        .args(["--retrieve", "--root"])
        .arg(root)
        .args(["--name", "nested"])
        .output()
        .expect("failed to run rustindex");
    let packets = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("every stdout line is one JSON packet"))
        .collect();
    (out, packets)
}

fn provenance(packets: &[serde_json::Value]) -> &serde_json::Value {
    packets
        .iter()
        .find(|p| p["kind"] == "rust_workspace_provenance")
        .expect("every run emits workspace provenance, scanned or not")
}

/// THE REPORTED CASE. The scan root carries no manifest; the crates live one
/// directory down, beside another language. The run must SCAN (exit 0) and
/// emit sites whose paths are relative to the scan root, because that is what
/// every downstream consumer joins on — rust-analyzer's own paths are
/// relative to the workspace it was pointed at.
///
/// A second, unloadable workspace rides along: one broken crate in a monorepo
/// must cost that crate only, and must be RECORDED, so a consumer can tell
/// "declined" from "clean".
#[test]
fn a_nested_workspace_is_scanned_and_a_broken_sibling_declines_alone() {
    if !rust_analyzer_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    copy_fixture(&root.join("rust").join("engine"));
    write(
        &root.join("go/cmd/main.go"),
        "package main\n\nfunc main() {}\n",
    );
    write(&root.join("broken/Cargo.toml"), "this is not a manifest\n");

    let (out, packets) = retrieve(root);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a repo whose Rust is one directory down is SCANNED, not declined: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let sites: Vec<&serde_json::Value> = packets
        .iter()
        .filter(|p| p["file_path"].is_string())
        .collect();
    assert!(
        !sites.is_empty(),
        "the nested crates must yield sites: {packets:#?}"
    );
    for site in &sites {
        let path = site["file_path"].as_str().unwrap();
        assert!(
            path.starts_with("rust/engine/"),
            "paths stay relative to the SCAN ROOT, not to the workspace: {path}"
        );
        assert!(
            root.join(path).is_file(),
            "a rebased path must still resolve to the source on disk: {path}"
        );
    }

    let prov = provenance(&packets);
    assert_eq!(prov["workspaces_loaded"], 1);
    assert_eq!(prov["workspaces_indexed"], 1);
    assert_eq!(
        prov["workspaces_declined"], 1,
        "the broken crate is recorded, not dropped: {prov:#?}"
    );
    let declined = prov["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["loaded"] == false)
        .expect("the declined workspace rides in provenance");
    assert_eq!(declined["path"], "broken");
    assert!(
        declined["reason"]
            .as_str()
            .unwrap()
            .contains("abstains rather than guessing"),
        "the decline carries the charter wording: {declined:#?}"
    );
    // Loud on stderr too: provenance is for machines, this is for the operator
    // reading a fleet log.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("broken"),
        "a declined workspace is announced: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// No manifest anywhere is an ABSTENTION, never a clean scan. Exit 0 with an
/// empty stream would tell rvl the Rust lane ran and found nothing.
#[test]
fn a_root_with_no_cargo_manifest_abstains() {
    if !rust_analyzer_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("go/cmd/main.go"), "package main\n");
    let (out, packets) = retrieve(tmp.path());
    assert_eq!(out.status.code(), Some(3), "abstain is exit 3");
    assert!(packets.is_empty(), "an abstention emits no packets");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("abstains rather than guessing"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// EVERY workspace declining is an abstention for the RUN. Per-workspace
/// tolerance must not degrade into "all of the Rust failed to load, exit 0,
/// zero findings" — which reads as clean.
#[test]
fn a_root_whose_every_workspace_fails_to_load_abstains_rather_than_reporting_clean() {
    if !rust_analyzer_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("a/Cargo.toml"), "not a manifest\n");
    write(&tmp.path().join("b/Cargo.toml"), "[package\nbroken =\n");
    let (out, packets) = retrieve(tmp.path());
    assert_eq!(
        out.status.code(),
        Some(3),
        "no workspace loaded, so nothing was scanned: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(packets.is_empty(), "an abstention emits no packets");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("all 2 cargo workspace(s)"),
        "the run says how many declined: {stderr}"
    );
}

/// A single-workspace repo — the shape every Rust repo had before this change
/// — must behave exactly as it did: scanned, paths unprefixed, and the
/// top-level `cargo_lockfile` still present for readers that predate the
/// per-workspace array.
#[test]
fn a_workspace_at_the_scan_root_is_unchanged() {
    if !rust_analyzer_available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    copy_fixture(tmp.path());
    let (out, packets) = retrieve(tmp.path());
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        packets.iter().any(|p| p["file_path"]
            .as_str()
            .is_some_and(|f| f.starts_with("app/"))),
        "a root workspace's paths gain no prefix: {packets:#?}"
    );
    let prov = provenance(&packets);
    assert_eq!(prov["workspaces_loaded"], 1);
    assert_eq!(prov["workspaces"][0]["path"], "");
    assert!(
        prov["cargo_lockfile"]["sha256"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "the pre-existing top-level lockfile record is kept: {prov:#?}"
    );
}
