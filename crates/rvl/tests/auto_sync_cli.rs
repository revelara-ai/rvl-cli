//! The cache keeps itself current (po-av01j.171): a scan starts at most one
//! background check per interval and never waits on it; offline, a CI pin and
//! CI itself turn the check off; init syncs before it finishes.
//!
//! No test here reaches the network. The API URL points at a local server
//! that answers every request with a 503, so every fetch fails at once, which
//! is also the fail-open case. (A closed port is not enough: some sandboxes
//! drop the connect instead of refusing it, and the fetch then waits out its
//! timeout.)

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A server that fails every request, for as long as the test process runs.
fn failing_api() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let _ = conn.read(&mut buf);
            let _ = conn.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    url
}

fn bin(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    c.env("HOME", home)
        .env("RVL_CACHE_DIR", home.join("cache"))
        .env("RVL_API_URL", failing_api());
    for k in [
        "RVL_OFFLINE",
        "RVL_SPEC_VERSION",
        "CI",
        "RVL_API_KEY",
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

/// An empty prebuilt packet stream: the scan takes the signed-cache path,
/// and with no cache installed it fails, which must not stop the check.
fn packets(home: &Path) -> PathBuf {
    let p = home.join("packets.jsonl");
    std::fs::write(&p, "").unwrap();
    p
}

fn stamp(home: &Path) -> PathBuf {
    home.join("cache").join(rvl_cache::auto::STAMP)
}

fn scan(home: &Path) -> Command {
    let mut c = bin(home);
    c.arg("scan").arg("--retrieved").arg(packets(home));
    c
}

#[test]
fn a_scan_claims_one_background_check_per_interval() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let started = std::time::Instant::now();
    scan(home).output().unwrap();
    assert!(
        stamp(home).is_file(),
        "a scan on the signed cache with no recent check must start one"
    );
    let first = std::fs::read_to_string(stamp(home)).unwrap();
    scan(home).output().unwrap();
    assert_eq!(
        std::fs::read_to_string(stamp(home)).unwrap(),
        first,
        "a second scan inside the interval must not claim another check"
    );
    // Not a timing test: a generous bound only catches a scan that waited on
    // the fetch it handed off.
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn offline_ci_and_a_pin_each_leave_the_cache_alone() {
    for (k, v) in [
        ("RVL_OFFLINE", "1"),
        ("CI", "true"),
        ("RVL_SPEC_VERSION", "2026-09-01.a"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        scan(home).env(k, v).output().unwrap();
        assert!(!stamp(home).exists(), "{k}={v} must suppress the check");
    }
}

#[test]
fn a_dev_specs_file_scan_does_not_touch_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let specs = home.join("specs.json");
    std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
    scan(home).arg("--specs-file").arg(&specs).output().unwrap();
    assert!(
        !stamp(home).exists(),
        "--specs-file bypasses the signed cache, so there is nothing to refresh"
    );
}

#[test]
fn a_pin_that_does_not_match_fails_the_scan_and_names_the_pin() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let out = scan(home)
        .arg("--spec-version")
        .arg("2026-09-01.a")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("pinned to 2026-09-01.a"),
        "a CI log must say why the gate refused: {stderr}"
    );
}

#[test]
fn the_background_check_is_silent_and_never_fails() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let out = bin(home).args(["sync", "--background"]).output().unwrap();
    assert!(out.status.success(), "a failed fetch is not a failure here");
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn git_init(dir: &Path) {
    let ok = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(ok.success());
}

#[test]
fn init_syncs_before_it_finishes_and_survives_a_failed_fetch() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    git_init(home);
    let out = bin(home)
        .current_dir(home)
        .args(["init", "-y", "--skip-plugin", "--no-context-files"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "a failed sync must not fail init: {stdout}{stderr}"
    );
    let line = stdout
        .lines()
        .find(|l| l.starts_with("Spec cache:"))
        .unwrap_or_else(|| panic!("init must report the sync: {stdout}"));
    assert!(line.contains("sync"), "a failure names the fix: {line}");
    let summary = stdout.split("Initialization Complete").nth(1).unwrap();
    assert!(summary.contains("Spec cache:"), "{stdout}");
}

#[test]
fn init_offline_says_it_skipped_the_sync() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    git_init(home);
    let out = bin(home)
        .current_dir(home)
        .env("RVL_OFFLINE", "1")
        .args(["init", "-y", "--skip-plugin", "--no-context-files"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Spec cache: not synced (RVL_OFFLINE=1)"),
        "{stdout}"
    );
}
