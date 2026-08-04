use std::process::Command;

#[test]
fn version_flag_reports_name_and_semver() {
    let out = Command::new(env!("CARGO_BIN_EXE_rvlscan"))
        .arg("--version")
        .output()
        .expect("failed to run rvlscan binary");

    assert!(out.status.success(), "--version exited non-zero");
    let stdout = String::from_utf8(out.stdout).expect("stdout not utf-8");
    assert_eq!(
        stdout.trim(),
        concat!("rvlscan ", env!("CARGO_PKG_VERSION")),
        "--version must print '<binary> <semver>'"
    );
}

// --- spec-cache distribution surface (po-3t3oj.13) ---

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rvlscan"))
}

#[test]
fn cache_status_reports_empty_store() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["cache", "status"])
        .env("RVLSCAN_CACHE_DIR", dir.path())
        .output()
        .expect("failed to run rvlscan");
    assert!(
        out.status.success(),
        "cache status must not fail on an empty store"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("no spec cache"), "got: {stdout}");
}

#[test]
fn sync_respects_offline_kill_switch() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .arg("sync")
        .env("RVLSCAN_CACHE_DIR", dir.path())
        .env("RVLSCAN_OFFLINE", "1")
        .output()
        .expect("failed to run rvlscan");
    assert!(out.status.success(), "offline sync is a successful no-op");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.to_lowercase().contains("offline"), "got: {stdout}");
}

#[test]
fn cache_import_refuses_missing_signature() {
    let dir = tempfile::tempdir().unwrap();
    let art = dir.path().join("specs.json");
    std::fs::write(&art, "{}").unwrap();
    let out = bin()
        .args(["cache", "import"])
        .arg(&art)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        !out.status.success(),
        "missing sig must fail the import (missing sig = failed sig)"
    );
}

// --- scan engine surface (po-3t3oj.15) ---

fn write_scan_fixtures(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    // Packets name real files: the index hashes file CONTENT, so a fixture
    // whose paths do not exist can be parsed but never indexed.
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    let unknown_go = src.join("unknown.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    std::fs::write(&unknown_go, "package svc\n\nfunc m() { u.Mystery() }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n         {{\"snapshot_id\":\"fixture\",\"file_path\":{unk:?},\"line_number\":20,\"func\":\"Mystery\",\"client_type\":\"x.Unknown\",\"snippet\":\"u.Mystery()\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
        unk = unknown_go.to_str().unwrap(),
    )).unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{"apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],"configs":[]}"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_with_specs_file_emits_findings_and_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_scan_fixtures(dir.path());
    let out_path = dir.path().join("findings.json");
    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout} {stderr}");
    // dev override is loud: unverified specs never load silently
    assert!(
        stderr.to_uppercase().contains("UNVERIFIED"),
        "no unverified banner: {stderr}"
    );
    // The severity ladder renders a COVERAGE section reporting the decided
    // rate; undecided outcomes are folded into coverage, never counted as
    // violations. The footer states the blocking/advisory verdict.
    assert!(
        stdout.contains("COVERAGE"),
        "ladder must render a coverage section: {stdout}"
    );
    assert!(
        stdout.contains("surfaces resolved"),
        "coverage must report the decided count: {stdout}"
    );
    assert!(
        stdout.contains("commit clean") || stdout.contains("blocked"),
        "ladder must render a verdict footer: {stdout}"
    );
    // findings written and well-formed
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().expect("findings must be a JSON array");
    assert_eq!(rows.len(), 2);
    for r in rows {
        assert!(r.get("site_id").is_some() && r.get("verdict").is_some());
    }
}

#[test]
fn scan_without_cache_or_override_fails_closed_with_guidance() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, _) = write_scan_fixtures(dir.path());
    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("empty-cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        !out.status.success(),
        "no verifiable spec cache must fail the scan"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("rvlscan sync") || stderr.contains("cache import"),
        "error must point at sync/import: {stderr}"
    );
}

// --- single-command scan: helper orchestration (po-3t3oj.25) ---

/// End-to-end: `rvlscan scan <dir>` with NO `--retrieved` must detect the Go
/// source, run goindex itself, and feed the packets into the pipeline. Requires
/// a `go` toolchain to build the helper; if `go` is absent the test is skipped
/// with a log line rather than failing (the feature is exercised, the CI env is
/// just missing the compiler).
#[test]
fn scan_without_retrieved_runs_the_go_helper() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    let goindex_src = workspace.join("helpers").join("goindex");
    let fixture = goindex_src.join("testdata").join("fixture");
    assert!(fixture.join("go.mod").is_file(), "fixture module missing");

    // Build goindex from source so the test exercises a real helper run.
    let dir = tempfile::tempdir().unwrap();
    let goindex_bin = dir.path().join("goindex");
    let build = Command::new("go")
        .args(["build", "-o"])
        .arg(&goindex_bin)
        .arg(".")
        .current_dir(&goindex_src)
        .output();
    match build {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            eprintln!(
                "SKIP scan_without_retrieved_runs_the_go_helper: `go build` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }
        Err(e) => {
            eprintln!("SKIP scan_without_retrieved_runs_the_go_helper: `go` not available: {e}");
            return;
        }
    }

    // A minimal (empty) spec set: the assertion is that packets were produced
    // and parsed (sites N, N>0), not that anything is decided.
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();

    let out = bin()
        .arg("scan")
        .arg(&fixture)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}\n{stderr}");
    // The helper produced packets that parsed into at least one site.
    assert!(
        stdout.contains("sites "),
        "verbose summary must report parsed sites: {stdout}"
    );
    assert!(
        !stdout.contains("sites 0 "),
        "the fixture must yield at least one site: {stdout}"
    );
    assert!(
        stdout.contains("COVERAGE"),
        "ladder must render a coverage section: {stdout}"
    );
}

/// With no `--retrieved` and no source under the target, the scan fails closed
/// with guidance toward the escape hatch.
#[test]
fn scan_without_retrieved_on_empty_dir_fails_with_guidance() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("empty");
    std::fs::create_dir_all(&target).unwrap();
    let out = bin()
        .arg("scan")
        .arg(&target)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(!out.status.success(), "no sources must fail the scan");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no supported source files") && stderr.contains("--retrieved"),
        "error must name the escape hatch: {stderr}"
    );
}

// --- incremental index surface (po-3t3oj.14) ---

#[test]
fn index_status_reports_empty_then_populated() {
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .args(["index", "status"])
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .output()
        .expect("run rvlscan");
    assert!(
        out.status.success(),
        "index status must work on an empty index"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("0 file"), "want empty count: {stdout}");
}

#[test]
fn index_init_indexes_packets_from_a_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, _) = write_scan_fixtures(dir.path());
    let out = bin()
        .args(["index", "init", "--retrieved"])
        .arg(&packets)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .output()
        .expect("run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "index init failed: {stdout} {stderr}");
    assert!(
        stdout.contains("indexed"),
        "want an indexed summary: {stdout}"
    );

    // status now reflects the indexed files
    let out = bin()
        .args(["index", "status"])
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .output()
        .expect("run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("0 file"),
        "index should be non-empty: {stdout}"
    );
}

// --- SIGPIPE (po-3t3oj.23) ---

#[test]
#[cfg(unix)]
fn output_piped_to_a_truncating_reader_does_not_panic() {
    use std::io::Read;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_scan_fixtures(dir.path());
    let mut child = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rvlscan");

    // Read one byte, then drop the pipe: this is what `| head -1` does.
    let mut stdout = child.stdout.take().unwrap();
    let mut one = [0u8; 1];
    let _ = stdout.read(&mut one);
    drop(stdout);

    let out = child.wait_with_output().expect("wait");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "closing the pipe must not panic the scanner: {stderr}"
    );
}

// --- background re-index: live mode + --detach (po-3t3oj.14 slice C) ---

/// Build goindex from source, or None when no Go toolchain is available (the
/// test is then skipped with a log line, matching the scan e2e convention).
fn build_goindex(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    let goindex_src = workspace.join("helpers").join("goindex");
    let goindex_bin = dir.join("goindex");
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&goindex_bin)
        .arg(".")
        .current_dir(&goindex_src)
        .output()
    {
        Ok(out) if out.status.success() => Some(goindex_bin),
        Ok(out) => {
            eprintln!(
                "SKIP: go build failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            None
        }
        Err(e) => {
            eprintln!("SKIP: go toolchain not available: {e}");
            None
        }
    }
}

fn goindex_fixture() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    workspace
        .join("helpers")
        .join("goindex")
        .join("testdata")
        .join("fixture")
}

/// `index reindex <repo>` with NO --retrieved runs the helpers itself: this is
/// the background warm a post-commit hook triggers, so it cannot depend on a
/// pre-produced packet stream existing.
#[test]
fn index_reindex_live_mode_runs_the_go_helper() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let fixture = goindex_fixture();

    let out = bin()
        .args(["index", "reindex"])
        .arg(&fixture)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "live reindex failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("retrieved"),
        "live reindex must report what it retrieved: {stdout}"
    );

    // The index now holds the fixture's files: a status check proves the
    // background warm actually landed packets.
    let status = bin()
        .args(["index", "status"])
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let status_out = String::from_utf8(status.stdout).unwrap();
    assert!(
        !status_out.starts_with("0 file(s)"),
        "index must not be empty after a live reindex: {status_out}"
    );

    // A second live pass over unchanged content retrieves nothing: the
    // hash-gate reuses everything, so the background warm is idempotent-cheap.
    let again = bin()
        .args(["index", "reindex"])
        .arg(&fixture)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let again_out = String::from_utf8(again.stdout).unwrap();
    assert!(
        again_out.contains("retrieved 0"),
        "unchanged content must be fully reused on the second pass: {again_out}"
    );
}

/// `--detach` returns the parent immediately (this is the line a post-commit
/// hook runs; the commit must not wait) while the child warms the index
/// behind it.
#[test]
fn index_reindex_detach_returns_immediately_and_child_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let fixture = goindex_fixture();

    let started = std::time::Instant::now();
    let out = bin()
        .args(["index", "reindex", "--detach"])
        .arg(&fixture)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let parent_elapsed = started.elapsed();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "detach parent must exit 0: {stdout}");
    assert!(
        stdout.contains("detached"),
        "parent must confirm the detached spawn: {stdout}"
    );
    // The whole point: the parent returns long before a helper run completes.
    assert!(
        parent_elapsed < std::time::Duration::from_secs(5),
        "detached parent took {parent_elapsed:?}; it must not wait for the reindex"
    );

    // The child eventually lands packets in the index.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let status = bin()
            .args(["index", "status"])
            .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
            .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
            .output()
            .expect("failed to run rvlscan");
        let s = String::from_utf8(status.stdout).unwrap();
        if !s.starts_with("0 file(s)") {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached child never populated the index: {s}"
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}
