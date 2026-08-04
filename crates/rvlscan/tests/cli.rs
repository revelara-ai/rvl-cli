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
    wait_for_indexed(&dir.path().join("index"), &dir.path().join("cache"), 60);
}

/// Poll `index status` until the index reports a non-zero file count.
///
/// A *failed* status is not evidence of anything. While a reindex holds
/// redb's exclusive lock, status cannot open the index at all: it exits
/// non-zero and prints nothing on stdout. Treating that empty stdout as
/// "populated" is exactly what made the original detach test vacuous
/// (po-l3jo5), so only a SUCCESSFUL status with a non-zero count ends the
/// wait; busy is a reason to keep waiting.
fn wait_for_indexed(index_dir: &std::path::Path, cache_dir: &std::path::Path, secs: u64) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut last;
    loop {
        let status = bin()
            .args(["index", "status"])
            .env("RVLSCAN_INDEX_DIR", index_dir)
            .env("RVLSCAN_CACHE_DIR", cache_dir)
            .output()
            .expect("failed to run rvlscan");
        if status.status.success() {
            let s = String::from_utf8(status.stdout).unwrap();
            if !s.starts_with("0 file(s)") {
                return;
            }
            last = s;
        } else {
            last = String::from_utf8_lossy(&status.stderr).trim().to_string();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "index never populated within {secs}s (last status: {last}); child log:\n{}",
            reindex_log(cache_dir)
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// The detached child's log, or a marker when it never wrote one. A detached
/// reindex that fails MUST leave this behind: "no log" is itself the finding.
fn reindex_log(cache_dir: &std::path::Path) -> String {
    let p = cache_dir.join("reindex.log");
    std::fs::read_to_string(&p).unwrap_or_else(|e| format!("<no {}: {e}>", p.display()))
}

/// A detached reindex must not silently lose its work when another process
/// already holds the index.
///
/// redb grants one process an exclusive lock on the database. Before
/// po-l3jo5 the detached child called `PacketIndex::open` once, hit
/// `DatabaseAlreadyOpen`, and died — invisibly, because the child's stdout
/// AND stderr were `Stdio::null()` while the parent had already printed
/// "detached ... continues in the background" and exited 0. The background
/// warm a post-commit hook fires did nothing at all, and said nothing about
/// it. This holds the lock deterministically rather than racing for it, so
/// the regression cannot hide behind whichever process happens to win.
#[test]
fn detached_reindex_waits_out_a_busy_index_and_leaves_a_log() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let fixture = goindex_fixture();
    let index_dir = dir.path().join("index");
    let cache_dir = dir.path().join("cache");

    // Hold the exclusive lock exactly as a concurrent scan or status would.
    let held = rvl_index::PacketIndex::open(&index_dir.join("packets.redb"))
        .expect("test must be able to open the index first");

    let out = bin()
        .args(["index", "reindex", "--detach"])
        .arg(&fixture)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_INDEX_DIR", &index_dir)
        .env("RVLSCAN_CACHE_DIR", &cache_dir)
        .output()
        .expect("failed to run rvlscan");
    assert!(
        out.status.success(),
        "detach parent must exit 0: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Long enough that a child which gives up on a busy index is already gone.
    std::thread::sleep(std::time::Duration::from_secs(3));
    drop(held);

    // A child that waited is still alive, and finishes the warm once free.
    wait_for_indexed(&index_dir, &cache_dir, 30);

    // ...and it is never silent again: the run left a readable trace.
    let log = reindex_log(&cache_dir);
    assert!(
        !log.trim().is_empty(),
        "detached child must log its run, got: {log}"
    );
}

// --- declared bounds: out-of-code bound evidence via .revelara.yaml (po-3t3oj.30) ---

/// A `scanner.bounds` declaration in `.revelara.yaml` is the out-of-code
/// bound channel: prod-level settings (statement_timeout, infra deadlines)
/// that NO retrieval depth can see. Declared whole-call this-client bounds
/// flip the exact client_type's findings from violates to satisfies, with
/// the policy provenance in the reason.
#[test]
fn declared_bound_converts_finding_to_satisfies_with_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { pool.Query(ctx, q) }\n").unwrap();
    let packets = dir.path().join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"db.RLSPool\",\"snippet\":\"pool.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[{"type":"db.RLSPool","method":"Query","site_count":1,"blocking":"yes","bounded_by":["client_config"],"confidence":0.95,"rationale":"pool query blocks"}],"configs":[]}"#).unwrap();

    let scan = |declared: bool| -> serde_json::Value {
        if declared {
            std::fs::write(
                dir.path().join(".revelara.yaml"),
                "scanner:\n  bounds:\n    - client_type: db.RLSPool\n      bounds: whole_call\n      reason: prod statement_timeout=15s bounds every pool query\n",
            )
            .unwrap();
        } else {
            let _ = std::fs::remove_file(dir.path().join(".revelara.yaml"));
        }
        let out_path = dir.path().join("findings.json");
        let out = bin()
            .arg("scan")
            .arg(dir.path())
            .arg("--retrieved")
            .arg(&packets)
            .arg("--specs-file")
            .arg(&specs)
            .arg("--out")
            .arg(&out_path)
            .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
            .output()
            .expect("failed to run rvlscan");
        assert!(
            out.status.success() || out.status.code() == Some(1),
            "scan errored: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap()
    };

    // Without the declaration: no bound evidence anywhere -> a finding.
    let without = scan(false);
    let verdict = without[0]["verdict"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert_eq!(
        verdict, "violates",
        "without a declaration the call has no bound: {without}"
    );

    // With the declaration: satisfied, and the reason carries the policy
    // provenance so the finding is auditable back to .revelara.yaml.
    let with = scan(true);
    let verdict = with[0]["verdict"].as_str().unwrap_or_default().to_string();
    let reason = with[0]["reason"].as_str().unwrap_or_default().to_string();
    assert_eq!(
        verdict, "satisfies",
        "declared whole-call bound must satisfy: {with}"
    );
    assert!(
        reason.contains("declared") && reason.contains("statement_timeout"),
        "reason must carry the policy provenance: {reason}"
    );
}

/// Declarations are narrow by design: expired entries and non-whole_call
/// bounds are inert, and OTHER client types are never broadened.
#[test]
fn declared_bound_is_exact_type_and_expiry_scoped() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { c.Do(req) }\n").unwrap();
    let packets = dir.path().join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Do\",\"client_type\":\"http.Client\",\"snippet\":\"c.Do(req)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[{"type":"http.Client","method":"Do","site_count":1,"blocking":"yes","bounded_by":["client_config"],"confidence":0.95,"rationale":"blocks"}],"configs":[]}"#).unwrap();
    // A declaration for a DIFFERENT type, plus an expired one for this type.
    std::fs::write(
        dir.path().join(".revelara.yaml"),
        "scanner:\n  bounds:\n    - client_type: db.RLSPool\n      bounds: whole_call\n      reason: other client\n    - client_type: http.Client\n      bounds: whole_call\n      reason: long gone\n      expires: \"2020-01-01\"\n",
    )
    .unwrap();

    let out_path = dir.path().join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(dir.path())
        .arg("--retrieved")
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(
        v[0]["verdict"].as_str().unwrap_or_default(),
        "violates",
        "an expired declaration and another type's declaration must both be inert: {v}"
    );
}
