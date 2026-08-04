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

// --- G5 content lane: secrets, RC-043 (po-av01j.6) ---

/// End-to-end: a repo with NO Go/Py/TS source but a planted (fake) token gets
/// a content-lane scan: the ladder names the `secret.<rule>` class, maps it to
/// RC-043, never prints the raw token, and blocks. A `.revelara.yaml` waiver
/// with the class matcher (the po-3t3oj.27 engine, unchanged) suppresses it.
#[test]
fn scan_detects_planted_secret_and_waiver_suppresses_it() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    // Fake token, assembled so no token-shaped literal sits in this source.
    let token = ["ghp", "_", "AbCd1234EfGh5678IjKl9012MnOp3456QrSt"].concat();
    std::fs::write(repo.join("prod.env"), format!("GH_TOKEN=\"{token}\"\n")).unwrap();

    let out = bin()
        .arg("scan")
        .arg(&repo)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success(),
        "content-only scan must succeed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("secret.github_token"),
        "ladder must name the secret class: {stdout}"
    );
    assert!(
        stdout.contains("RC-043"),
        "finding must be born control-mapped: {stdout}"
    );
    assert!(
        !stdout.contains(&token),
        "the raw secret must never render: {stdout}"
    );
    assert!(
        stdout.contains("BLOCKING"),
        "a live token in runtime scope must block: {stdout}"
    );

    // Waive the class and re-scan: suppressed, not blocking.
    std::fs::write(
        repo.join(".revelara.yaml"),
        "scanner:\n  waivers:\n  - matcher: secret.github_token\n    reason: fixture\n",
    )
    .unwrap();
    let out2 = bin()
        .arg("scan")
        .arg(&repo)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout2 = String::from_utf8(out2.stdout).unwrap();
    assert!(out2.status.success(), "waived scan must succeed: {stdout2}");
    assert!(
        !stdout2.contains("BLOCKING"),
        "a waived finding must not block: {stdout2}"
    );
    assert!(
        stdout2.contains("suppressed"),
        "footer must report the suppression: {stdout2}"
    );
}

// --- G2 server-entry lane (po-av01j.3) ---

/// The hand-authored SEED server-spec corpus (RC-020/RC-069/RC-018); the
/// production corpus rides the LLM factory.
const SERVER_SPECS_SEED: &str = include_str!("testdata/server_specs_seed.json");

/// One JSONL server-entry registration record for a fixture stream.
fn server_entry_line(file: &str, line: u32, method: &str, snippet: &str) -> String {
    serde_json::json!({
        "snapshot_id": "fixture",
        "file_path": file,
        "line_number": line,
        "func": method,
        "client_type": "net/http.ServeMux",
        "snippet": snippet,
        "lang": "go",
        "site_kind": "server_entry",
    })
    .to_string()
}

/// End-to-end: a `--retrieved` stream carrying server-entry registrations is
/// judged by the G2 lane against the seed specs. A route surface with no
/// health endpoint and no rate limiter surfaces RC-020 and RC-069 as ADVISORY
/// findings; the server-entry records stay out of the G1 site count and out
/// of the `--out` eval rows.
#[test]
fn scan_surfaces_server_entry_findings_from_a_retrieved_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (packets_path, _) = write_scan_fixtures(dir.path());
    let mut stream = std::fs::read_to_string(&packets_path).unwrap();
    stream.push_str(&server_entry_line(
        "routes.go",
        10,
        "HandleFunc",
        r#"mux.HandleFunc("/users", usersHandler)"#,
    ));
    stream.push('\n');
    stream.push_str(&server_entry_line(
        "routes.go",
        11,
        "HandleFunc",
        r#"mux.HandleFunc("/orders", ordersHandler)"#,
    ));
    stream.push('\n');
    std::fs::write(&packets_path, stream).unwrap();
    let specs = dir.path().join("server_specs.json");
    std::fs::write(&specs, SERVER_SPECS_SEED).unwrap();

    let out_path = dir.path().join("findings.json");
    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets_path)
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
    assert!(
        stdout.contains("RC-020"),
        "missing health-endpoint violation must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-069"),
        "missing rate-limiter violation must surface: {stdout}"
    );
    assert!(
        !stdout.contains("RC-018"),
        "RC-018 is a judgement control; absence must abstain, never surface: {stdout}"
    );
    assert!(
        stdout.contains("ADVISORY") && !stdout.contains("BLOCKING"),
        "server-entry findings are advisory, never blocking: {stdout}"
    );
    // The G1 site count excludes server-entry records (2 fixture G1 sites),
    // and the verbose line reports the server-entry inventory separately.
    assert!(
        stdout.contains("sites 2") && stdout.contains("server-entry 2"),
        "server-entry records must not inflate the G1 site count: {stdout}"
    );
    // The --out eval rows are the G1 lane only.
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    assert_eq!(
        rows.as_array().unwrap().len(),
        2,
        "server-entry records must not become eval rows: {rows}"
    );
}

/// The healthy shape: a health route plus rate-limiting middleware satisfies
/// RC-020/RC-069 and nothing from the server lane surfaces in the ladder.
#[test]
fn scan_with_health_route_and_limiter_surfaces_no_server_findings() {
    let dir = tempfile::tempdir().unwrap();
    let (packets_path, _) = write_scan_fixtures(dir.path());
    let mut stream = std::fs::read_to_string(&packets_path).unwrap();
    stream.push_str(&server_entry_line(
        "routes.go",
        10,
        "HandleFunc",
        r#"mux.HandleFunc("/healthz", healthHandler)"#,
    ));
    stream.push('\n');
    stream.push_str(&server_entry_line(
        "routes.go",
        12,
        "Use",
        "r.Use(middleware.Throttle(100))",
    ));
    stream.push('\n');
    std::fs::write(&packets_path, stream).unwrap();
    let specs = dir.path().join("server_specs.json");
    std::fs::write(&specs, SERVER_SPECS_SEED).unwrap();

    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets_path)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}");
    assert!(
        !stdout.contains("RC-020") && !stdout.contains("RC-069"),
        "a satisfied server-entry control must not surface: {stdout}"
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

// --- G6 config lane (po-av01j.2) ---

/// A repo with one Go call site, one GitHub Actions workflow, and one
/// unsupported-format config file; specs cover the call AND two config keys.
fn write_config_lane_fixtures(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    std::fs::create_dir_all(dir.join(".github/workflows")).unwrap();
    std::fs::write(
        dir.join(".github/workflows/ci.yml"),
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join(".circleci")).unwrap();
    std::fs::write(dir.join(".circleci/config.yml"), "version: 2\n").unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{
        "apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],
        "configs":[],
        "config_keys":[
            {"format":"github-actions","key":"job.timeout-minutes","expect":{"kind":"present"},"confidence":0.9,"control":"RC-013","severity":"medium","fix":"set jobs.<id>.timeout-minutes","rationale":"6h default"},
            {"format":"github-actions","key":"step.uses.ref","expect":{"kind":"pattern","name":"sha40"},"confidence":0.9,"control":"RC-045","rationale":"pin actions to full SHAs"}
        ]
    }"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_runs_the_config_lane_and_reports_config_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_config_lane_fixtures(dir.path());
    let out = bin()
        .arg("scan")
        .arg(dir.path())
        .arg("--retrieved")
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout} {stderr}");

    // Two config findings surface: the missing job timeout (explicit-Present
    // spec vs the 360-minute platform default) and the tag-pinned action
    // (sha40 pattern vs "v4").
    assert!(
        stdout.contains("github-actions job.timeout-minutes"),
        "missing timeout must surface: {stdout}"
    );
    assert!(
        stdout.contains("github-actions step.uses.ref"),
        "unpinned action must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-013"),
        "the config spec's control rides into the ladder: {stdout}"
    );
    // Coverage: the lane reports its own resolution line and the
    // identity-only sighting of the unsupported CircleCI config.
    assert!(
        stdout.contains("settings resolved"),
        "config coverage line: {stdout}"
    );
    assert!(
        stdout.contains("unsupported config formats sighted: circleci (1)"),
        "sightings line: {stdout}"
    );
}

#[test]
fn config_findings_are_waivable_by_format_key_rule() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_config_lane_fixtures(dir.path());
    // Waive both config classes via .revelara.yaml, the same mechanism code
    // classes use; the rule is `<format>.<key>`.
    std::fs::write(
        dir.path().join(".revelara.yaml"),
        "scanner:\n  waivers:\n    - matcher: github-actions.job.timeout-minutes\n      reason: accepted for now\n    - matcher: github-actions.step.uses.ref\n      reason: dependabot keeps refs fresh\n",
    )
    .unwrap();
    let out = bin()
        .arg("scan")
        .arg(dir.path())
        .arg("--retrieved")
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}");
    assert!(
        !stdout.contains("github-actions job.timeout-minutes"),
        "waived config class must not render: {stdout}"
    );
    assert!(
        stdout.contains("suppressed"),
        "waived config classes are counted in the footer: {stdout}"
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

// --- G3 background-job lane (po-av01j.4) ---

/// The SEED spec fixture for the background-job lane (RC-060 + job-altitude
/// timeout re-application). Production specs ride the LLM factory; this file
/// exists so the e2e tests exercise real verdicts.
fn background_jobs_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("background_jobs_specs.json")
}

fn helper_fixture(helper: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    workspace
        .join("helpers")
        .join(helper)
        .join("testdata")
        .join("fixture")
}

/// Run `rvlscan scan <fixture>` with the seed background-job specs and return
/// the findings rows from `--out`. `envs` carries the helper override.
fn scan_fixture_findings(
    dir: &std::path::Path,
    fixture: &std::path::Path,
    envs: &[(&str, &std::ffi::OsStr)],
) -> Vec<serde_json::Value> {
    let out_path = dir.join("findings.json");
    let mut cmd = bin();
    cmd.arg("scan")
        .arg(fixture)
        .arg("--specs-file")
        .arg(background_jobs_specs())
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CACHE_DIR", dir.join("cache"));
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("failed to run rvlscan");
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    rows.as_array().expect("findings must be an array").clone()
}

/// (verdict, reason) of every finding whose site_id contains `path_frag`.
fn verdicts_for(rows: &[serde_json::Value], path_frag: &str) -> Vec<(String, String)> {
    rows.iter()
        .filter(|r| r["site_id"].as_str().is_some_and(|s| s.contains(path_frag)))
        .map(|r| {
            (
                r["verdict"].as_str().unwrap_or_default().to_string(),
                r["reason"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Go e2e: goindex retrieves the cron/ticker fixture, and the job-altitude
/// timeout judgment (existing machinery, new sites) tells the bare cron
/// registration from the one whose closure derives a deadline.
#[test]
fn scan_decides_go_background_job_sites_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let rows = scan_fixture_findings(
        dir.path(),
        &helper_fixture("goindex"),
        &[("RVLSCAN_GOINDEX", goindex_bin.as_os_str())],
    );
    let jobs = verdicts_for(&rows, "jobs.go");
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the bare cron registration must violate: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("deadline derived in scope")),
        "the deadline-deriving registration must satisfy: {jobs:?}"
    );
    // The ticker loop's seed spec is `depends`: routed to per-site judgment.
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "abstain" && r.contains("depends")),
        "the ticker worker loop must abstain on the depends spec: {jobs:?}"
    );
}

// --- G4 emission lane (po-av01j.5) ---

/// A `--retrieved` stream carrying emission-point aggregates surfaces the
/// emission-lane findings (RC-027 swallow gap, RC-046 tracing gap) as
/// ADVISORY ladder items, while the aggregates themselves stay OUT of the G1
/// pipeline: coverage counts only the real call site, and `--out` rows carry
/// only G1 verdicts.
#[test]
fn scan_surfaces_emission_findings_and_keeps_them_out_of_g1_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let db = db_go.to_str().unwrap();

    let packets = dir.path().join("retrieved.jsonl");
    let cat = |c: &str, n: u32| {
        format!(
            r#"[{{"index":0,"name":"emission_category","value":"{c}","how":"aggregate"}},{{"index":0,"name":"emission_count","value":"{n}","how":"aggregate"}}]"#
        )
    };
    std::fs::write(
        &packets,
        format!(
            "{}\n{}\n{}\n",
            format_args!(
                r#"{{"snapshot_id":"fx","file_path":{db:?},"line_number":10,"func":"Query","client_type":"github.com/jackc/pgx/v5.Tx","snippet":"tx.Query(ctx, q)","lang":"go"}}"#
            ),
            format_args!(
                r#"{{"snapshot_id":"fx","file_path":{db:?},"line_number":20,"symbol":"q","func":"recover","client_type":"recover_block","site_kind":"emission_point","const_args":{},"lang":"go"}}"#,
                cat("error_capture", 2)
            ),
            format_args!(
                r#"{{"snapshot_id":"fx","file_path":{db:?},"line_number":12,"symbol":"q","func":"Error","client_type":"log/slog.Logger","site_kind":"emission_point","const_args":{},"lang":"go"}}"#,
                cat("log", 7)
            ),
        ),
    )
    .unwrap();

    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, concat!(
        r#"{"apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],"#,
        r#""configs":[],"#,
        r#""emissions":["#,
        r#"{"type":"recover_block","category":"error_capture","control":"RC-027","role":"violates","confidence":0.9,"rationale":"a recover with no emission swallows the panic"},"#,
        r#"{"type":"log/slog.Logger","category":"log","control":"RC-061","role":"satisfies","confidence":0.9,"rationale":"structured log emission"},"#,
        r#"{"type":"go.opentelemetry.io/otel/trace.Tracer","category":"trace","control":"RC-046","role":"satisfies","confidence":0.9,"rationale":"otel span"}"#,
        r#"]}"#,
    )).unwrap();

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

    // The emission lane surfaces both gaps, control-mapped and advisory.
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "RC-027 swallow gap missing from the ladder: {stdout}"
    );
    assert!(
        stdout.contains("emission.RC-046"),
        "RC-046 tracing gap missing from the ladder: {stdout}"
    );
    assert!(
        !stdout.contains("BLOCKING"),
        "emission findings are advisory, never blocking: {stdout}"
    );
    // The aggregates stay out of the G1 surface count (1 call site, not 3).
    assert!(
        stdout.contains("sites 1 "),
        "emission aggregates leaked into the G1 site list: {stdout}"
    );
    // --out rows are the G1 eval contract: one row, the call site.
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "only G1 findings belong in --out: {rows:?}");
}

/// The hand-authored SEED emission-spec corpus (test-grade; the production
/// corpus rides the LLM factory, HITL — follow-up bead under po-av01j).
fn g4_seed_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("g4_seed_specs.json")
}

fn helpers_dir() -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .join("helpers")
}

/// Python e2e: celery's decorator idiom IS the job bound — @shared_task with
/// time_limit satisfies, the bare @app.task violates, and a classic-call-site
/// spec (rq.Queue.enqueue, no site_kinds) must never decide a background_job
/// site (the applicability guard, end to end).
#[test]
fn scan_decides_python_background_job_sites_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("SKIP scan_decides_python_background_job_sites_end_to_end: no python3");
        return;
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    let pyindex = workspace.join("helpers").join("pyindex").join("pyindex.py");
    let rows = scan_fixture_findings(
        dir.path(),
        &helper_fixture("pyindex"),
        &[("RVLSCAN_PYINDEX", pyindex.as_os_str())],
    );
    let jobs = verdicts_for(&rows, "jobs.py");
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("bounding decorator")),
        "@shared_task(time_limit=120) must satisfy via the decorator bound: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the bare @app.task must violate: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "abstain" && r.contains("site kind")),
        "the classic rq.Queue.enqueue spec must not decide the background_job dispatch: {jobs:?}"
    );
}

/// TypeScript e2e: the bullmq dispatch with a per-job timeout option
/// satisfies via the call-arg mechanism; the bare dispatch violates.
#[test]
fn scan_decides_typescript_background_job_sites_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    if std::process::Command::new("node")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("SKIP scan_decides_typescript_background_job_sites_end_to_end: no node");
        return;
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    let tsindex_dir = workspace.join("helpers").join("tsindex");
    if !tsindex_dir.join("node_modules").join("typescript").is_dir() {
        eprintln!(
            "SKIP scan_decides_typescript_background_job_sites_end_to_end: run `npm install` in helpers/tsindex first"
        );
        return;
    }
    let tsindex_js = tsindex_dir.join("tsindex.js");
    let rows = scan_fixture_findings(
        dir.path(),
        &helper_fixture("tsindex"),
        &[("RVLSCAN_TSINDEX", tsindex_js.as_os_str())],
    );
    let jobs = verdicts_for(&rows, "jobs.ts");
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("timeout argument at the call")),
        "the timeout-carrying dispatch must satisfy: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the bare dispatch must violate: {jobs:?}"
    );
}

/// Go, live end to end: goindex inventories the fixture's emissions (slog
/// aggregates, the recover_block swallow), the seed specs judge them, and the
/// ladder surfaces RC-027 (swallow) and RC-046 (no spans at I/O boundaries)
/// as advisory emission findings.
#[test]
fn live_go_scan_surfaces_g4_emission_findings() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let out = bin()
        .arg("scan")
        .arg(goindex_fixture())
        .arg("--specs-file")
        .arg(g4_seed_specs())
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "the recover_block swallow must surface under RC-027: {stdout}"
    );
    assert!(
        stdout.contains("emission.RC-046"),
        "untraced I/O boundaries must surface under RC-046: {stdout}"
    );
    assert!(
        !stdout.contains("BLOCKING"),
        "emission findings are advisory, never blocking: {stdout}"
    );
}

/// Python, live end to end: pyindex inventories except-blocks that swallow
/// vs log, and the seed specs surface the RC-027 gap.
#[test]
fn live_py_scan_surfaces_g4_emission_findings() {
    let dir = tempfile::tempdir().unwrap();
    let pyindex = helpers_dir().join("pyindex").join("pyindex.py");
    let fixture = helpers_dir()
        .join("pyindex")
        .join("testdata")
        .join("fixture");
    let out = bin()
        .arg("scan")
        .arg(&fixture)
        .arg("--specs-file")
        .arg(g4_seed_specs())
        .env("RVLSCAN_PYINDEX", &pyindex)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "the except_handler swallow must surface under RC-027: {stdout}"
    );
    assert!(
        !stdout.contains("BLOCKING"),
        "emission findings are advisory, never blocking: {stdout}"
    );
}

/// TypeScript, live end to end: the fixture's openai call has no surrounding
/// emission, so the seed specs surface the RC-061 emission-half gap (the LLM
/// call-site half rides G1). Skipped when node or the tsindex `typescript`
/// dependency is unavailable, matching the goindex skip convention.
#[test]
fn live_ts_scan_surfaces_llm_observability_gap() {
    let tsdir = helpers_dir().join("tsindex");
    let ready = Command::new("node")
        .args(["-e", "require('typescript')"])
        .current_dir(&tsdir)
        .output();
    match ready {
        Ok(out) if out.status.success() => {}
        Ok(_) => {
            eprintln!("SKIP live_ts_scan: tsindex needs `npm install` (typescript missing)");
            return;
        }
        Err(e) => {
            eprintln!("SKIP live_ts_scan: node not available: {e}");
            return;
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .arg("scan")
        .arg(tsdir.join("testdata").join("fixture"))
        .arg("--specs-file")
        .arg(g4_seed_specs())
        .env("RVLSCAN_TSINDEX", tsdir.join("tsindex.js"))
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("emission.RC-061"),
        "the uninstrumented LLM call must surface under RC-061: {stdout}"
    );
    assert!(
        stdout.contains("emission.RC-027"),
        "the catch_clause swallow must surface under RC-027: {stdout}"
    );
    assert!(
        !stdout.contains("BLOCKING"),
        "emission findings are advisory, never blocking: {stdout}"
    );
}

// --- G7 repo-structure lane (po-av01j.7) ---

/// A `--retrieved` stream carrying a `repo_structure` record surfaces its
/// violations in the ladder as ADVISORY findings with the control code, and
/// the record itself never pollutes the site list.
#[test]
fn scan_surfaces_repo_structure_findings_from_a_retrieved_stream() {
    let dir = tempfile::tempdir().unwrap();
    let (packets_path, specs) = write_scan_fixtures(dir.path());
    let mut stream = std::fs::read_to_string(&packets_path).unwrap();
    stream.push_str(concat!(
        r#"{"kind":"repo_structure","snapshot_id":"fixture","walk_complete":true,"#,
        r#""ecosystems":[{"name":"go","source_files":40,"test_files":0,"integration_markers":[]}],"#,
        r#""coverage_configs":[],"contract_frameworks":[],"manifests":[],"runbook_dirs":[]}"#,
        "\n"
    ));
    std::fs::write(&packets_path, stream).unwrap();

    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets_path)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout} {stderr}");
    assert!(
        stdout.contains("RC-033"),
        "untested-repo violation missing from the ladder: {stdout}"
    );
    assert!(
        stdout.contains("ADVISORY") && !stdout.contains("BLOCKING"),
        "structure findings are advisory, never blocking: {stdout}"
    );
    // The sites|specs line counts only real sites: the structure record must
    // not have been misparsed into a junk site (2 fixture sites, not 3).
    assert!(
        stdout.contains("sites 2"),
        "repo_structure record leaked into the site list: {stdout}"
    );
}

// --- G6 config lane, Kubernetes family (po-av01j.20) ---

/// A repo with a kustomize base+overlay pair and SEED (test-grade)
/// Kubernetes config-key specs for three representative controls: probe
/// presence (RC-020), resource-limit presence (RC-024), image pin shape
/// (RC-045). The production spec corpus is factory-authored (HITL);
/// these exist to prove the lane end to end.
fn write_k8s_lane_fixtures(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    // A minimal code-lane fixture so the scan exercises both lanes at once.
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();

    // Base: a deployment with limits but no probes, tag-pinned.
    std::fs::create_dir_all(dir.join("k8s/base")).unwrap();
    std::fs::write(
        dir.join("k8s/base/deployment.yaml"),
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers:\n        - name: app\n          image: web:v1.2.3\n          resources:\n            limits:\n              cpu: 500m\n              memory: 256Mi\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("k8s/base/kustomization.yaml"),
        "resources:\n  - deployment.yaml\n",
    )
    .unwrap();
    // Overlay: retags the image to latest — the violating pin shape must be
    // the TRANSFORMED one, proving the overlay chain end to end.
    std::fs::create_dir_all(dir.join("k8s/overlays/prod")).unwrap();
    std::fs::write(
        dir.join("k8s/overlays/prod/kustomization.yaml"),
        "resources:\n  - ../../base\nimages:\n  - name: web\n    newTag: latest\n",
    )
    .unwrap();

    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{
        "apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],
        "configs":[],
        "config_keys":[
            {"format":"kubernetes","key":"container.liveness-probe","expect":{"kind":"present"},"confidence":0.9,"control":"RC-020","severity":"medium","fix":"add a livenessProbe to the container","rationale":"no probe means no restart on hang"},
            {"format":"kubernetes","key":"container.resources.limits.cpu","expect":{"kind":"present"},"confidence":0.9,"control":"RC-024","severity":"medium","fix":"set resources.limits.cpu","rationale":"unbounded cpu"},
            {"format":"kubernetes","key":"container.image.pin","expect":{"kind":"one_of","values":["digest","tag"]},"confidence":0.9,"control":"RC-045","severity":"high","fix":"pin the image to a tag or digest","rationale":"latest is unpinned"}
        ]
    }"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_runs_the_kubernetes_config_family_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_k8s_lane_fixtures(dir.path());
    let out = bin()
        .arg("scan")
        .arg(dir.path())
        .arg("--retrieved")
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout} {stderr}");

    // The missing probe violates the Present spec (both base and overlay
    // units repeat it — one grouped class).
    assert!(
        stdout.contains("kubernetes container.liveness-probe"),
        "missing probe must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-020"),
        "the config spec's control rides into the ladder: {stdout}"
    );
    // The cpu limit is authored in the base: RC-024 must NOT surface.
    assert!(
        !stdout.contains("kubernetes container.resources.limits.cpu"),
        "an authored limit is not a finding: {stdout}"
    );
    // The overlay retagged web:v1.2.3 to :latest; the pin-shape violation
    // proves the images transformer resolved the EFFECTIVE value.
    assert!(
        stdout.contains("kubernetes container.image.pin"),
        "the overlay's latest tag must surface: {stdout}"
    );
    assert!(stdout.contains("RC-045"), "pin control missing: {stdout}");
    assert!(
        stdout.contains("settings resolved"),
        "config coverage line: {stdout}"
    );
}
