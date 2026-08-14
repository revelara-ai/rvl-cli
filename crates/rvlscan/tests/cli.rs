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

/// The `scan` exit code that means "BLOCKING findings remain" — the gate
/// firing. Kept distinct from 1 (scanner broke) and 2 (usage error) so a CI
/// gate can tell "your code has a problem" from "the scanner is broken".
/// Mirrors `EXIT_BLOCKED` in `crates/rvlscan/src/main.rs`.
const EXIT_BLOCKED: i32 = 3;

/// "The scan RAN" — it reached a verdict, clean (0) or blocked (EXIT_BLOCKED).
/// For tests that assert on a lane's OUTPUT rather than on the gate: they must
/// not care whether the fixture happens to block, but they must still fail on
/// 1 (scanner error) and 2 (usage error).
fn scan_reached_a_verdict(out: &std::process::Output) -> bool {
    matches!(out.status.code(), Some(0) | Some(EXIT_BLOCKED))
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
            // A toolchain we do not have is a skip; OUR code failing to build
            // is a defect. Swallowing this as a skip is how a helper that
            // could not compile shipped once already (po-av01j.47).
            panic!(
                "goindex failed to build: {}",
                String::from_utf8_lossy(&out.stderr)
            );
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
fn scan_errors_with_guidance_when_a_needed_retriever_is_absent() {
    // po-av01j.148, the decided rule: do not bundle the helpers, probe for them
    // and error out when one is NEEDED and absent. A gate that cannot read a
    // language the repo contains must not pass -- reporting "commit clean"
    // there is a clean bill of health over a language nobody looked at.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("gorepo");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("go.mod"), "module x\n\ngo 1.22\n").unwrap();
    std::fs::write(target.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
    let out = bin()
        .arg("scan")
        .arg(&target)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env_remove("RVLSCAN_GOINDEX")
        .env("PATH", "/nonexistent")
        .output()
        .expect("failed to run rvlscan");
    assert!(
        !out.status.success(),
        "a missing needed retriever must fail"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("no retriever for") && stderr.contains("Go"),
        "the error must name the language: {stderr}"
    );
    assert!(
        stderr.contains("RVLSCAN_ALLOW_MISSING_HELPERS"),
        "and it must name the deliberate escape hatch: {stderr}"
    );
}

#[test]
fn an_empty_dir_no_longer_fails_for_having_no_source() {
    // Nothing is NEEDED here, so there is nothing to error about. A repository
    // of pure infrastructure is the real case this unblocks; an empty directory
    // is its degenerate form. Whatever else this run does, it must not fail
    // because no language was detected.
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("empty");
    std::fs::create_dir_all(&target).unwrap();
    let out = bin()
        .arg("scan")
        .arg(&target)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        !stderr.contains("no supported source files"),
        "absence of source is not an error when no helper was needed: {stderr}"
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
    // The scan RAN (it is not a scanner error), and it BLOCKED. Asserting
    // `success()` here is what let the gate ship broken for months: the
    // footer said "blocked" while the shell said 0 (po-av01j.94).
    assert_eq!(
        out.status.code(),
        Some(EXIT_BLOCKED),
        "a blocking content-lane scan must exit {EXIT_BLOCKED}: {stdout}\n{stderr}"
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
    // ...and a waived-clean scan is exit 0: waiving is how a repo un-blocks.
    assert_eq!(
        out2.status.code(),
        Some(0),
        "a waived (clean) scan must exit 0: {stdout2}"
    );
}

// --- exit-code contract (po-av01j.94) ---
//
// `rvlscan scan` is wired into pre-commit hooks and CI gates, so its exit code
// IS the gate. The contract, in one place:
//
//   0  scan completed, nothing blocking remains after waivers
//   1  scan could not complete (scanner error)
//   2  usage error (bad flag/argument)
//   3  scan completed, BLOCKING findings remain  <- the gate firing
//
// These two tests are the whole contract for the blocking axis: a blocking
// result must be non-zero and specifically 3, an advisory-only result must be
// 0. Every other scan test asserts on printed strings; without these, exit-0
// -while-blocking regresses silently.

/// A blocking finding must fail the process, and with the dedicated blocked
/// code rather than the generic error code — a hook has to distinguish
/// "your code has a problem" from "the scanner is broken".
#[test]
fn blocking_scan_exits_with_the_blocked_code_not_zero() {
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
    // Guard against a vacuous pass: the run must actually have blocked.
    assert!(
        stdout.contains("BLOCKING") && stdout.contains("blocked"),
        "fixture must produce a blocking ladder: {stdout}\n{stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(EXIT_BLOCKED),
        "a blocking scan must exit {EXIT_BLOCKED} so a CI gate fails: {stdout}\n{stderr}"
    );
}

/// The other half of the contract: advisory findings inform, they do not
/// block. An advisory-only scan stays exit 0, or the gate cries wolf and
/// teams disable it.
#[test]
fn advisory_only_scan_exits_zero() {
    let dir = tempfile::tempdir().unwrap();
    let (packets_path, _) = write_scan_fixtures(dir.path());
    let mut stream = std::fs::read_to_string(&packets_path).unwrap();
    // Server-entry registrations with no health endpoint and no rate limiter:
    // RC-020/RC-069 surface, and the G2 lane is advisory by construction.
    stream.push_str(&server_entry_line(
        "routes.go",
        10,
        "HandleFunc",
        r#"mux.HandleFunc("/users", usersHandler)"#,
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
    let stderr = String::from_utf8(out.stderr).unwrap();
    // Guard against a vacuous pass: there must be findings, just not blocking.
    assert!(
        stdout.contains("ADVISORY") && !stdout.contains("BLOCKING"),
        "fixture must produce an advisory-only ladder: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("commit clean"),
        "advisory-only must print the clean footer: {stdout}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "advisory findings must not fail the process: {stdout}\n{stderr}"
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
            // See above: our own build failing is never a skip.
            panic!(
                "goindex failed to build: {}",
                String::from_utf8_lossy(&out.stderr)
            );
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

// --- G6 dep-manifests family (po-av01j.22) ---

/// A repo with a floating base image and a toolchain-less go.mod; SEED
/// test-grade ConfigKeySpecs judge both (the production corpus is a factory
/// follow-up). The G7 structure lane covers lockfile PRESENCE separately;
/// these specs judge per-KEY resolved values, the config-spec altitude.
#[test]
fn scan_runs_the_dep_manifests_family_with_seed_specs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let src = root.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = root.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    std::fs::write(root.join("Dockerfile"), "FROM alpine:latest\nRUN true\n").unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/svc\n\ngo 1.22\n").unwrap();
    let specs = root.join("specs.json");
    std::fs::write(&specs, r#"{
        "apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],
        "configs":[],
        "config_keys":[
            {"format":"dep-manifests","key":"dockerfile.base_image_pin","expect":{"kind":"one_of","values":["digest","tag"]},"confidence":0.9,"control":"RC-045","severity":"medium","fix":"pin the base image to an immutable tag or digest","rationale":"a floating base image changes under you"},
            {"format":"dep-manifests","key":"go_mod.toolchain","expect":{"kind":"present"},"confidence":0.9,"control":"RC-070","severity":"low","fix":"pin a toolchain directive in go.mod","rationale":"unpinned toolchain floats with the host"}
        ]
    }"#).unwrap();
    let out = bin()
        .arg("scan")
        .arg(root)
        .arg("--retrieved")
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", root.join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout} {stderr}");

    // The floating base image violates the pin-shape spec (the seed-spec
    // acceptance case) and the spec's control rides the ladder.
    assert!(
        stdout.contains("dep-manifests dockerfile.base_image_pin"),
        "floating base image must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-045"),
        "the pinning spec's control rides into the ladder: {stdout}"
    );
    // The absent toolchain resolves through the documented `local` default,
    // which an explicit-Present spec judges as a violation.
    assert!(
        stdout.contains("dep-manifests go_mod.toolchain"),
        "toolchain-less go.mod must surface: {stdout}"
    );
}

// --- G6 Prometheus/sloth family (po-av01j.21) ---

/// A repo with a literal Prometheus rules file (one alert missing `for:` and
/// severity, one carrying both), a sloth SLO file, and an alertmanager
/// config. Seed TEST-GRADE ConfigKeySpecs cover the family's two example
/// controls: for-duration presence and severity-label presence (the
/// production corpus is a follow-up factory bead).
fn write_prometheus_family_fixtures(
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    std::fs::create_dir_all(dir.join("deploy/alerts")).unwrap();
    std::fs::write(
        dir.join("deploy/alerts/api.yml"),
        "groups:\n- name: api\n  rules:\n  - alert: HighErrorRate\n    expr: rate(errors[5m]) > 0.1\n  - alert: SlowRequests\n    expr: latency > 1\n    for: 5m\n    labels:\n      severity: page\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("deploy/alerts/slo.yml"),
        "version: prometheus/v1\nservice: api\nslos:\n- name: availability\n  objective: 99.9\n  alerting:\n    page_alert:\n      labels:\n        severity: page\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("alertmanager.yml"),
        "route:\n  receiver: default\nreceivers:\n- name: default\n",
    )
    .unwrap();
    // One minimal code packet: a scan refuses an empty retrieved stream.
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":3,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{
        "apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],
        "configs":[],
        "config_keys":[
            {"format":"prometheus-rules","key":"rule.for","expect":{"kind":"present"},"confidence":0.9,"control":"RC-001","severity":"medium","fix":"set a for: duration so the alert requires a sustained breach","rationale":"test-grade seed: an absent for fires on first evaluation (0s default)"},
            {"format":"prometheus-rules","key":"rule.labels.severity","expect":{"kind":"pattern","name":"nonempty"},"confidence":0.9,"control":"RC-001","severity":"medium","fix":"label the alert with a routing severity","rationale":"test-grade seed: unlabeled alerts cannot route"}
        ]
    }"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_runs_the_prometheus_family_and_surfaces_missing_for_and_severity() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_prometheus_family_fixtures(dir.path());
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

    // HighErrorRate violates both seed specs (no for:, no severity); the
    // SlowRequests alert satisfies both, so each class has one site.
    assert!(
        stdout.contains("prometheus-rules rule.for"),
        "missing for: must surface: {stdout}"
    );
    assert!(
        stdout.contains("prometheus-rules rule.labels.severity"),
        "missing severity label must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-001"),
        "the seed spec's control rides into the ladder: {stdout}"
    );
    // The sloth file contributes packets (unspecced: abstentions), and the
    // alertmanager config is identified without being inventoried.
    assert!(
        stdout.contains("unsupported config formats sighted: alertmanager (1)"),
        "alertmanager identity sighting: {stdout}"
    );
}

// --- G6 Terraform family (po-av01j.23) ---

/// A repo whose Terraform has one violation of each seed spec (an unpinned
/// provider, no state backend) and one satisfied key (an exactly-pinned
/// registry module), plus a Go call site so the scan mirrors the GHA fixture.
fn write_terraform_lane_fixtures(
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    std::fs::write(
        dir.join("main.tf"),
        r#"terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}
"#,
    )
    .unwrap();
    // SEED, test-grade config specs (the production corpus is a follow-up
    // factory run): unpinned provider violates, missing remote state
    // violates, an exact or ref pin satisfies.
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{
        "apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],
        "configs":[],
        "config_keys":[
            {"format":"terraform","key":"provider.version-constraint","expect":{"kind":"present"},"confidence":0.9,"control":"RC-045","severity":"medium","fix":"pin provider versions in required_providers","rationale":"an unconstrained provider floats to the newest release"},
            {"format":"terraform","key":"terraform.backend","expect":{"kind":"present"},"confidence":0.9,"control":"RC-030","severity":"medium","fix":"configure a remote state backend in the terraform block","rationale":"local state cannot be shared, locked, or recovered"},
            {"format":"terraform","key":"module.pin-class","expect":{"kind":"one_of","values":["exact","ref-pinned"]},"confidence":0.9,"control":"RC-045","rationale":"registry/git modules pin to an exact version or ref"}
        ]
    }"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_runs_the_terraform_family_with_seed_specs() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_terraform_lane_fixtures(dir.path());
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

    // The two seeded violations surface as config classes...
    assert!(
        stdout.contains("terraform provider.version-constraint"),
        "unpinned provider must surface: {stdout}"
    );
    assert!(
        stdout.contains("terraform terraform.backend"),
        "missing remote state must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-030"),
        "the config spec's control rides into the ladder: {stdout}"
    );
    // ...and the exactly-pinned registry module satisfies its spec, so
    // pin-class never renders as a finding.
    assert!(
        !stdout.contains("terraform module.pin-class"),
        "a satisfied config key is not a finding: {stdout}"
    );
    // Terraform is a supported format now: never sighted as unsupported.
    assert!(
        !stdout.contains("unsupported config formats sighted: terraform"),
        "supported formats must not be sighted: {stdout}"
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

/// The SEED corpus declaring UNBOUNDED SENTINELS (po-av01j.25): the values of
/// an API's own timeout argument that mean no bound.
fn sentinel_seed_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sentinel_seed_specs.json")
}

/// Python, live end to end: the whole pipeline (pyindex retrieval → schema-v2
/// const_args → value-aware propagation) must tell `timeout=5` from
/// `timeout=None`. Both calls carry a timeout ARGUMENT, so the pre-sentinel
/// engine passed both; only the resolved VALUE separates them, and the seed
/// corpus — not the engine — is where that knowledge lives.
#[test]
fn scan_violates_a_sentinel_timeout_argument_end_to_end() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("SKIP scan_violates_a_sentinel_timeout_argument_end_to_end: no python3");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("svc.py"),
        "import requests\n\n\
         def bounded():\n    \
             return requests.get(\"https://api.example.com/a\", timeout=5)\n\n\
         def unbounded():\n    \
             return requests.get(\"https://api.example.com/b\", timeout=None)\n",
    )
    .unwrap();
    let out_path = dir.path().join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(&src)
        .arg("--specs-file")
        .arg(sentinel_seed_specs())
        .arg("--out")
        .arg(&out_path)
        .env(
            "RVLSCAN_PYINDEX",
            helpers_dir().join("pyindex").join("pyindex.py"),
        )
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = verdicts_for(rows.as_array().unwrap(), "svc.py");
    assert!(
        rows.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("timeout=5")),
        "a real timeout still bounds the call: {rows:?}"
    );
    let (verdict, reason) = rows
        .iter()
        .find(|(_, r)| r.contains("None"))
        .unwrap_or_else(|| panic!("no finding cited the sentinel value: {rows:?}"));
    assert_eq!(
        verdict, "violates",
        "timeout=None blocks forever and must not credit a bound: {reason}"
    );
    assert!(
        reason.contains("timeout=None") && reason.contains("literal"),
        "the reason must cite the resolved value and how it was determined: {reason}"
    );
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

// --- C/C++ G1 lane (po-av01j.12) ---

/// Locate the cindex helper (a workspace bin built alongside rvlscan) and
/// verify its libclang engine loads. None (with a SKIP log line) when the
/// binary is missing or no libclang is installed — the e2e is exercised
/// wherever the engine exists, and the environment gap is loud, not silent.
fn cindex_helper(test: &str) -> Option<std::path::PathBuf> {
    let bin = std::path::Path::new(env!("CARGO_BIN_EXE_rvlscan"))
        .parent()
        .unwrap()
        .join("cindex");
    if !bin.is_file() {
        eprintln!("SKIP {test}: cindex not built (run `cargo build -p cindex`)");
        return None;
    }
    match std::process::Command::new(&bin)
        .arg("--engine-check")
        .output()
    {
        Ok(out) if out.status.success() => Some(bin),
        Ok(out) => {
            eprintln!(
                "SKIP {test}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
            None
        }
        Err(e) => {
            eprintln!("SKIP {test}: cannot run cindex: {e}");
            None
        }
    }
}

/// C e2e: cindex retrieves the compile-db fixture LIVE (detection via
/// compile_commands.json, helper via RVLSCAN_CINDEX), the seed specs judge
/// the C identities, and the judgments map the surfaced classes to RC-019 /
/// RC-022 on the ladder. The macro-wrapped perform site flows through the
/// pipeline like any other — the v2 macro flag is packet evidence, never a
/// verdict gate.
#[test]
fn scan_decides_c_sites_end_to_end_with_seed_specs() {
    let Some(cindex) = cindex_helper("scan_decides_c_sites_end_to_end_with_seed_specs") else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().and_then(|p| p.parent()).unwrap();
    let fixture = workspace
        .join("crates")
        .join("cindex")
        .join("testdata")
        .join("fixture-c");
    let fixtures = manifest.join("tests").join("fixtures");
    let out_path = dir.path().join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(&fixture)
        .arg("--specs-file")
        .arg(fixtures.join("c_seed_specs.json"))
        .arg("--judgments")
        .arg(fixtures.join("c_seed_judgments.json"))
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CINDEX", &cindex)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    // This fixture plants blocking identities, so a working scan exits
    // EXIT_BLOCKED, not 0. Exit 1 stays tolerated: cindex can be present but
    // fail at runtime without a system libclang.
    assert!(
        scan_reached_a_verdict(&out) || out.status.code() == Some(1),
        "scan errored: {stdout}\n{stderr}"
    );
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().expect("findings must be an array").clone();
    let main_c = verdicts_for(&rows, "src/main.c");

    // Every planted blocking identity with no visible bound violates: two
    // curl_easy_perform sites (the macro-wrapped one included), PQexec,
    // PQconnectdb, redisCommand, redisConnect, connect, recv.
    let violates = main_c
        .iter()
        .filter(|(v, r)| v == "violates" && r.contains("no bound anywhere"))
        .count();
    assert_eq!(
        violates, 8,
        "planted blocking sites must violate: {main_c:?}"
    );
    // The non-blocking setopt sites resolve as not_applicable, never noise.
    let not_applicable = main_c
        .iter()
        .filter(|(v, r)| v == "not_applicable" && r.contains("does not block"))
        .count();
    assert_eq!(
        not_applicable, 2,
        "both setopt sites are non-blocking: {main_c:?}"
    );

    // The judgments map the surfaced classes to their controls on the ladder.
    assert!(
        stdout.contains("RC-019"),
        "the curl/libpq timeout class must surface control-mapped: {stdout}"
    );
    assert!(
        stdout.contains("RC-022"),
        "the hiredis retry class must surface control-mapped: {stdout}"
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

// --- Java lane (po-av01j.9) ---

/// The hand-authored SEED Java spec corpus (test-grade; RC-019 timeouts,
/// RC-022 retry-posture rationale, RC-060 job altitude, and a self-contained
/// emission section). The production corpus rides the LLM factory, HITL.
fn java_seed_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("java_seed_specs.json")
}

/// The javaindex helper source, iff a JDK is available (the helper runs in
/// JEP 330 source-file mode and needs javac). Skip-if-no-jdk, matching the
/// goindex/node skip convention.
fn javaindex_ready() -> Option<std::path::PathBuf> {
    match std::process::Command::new("javac").arg("-version").output() {
        Ok(out) if out.status.success() => {}
        _ => {
            eprintln!("SKIP java scan: no JDK (javac not available)");
            return None;
        }
    }
    Some(helpers_dir().join("javaindex").join("javaindex.java"))
}

/// Java e2e: javaindex retrieves the fixture, and the seed specs decide all
/// three ways. The bare @Scheduled registration violates (job altitude, no
/// bound), the @Scheduled next to @Transactional(timeout = 30) satisfies via
/// the bounding-decorator mechanism, the classic-only java.util.Timer spec
/// abstains on a background_job site (applicability control), and the JDBC
/// executeQuery with no bound anywhere violates on the G1 lane.
#[test]
fn scan_decides_java_sites_end_to_end() {
    let Some(javaindex) = javaindex_ready() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(helper_fixture("javaindex"))
        .arg("--specs-file")
        .arg(java_seed_specs())
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_JAVAINDEX", &javaindex)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().expect("findings must be an array").clone();

    let jobs = verdicts_for(&rows, "Jobs.java");
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the bare @Scheduled registration must violate: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "satisfies" && r.contains("bounding decorator")),
        "@Scheduled beside @Transactional(timeout = 30) must satisfy via the decorator bound: {jobs:?}"
    );
    assert!(
        jobs.iter()
            .any(|(v, r)| v == "abstain" && r.contains("site kind")),
        "the classic java.util.Timer spec must not decide the background_job site: {jobs:?}"
    );

    let svc = verdicts_for(&rows, "Service.java");
    assert!(
        svc.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the unbounded JDBC executeQuery must violate: {svc:?}"
    );
}

/// Java, live end to end: javaindex inventories the fixture's emissions (the
/// slf4j aggregates, the swallowing catch), and the seed specs surface the
/// RC-027 swallow gap in the ladder.
#[test]
fn live_java_scan_surfaces_g4_emission_findings() {
    let Some(javaindex) = javaindex_ready() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .arg("scan")
        .arg(helper_fixture("javaindex"))
        .arg("--specs-file")
        .arg(java_seed_specs())
        .env("RVLSCAN_JAVAINDEX", &javaindex)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "the swallowing catch must surface under RC-027: {stdout}"
    );
}

// --- Rust G1 lane (po-av01j.11) ---

/// The hand-authored SEED Rust spec corpus (test-grade; RC-019 at reqwest /
/// sqlx identities — the production corpus rides the LLM factory, HITL).
fn rust_seed_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata")
        .join("rust_seed_specs.json")
}

/// Rust, live end to end: `rvlscan scan <fixture>` must detect Rust, run the
/// rustindex helper (a workspace binary — built by cargo next to rvlscan, the
/// same adjacency a release ships), and feed its packets through the pipeline
/// with the seed specs. Skipped when rust-analyzer is unavailable, matching
/// the goindex skip convention.
#[test]
fn live_rust_scan_runs_the_rustindex_helper() {
    match Command::new("rust-analyzer").arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("SKIP live_rust_scan: rust-analyzer not available (rustup component)");
            return;
        }
    }
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf();
    // The helper is a workspace bin: usually already built next to rvlscan.
    let rustindex = std::path::Path::new(env!("CARGO_BIN_EXE_rvlscan"))
        .parent()
        .unwrap()
        .join("rustindex");
    if !rustindex.is_file() {
        let build = Command::new("cargo")
            .args(["build", "-p", "rustindex"])
            .current_dir(&workspace)
            .output();
        match build {
            Ok(o) if o.status.success() && rustindex.is_file() => {}
            Ok(o) => {
                // Our own crate failing to build is a defect, not a skip.
                panic!(
                    "rustindex failed to build: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => {
                eprintln!("SKIP live_rust_scan: cargo not available: {e}");
                return;
            }
        }
    }
    let fixture = workspace
        .join("crates")
        .join("rustindex")
        .join("testdata")
        .join("fixture");
    assert!(fixture.join("Cargo.toml").is_file(), "fixture missing");

    let dir = tempfile::tempdir().unwrap();
    let out = bin()
        .arg("scan")
        .arg(&fixture)
        .arg("--specs-file")
        .arg(rust_seed_specs())
        .env("RVLSCAN_RUSTINDEX", &rustindex)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("sites ") && !stdout.contains("sites 0 "),
        "the fixture must yield parsed G1 sites: {stdout}"
    );
    assert!(
        stdout.contains("server-entry 2"),
        "both .route() registrations must ride the G2 partition: {stdout}"
    );
    assert!(
        stdout.contains("COVERAGE"),
        "ladder must render a coverage section: {stdout}"
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

// --- hook-mode agent adjudication (po-av01j.15) ---

/// Copy the goindex fixture into a writable temp repo so the test can commit
/// consent into `.revelara.yaml` without touching the shared fixture tree.
fn copy_fixture_to(dst: &std::path::Path) {
    fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir(&entry.path(), &to);
            } else {
                std::fs::copy(entry.path(), &to).unwrap();
            }
        }
    }
    copy_dir(&goindex_fixture(), dst);
}

/// End-to-end hook lane: with EVERY consent layer on and a stub agent
/// (RVLSCAN_AGENT_CMD), an incremental hook scan makes ONE batched invocation
/// over the delta's undecided sites, renders the provenance-tagged AGENT
/// block, and records identity-only telemetry locally. The stub replies `[]`
/// (a valid, empty verdict set), so every site stays undecided and the
/// deterministic result is visibly unchanged.
#[cfg(unix)]
#[test]
fn hook_scan_with_consent_runs_the_stub_agent_and_records_telemetry() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let repo = dir.path().join("repo");
    copy_fixture_to(&repo);
    // Pre-warm the Go build/list cache: the first packages.Load on a cold CI
    // runner can exceed the hook's 10s deterministic fail-open cap on its
    // own, which would degrade this scan to zero sites and starve the agent
    // lane the test exists to exercise.
    let _ = std::process::Command::new(&goindex_bin)
        .args(["--retrieve", "--root"])
        .arg(&repo)
        .args(["--name", "warm"])
        .output();
    std::fs::write(
        repo.join(".revelara.yaml"),
        "scanner:\n  use_agent: allow\n  agent_hooks:\n    pre_commit:\n      enabled: true\n      budget_seconds: 20\n",
    )
    .unwrap();

    // The stub approved agent: proof of invocation + a valid empty verdict set.
    let stub = dir.path().join("agent-stub.sh");
    std::fs::write(&stub, "#!/bin/sh\necho '[]'\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

    // Empty specs: every fixture site abstains (no spec), i.e. is undecided.
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();

    let home = dir.path().join("home"); // isolates org policy + user config
    std::fs::create_dir_all(&home).unwrap();
    let out = bin()
        .args(["scan", "--incremental", "--hook", "pre-commit"])
        .arg(&repo)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("RVLSCAN_AGENT_CMD", &stub)
        .env("HOME", &home)
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "hook scan failed: {stdout}\n{stderr}");
    assert!(
        stdout.contains("AGENT"),
        "consented hook run must render the agent block: {stdout}"
    );
    assert!(
        stdout.contains("stay undecided"),
        "an empty verdict set leaves the sites undecided: {stdout}"
    );
    assert!(
        !stdout.contains("BLOCKING"),
        "advisory mode must never produce blocking rows: {stdout}"
    );

    // Identity-only telemetry landed locally, next to last-scan.json.
    let telemetry = dir.path().join("agent-telemetry.jsonl");
    let text = std::fs::read_to_string(&telemetry).expect("telemetry file must exist");
    let row: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(row["hook"], "pre-commit");
    assert_eq!(row["agent"], "custom");
    assert!(row["latency_ms"].is_u64());
    assert_eq!(row["timed_out"], false);
    assert!(
        !text.contains("svc.go") && !text.contains(repo.to_str().unwrap()),
        "telemetry must never carry file paths: {text}"
    );
}

/// The consent default: the SAME hook invocation with no `.revelara.yaml`
/// consent renders no agent block, invokes nothing, and records no telemetry.
#[test]
fn hook_scan_without_consent_stays_deterministic_only() {
    let dir = tempfile::tempdir().unwrap();
    let Some(goindex_bin) = build_goindex(dir.path()) else {
        return;
    };
    let repo = dir.path().join("repo");
    copy_fixture_to(&repo);
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let out = bin()
        .args(["scan", "--incremental", "--hook", "pre-commit"])
        .arg(&repo)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_GOINDEX", &goindex_bin)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .env("RVLSCAN_INDEX_DIR", dir.path().join("index"))
        .env("HOME", &home)
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "hook scan failed: {stdout}\n{stderr}");
    assert!(
        !stdout.contains("AGENT"),
        "no consent must mean no agent block: {stdout}"
    );
    assert!(
        !dir.path().join("agent-telemetry.jsonl").exists(),
        "no consent must mean no telemetry"
    );
}

// --- G6 Argo/Flux family (po-av01j.24) ---

/// A repo with GitOps CRs only (no code lane): an Argo CD Application that
/// auto-syncs a floating branch with no retry and no selfHeal, a Flux
/// GitRepository tracking a branch, and an Argo Rollout the family does not
/// parse. Seed config-key specs cover the pin-shape and remediation keys.
fn write_argo_flux_fixtures(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    // The config lane is the subject; the code lane gets one unspecced Go
    // site so the packet stream is non-empty (the scan requires sites).
    let src = dir.join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    let packets = dir.join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":3,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
    )).unwrap();
    std::fs::create_dir_all(dir.join("deploy")).unwrap();
    std::fs::write(
        dir.join("deploy/app.yaml"),
        "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  project: default\n  source:\n    repoURL: https://example.com/repo.git\n    path: k8s\n    targetRevision: main\n  syncPolicy:\n    automated: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("deploy/gitrepo.yaml"),
        "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: podinfo\nspec:\n  interval: 1m\n  ref:\n    branch: main\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("deploy/rollout.yaml"),
        "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\n",
    )
    .unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{
        "config_keys":[
            {"format":"argo-cd","key":"application.targetRevision.shape","expect":{"kind":"equals","value":"pinned"},"confidence":0.9,"control":"RC-050","severity":"medium","fix":"pin targetRevision to a tag or commit SHA","rationale":"HEAD/branch refs float"},
            {"format":"argo-cd","key":"application.syncPolicy.automated.selfHeal","expect":{"kind":"equals","value":"true"},"confidence":0.9,"control":"RC-036","severity":"medium","fix":"set syncPolicy.automated.selfHeal: true","rationale":"drift is not remediated by default"},
            {"format":"argo-cd","key":"application.syncPolicy.retry","expect":{"kind":"pattern","name":"configured"},"confidence":0.9,"control":"RC-036","severity":"medium","fix":"set syncPolicy.retry (limit + backoff)","rationale":"an automated sync loop needs a bounded retry"},
            {"format":"flux","key":"gitrepository.ref.shape","expect":{"kind":"one_of","values":["commit","semver","tag"]},"confidence":0.9,"control":"RC-050","severity":"medium","fix":"track a tag, semver range, or commit instead of a branch","rationale":"branch refs float"}
        ]
    }"#).unwrap();
    (packets, specs)
}

#[test]
fn scan_runs_the_argo_flux_family_and_reports_its_findings() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_argo_flux_fixtures(dir.path());
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

    // The floating targetRevision violates the pin-shape spec.
    assert!(
        stdout.contains("argo-cd application.targetRevision.shape"),
        "floating targetRevision must surface: {stdout}"
    );
    // Automated sync without selfHeal: the documented false default governs.
    assert!(
        stdout.contains("argo-cd application.syncPolicy.automated.selfHeal"),
        "selfHeal-off must surface: {stdout}"
    );
    // The issue's canonical decidable absence: automated sync, no retry —
    // an as-authored-absent packet judged by the `configured` pattern.
    assert!(
        stdout.contains("argo-cd application.syncPolicy.retry"),
        "missing retry must surface: {stdout}"
    );
    // The Flux source tracks a branch: shape-only fact vs the pin spec.
    assert!(
        stdout.contains("flux gitrepository.ref.shape"),
        "branch-tracking GitRepository must surface: {stdout}"
    );
    assert!(
        stdout.contains("RC-050"),
        "the deciding spec's control rides into the ladder: {stdout}"
    );
    // The unparsed Argo Rollout is a product-identity sighting, never a
    // generic kubernetes one.
    assert!(
        stdout.contains("argo-rollouts (1)"),
        "unrecognized argo kind must be sighted by product: {stdout}"
    );
    assert!(
        !stdout.contains("kubernetes (1)"),
        "argo/flux CRs must never sight as generic kubernetes: {stdout}"
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
    // The `:latest` retag below is a high-severity config violation, so this
    // lane BLOCKS: exit EXIT_BLOCKED, not 0. (It exited 0 before po-av01j.94 —
    // proof the config lane's gate was decorative too.)
    assert_eq!(
        out.status.code(),
        Some(EXIT_BLOCKED),
        "blocking config lane must exit {EXIT_BLOCKED}: {stdout} {stderr}"
    );

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

// --- C# lane (po-av01j.10) ---

/// The hand-authored SEED C# spec corpus (test-grade): RC-019 timeout and
/// RC-022 retry judgments at C# identities, plus the C# emission identities
/// for the G4 lane. The production corpus rides the LLM factory, HITL — see
/// the gate-set mint bead under po-av01j.
fn csharp_seed_specs() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("csharp_seed_specs.json")
}

/// C#, golden packet stream: a `--retrieved` stream shaped exactly like
/// csindex output is decided by the seed C# specs WITHOUT a dotnet SDK
/// present. This is the contract test for the Rust side of the lane: the
/// satisfies / violates / abstain shapes, G2 registrations routed out of the
/// G1 lane, and a G4 catch_clause swallow surfacing under RC-027.
#[test]
fn scan_decides_csharp_g1_sites_from_a_retrieved_stream() {
    let dir = tempfile::tempdir().unwrap();
    let packets = dir.path().join("retrieved.jsonl");
    let mk = |line: u32, symbol: &str, func: &str, ctype: &str, snippet: &str, extra: &str| {
        format!(
            r#"{{"packet_schema":2,"snapshot_id":"fx","file_path":"Svc.cs","line_number":{line},"symbol":{symbol:?},"func":{func:?},"receiver":"_c","client_type":{ctype:?},"snippet":{snippet:?},"lang":"csharp"{extra}}}"#
        )
    };
    let stream = [
        // Satisfies: HttpClient carries a whole-call default Timeout (100s),
        // spec knowledge riding the this_client config spec.
        mk(
            10,
            "FetchUser",
            "GetAsync",
            "System.Net.Http.HttpClient",
            "await _c.GetAsync(url)",
            "",
        ),
        // Violates: a gRPC call has NO default deadline; the seed spec says
        // the bound rides CallOptions at the call, and none is present.
        mk(
            20,
            "SayHello",
            "AsyncUnaryCall",
            "Grpc.Core.CallInvoker",
            "_c.AsyncUnaryCall(method, host, options, req)",
            "",
        ),
        // Abstain: librdkafka retries internally; whether app-level retry
        // wrapping is needed is per-site judgment (RC-022 seed, depends).
        mk(
            30,
            "Publish",
            "ProduceAsync",
            "Confluent.Kafka.IProducer",
            "await _c.ProduceAsync(topic, msg)",
            "",
        ),
        // A G2 route registration must be routed OUT of the G1 lane.
        mk(
            40,
            "MapRoutes",
            "MapGet",
            "Microsoft.AspNetCore.Builder.WebApplication",
            "app.MapGet(\"/health\", handler)",
            r#","site_kind":"server_entry""#,
        ),
        // A G4 catch_clause swallow aggregate surfaces under RC-027.
        mk(
            50,
            "Handle",
            "catch",
            "catch_clause",
            "",
            r#","site_kind":"emission_point","const_args":[{"index":0,"name":"emission_category","value":"error_capture","how":"aggregate"},{"index":0,"name":"emission_count","value":"1","how":"aggregate"}]"#,
        ),
    ]
    .join("\n");
    std::fs::write(&packets, stream + "\n").unwrap();

    let out_path = dir.path().join("findings.json");
    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets)
        .arg("--specs-file")
        .arg(csharp_seed_specs())
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {stdout}\n{stderr}"
    );

    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().unwrap().clone();
    let g1 = verdicts_for(&rows, "Svc.cs");
    assert!(
        g1.iter().any(
            |(v, r)| v == "satisfies" && r.contains("client config System.Net.Http.HttpClient")
        ),
        "HttpClient's default whole-call Timeout must satisfy via the config spec: {g1:?}"
    );
    assert!(
        g1.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the deadline-less gRPC call must violate: {g1:?}"
    );
    assert!(
        g1.iter()
            .any(|(v, r)| v == "abstain" && r.contains("depends")),
        "the Kafka produce must abstain on the depends spec: {g1:?}"
    );
    // The route registration and the emission aggregate stay OUT of the G1
    // verdict rows (their lanes judge them).
    assert!(
        !g1.iter().any(|(_, r)| r.contains("MapGet")),
        "a server_entry registration must not be judged as a client call: {g1:?}"
    );
    assert_eq!(
        rows.len(),
        3,
        "only the three G1 call sites belong in --out: {rows:?}"
    );
    // The G4 swallow surfaces in the ladder, control-mapped and advisory.
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "the catch_clause swallow must surface under RC-027: {stdout}"
    );
}

/// Build csindex with the dotnet SDK, or skip (returns None) when the SDK or
/// its NuGet restore (Roslyn) is unavailable — matching the tsindex
/// "run npm install first" skip convention.
fn build_csindex(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    if std::process::Command::new("dotnet")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("SKIP csindex e2e: no dotnet SDK");
        return None;
    }
    let csdir = helpers_dir().join("csindex");
    let out_dir = dir.join("csindex-build");
    let out = std::process::Command::new("dotnet")
        .args(["build", "-c", "Release", "-o"])
        .arg(&out_dir)
        .current_dir(&csdir)
        .output()
        .ok()?;
    if !out.status.success() {
        // The SDK being absent is a skip (handled above); the SDK being
        // present while OUR helper fails to compile is a defect. This exact
        // branch hid four CS0103 errors through an entire epic (po-av01j.47),
        // because a green skip reads identically to a green pass.
        panic!(
            "csindex failed to build: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let dll = out_dir.join("csindex.dll");
    if dll.is_file() {
        Some(dll)
    } else {
        panic!("csindex built but produced no csindex.dll at {out_dir:?}")
    }
}

/// C#, live end to end: csindex retrieves the fixture (Roslyn engine), and
/// the seed specs decide the same three shapes the golden-stream test pins,
/// plus the catch_clause swallow from the fixture's emitters.
#[test]
fn scan_decides_csharp_sites_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let Some(csindex_dll) = build_csindex(dir.path()) else {
        return;
    };
    let out_path = dir.path().join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(helper_fixture("csindex"))
        .arg("--specs-file")
        .arg(csharp_seed_specs())
        .arg("--out")
        .arg(&out_path)
        .env("RVLSCAN_CSINDEX", &csindex_dll)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        out.status.success() || out.status.code() == Some(1),
        "scan errored: {stdout}\n{stderr}"
    );
    let rows: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = rows.as_array().unwrap().clone();
    let g1 = verdicts_for(&rows, "Svc.cs");
    assert!(
        g1.iter().any(
            |(v, r)| v == "satisfies" && r.contains("client config System.Net.Http.HttpClient")
        ),
        "the fixture's HttpClient call must satisfy: {g1:?}"
    );
    assert!(
        g1.iter()
            .any(|(v, r)| v == "violates" && r.contains("no bound anywhere")),
        "the fixture's deadline-less gRPC call must violate: {g1:?}"
    );
    assert!(
        g1.iter()
            .any(|(v, r)| v == "abstain" && r.contains("depends")),
        "the fixture's Kafka produce must abstain: {g1:?}"
    );
    assert!(
        stdout.contains("emission.RC-027") && stdout.contains("swallow"),
        "the fixture's swallowing catch must surface under RC-027: {stdout}"
    );
}

// --- the shape-only report on the wire (po-av01j.63) ---

/// End to end through the real binary: the report payload names the language
/// each surface was written in, and a shape seen in TWO languages names
/// NEITHER. Unit tests cover the fold; this covers the plumbing — the language
/// has to survive packet parse, propagation, and serialization to be worth
/// anything, and none of that is exercised by testing `build_report` directly.
///
/// It is also the end-to-end privacy audit: the fixture's packets carry real
/// snippets and real absolute file paths, and neither may appear in the payload.
#[test]
fn report_payload_names_each_surface_language_and_never_carries_source() {
    let dir = tempfile::tempdir().unwrap();
    let (packets_path, specs) = write_scan_fixtures(dir.path());

    // Two sites, one shape, two languages: an unresolved receiver emits a bare
    // `HttpClient` in both C# and Java.
    let mixed_src = dir.path().join("Svc.cs");
    std::fs::write(&mixed_src, "class Svc { void M() { c.SendThing(r); } }\n").unwrap();
    let mut stream = std::fs::read_to_string(&packets_path).unwrap();
    for lang in ["csharp", "java"] {
        stream.push_str(
            &serde_json::json!({
                "snapshot_id": "fixture",
                "file_path": mixed_src.to_str().unwrap(),
                "line_number": 30,
                "func": "SendThing",
                "client_type": "HttpClient",
                "snippet": "c.SendThing(r)",
                "lang": lang,
            })
            .to_string(),
        );
        stream.push('\n');
    }
    std::fs::write(&packets_path, stream).unwrap();

    let out = bin()
        .args(["report", "--retrieved"])
        .arg(&packets_path)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--json")
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "report failed: {stdout} {stderr}");

    let payload: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let surfaces = payload["surfaces"].as_array().unwrap();
    let find = |ct: &str| {
        surfaces
            .iter()
            .find(|s| s["client_type"] == ct)
            .unwrap_or_else(|| panic!("{ct} missing from the payload: {stdout}"))
    };

    // The spec'd pgx call is DECIDED and never reported; the unknown Go call is.
    let unknown = find("x.Unknown");
    assert_eq!(unknown["lang"], "go", "a Go surface must say so: {stdout}");
    assert_eq!(unknown["site_count"], 1);

    // Two languages, one shape: still ONE surface, and it names neither.
    let mixed = find("HttpClient");
    assert_eq!(
        mixed["lang"], "",
        "a shape seen in two languages must claim neither: {stdout}"
    );
    assert_eq!(mixed["site_count"], 2, "both sites still count: {stdout}");

    // The privacy contract, on the real payload: no snippets, no paths.
    assert!(
        !stdout.contains("u.Mystery()") && !stdout.contains("c.SendThing(r)"),
        "a snippet leaked into the report payload: {stdout}"
    );
    assert!(
        !stdout.contains("unknown.go") && !stdout.contains("Svc.cs"),
        "a file path leaked into the report payload: {stdout}"
    );
}

// --- generated-code exclusion (po-av01j.133.7) ---

/// A Go mini-repo: one hand-written file and one that declares itself generated.
fn repo_with_a_generated_file(root: &std::path::Path) {
    let w = |rel: &str, body: &str| {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    w("go.mod", "module example.com/svc\n\ngo 1.22\n");
    w(
        "handler.go",
        "package svc\n\nimport \"net/http\"\n\nfunc Get() {\n\thttp.Get(\"http://x\")\n}\n",
    );
    w(
        "api.pb.go",
        "// Code generated by protoc-gen-go. DO NOT EDIT.\n// source: api.proto\n\n\
         package svc\n\nimport \"net/http\"\n\nfunc Gen() {\n\thttp.Get(\"http://y\")\n}\n",
    );
}

#[test]
fn generated_files_are_excluded_and_the_exclusion_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    repo_with_a_generated_file(dir.path());
    let out = bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .env("RVLSCAN_ALLOW_MISSING_HELPERS", "1")
        .output()
        .expect("failed to run rvlscan");
    if !scan_reached_a_verdict(&out) {
        return; // no Go helper on this machine; nothing to assert about
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("Go") {
        return; // the Go lane did not run here
    }
    assert!(
        text.contains("machine-generated file"),
        "the exclusion must be reported, never silent: {text}"
    );
}

#[test]
fn a_generated_banner_is_matched_by_evidence_not_by_path() {
    // The banner decides, so a file named like generated code but written by
    // hand is still scanned, and a plainly-named file that declares itself
    // generated is still excluded. Path rules would get both backwards.
    let dir = tempfile::tempdir().unwrap();
    let w = |rel: &str, body: &str| {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    w("go.mod", "module example.com/svc\n\ngo 1.22\n");
    // Hand-written, despite living in a directory called proto.
    w(
        "proto/handler.go",
        "package proto\n\nimport \"net/http\"\n\nfunc A() {\n\thttp.Get(\"http://x\")\n}\n",
    );
    let out = bin()
        .args(["scan", dir.path().to_str().unwrap()])
        .env("RVLSCAN_ALLOW_MISSING_HELPERS", "1")
        .output()
        .expect("failed to run rvlscan");
    if !scan_reached_a_verdict(&out) {
        return;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("machine-generated file"),
        "a hand-written file under proto/ must not be excluded: {text}"
    );
}

// --- scan submission mode (po-av01j.153, rvl-cli parity) ---

mod submit_mock {
    //! Just enough HTTP/1.1 for ureq: serves scripted responses in order and
    //! records every request, so the CLI-level submission tests are hermetic.
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct Recorded {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Recorded {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }
    }

    pub struct MockServer {
        pub base_url: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl MockServer {
        pub fn start(responses: Vec<(u16, &'static str)>) -> MockServer {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let requests: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
            let reqs = Arc::clone(&requests);
            std::thread::spawn(move || {
                let mut script = responses.into_iter();
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { continue };
                    let next = script.next().unwrap_or((500, "exhausted"));
                    let _ = handle(stream, next, &reqs);
                }
            });
            MockServer { base_url, requests }
        }

        pub fn recorded(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn handle(
        stream: std::net::TcpStream,
        (status, resp_body): (u16, &str),
        reqs: &Arc<Mutex<Vec<Recorded>>>,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();
        let mut headers = Vec::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end().to_string();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let (k, v) = (k.trim().to_string(), v.trim().to_string());
                if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.parse().unwrap_or(0);
                }
                headers.push((k, v));
            }
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }
        reqs.lock().unwrap().push(Recorded {
            method,
            path,
            headers,
            body,
        });
        let mut out = stream;
        write!(
            out,
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            resp_body.len()
        )?;
        out.write_all(resp_body.as_bytes())?;
        Ok(())
    }
}

const SUBMIT_RESPONSE: &str = r#"{
  "scan_id": "scan-cli-1",
  "service": "checkout-api",
  "summary": {"total": 2, "created": 2, "updated": 0, "unchanged": 0,
              "critical": 0, "high": 0, "medium": 2, "low": 0},
  "findings": [
    {"risk_id": "u1", "risk_code": "R-101", "title": "Missing timeout",
     "status": "created", "score": 61, "priority": "medium"},
    {"risk_id": "u2", "risk_code": "R-102", "title": "No circuit breaker",
     "status": "created", "score": 55, "priority": "medium"}
  ],
  "timestamp": "2026-08-13T00:00:00Z",
  "effective_tolerance": {"tolerance_target": 25, "tolerance_headroom_pct": 20,
                          "strict_enforcement": false}
}"#;

fn write_scan_parts(dir: &std::path::Path) -> std::path::PathBuf {
    let parts = dir.join("scan-parts");
    std::fs::create_dir_all(&parts).unwrap();
    std::fs::write(
        parts.join("01-stack.json"),
        r#"{"stack":{"languages":["go"]},"repo_url":"https://example.com/repo"}"#,
    )
    .unwrap();
    std::fs::write(
        parts.join("02-findings.json"),
        r#"{"findings":[{"title":"Missing timeout","category":"resilience","likelihood":"high","impact":"high","risk_score":61,"uca_type":"Not Provided"}]}"#,
    )
    .unwrap();
    std::fs::write(
        parts.join("03-findings.json"),
        r#"{"findings":[{"title":"No circuit breaker","category":"resilience","likelihood":"medium","impact":"high","risk_score":"55"}]}"#,
    )
    .unwrap();
    parts
}

/// The drop-in skill invocation `rvl scan --service X --target Y
/// --scan-dir DIR` works against this binary verbatim: parts merge in
/// alphabetical order, findings normalize (enum casing, numeric-as-string
/// risk_score), the wire body matches the rvl-cli contract, and the
/// success render names the created risk codes.
#[test]
fn scan_submission_merges_parts_and_posts_to_the_risk_register() {
    let dir = tempfile::tempdir().unwrap();
    let parts = write_scan_parts(dir.path());
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let server = submit_mock::MockServer::start(vec![(200, SUBMIT_RESPONSE)]);

    let out = bin()
        .args(["scan", "--service", "checkout-api", "--target"])
        .arg(dir.path())
        .arg("--scan-dir")
        .arg(&parts)
        .env("RVL_API_KEY", "pk_cli_test")
        .env("RVL_API_URL", &server.base_url)
        .env("HOME", &home)
        .env_remove("RVL_ORG_NAME")
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "submit failed: {stdout}\n{stderr}");

    // Success render: summary counts, created risk codes, tolerance line.
    assert!(stdout.contains("Scan submitted successfully"), "{stdout}");
    assert!(stdout.contains("Scan ID: scan-cli-1"), "{stdout}");
    assert!(
        stdout.contains("Total: 2 (Created: 2, Updated: 0, Unchanged: 0)"),
        "{stdout}"
    );
    assert!(stdout.contains("[NEW] R-101: Missing timeout"), "{stdout}");
    assert!(
        stdout.contains("[NEW] R-102: No circuit breaker"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Effective tolerance: target=25, headroom=20%, strict=false"),
        "{stdout}"
    );
    // Merge + normalization narration on stderr.
    assert!(stderr.contains("Merged: 01-stack.json"), "{stderr}");
    assert!(stderr.contains("Merged: 02-findings.json"), "{stderr}");
    assert!(stderr.contains("[coerced]"), "{stderr}");
    assert!(
        stderr.contains("Scan parts kept at"),
        "no --cleanup-on-success keeps the parts: {stderr}"
    );

    // The wire body: one POST carrying the merged, normalized request.
    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/risks/scan");
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_cli_test"));
    let body = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(
        body.starts_with(r#"{"service":"checkout-api","scan_type":"full","scan_mode":"auto""#),
        "{body}"
    );
    assert!(body.contains(r#""title":"Missing timeout""#), "{body}");
    assert!(body.contains(r#""title":"No circuit breaker""#), "{body}");
    assert!(
        body.contains(r#""uca_type":"not_provided""#),
        "enum casing normalized on the wire: {body}"
    );
    assert!(
        body.contains(r#""risk_score":55"#),
        "numeric-as-string risk_score coerced: {body}"
    );
    assert!(
        body.contains(r#""repo_url":"https://example.com/repo""#),
        "{body}"
    );
    assert!(body.contains(r#""scanner_id":"rvlscan/"#), "{body}");
    assert!(body.contains(r#""idempotency_key":""#), "{body}");
}

/// `--dry-run` validates and normalizes without submitting (po-4g59y):
/// machine-readable JSON summary on stdout, human framing on stderr, no
/// HTTP request at all. The API URL points at an unroutable port to prove
/// nothing is sent.
#[test]
fn scan_submission_dry_run_prints_summary_and_never_posts() {
    let dir = tempfile::tempdir().unwrap();
    let parts = write_scan_parts(dir.path());
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let out = bin()
        .args(["scan", "--service", "checkout-api", "--dry-run"])
        .arg("--scan-dir")
        .arg(&parts)
        .env("RVL_API_KEY", "pk_cli_test")
        // Unroutable: a request attempt would error, so success proves
        // the dry run never touched the network.
        .env("RVL_API_URL", "http://127.0.0.1:9")
        .env("HOME", &home)
        .env_remove("RVL_ORG_NAME")
        .output()
        .expect("failed to run rvlscan");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(out.status.success(), "dry run failed: {stdout}\n{stderr}");

    assert!(
        stderr.contains("Dry run - would submit to http://127.0.0.1:9"),
        "{stderr}"
    );
    let summary: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be the JSON summary");
    assert_eq!(summary["dry_run"], serde_json::Value::Bool(true));
    assert_eq!(summary["service"], "checkout-api");
    assert_eq!(summary["findings"], 2);
    assert_eq!(summary["scan_type"], "full");
    // po-gli2z counts ride the summary so CI can assert no STPA loss.
    assert_eq!(summary["findings_with_stpa"], 1);
    assert_eq!(summary["findings_coerced"], 2);
    assert_eq!(summary["findings_with_dropped"], 0);
    // No --target flag given: the key is absent, mirroring rvl-cli.
    assert!(summary.get("target").is_none(), "{stdout}");
}

/// `--cleanup-on-success` removes the scan-parts directory after a 2xx.
#[test]
fn scan_submission_cleanup_on_success_removes_parts() {
    let dir = tempfile::tempdir().unwrap();
    let parts = write_scan_parts(dir.path());
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let server = submit_mock::MockServer::start(vec![(200, SUBMIT_RESPONSE)]);

    let out = bin()
        .args(["scan", "--service", "checkout-api", "--cleanup-on-success"])
        .arg("--scan-dir")
        .arg(&parts)
        .env("RVL_API_KEY", "pk_cli_test")
        .env("RVL_API_URL", &server.base_url)
        .env("HOME", &home)
        .env_remove("RVL_ORG_NAME")
        .output()
        .expect("failed to run rvlscan");
    assert!(out.status.success());
    assert!(!parts.exists(), "scan parts must be removed after a 2xx");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Removed scan parts at"), "{stderr}");
}

/// A failed submit preserves the parts and prints the re-run hint.
#[test]
fn scan_submission_failure_preserves_parts_with_rerun_hint() {
    let dir = tempfile::tempdir().unwrap();
    let parts = write_scan_parts(dir.path());
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let server = submit_mock::MockServer::start(vec![(
        400,
        r#"{"code":"validation_failed","message":"bad request"}"#,
    )]);

    let out = bin()
        .args(["scan", "--service", "checkout-api", "--cleanup-on-success"])
        .arg("--scan-dir")
        .arg(&parts)
        .env("RVL_API_KEY", "pk_cli_test")
        .env("RVL_API_URL", &server.base_url)
        .env("HOME", &home)
        .env_remove("RVL_ORG_NAME")
        .output()
        .expect("failed to run rvlscan");
    assert_eq!(out.status.code(), Some(1), "submit failure exits 1");
    assert!(parts.exists(), "scan parts survive a failed submit");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("Scan parts preserved at"), "{stderr}");
    assert!(
        stderr.contains("server error (400 validation_failed)"),
        "{stderr}"
    );
}

/// `--service` with no input source gets rvl-cli's error, and never runs
/// the deterministic scan.
#[test]
fn scan_service_without_input_source_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let out = bin()
        .args(["scan", "--service", "svc"])
        .env("RVL_API_KEY", "pk_cli_test")
        .env("HOME", &home)
        .env_remove("RVL_ORG_NAME")
        .output()
        .expect("failed to run rvlscan");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Must specify --stdin, --file, or --scan-dir"),
        "{stderr}"
    );
}

/// Plain `rvlscan scan <path>` (no submission flag) still runs the
/// deterministic scanner: no network, no submit output, same verdict
/// surface as before this feature landed.
#[test]
fn plain_scan_stays_deterministic_and_never_submits() {
    let dir = tempfile::tempdir().unwrap();
    let (packets, specs) = write_scan_fixtures(dir.path());
    let out = bin()
        .args(["scan", "--retrieved"])
        .arg(&packets)
        .arg("--specs-file")
        .arg(&specs)
        .env("RVLSCAN_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvlscan");
    assert!(
        scan_reached_a_verdict(&out),
        "deterministic scan must still reach a verdict"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("Scan submitted"),
        "no submission on the deterministic path: {stdout}"
    );
}
