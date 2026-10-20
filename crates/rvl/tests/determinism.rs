//! Two scans of one tree on one pinned spec version give the same answer,
//! lane by lane.
//!
//! The corpus a scan judges against moves every six hours, so a result is
//! reproducible only with `--spec-version`. These tests hold that pin fixed
//! and the tree fixed, scan twice, and require the `--out` document to be
//! byte-identical and the human output identical apart from its timing line.
//! Any ordering that leans on hash iteration, the clock, or the order the
//! filesystem lists a directory shows up here as a diff.
//!
//! Every scan runs on a SIGNED commercial tier, trusted through the
//! debug-only `RVL_TEST_KEYSET_HEX` seam, because a pin binds only the signed
//! cache: a `--specs-file` scan has no content version to pin.

#![cfg(debug_assertions)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// The debug-only variable that adds test verifying keys to the pinned keyset.
/// Mirrors `TEST_KEYSET_ENV` in `crates/rvl/src/keyset.rs`.
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

/// `rvl scan` exit codes that mean the scan reached a verdict: clean, or
/// blocked by its findings. Mirrors `EXIT_BLOCKED` in `crates/rvl/src/main.rs`.
const VERDICT_CODES: [i32; 2] = [0, 3];

/// The G1 Go stand-in the other lanes share (see `docs/test-packets.md`).
const PGX_QUERY_SPEC: &str = r#"{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}"#;

/// One lane's fixture: a tree, an optional prebuilt packet stream, and the
/// `specs` object of the signed tier the scan is pinned to.
struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
    retrieved: Option<PathBuf>,
    version: String,
    key_hex: String,
}

impl Fixture {
    /// A fresh tree under a temp dir, with `specs` signed and installed as
    /// the commercial tier at a content version the scans pin.
    fn new(specs: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let repo = root.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let version = format!("{}.1", rvl_cache::today_utc());
        let key_hex = install_signed_commercial_tier(&root, specs, &version);
        Fixture {
            _dir: dir,
            root,
            repo,
            retrieved: None,
            version,
            key_hex,
        }
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.repo.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        p
    }

    /// Feed the scan this packet stream, one JSON value per line.
    fn retrieved(&mut self, lines: &[String]) {
        let p = self.root.join("retrieved.jsonl");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        self.retrieved = Some(p);
    }

    /// One pinned scan and the `--out` document it wrote. Every scan writes
    /// the same path, because the human output names it; the previous
    /// document is removed first, so a scan that writes none fails here.
    fn scan(&self) -> (std::process::Output, Vec<u8>) {
        let out_path = self.root.join("scan.json");
        let _ = std::fs::remove_file(&out_path);
        let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
        c.arg("scan").arg(&self.repo);
        if let Some(r) = &self.retrieved {
            c.arg("--retrieved").arg(r);
        }
        c.arg("--spec-version")
            .arg(&self.version)
            .arg("--out")
            .arg(&out_path)
            .arg("--color")
            .arg("never")
            .env("RVL_CACHE_DIR", self.root.join("cache"))
            .env("HOME", self.root.join("home"))
            .env(TEST_KEYSET_ENV, &self.key_hex)
            // No network: offline also turns the background cache check off.
            .env("RVL_OFFLINE", "1");
        for k in [
            "RVL_SPEC_VERSION",
            "RVL_API_KEY",
            "RVL_BASE_REF",
            "GITHUB_BASE_REF",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "NO_COLOR",
        ] {
            c.env_remove(k);
        }
        let out = c.output().expect("failed to run rvl");
        let doc = std::fs::read(&out_path).unwrap_or_else(|e| {
            panic!(
                "{}: no --out document ({e}):\n{}\n{}",
                out_path.display(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out, doc)
    }

    /// Scan twice and require the same answer. Returns the `--out` document
    /// and the human output, for the per-lane check that the lane ran.
    fn assert_deterministic(&self) -> (serde_json::Value, String) {
        let (first, first_doc) = self.scan();
        let (second, second_doc) = self.scan();
        let stdout = String::from_utf8_lossy(&first.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&first.stderr).into_owned();
        assert!(
            VERDICT_CODES.contains(&first.status.code().unwrap_or(-1)),
            "the scan did not run:\n{stdout}\n{stderr}"
        );
        assert!(
            stderr.contains(TEST_KEYSET_ENV),
            "the scan must run on the signed test tier: {stderr}"
        );
        assert!(
            !stderr.contains("spec cache pinned to"),
            "the scan must run on the pinned version: {stderr}"
        );
        assert_eq!(first.status.code(), second.status.code());
        assert!(
            first_doc == second_doc,
            "--out differs between two scans of one tree on one pinned spec version:\n{}",
            first_difference(&first_doc, &second_doc)
        );
        let (a, b) = (
            without_timing(&stdout),
            without_timing(&String::from_utf8_lossy(&second.stdout)),
        );
        assert!(
            a == b,
            "the human output differs between two scans of one tree on one pinned \
             spec version:\n{}",
            first_difference(a.as_bytes(), b.as_bytes())
        );
        let doc = serde_json::from_slice(&first_doc).expect("--out is JSON");
        (doc, stdout)
    }
}

/// Sign a commercial-tier envelope carrying `specs` at content version
/// `version` and install it under `<root>/cache`. Returns the public half,
/// hex encoded, which is the only thing a scan needs to trust it.
fn install_signed_commercial_tier(root: &Path, specs: &str, version: &str) -> String {
    use base64::Engine;
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let key_hex = hex::encode(signing.verifying_key().to_bytes());
    let keyset = rvl_cache::Keyset::from_hex(&[key_hex.as_str()]).unwrap();
    let bytes =
        format!(r#"{{"schema":1,"content_version":"{version}","specs":{specs}}}"#).into_bytes();
    let sig = base64::engine::general_purpose::STANDARD.encode(signing.sign(&bytes).to_bytes());
    let store = rvl_cache::CacheStore::open(&root.join("cache")).unwrap();
    let outcome = store.install(&bytes, &sig, &keyset);
    assert!(
        matches!(outcome, rvl_cache::SyncOutcome::Installed { .. }),
        "the test envelope must install: {outcome:?}"
    );
    key_hex
}

/// The human output with its timing line taken out: the wall-clock figure is
/// the one thing two identical scans may disagree on.
fn without_timing(stdout: &str) -> String {
    stdout
        .lines()
        .filter(|l| !is_timing_line(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The ladder's first line, `rvl scan complete in 0.42s`, built in
/// `run_scan`: the only line that carries the wall clock.
fn is_timing_line(line: &str) -> bool {
    line.contains("scan complete in ")
}

/// The first line where two outputs part, for a failure message a reader can
/// act on without diffing two temp files by hand.
fn first_difference(a: &[u8], b: &[u8]) -> String {
    let (a, b) = (String::from_utf8_lossy(a), String::from_utf8_lossy(b));
    let (mut la, mut lb) = (a.lines(), b.lines());
    let mut n = 1;
    loop {
        match (la.next(), lb.next()) {
            (Some(x), Some(y)) if x == y => n += 1,
            (None, None) => return "(no line differs; the bytes do)".into(),
            (x, y) => return format!("line {n}:\n  first:  {x:?}\n  second: {y:?}"),
        }
    }
}

/// A G1 client-call packet, in the shape `write_scan_fixtures` in `cli.rs`
/// uses.
fn g1_line(file: &Path, line: u32, func: &str, client_type: &str, snippet: &str) -> String {
    serde_json::json!({
        "snapshot_id": "fixture",
        "file_path": file.to_str().unwrap(),
        "line_number": line,
        "func": func,
        "client_type": client_type,
        "snippet": snippet,
        "lang": "go",
    })
    .to_string()
}

/// The Go file the pgx stand-in site sits in, and its packet.
const PGX_QUERY_GO: &str = "package svc\n\nfunc q() { tx.Query(ctx, q) }\n";

fn pgx_query_line(file: &Path) -> String {
    g1_line(
        file,
        3,
        "Query",
        "github.com/jackc/pgx/v5.Tx",
        "tx.Query(ctx, q)",
    )
}

/// G1, the client-call lane: one resolved site, one with no spec, in two
/// files, so the `sites` rows and the undecided list each have an order to
/// keep.
#[test]
fn g1_client_calls_scan_the_same_twice() {
    let mut fx = Fixture::new(&format!(r#"{{"apis":[{PGX_QUERY_SPEC}],"configs":[]}}"#));
    let db = fx.write("svc/db.go", PGX_QUERY_GO);
    let unk = fx.write(
        "svc/unknown.go",
        "package svc\n\nfunc m() { u.Mystery() }\n",
    );
    let other = fx.write("api/z.go", "package api\n\nfunc n() { v.Other() }\n");
    fx.retrieved(&[
        pgx_query_line(&db),
        g1_line(&unk, 3, "Mystery", "x.Unknown", "u.Mystery()"),
        g1_line(&other, 3, "Other", "y.Other", "v.Other()"),
    ]);
    let (doc, _) = fx.assert_deterministic();
    assert_eq!(doc["sites"].as_array().unwrap().len(), 3, "{doc}");
}

/// G2, the server-entry lane: route registrations judged by the seed server
/// specs.
#[test]
fn g2_server_entries_scan_the_same_twice() {
    let seed = include_str!("testdata/server_specs_seed.json");
    let mut fx = Fixture::new(seed);
    let routes = fx.write(
        "routes.go",
        "package main\n\nfunc routes() {\n\tmux.HandleFunc(\"/users\", users)\n\tmux.HandleFunc(\"/orders\", orders)\n}\n",
    );
    let entry = |line: u32, snippet: &str| {
        serde_json::json!({
            "snapshot_id": "fixture",
            "file_path": routes.to_str().unwrap(),
            "line_number": line,
            "func": "HandleFunc",
            "client_type": "net/http.ServeMux",
            "snippet": snippet,
            "lang": "go",
            "site_kind": "server_entry",
        })
        .to_string()
    };
    fx.retrieved(&[
        entry(4, r#"mux.HandleFunc("/users", users)"#),
        entry(5, r#"mux.HandleFunc("/orders", orders)"#),
    ]);
    let (_, stdout) = fx.assert_deterministic();
    assert!(
        stdout.contains("RC-020") && stdout.contains("RC-069"),
        "the G2 lane must judge the routes: {stdout}"
    );
}

/// G4, the emission-point lane: a recover with no emission and a slog
/// aggregate, judged by emission specs.
#[test]
fn g4_emission_points_scan_the_same_twice() {
    let mut fx = Fixture::new(&format!(
        "{{\"apis\":[{PGX_QUERY_SPEC}],\"configs\":[],\"emissions\":[{},{},{}]}}",
        r#"{"type":"recover_block","category":"error_capture","control":"RC-027","role":"violates","confidence":0.9,"rationale":"a recover with no emission swallows the panic"}"#,
        r#"{"type":"log/slog.Logger","category":"log","control":"RC-061","role":"satisfies","confidence":0.9,"rationale":"structured log emission"}"#,
        r#"{"type":"go.opentelemetry.io/otel/trace.Tracer","category":"trace","control":"RC-046","role":"satisfies","confidence":0.9,"rationale":"otel span"}"#,
    ));
    let db = fx.write("svc/db.go", PGX_QUERY_GO);
    let aggregate = |line: u32, func: &str, client_type: &str, category: &str, n: u32| {
        serde_json::json!({
            "snapshot_id": "fixture",
            "file_path": db.to_str().unwrap(),
            "line_number": line,
            "symbol": "q",
            "func": func,
            "client_type": client_type,
            "site_kind": "emission_point",
            "const_args": [
                {"index": 0, "name": "emission_category", "value": category, "how": "aggregate"},
                {"index": 0, "name": "emission_count", "value": n.to_string(), "how": "aggregate"},
            ],
            "lang": "go",
        })
        .to_string()
    };
    fx.retrieved(&[
        pgx_query_line(&db),
        aggregate(20, "recover", "recover_block", "error_capture", 2),
        aggregate(12, "Warn", "log/slog.Logger", "log", 7),
    ]);
    let (_, stdout) = fx.assert_deterministic();
    assert!(
        stdout.contains("RC-027"),
        "the G4 lane must surface the swallowed panic: {stdout}"
    );
}

/// G5, the content-pattern lane: secrets in several files of a tree with no
/// language, so the scan reads the tree itself and the lane's directory walk
/// decides the order.
#[test]
fn g5_content_patterns_scan_the_same_twice() {
    let fx = Fixture::new(r#"{"apis":[],"configs":[]}"#);
    // Fake tokens, assembled so no token-shaped literal sits in this source.
    let token = |tail: &str| ["ghp", "_", "AbCd1234EfGh5678IjKl9012MnOp", tail].concat();
    fx.write("prod.env", &format!("GH_TOKEN=\"{}\"\n", token("3456QrSt")));
    fx.write(
        "deploy/b.env",
        &format!("TOKEN=\"{}\"\n", token("7890UvWx")),
    );
    fx.write(
        "deploy/a.env",
        &format!("TOKEN=\"{}\"\n", token("1234YzAb")),
    );
    let (_, stdout) = fx.assert_deterministic();
    assert!(
        stdout.contains("secret.github_token"),
        "the G5 lane must find the tokens: {stdout}"
    );
}

/// G6, the config lane: a GitHub Actions workflow judged by config-key specs,
/// beside a config format the lane only sights.
#[test]
fn g6_config_keys_scan_the_same_twice() {
    let mut fx = Fixture::new(&format!(
        "{{\"apis\":[{PGX_QUERY_SPEC}],\"configs\":[],\"config_keys\":[{},{}]}}",
        r#"{"format":"github-actions","key":"job.timeout-minutes","expect":{"kind":"present"},"confidence":0.9,"control":"RC-013","severity":"medium","fix":"set jobs.<id>.timeout-minutes","rationale":"6h default"}"#,
        r#"{"format":"github-actions","key":"step.uses.ref","expect":{"kind":"pattern","name":"sha40"},"confidence":0.9,"control":"RC-045","rationale":"pin actions to full SHAs"}"#,
    ));
    let db = fx.write("svc/db.go", PGX_QUERY_GO);
    let workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-go@v5\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n";
    fx.write(".github/workflows/ci.yml", workflow);
    fx.write(".github/workflows/release.yml", workflow);
    fx.write(".circleci/config.yml", "version: 2\n");
    fx.retrieved(&[pgx_query_line(&db)]);
    let (_, stdout) = fx.assert_deterministic();
    assert!(
        stdout.contains("github-actions job.timeout-minutes"),
        "the G6 lane must judge the workflows: {stdout}"
    );
}

/// G7, the repo-structure lane: the `repo_structure` record a prebuilt
/// stream carries, judged control by control.
#[test]
fn g7_repo_structure_scans_the_same_twice() {
    let mut fx = Fixture::new(&format!(r#"{{"apis":[{PGX_QUERY_SPEC}],"configs":[]}}"#));
    let db = fx.write("svc/db.go", PGX_QUERY_GO);
    fx.retrieved(&[
        pgx_query_line(&db),
        r#"{"kind":"repo_structure","snapshot_id":"fixture","ecosystems":[],"walk_complete":true}"#
            .to_string(),
    ]);
    let (doc, _) = fx.assert_deterministic();
    assert_eq!(doc["structure"].as_array().unwrap().len(), 6, "{doc}");
}
