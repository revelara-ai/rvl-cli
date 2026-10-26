//! The decision-model lane end to end: `rvl model sync` against a mock API
//! serving a signed fixture manifest and the tiny fixture model (with a cell
//! head), then `rvl scan` deciding a served frame question on an undecided
//! site, offline, from the cached bundle.
//!
//! The spec cache and the manifest are signed with a key minted here and
//! trusted through the debug-only `RVL_TEST_KEYSET_HEX` seam. The scans need
//! ONNX Runtime: the one `RVL_ONNXRUNTIME` names, or the pinned library
//! `ci/fetch-onnxruntime.sh` lays out beside the binary; without either they
//! skip through `rvl-testgate`, which fails them under
//! `RVLSCAN_REQUIRE_ENGINES` (CI). Sync and its refusals need no runtime.

#![cfg(debug_assertions)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use ed25519_dalek::Signer;

/// Mirrors `TEST_KEYSET_ENV` in `crates/rvl/src/keyset.rs`.
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

const BLOBS: &str = "/api/v1/scanner/model/blobs/";

/// RC-019 is served and asks a question whose words the tiny model reads as
/// a violation; RC-022 is withheld; RC-030 is a config frame the call-site
/// lane does not ask.
const SPECS: &str = r#"{"apis":[],"frames":[
  {"control":"RC-019","version":"v1","habitat":"call_site","class_markers":["mystery"],
   "question":"Does the call block and wait forever?","cells":[
     {"id":"M1","kind":"manifestation","verdict":"violates","definition":"No deadline on the call"},
     {"id":"M2","kind":"manifestation","verdict":"violates","definition":"A deadline nobody enforces"},
     {"id":"S1","kind":"satisfying","verdict":"satisfies","definition":"A deadline from the caller"},
     {"id":"C1","kind":"context","verdict":"not_applicable","definition":"Test or mock code"}]},
  {"control":"RC-022","version":"v2","habitat":"call_site","question":"Is it retried?",
   "cells":[{"id":"M1","kind":"manifestation","verdict":"violates","definition":"No retry"}]},
  {"control":"RC-030","version":"v1","habitat":"config","question":"Is it set?","cells":[]}
]}"#;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rvl-model/testdata/tiny-classifier")
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    repo: PathBuf,
    retrieved: PathBuf,
    signing: ed25519_dalek::SigningKey,
    key_hex: String,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let repo = root.join("repo");
        std::fs::create_dir_all(repo.join("svc")).unwrap();
        std::fs::write(
            repo.join(".revelara.yaml"),
            "scanner:\n  decision_model: on\n  model_threads: 1\n",
        )
        .unwrap();
        std::fs::write(
            repo.join("svc/a.go"),
            "package svc\n\nfunc m() { u.Mystery() }\n",
        )
        .unwrap();
        let retrieved = root.join("retrieved.jsonl");
        let line = serde_json::json!({
            "snapshot_id": "fixture",
            "file_path": repo.join("svc/a.go").to_str().unwrap(),
            "line_number": 3,
            "func": "Mystery",
            "client_type": "x.Unknown",
            "snippet": "u.Mystery()",
            "lang": "go",
        });
        std::fs::write(&retrieved, format!("{line}\n")).unwrap();
        let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
        let key_hex = hex::encode(signing.verifying_key().to_bytes());
        let fx = Fixture {
            _dir: dir,
            root,
            repo,
            retrieved,
            signing,
            key_hex,
        };
        fx.install_spec_cache();
        fx
    }

    fn sign(&self, bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signing.sign(bytes).to_bytes())
    }

    fn install_spec_cache(&self) {
        let version = format!("{}.1", rvl_cache::today_utc());
        let bytes =
            format!(r#"{{"schema":1,"content_version":"{version}","specs":{SPECS}}}"#).into_bytes();
        let keyset = rvl_cache::Keyset::from_hex(&[self.key_hex.as_str()]).unwrap();
        let store = rvl_cache::CacheStore::open(&self.root.join("cache")).unwrap();
        let outcome = store.install(&bytes, &self.sign(&bytes), &keyset);
        assert!(
            matches!(outcome, rvl_cache::SyncOutcome::Installed { .. }),
            "{outcome:?}"
        );
    }

    /// The fixture manifest and the blobs it names, by URL path.
    fn published(&self) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
        let mut files = Vec::new();
        let mut blobs = Vec::new();
        for name in ["model.onnx", "tokenizer.json", "cells.json"] {
            let bytes = std::fs::read(fixture_dir().join(name)).unwrap();
            let sha = sha256_hex(&bytes);
            files.push(serde_json::json!({"name": name, "sha256": sha, "size": bytes.len()}));
            blobs.push((format!("{BLOBS}{sha}"), bytes));
        }
        let manifest = serde_json::json!({
            "schema_version": 1,
            "model_id": "rvl-fixture/tiny-classifier",
            "weights_sha256": files[0]["sha256"],
            "layout": "compact",
            "max_len": 64,
            "temperature": 1.5,
            "gate": {"min_precision": 0.8, "max_ece": 0.05},
            "served_controls": [{"control": "RC-019", "precision": 0.88, "ece": 0.03}],
            "withheld_controls": [{"control": "RC-022", "precision": 0.61, "ece": 0.09}],
            "bundle_url": BLOBS,
            "files": files,
            "published_at": "2026-10-26T00:00:00Z",
            "a_later_field": {"ignored": true},
        });
        (serde_json::to_vec(&manifest).unwrap(), blobs)
    }

    fn rvl(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
        c.args(args)
            .env("RVL_CACHE_DIR", self.root.join("cache"))
            .env("HOME", self.root.join("home"))
            .env(TEST_KEYSET_ENV, &self.key_hex)
            .env("RVL_API_KEY", "pk_test")
            .env_remove("RVL_SPEC_VERSION")
            .env_remove("NO_COLOR")
            .env_remove("CI");
        c
    }

    fn model_sync(&self, base: &str) -> Output {
        self.rvl(&["model", "sync"])
            .env("RVL_API_URL", base)
            .env_remove("RVL_OFFLINE")
            .output()
            .unwrap()
    }

    /// One offline scan and its `--out` document.
    fn scan(&self, ort: &Path) -> (Output, Vec<u8>) {
        let out_path = self.root.join("scan.json");
        let _ = std::fs::remove_file(&out_path);
        let out = self
            .rvl(&["scan"])
            .arg(&self.repo)
            .arg("--retrieved")
            .arg(&self.retrieved)
            .arg("--out")
            .arg(&out_path)
            .args(["--color", "never"])
            .env("RVL_OFFLINE", "1")
            .env("RVL_ONNXRUNTIME", ort)
            .output()
            .unwrap();
        let doc = std::fs::read(&out_path).unwrap_or_else(|e| {
            panic!(
                "no --out document ({e}):\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out, doc)
    }
}

/// Serve the model endpoint with `signature`, and the blobs.
fn serve(manifest: Vec<u8>, signature: String, blobs: Vec<(String, Vec<u8>)>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let mut body = br#"{"manifest":"#.to_vec();
    body.extend_from_slice(&manifest);
    body.extend_from_slice(format!(r#","signature":"{signature}"}}"#).as_bytes());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let _ = reader.read_line(&mut request);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                    break;
                }
            }
            let path = request.split_whitespace().nth(1).unwrap_or("").to_string();
            let found = if path == "/api/v1/scanner/model" {
                Some(body.clone())
            } else {
                blobs
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map(|(_, b)| b.clone())
            };
            let (status, bytes) = match found {
                Some(b) => ("200 OK", b),
                None => ("404 Not Found", Vec::new()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(&bytes);
        }
    });
    base
}

/// The ONNX Runtime library for the scans, or `None` after a SKIP line.
fn runtime(test: &str) -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("RVL_ONNXRUNTIME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let beside = Path::new(env!("CARGO_BIN_EXE_rvl"))
        .parent()
        .unwrap()
        .join("onnxruntime");
    if beside.is_dir() {
        return Some(beside);
    }
    rvl_testgate::skip(
        test,
        format_args!(
            "no ONNX Runtime: run ci/fetch-onnxruntime.sh <host-triple> target/debug, or set \
             RVL_ONNXRUNTIME"
        ),
    );
    None
}

fn text(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn a_served_control_is_decided_offline_from_the_synced_bundle() {
    let fx = Fixture::new();
    let (manifest, blobs) = fx.published();
    let sig = fx.sign(&manifest);
    let synced = fx.model_sync(&serve(manifest, sig, blobs));
    assert!(synced.status.success(), "{}", text(&synced));
    assert!(
        text(&synced).contains("installed decision model rvl-fixture/tiny-classifier"),
        "{}",
        text(&synced)
    );

    let Some(ort) = runtime("a_served_control_is_decided_offline_from_the_synced_bundle") else {
        return;
    };
    let (first, doc) = fx.scan(&ort);
    let (second, again) = fx.scan(&ort);
    let out = text(&first);
    assert!(
        [0, 3].contains(&first.status.code().unwrap_or(-1)),
        "the scan did not run:\n{out}"
    );
    assert_eq!(first.status.code(), second.status.code());
    assert!(doc == again, "two scans wrote different --out bytes");

    let doc: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    let model = &doc["decision_model"];
    assert_eq!(model["not_run"], serde_json::Value::Null, "{model}");
    assert_eq!(model["model_id"], "rvl-fixture/tiny-classifier");
    let digest = format!(
        "sha256:{}",
        sha256_hex(&std::fs::read(fixture_dir().join("model.onnx")).unwrap())
    );
    assert_eq!(model["weights_digest"], digest.as_str());
    let sites = model["sites"].as_array().unwrap();
    assert_eq!(sites.len(), 1, "only the served control is asked: {model}");
    let d = &sites[0];
    assert_eq!(d["control"], "RC-019");
    assert_eq!(d["verdict"], "violates", "{d}");
    assert_eq!(d["cell"], "M1", "{d}");
    assert_eq!(d["reason"], "RC-019 violates, M1: No deadline on the call");
    assert_eq!(d["model_id"], "rvl-fixture/tiny-classifier");
    assert_eq!(d["weights_digest"], digest.as_str());
    assert!(d["confidence"].as_f64().unwrap() > 0.25, "{d}");
    assert_eq!(
        model["unserved"],
        serde_json::json!([{"control": "RC-022", "sites": 1}])
    );
    assert_eq!(model["withheld_controls"], serde_json::json!(["RC-022"]));

    // The violation is an advisory ladder row; the scan's gate is untouched.
    let row = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["class"] == "model.RC-019")
        .unwrap_or_else(|| panic!("no model finding: {doc}"));
    assert_eq!(row["severity"], "advisory");
    assert_eq!(row["control"], "RC-019");
    assert!(
        out.contains("decision model abstains on controls it does not serve: RC-022 (1)"),
        "{out}"
    );
    assert!(
        out.contains("RC-019 violates, M1: No deadline on the call"),
        "{out}"
    );

    // A cached file changed on disk is refused, not run.
    let cached = fx.root.join("cache/model/current/model.onnx");
    let mut bytes = std::fs::read(&cached).unwrap();
    bytes.push(0);
    std::fs::write(&cached, bytes).unwrap();
    let (tampered, doc) = fx.scan(&ort);
    let doc: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    assert!(
        doc["decision_model"]["not_run"]
            .as_str()
            .unwrap_or_default()
            .contains("not the one the manifest signs"),
        "{}",
        text(&tampered)
    );
    assert!(doc["decision_model"]["sites"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn a_bundle_with_a_bad_signature_is_refused() {
    let fx = Fixture::new();
    let (manifest, blobs) = fx.published();
    let other = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let forged = base64::engine::general_purpose::STANDARD.encode(other.sign(&manifest).to_bytes());
    let synced = fx.model_sync(&serve(manifest, forged, blobs));
    assert!(!synced.status.success(), "{}", text(&synced));
    assert!(
        text(&synced).contains("refused the published model bundle"),
        "{}",
        text(&synced)
    );
    assert!(
        !fx.root.join("cache/model/current").exists(),
        "nothing is cached from a refused bundle"
    );
}

#[test]
fn a_blob_that_does_not_hash_to_its_listed_digest_is_refused() {
    let fx = Fixture::new();
    let (manifest, mut blobs) = fx.published();
    blobs[1].1.push(b'\n');
    let sig = fx.sign(&manifest);
    let synced = fx.model_sync(&serve(manifest, sig, blobs));
    assert!(!synced.status.success(), "{}", text(&synced));
    assert!(
        text(&synced).contains("tokenizer.json does not hash to its listed sha256"),
        "{}",
        text(&synced)
    );
    assert!(!fx.root.join("cache/model/current").exists());
}

#[test]
fn without_a_cached_bundle_the_lane_says_how_to_get_one() {
    let fx = Fixture::new();
    // No runtime is needed: the lane stops before loading one.
    let (out, doc) = fx.scan(Path::new("/nonexistent"));
    let doc: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    let why = doc["decision_model"]["not_run"]
        .as_str()
        .unwrap_or_default();
    assert!(why.contains("model sync"), "{why}");
    assert!(
        text(&out).contains("decision model: not run"),
        "{}",
        text(&out)
    );
}
