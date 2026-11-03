//! A first scan on a machine with no spec cache syncs before it loads, and
//! offline its refusal names the sync to run. A fresh CI runner is
//! this machine on every run.
//!
//! The API is a local server that serves an OSS tier signed by a test key,
//! which a debug build trusts through `RVL_TEST_KEYSET_HEX`.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Mirrors `TEST_KEYSET_ENV` in `crates/rvl/src/keyset.rs`.
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

const OSS_PATH: &str = "/api/v1/scanner/spec-cache/oss";

/// An OSS envelope signed by a fresh key: the bytes, the signature and the
/// public half, hex encoded.
fn signed_oss_tier() -> (Vec<u8>, String, String) {
    use base64::Engine;
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": format!("{}.1", rvl_cache::today_utc()),
        "specs": {"server": [], "emissions": [], "config_keys": []},
    }))
    .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(signing.sign(&bytes).to_bytes());
    (bytes, sig, hex::encode(signing.verifying_key().to_bytes()))
}

/// A server that serves the OSS artifact and its signature, and 404s the
/// rest. Returns its base URL.
fn serve(bytes: Vec<u8>, sig: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or_default();
            let body: Option<&[u8]> = if path == OSS_PATH {
                Some(&bytes)
            } else if path == format!("{OSS_PATH}.sig") {
                Some(sig.as_bytes())
            } else {
                None
            };
            let _ = match body {
                Some(b) => {
                    let _ = write!(
                        conn,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    );
                    conn.write_all(b)
                }
                None => conn.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                ),
            };
        }
    });
    base
}

/// `rvl scan` of an empty packet stream with the cache and HOME under `home`.
fn scan(home: &Path) -> Command {
    let packets = home.join("packets.jsonl");
    std::fs::write(&packets, "").unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    c.arg("scan")
        .arg("--retrieved")
        .arg(&packets)
        .env("HOME", home)
        .env("RVL_CACHE_DIR", cache(home));
    for k in [
        "RVL_OFFLINE",
        "RVL_SPEC_VERSION",
        "RVL_API_KEY",
        "RVL_API_URL",
        "CI",
        TEST_KEYSET_ENV,
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

fn cache(home: &Path) -> PathBuf {
    home.join("cache")
}

#[cfg(debug_assertions)]
#[test]
fn a_scan_on_an_empty_cache_syncs_first_and_then_scans() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let (bytes, sig, key) = signed_oss_tier();
    let base = serve(bytes, sig);

    let out = scan(home)
        .env("RVL_API_URL", &base)
        .env(TEST_KEYSET_ENV, &key)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("no spec cache is installed: running 'rvl sync' before the first scan"),
        "{stderr}"
    );
    assert!(stderr.contains("oss tier installed"), "{stderr}");
    let oss = rvl_cache::CacheStore::open(&cache(home).join(rvl_cache::OSS_DIR)).unwrap();
    assert!(!oss.is_empty(), "the sync must have installed the OSS tier");

    // The cache is installed now: the next scan loads it and fetches nothing
    // first, with the server gone.
    let again = scan(home)
        .env("RVL_API_URL", "http://127.0.0.1:9")
        .env("RVL_OFFLINE", "1")
        .env(TEST_KEYSET_ENV, &key)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert_eq!(again.status.code(), Some(0), "{stderr}");
    assert!(!stderr.contains("before the first scan"), "{stderr}");
}

#[test]
fn an_offline_scan_on_an_empty_cache_names_the_sync_to_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let out = scan(home)
        // Nothing listens here; offline must not try.
        .env("RVL_API_URL", "http://127.0.0.1:9")
        .env("RVL_OFFLINE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("no spec cache tier loadable"), "{stderr}");
    assert!(
        stderr.contains(
            "RVL_OFFLINE is set, so this scan did not sync first: run 'rvl sync' \
             with network access"
        ),
        "{stderr}"
    );
    assert!(!stderr.contains("before the first scan"), "{stderr}");
}
