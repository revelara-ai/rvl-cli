//! A FIRST SCAN SYNCS. A CI runner starts with no spec cache, and a scan
//! with none cannot judge anything, so the reference CI job used to fail on
//! its first run with "no spec cache tier loadable". With network access the
//! scan now syncs before it loads; offline it says why it did not, and a scan
//! that needs the cache exits 1 naming `rvl sync`.
//!
//! The server is local: it serves an OSS artifact signed with a fresh key,
//! which a debug build trusts through `RVL_TEST_KEYSET_HEX`.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::Command;

/// Mirrors `TEST_KEYSET_ENV` in `crates/rvl/src/keyset.rs`.
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

/// An OSS envelope signed with a fresh key: the bytes, the base64 signature
/// and the verifying key, hex encoded.
fn signed_oss_artifact() -> (Vec<u8>, String, String) {
    use base64::Engine;
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": format!("{}.1", rvl_cache::today_utc()),
        "specs": {"apis": [], "configs": []},
    }))
    .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(signing.sign(&bytes).to_bytes());
    (bytes, sig, hex::encode(signing.verifying_key().to_bytes()))
}

/// A server for the OSS tier's two paths, and 404 for anything else.
fn serve(bytes: Vec<u8>, sig: String) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for mut conn in listener.incoming().flatten() {
            let mut buf = [0u8; 4096];
            let n = conn.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]);
            let path = request.split_whitespace().nth(1).unwrap_or_default();
            let (status, body): (&str, &[u8]) = match path {
                "/api/v1/scanner/spec-cache/oss" => ("200 OK", &bytes),
                "/api/v1/scanner/spec-cache/oss.sig" => ("200 OK", sig.as_bytes()),
                _ => ("404 Not Found", b""),
            };
            let _ = write!(
                conn,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = conn.write_all(body);
        }
    });
    url
}

/// `rvl scan` on an empty prebuilt packet stream with an empty cache.
fn scan(home: &Path, api: &str) -> Command {
    let packets = home.join("packets.jsonl");
    std::fs::write(&packets, "").unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    c.arg("scan")
        .arg("--retrieved")
        .arg(packets)
        .env("HOME", home)
        .env("RVL_CACHE_DIR", home.join("cache"))
        .env("RVL_API_URL", api);
    for k in [
        "RVL_OFFLINE",
        "RVL_SPEC_VERSION",
        "RVL_API_KEY",
        TEST_KEYSET_ENV,
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

#[cfg(debug_assertions)]
#[test]
fn an_empty_cache_scan_syncs_first_and_then_scans() {
    let (bytes, sig, key) = signed_oss_artifact();
    let api = serve(bytes, sig);
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let out = scan(home, &api)
        .env(TEST_KEYSET_ENV, key)
        // CI turns the background check off; it must not turn this sync off.
        .env("CI", "true")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("running 'rvl sync' before the first scan"),
        "{stderr}"
    );
    assert!(stderr.contains("oss tier installed"), "{stderr}");
    assert!(
        home.join("cache/oss/current/specs.json").is_file(),
        "the sync must have installed the OSS tier"
    );

    // The second scan finds the cache and does not sync again.
    let again = scan(home, &api).env("CI", "true").output().unwrap();
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(!stderr.contains("before the first scan"), "{stderr}");
}

#[test]
fn an_offline_empty_cache_scan_exits_1_and_names_rvl_sync() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    // Nothing listens here, and offline nothing may try.
    let out = scan(home, "http://127.0.0.1:9")
        .env("RVL_OFFLINE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("no spec cache is installed and RVL_OFFLINE is set"),
        "{stderr}"
    );
    assert!(stderr.contains("run 'rvl sync'"), "{stderr}");
}
