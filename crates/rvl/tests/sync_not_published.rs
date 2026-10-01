//! `rvl sync` SAYS WHEN THE SERVER HAS NEVER PUBLISHED (po-gcn3q).
//!
//! A 404 from the spec-cache endpoint used to print the same "fetch failed"
//! line as a dead network, so a user could not tell "retry later" from
//! "nothing exists to fetch".

use std::io::{Read, Write};
use std::process::Command;

/// A loopback server that answers every request with `status` and an empty
/// body. Returns its base URL.
fn serve_status(status: &'static str) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    base
}

fn sync_against(base: &str) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_rvl"))
        .arg("sync")
        .env("HOME", home.path())
        .env("RVL_CACHE_DIR", home.path().join("cache"))
        .env("RVL_API_URL", base)
        .env("RVL_API_KEY", "test-key")
        .env_remove("RVL_OFFLINE")
        .output()
        .expect("running rvl sync")
}

#[test]
fn sync_names_a_404_as_never_published_for_both_tiers() {
    let base = serve_status("404 Not Found");
    let out = sync_against(&base);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "an explicit sync that refreshed nothing must exit nonzero"
    );
    assert!(!stderr.contains("fetch failed"), "{stderr}");
    for path in [
        "/api/v1/scanner/spec-cache/oss",
        "/api/v1/scanner/spec-cache:",
    ] {
        assert!(
            stderr.contains(&format!("{base}{path}")),
            "stderr must name {path}: {stderr}"
        );
    }
    assert_eq!(
        stderr.matches("has not published a spec cache").count(),
        2,
        "{stderr}"
    );
}

#[test]
fn sync_still_says_fetch_failed_for_a_server_error() {
    let out = sync_against(&serve_status("500 Internal Server Error"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("fetch failed"), "{stderr}");
    assert!(!stderr.contains("has not published"), "{stderr}");
}
