//! The wire behavior of the plugin `HttpFetcher` against a loopback mock
//! (po-av01j.236, ureq 2 -> 3): which requests carry credentials, which
//! response headers the tarball download reads, that an error status is an
//! error, and that proxy variables in the environment are not read.
//! This file holds one test because it owns the process environment.

use rvl_skills::fetch::{Fetcher, HttpFetcher};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Record `"METHOD /path"` and the Authorization header of each request.
fn serve(seen: &Seen, version_status: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::clone(seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = handle(stream, &seen, version_status);
        }
    });
    base
}

fn handle(stream: std::net::TcpStream, seen: &Seen, version_status: &str) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut auth = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("authorization") {
                auth = Some(v.trim().to_string());
            }
        }
    }
    seen.lock()
        .unwrap()
        .push((format!("{method} {path}"), auth));

    let (status, extra, body) = match path.as_str() {
        "/api/v1/plugin" => (
            version_status,
            "",
            r#"{"version":"0.2.0+abc","semver":"0.2.0"}"#.to_string(),
        ),
        "/api/v1/plugin/signing-key" => (
            "200 OK",
            "",
            format!(r#"{{"algorithm":"EdDSA","public_key":"{KEY_HEX}"}}"#),
        ),
        "/api/v1/plugin/editors" => (
            "200 OK",
            "",
            r#"[{"name":"claude","displayName":"Claude Code","tier":1}]"#.to_string(),
        ),
        "/api/v1/plugin/download?editor=claude" => (
            "200 OK",
            "X-Plugin-SemVer: 0.2.0+abc\r\nX-Checksum: sha256:feed\r\n",
            "tarball-bytes".to_string(),
        ),
        _ => ("404 Not Found", "", String::new()),
    };
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn http_fetcher_wire_behavior() {
    // A proxy that refuses every connection. A client that reads these
    // variables cannot reach the mock.
    let proxy = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let fetcher = HttpFetcher {
        // The trailing slash must not make a double slash in the path.
        base_url: format!("{}/", serve(&seen, "200 OK")),
        org_key: "org-key".into(),
    };

    assert_eq!(fetcher.fetch_version().expect("version"), "0.2.0");
    let key = fetcher.fetch_signing_key().expect("signing key");
    assert_eq!(key[..4], [0, 1, 2, 3]);
    let editors = fetcher.fetch_editors().expect("editors");
    assert_eq!(editors[0].name, "claude");
    let tarball = fetcher.fetch_tarball("claude").expect("tarball");
    assert_eq!(tarball.bytes, b"tarball-bytes");
    assert_eq!(tarball.version, "0.2.0");
    assert_eq!(tarball.checksum.as_deref(), Some("sha256:feed"));

    // GET only; credentials go to the two authenticated endpoints only.
    let bearer = Some("Bearer org-key".to_string());
    assert_eq!(
        *seen.lock().unwrap(),
        [
            ("GET /api/v1/plugin".to_string(), bearer.clone()),
            ("GET /api/v1/plugin/signing-key".to_string(), None),
            ("GET /api/v1/plugin/editors".to_string(), None),
            (
                "GET /api/v1/plugin/download?editor=claude".to_string(),
                bearer
            ),
        ]
    );

    // An error status is an error, not a body to parse.
    let failing = HttpFetcher {
        base_url: serve(&seen, "500 Internal Server Error"),
        org_key: "org-key".into(),
    };
    let err = failing.fetch_version().unwrap_err().to_string();
    assert!(err.contains("500"), "{err}");
    // An endpoint that is not there is an error too.
    assert!(failing.fetch_tarball("vim").is_err());
}
