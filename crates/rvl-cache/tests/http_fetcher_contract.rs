//! The wire behavior of the two HTTP fetchers that a major change of the
//! HTTP crate can move without a compile error (po-av01j.236, ureq 2 -> 3).
//! This file holds one test because it owns the process environment.

use rvl_cache::{Fetched, Fetcher, HttpFetcher, OssHttpFetcher};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

type Seen = Arc<Mutex<Vec<(String, Vec<(String, String)>)>>>;

/// Serve `artifact` at any path and `sig` at any path that ends in `.sig`.
/// Record the path and the request headers (names in lower case).
fn serve(seen: &Seen) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::clone(seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let _ = handle(stream, &seen);
        }
    });
    base
}

fn handle(stream: std::net::TcpStream, seen: &Seen) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let body = if path.ends_with(".sig") {
        "c2lnbmF0dXJl"
    } else {
        "artifact-bytes"
    };
    seen.lock().unwrap().push((path, headers));
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[test]
fn fetchers_ignore_proxy_env_and_send_the_same_headers() {
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
    let base = serve(&seen);

    let commercial = HttpFetcher {
        // The trailing slash must not make a double slash in the path.
        base_url: format!("{base}/"),
        org_key: "org-key".into(),
    };
    let Fetched::New { bytes, sig_b64 } = commercial.fetch(Some("abc123")).expect("fetch") else {
        panic!("a 200 must be Fetched::New");
    };
    assert_eq!(bytes, b"artifact-bytes");
    assert_eq!(sig_b64, "c2lnbmF0dXJl");

    let oss = OssHttpFetcher {
        base_url: base.clone(),
    };
    let Fetched::New { bytes, sig_b64 } = oss.fetch(None).expect("fetch") else {
        panic!("a 200 must be Fetched::New");
    };
    assert_eq!(bytes, b"artifact-bytes");
    assert_eq!(sig_b64, "c2lnbmF0dXJl");

    let recorded = seen.lock().unwrap().clone();
    let paths: Vec<&str> = recorded.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/api/v1/scanner/spec-cache",
            "/api/v1/scanner/spec-cache.sig",
            "/api/v1/scanner/spec-cache/oss",
            "/api/v1/scanner/spec-cache/oss.sig",
        ]
    );
    // Commercial: bearer auth on both requests, the hash only on the artifact.
    assert_eq!(
        header(&recorded[0].1, "authorization"),
        Some("Bearer org-key")
    );
    assert_eq!(header(&recorded[0].1, "if-none-match"), Some("\"abc123\""));
    assert_eq!(
        header(&recorded[1].1, "authorization"),
        Some("Bearer org-key")
    );
    assert_eq!(header(&recorded[1].1, "if-none-match"), None);
    // OSS: no credentials, and no condition when there is no current hash.
    assert_eq!(header(&recorded[2].1, "authorization"), None);
    assert_eq!(header(&recorded[2].1, "if-none-match"), None);
    assert_eq!(header(&recorded[3].1, "authorization"), None);
}
