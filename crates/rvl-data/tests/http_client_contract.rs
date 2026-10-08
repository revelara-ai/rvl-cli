//! The HTTP client behavior that a major change of the HTTP crate can move
//! without a compile error (po-av01j.236, ureq 2 -> 3): proxy variables in
//! the environment, the response size limit, a POST with no body, and the
//! body of an error response. The mock is a loopback server; no live calls.
//!
//! One test owns the process environment. The lockfile test reads no
//! environment, so the two can run in parallel.

use rvl_data::client::Client;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// More than the 10 MB default limit of ureq 3's `read_to_vec`.
const LARGE_BODY_LEN: usize = 11 * 1024 * 1024;

/// `"METHOD /path"`, the request body, and the Transfer-Encoding header.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>, Option<String>)>>>;

/// Serve canned responses by path and record each request. Returns the
/// base URL.
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
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    let mut transfer_encoding = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
            if k.trim().eq_ignore_ascii_case("transfer-encoding") {
                transfer_encoding = Some(v.trim().to_string());
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    seen.lock()
        .unwrap()
        .push((format!("{method} {path}"), body, transfer_encoding));

    let (status, resp_body): (&str, Vec<u8>) = match path.as_str() {
        "/large" => ("200 OK", vec![b'x'; LARGE_BODY_LEN]),
        "/plain-503" => ("503 Service Unavailable", b"upstream is down".to_vec()),
        "/envelope-422" => (
            "422 Unprocessable Entity",
            br#"{"error":"invalid","message":"bad team"}"#.to_vec(),
        ),
        _ => ("200 OK", br#"{"ok":true}"#.to_vec()),
    };
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    )?;
    out.write_all(&resp_body)
}

/// An address that nothing listens on: bind, read the address, drop.
fn dead_addr() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
}

#[test]
fn client_ignores_proxy_env_reads_large_bodies_and_keeps_error_bodies() {
    // A proxy that refuses every connection. A client that reads these
    // variables cannot reach the mock.
    let proxy = dead_addr();
    for var in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        std::env::set_var(var, &proxy);
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let base = serve(&seen);
    let client = Client {
        api_url: base.clone(),
        api_key: "pk_test_key".into(),
        org_id: None,
    };

    // The proxy variables are not read.
    let body = client
        .request("GET", &format!("{base}/ok"), None)
        .expect("a proxy variable in the environment must not change the route");
    assert_eq!(body, br#"{"ok":true}"#);

    // A response larger than 10 MB arrives complete.
    let body = client
        .request("GET", &format!("{base}/large"), None)
        .expect("a large response must not be an error");
    assert_eq!(body.len(), LARGE_BODY_LEN);

    // A POST with no body reaches the server as a POST with an empty body
    // of a known length. ureq 3 sends a request that has a body method and
    // no body as `Transfer-Encoding: chunked`, which the mock (and some
    // servers and proxies) do not read.
    client
        .request("POST", &format!("{base}/verify"), None)
        .expect("POST with no body");
    // A PATCH carries its body.
    client
        .request("PATCH", &format!("{base}/patch"), Some(b"{\"a\":1}"))
        .expect("PATCH with a body");
    let recorded = seen.lock().unwrap().clone();
    assert!(recorded.contains(&("POST /verify".to_string(), Vec::new(), None)));
    assert!(recorded.contains(&("PATCH /patch".to_string(), b"{\"a\":1}".to_vec(), None)));
    assert!(
        recorded.iter().all(|(_, _, te)| te.is_none()),
        "no request is chunked: {recorded:?}"
    );

    // The body of an error response reaches the message.
    let err = client
        .request("GET", &format!("{base}/plain-503"), None)
        .unwrap_err();
    assert_eq!(err, "server error (503): upstream is down");
    let err = client
        .request("POST", &format!("{base}/envelope-422"), Some(b"{}"))
        .unwrap_err();
    assert_eq!(err, "server error (422): invalid: bad team");

    // A dead server is a transport error, not a status error.
    let dead = dead_addr();
    let err = client
        .request("GET", &format!("{dead}/ok"), None)
        .unwrap_err();
    assert!(err.starts_with("request failed: "), "{err}");
    assert!(err.contains(&dead), "the message names the URL: {err}");
}

/// Two majors of the HTTP crate in one binary means two TLS stacks and two
/// sets of defaults. The workspace must resolve exactly one, major 3.
#[test]
fn the_workspace_resolves_one_ureq_and_it_is_major_3() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("read Cargo.lock");
    let versions: Vec<&str> = lock
        .split("[[package]]")
        .filter(|p| p.contains("\nname = \"ureq\"\n"))
        .filter_map(|p| p.lines().find_map(|l| l.strip_prefix("version = ")))
        .collect();
    assert_eq!(
        versions.len(),
        1,
        "ureq versions in Cargo.lock: {versions:?}"
    );
    assert!(versions[0].starts_with("\"3."), "{versions:?}");
}
