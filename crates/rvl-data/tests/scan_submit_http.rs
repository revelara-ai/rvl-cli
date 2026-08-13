//! Hermetic scan-submission tests against a mock HTTP backend: no live API
//! calls, ever. The mock speaks just enough HTTP/1.1 for ureq, serves a
//! scripted SEQUENCE of responses (so 429-then-200 retry paths are
//! deterministic), and records every request for assertions.

use rvl_data::client::Client;
use rvl_data::scan_submit::{submit_scan, ScanRequest};
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One scripted response: status, extra headers, body.
type Scripted = (u16, Vec<(&'static str, &'static str)>, &'static str);

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    /// Serve `responses` in order, one per connection; after the script is
    /// exhausted every request gets 500. The accept-loop thread lives until
    /// the test process exits, which is fine for a test binary.
    fn start(responses: Vec<Scripted>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        std::thread::spawn(move || {
            let mut script = responses.into_iter();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let next = script.next().unwrap_or((500, vec![], "exhausted"));
                let _ = handle(stream, next, &reqs);
            }
        });
        MockServer { base_url, requests }
    }

    fn client(&self) -> Client {
        Client {
            api_url: self.base_url.clone(),
            api_key: "pk_test_key".into(),
            org_id: Some("org-uuid-1".into()),
        }
    }

    fn recorded(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

fn handle(
    stream: std::net::TcpStream,
    (status, extra_headers, resp_body): Scripted,
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

    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        429 => "Too Many Requests",
        _ => "Status",
    };
    let extras: String = extra_headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extras}Connection: close\r\n\r\n",
        resp_body.len()
    )?;
    out.write_all(resp_body.as_bytes())?;
    Ok(())
}

fn request_fixture() -> ScanRequest {
    let mut req: ScanRequest = serde_json::from_value(json!({
        "service": "checkout-api",
        "scan_type": "full",
        "scan_mode": "auto",
        "findings": [
            {"title": "Missing timeout", "category": "resilience",
             "likelihood": "high", "impact": "high", "risk_score": 61}
        ]
    }))
    .unwrap();
    req.metadata.scanner_id = "rvlscan/0.0.0-test".into();
    req
}

const HAPPY_RESPONSE: &str = r#"{
  "scan_id": "scan-123",
  "service": "checkout-api",
  "summary": {"total": 1, "created": 1, "updated": 0, "unchanged": 0,
              "critical": 0, "high": 1, "medium": 0, "low": 0},
  "findings": [
    {"risk_id": "uuid-1", "risk_code": "R-101", "title": "Missing timeout",
     "status": "created", "score": 61, "priority": "high"}
  ],
  "warnings": ["one server warning"],
  "timestamp": "2026-08-13T00:00:00Z",
  "effective_tolerance": {"tolerance_target": 25, "tolerance_headroom_pct": 20,
                          "strict_enforcement": false}
}"#;

#[test]
fn happy_path_posts_scan_and_parses_response() {
    let server = MockServer::start(vec![(200, vec![], HAPPY_RESPONSE)]);
    let mut req = request_fixture();
    let resp = submit_scan(&server.client(), &mut req, Duration::from_secs(5)).expect("2xx");

    assert_eq!(resp.scan_id, "scan-123");
    assert_eq!(resp.service, "checkout-api");
    assert_eq!(resp.summary.total, 1);
    assert_eq!(resp.summary.created, 1);
    let findings = resp.findings.as_ref().unwrap();
    assert_eq!(findings[0].risk_code, "R-101");
    assert_eq!(findings[0].status, "created");
    let et = resp.effective_tolerance.as_ref().unwrap();
    assert_eq!(et.tolerance_target, 25);
    assert_eq!(resp.warnings, vec!["one server warning".to_string()]);

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/risks/scan");
    assert_eq!(reqs[0].header("Content-Type"), Some("application/json"));
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
    assert_eq!(reqs[0].header("X-Organization-ID"), Some("org-uuid-1"));
    let body = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(
        body.starts_with(r#"{"service":"checkout-api","scan_type":"full""#),
        "{body}"
    );
    assert!(
        body.contains(r#""idempotency_key":""#),
        "derived key on the wire: {body}"
    );
}

#[test]
fn rate_limit_retries_once_honoring_retry_after() {
    let server = MockServer::start(vec![
        (429, vec![("Retry-After", "1")], "{}"),
        (200, vec![], HAPPY_RESPONSE),
    ]);
    let mut req = request_fixture();
    let start = std::time::Instant::now();
    let resp = submit_scan(&server.client(), &mut req, Duration::from_secs(5))
        .expect("429 then 200 must succeed");
    assert_eq!(resp.scan_id, "scan-123");
    assert!(
        start.elapsed() >= Duration::from_secs(1),
        "the declared Retry-After delay must be honored"
    );

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 2, "exactly one retry");
    assert_eq!(
        reqs[0].body, reqs[1].body,
        "the retry must carry the identical body (same idempotency key)"
    );
}

#[test]
fn second_rate_limit_is_a_hard_error() {
    let server = MockServer::start(vec![
        (429, vec![("Retry-After", "1")], "{}"),
        (
            429,
            vec![("Retry-After", "1")],
            r#"{"message":"slow down"}"#,
        ),
    ]);
    let mut req = request_fixture();
    let err = submit_scan(&server.client(), &mut req, Duration::from_secs(5)).unwrap_err();
    assert!(err.contains("server error (429"), "{err}");
    assert_eq!(server.recorded().len(), 2, "only one retry, ever");
}

#[test]
fn auth_failure_names_the_api_url_and_login_hint() {
    let server = MockServer::start(vec![(401, vec![], "{}")]);
    let mut req = request_fixture();
    let err = submit_scan(&server.client(), &mut req, Duration::from_secs(5)).unwrap_err();
    assert_eq!(
        err,
        format!(
            "authentication failed against {} - run 'rvlscan login' to reconfigure (status 401)",
            server.base_url
        )
    );
}

#[test]
fn server_error_envelope_is_surfaced_verbatim() {
    let server = MockServer::start(vec![(
        400,
        vec![],
        r#"{"code":"validation_failed","message":"scan_type must be one of full|incremental|targeted"}"#,
    )]);
    let mut req = request_fixture();
    let err = submit_scan(&server.client(), &mut req, Duration::from_secs(5)).unwrap_err();
    assert_eq!(
        err,
        format!(
            "server error (400 validation_failed) from {}: scan_type must be one of full|incremental|targeted",
            server.base_url
        )
    );
}
