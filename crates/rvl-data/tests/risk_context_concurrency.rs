//! Hermetic proof that `rvl risk context` issues its three fetches
//! CONCURRENTLY, the way rvl-cli's Go implementation does with a
//! sync.WaitGroup (po-av01j.200), and that concurrency changes nothing about
//! the result: the same composed body, and the same partial-failure behaviour
//! no matter which reply lands first.
//!
//! Unlike the mock in `http_parity.rs`, this one serves every connection on
//! its own thread and holds each response open for `DELAY`, so a sequential
//! implementation is distinguishable from a concurrent one by wall clock and
//! by whether the three in-flight windows overlap.

use rvl_data::client::Client;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-request server-side delay. Sequential fetches cost 3x this; concurrent
/// fetches cost ~1x. Large enough to swamp scheduling jitter, small enough to
/// keep the test fast.
const DELAY: Duration = Duration::from_millis(200);

/// An exact "METHOD /path?query" route -> (status, body).
type Routes = Vec<(&'static str, u16, &'static str)>;

/// When a request entered and left the handler, relative to server start.
#[derive(Debug, Clone)]
struct Window {
    line: String,
    start: Duration,
    end: Duration,
}

struct MockServer {
    base_url: String,
    windows: Arc<Mutex<Vec<Window>>>,
}

impl MockServer {
    fn start(routes: Routes) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let windows: Arc<Mutex<Vec<Window>>> = Arc::new(Mutex::new(Vec::new()));
        let wins = Arc::clone(&windows);
        let t0 = Instant::now();
        std::thread::spawn(move || {
            let routes = Arc::new(routes);
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                // One thread per connection: the server must never be the
                // thing that serializes the client.
                let routes = Arc::clone(&routes);
                let wins = Arc::clone(&wins);
                std::thread::spawn(move || {
                    let _ = handle(stream, &routes, &wins, t0);
                });
            }
        });
        MockServer { base_url, windows }
    }

    fn client(&self) -> Client {
        Client {
            api_url: self.base_url.clone(),
            api_key: "pk_test_key".into(),
            org_id: Some("org-uuid-1".into()),
        }
    }

    fn windows(&self) -> Vec<Window> {
        self.windows.lock().unwrap().clone()
    }
}

fn handle(
    stream: std::net::TcpStream,
    routes: &Routes,
    wins: &Arc<Mutex<Vec<Window>>>,
    t0: Instant,
) -> std::io::Result<()> {
    let start = t0.elapsed();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end().to_string();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
    }

    let key = format!("{method} {path}");
    let (status, body) = routes
        .iter()
        .find(|(route, _, _)| *route == key)
        .map(|(_, s, b)| (*s, *b))
        .unwrap_or((404, ""));

    // Hold the request open so overlap is observable.
    std::thread::sleep(DELAY);

    // Record BEFORE writing: the client cannot observe the response until the
    // window is in the log, so the caller never races the recording.
    wins.lock().unwrap().push(Window {
        line: key,
        start,
        end: t0.elapsed(),
    });

    let mut stream = stream;
    let resp = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()?;
    Ok(())
}

const DETAIL: &str = r#"{"risk_code":"R-001","score":10}"#;
const CONTEXT: &str = r#"{"risk":{"risk_code":"R-001"},"controls":[]}"#;
const STATS: &str =
    r#"{"coverage":{"total_controls":10,"assessed_controls":5,"coverage_percentage":50.0}}"#;

fn all_routes() -> Routes {
    vec![
        ("GET /api/v1/risks/R-001", 200, DETAIL),
        ("GET /api/v1/risks/R-001/context", 200, CONTEXT),
        ("GET /api/v1/risks/stats", 200, STATS),
    ]
}

/// The composed body the three routes above must produce, top-level keys
/// sorted the way Go re-marshals a map: controls, coverage_gap, detail, risk.
const WANT_JSON: &str = "{\n  \"controls\": [],\n  \"coverage_gap\": {\n    \"total_controls\": 10,\n    \"assessed_controls\": 5,\n    \"coverage_percentage\": 50\n  },\n  \"detail\": {\n    \"risk_code\": \"R-001\",\n    \"score\": 10\n  },\n  \"risk\": {\n    \"risk_code\": \"R-001\"\n  }\n}\n";

#[test]
fn risk_context_fetches_all_three_endpoints_concurrently() {
    let server = MockServer::start(all_routes());

    let started = Instant::now();
    let out = rvl_data::risk::context_output(&server.client(), "R-001", Some("json")).unwrap();
    let elapsed = started.elapsed();

    // Output is unaffected by the concurrency.
    assert_eq!(out, WANT_JSON);

    let windows = server.windows();
    assert_eq!(windows.len(), 3, "expected 3 requests, got {windows:?}");
    let mut lines: Vec<&str> = windows.iter().map(|w| w.line.as_str()).collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        vec![
            "GET /api/v1/risks/R-001",
            "GET /api/v1/risks/R-001/context",
            "GET /api/v1/risks/stats",
        ]
    );

    // All three were in flight at the same instant: the last one to start did
    // so before the first one finished. Sequential fetching cannot do this.
    let last_start = windows.iter().map(|w| w.start).max().unwrap();
    let first_end = windows.iter().map(|w| w.end).min().unwrap();
    assert!(
        last_start < first_end,
        "requests did not overlap (last start {last_start:?} >= first end {first_end:?}): {windows:?}"
    );

    // And the wall clock reflects it: ~1x DELAY, not ~3x. The bound is
    // deliberately loose so this is a concurrency assertion, not a benchmark.
    assert!(
        elapsed < DELAY * 2,
        "risk context took {elapsed:?}, expected well under {:?} (3 sequential fetches would be ~{:?})",
        DELAY * 2,
        DELAY * 3
    );
}

/// The `--format=json` composition sorts keys itself (a BTreeMap, matching
/// Go's map re-marshal), so the order the three replies arrive in must not
/// leak into the output. Concurrency makes arrival order nondeterministic;
/// this pins the key order regardless.
#[test]
fn json_key_order_is_independent_of_reply_order() {
    let server = MockServer::start(all_routes());
    let out = rvl_data::risk::context_output(&server.client(), "R-001", Some("json")).unwrap();
    assert_eq!(out, WANT_JSON);

    let keys: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("  \""))
        .map(|l| l.trim_start().split('"').nth(1).unwrap())
        .collect();
    assert_eq!(keys, vec!["controls", "coverage_gap", "detail", "risk"]);
}

/// Matching Go: stats is best-effort. Its failure is discarded (`_ = statsErr`)
/// and the command still renders, minus the coverage section.
#[test]
fn stats_failure_is_tolerated_and_coverage_is_dropped() {
    let server = MockServer::start(vec![
        ("GET /api/v1/risks/R-001", 200, DETAIL),
        ("GET /api/v1/risks/R-001/context", 200, CONTEXT),
        // no stats route -> 404
    ]);
    let out = rvl_data::risk::context_output(&server.client(), "R-001", Some("json")).unwrap();
    assert!(!out.contains("coverage_gap"), "{out}");
    assert!(out.contains("\"detail\""), "{out}");
    assert!(out.contains("\"risk\""), "{out}");
}

/// Matching Go: the command only fails when BOTH detail and context fail, and
/// the message it reports is the DETAIL error, never whichever error happened
/// to arrive first.
#[test]
fn both_failing_reports_the_detail_error_not_the_first_to_arrive() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/risks/R-001",
            500,
            r#"{"error":"detail","message":"detail boom"}"#,
        ),
        (
            "GET /api/v1/risks/R-001/context",
            500,
            r#"{"error":"ctx","message":"ctx boom"}"#,
        ),
        ("GET /api/v1/risks/stats", 200, STATS),
    ]);
    let f = rvl_data::risk::context_output(&server.client(), "R-001", None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error fetching risk context: server error (500): detail: detail boom"
    );
}

/// Matching Go: one of the pair failing is survivable. Detail alone still
/// renders, and context alone still renders.
#[test]
fn a_single_failure_of_the_pair_still_renders() {
    let detail_only = MockServer::start(vec![
        ("GET /api/v1/risks/R-001", 200, DETAIL),
        ("GET /api/v1/risks/stats", 200, STATS),
    ]);
    let out = rvl_data::risk::context_output(&detail_only.client(), "R-001", None).unwrap();
    assert!(out.contains("R-001"), "{out}");

    let context_only = MockServer::start(vec![
        ("GET /api/v1/risks/R-001/context", 200, CONTEXT),
        ("GET /api/v1/risks/stats", 200, STATS),
    ]);
    let out = rvl_data::risk::context_output(&context_only.client(), "R-001", None).unwrap();
    assert!(out.contains("R-001"), "{out}");
}
