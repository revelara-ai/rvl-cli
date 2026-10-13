//! Hermetic HTTP tests of `factor list`, `factor show` and `factor lookup`
//! against a mock backend: no live API calls, ever. The mock speaks just
//! enough HTTP/1.1 for ureq and records the path, the headers and the body
//! of every request.

use rvl_data::client::Client;
use rvl_data::factor::{list_output, lookup_output, show_output};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

/// A canned route: exact "METHOD /path?query" -> (status, body).
type Routes = Vec<(&'static str, u16, &'static str)>;

/// One request as the mock received it.
#[derive(Clone)]
struct Recorded {
    /// "METHOD /path?query".
    line: String,
    /// Each header as (name in lower case, value).
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    /// Serve `routes` on an ephemeral port. Unmatched requests get 404
    /// with an empty body. The accept loop thread lives until the test
    /// process exits, which is fine for a test binary.
    fn start(routes: Routes) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let _ = handle(stream, &routes, &reqs);
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

    /// Each request as "METHOD /path?query", in arrival order.
    fn recorded(&self) -> Vec<String> {
        self.full().into_iter().map(|r| r.line).collect()
    }

    /// Each request with its headers and its body, in arrival order.
    fn full(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

fn handle(
    stream: std::net::TcpStream,
    routes: &Routes,
    reqs: &Arc<Mutex<Vec<Recorded>>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            headers.push((name.to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    // A GET has no Content-Length, so its body is empty.
    let len = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;

    let key = format!("{method} {path}");
    let (status, resp_body) = routes
        .iter()
        .find(|(route, _, _)| *route == key)
        .map(|(_, s, b)| (*s, *b))
        .unwrap_or((404, ""));
    reqs.lock().unwrap().push(Recorded {
        line: key,
        headers,
        body,
    });

    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Status",
    };
    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    )?;
    out.write_all(resp_body.as_bytes())?;
    Ok(())
}

const LIST_BODY: &str = r#"{"factors":[{"code":"CF-0021","name":"Unbounded retry","definition":"A caller retries with no limit.","category":3,"category_name":"Load and capacity","tags":["retry"],"note":"","status":"active","code_addressable":true,"public_incidents":42,"public_organizations":17,"top10_slot":2},{"code":"CF-0107","name":"Stale runbook","definition":"The runbook is out of date.","category":6,"category_name":"Operations","tags":null,"note":"","status":"active","code_addressable":false,"public_incidents":5,"public_organizations":4}],"total":2,"edition":"2026.2"}"#;

const SHOW_BODY: &str = r#"{"factor":{"code":"CF-0021","name":"Unbounded retry","definition":"A caller retries with no limit.","category":3,"category_name":"Load and capacity","tags":["retry"],"note":"Split from CF-0019.","status":"active","code_addressable":true,"public_incidents":42,"public_organizations":17,"top10_slot":2},"edition":"2026.2","tell":"A loop around a network call with no attempt counter.","card_status":"evaluated","guards":[{"position":2,"text":"Add jitter to the backoff."},{"position":1,"text":"Cap the attempts."}],"quotes":[{"organization":"Example Cloud","reported_on":"2025-03-14","source_url":"https://example.com/postmortem","text":"Clients retried without backoff."}],"controls":[{"control_code":"RC-018","control_name":"Timeouts","relation":"mitigates","note":"","contested":false},{"control_code":"RC-012","control_name":"Retry budgets","relation":"prevents","note":"","contested":false},{"control_code":"RC-040","control_name":"Automatic retries","relation":"induces","note":"","contested":true},{"control_code":"RC-061","control_name":"Structured logs","relation":"detects","note":"","contested":false}],"related_risks":[{"id":"risk-uuid-1","risk_code":"R-014","title":"Retry storm on checkout","score":88,"status":"applicable","via_control":"RC-012"}]}"#;

#[test]
fn factor_list_and_show_json_are_raw_passthrough() {
    let server = MockServer::start(vec![
        ("GET /api/v1/causal-factors", 200, LIST_BODY),
        ("GET /api/v1/causal-factors/CF-0021", 200, SHOW_BODY),
    ]);
    let out = list_output(&server.client(), None, false, Some("json")).unwrap();
    assert_eq!(out, format!("{LIST_BODY}\n"));
    let out = show_output(&server.client(), "CF-0021", Some("json")).unwrap();
    assert_eq!(out, format!("{SHOW_BODY}\n"));
}

#[test]
fn factor_list_sends_category_and_top10() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/causal-factors?category=3&top10=true",
            200,
            LIST_BODY,
        ),
        ("GET /api/v1/causal-factors?category=6", 200, LIST_BODY),
        ("GET /api/v1/causal-factors?top10=true", 200, LIST_BODY),
        ("GET /api/v1/causal-factors", 200, LIST_BODY),
    ]);
    let client = server.client();
    let out = list_output(&client, Some(3), true, None).unwrap();
    list_output(&client, Some(6), false, None).unwrap();
    list_output(&client, None, true, None).unwrap();
    list_output(&client, None, false, None).unwrap();
    assert_eq!(
        server.recorded(),
        [
            "GET /api/v1/causal-factors?category=3&top10=true",
            "GET /api/v1/causal-factors?category=6",
            "GET /api/v1/causal-factors?top10=true",
            "GET /api/v1/causal-factors",
        ]
    );
    // The table has the edition, the count wording and one row per factor.
    assert!(out.contains("edition 2026.2"), "{out}");
    assert!(
        out.contains(
            "Public counts are reports that describe the condition. They are not a rate of occurrence."
        ),
        "{out}"
    );
    assert!(out.contains("CF-0021"), "{out}");
    assert!(out.contains("Stale runbook"), "{out}");
}

#[test]
fn factor_show_renders_quotes_controls_and_related_risks() {
    let server = MockServer::start(vec![("GET /api/v1/causal-factors/cf-0021", 200, SHOW_BODY)]);
    // The code goes to the server as the user typed it.
    let out = show_output(&server.client(), "cf-0021", None).unwrap();
    assert_eq!(server.recorded(), ["GET /api/v1/causal-factors/cf-0021"]);
    for want in [
        "Causal factor: CF-0021 - Unbounded retry",
        "Category: 3 (Load and capacity)",
        "Status: active",
        "A caller retries with no limit.",
        "Split from CF-0019.",
        "Reliability Top 10: #2 (edition 2026.2)",
        "42 public incident reports from 17 organizations",
        "Example Cloud, 2025-03-14",
        "Clients retried without backoff.",
        "https://example.com/postmortem",
        "RC-012  Retry budgets",
        "RC-040  Automatic retries (contested)",
        "A loop around a network call with no attempt counter.",
        "1. Cap the attempts.",
        "R-014",
        "Retry storm on checkout (via RC-012)",
    ] {
        assert!(out.contains(want), "missing {want:?} in:\n{out}");
    }
    // The relations come in a fixed order, whatever order the server used.
    let at = |s: &str| {
        out.find(s)
            .unwrap_or_else(|| panic!("missing {s:?} in:\n{out}"))
    };
    assert!(at("Prevents:") < at("Detects:"));
    assert!(at("Detects:") < at("Mitigates:"));
    assert!(at("Mitigates:") < at("Can induce:"));
}

#[test]
fn factor_show_of_a_merged_code_names_its_target() {
    let server = MockServer::start(vec![(
        "GET /api/v1/causal-factors/CF-0019",
        200,
        r#"{"factor":{"code":"CF-0019","name":"Retry without limit","definition":"Old entry.","category":3,"category_name":"Load and capacity","tags":[],"note":"","status":"merged","merged_into":"CF-0021","code_addressable":true,"public_incidents":0,"public_organizations":0},"edition":"2026.2","tell":"","card_status":"none","guards":[],"quotes":[],"controls":[],"related_risks":[]}"#,
    )]);
    let out = show_output(&server.client(), "CF-0019", None).unwrap();
    assert!(out.contains("Status: merged"), "{out}");
    assert!(out.contains("Merged into CF-0021"), "{out}");
}

#[test]
fn factor_show_404_names_the_code() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/causal-factors/CF-9999",
            404,
            r#"{"error":"not_found","message":"no causal factor has this code"}"#,
        ),
        (
            "GET /api/v1/causal-factors/CF-1",
            400,
            r#"{"error":"bad_request","message":"the code does not have the form CF-0001"}"#,
        ),
    ]);
    let f = show_output(&server.client(), "CF-9999", None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error: causal factor CF-9999 not found: server error (404): not_found: no causal factor has this code"
    );
    // A 400 prints the server message, with no "not found" claim.
    let f = show_output(&server.client(), "CF-1", None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error: server error (400): bad_request: the code does not have the form CF-0001"
    );
}

#[test]
fn factor_show_tolerates_null_lists() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/causal-factors/CF-0107",
            200,
            r#"{"factor":{"code":"CF-0107","name":"Stale runbook","definition":"The runbook is out of date.","category":6,"category_name":"Operations","tags":null,"note":"","status":"active","code_addressable":false,"public_incidents":5,"public_organizations":4},"edition":"2026.2","tell":"","card_status":"none","guards":null,"quotes":null,"controls":null,"related_risks":null}"#,
        ),
        (
            "GET /api/v1/causal-factors",
            200,
            r#"{"factors":null,"total":0,"edition":"2026.2"}"#,
        ),
    ]);
    let out = show_output(&server.client(), "CF-0107", None).unwrap();
    assert!(
        out.contains("Causal factor: CF-0107 - Stale runbook"),
        "{out}"
    );
    // A section with no rows is not printed.
    for absent in [
        "Quotes",
        "Controls",
        "Tell",
        "Guards",
        "Related risks",
        "Top 10",
    ] {
        assert!(!out.contains(absent), "unexpected {absent:?} in:\n{out}");
    }
    let out = list_output(&server.client(), None, false, None).unwrap();
    assert_eq!(out, "No causal factors found.\n");
}

const LOOKUP_PATH: &str = "POST /api/v1/causal-factors/lookup";

const LOOKUP_BODY: &str = r#"{"edition":"2026.2","factors":[{"code":"CF-0021","name":"Unbounded retry","category":3,"score":0.91,"public_incidents":42,"public_organizations":17,"top10_slot":2,"card":"CF-0021 Unbounded retry\nTell: a loop around a network call with no attempt counter.\nGuard: cap the attempts."},{"code":"CF-0107","name":"Stale runbook","category":6,"score":0.4,"public_incidents":5,"public_organizations":4,"definition":"The runbook is out of date."}]}"#;

#[test]
fn factor_lookup_sends_the_description_and_the_limit_in_a_post_body_with_no_other_key() {
    let server = MockServer::start(vec![(LOOKUP_PATH, 200, LOOKUP_BODY)]);
    let description = "add a retry around the \"payment\" call";
    lookup_output(&server.client(), description, 2, None).unwrap();

    let requests = server.full();
    assert_eq!(requests.len(), 1);
    let req = &requests[0];
    // The method and the path, with no query: the description is not in a URL.
    assert_eq!(req.line, LOOKUP_PATH);

    let body: serde_json::Value = serde_json::from_slice(&req.body).expect("a JSON body");
    let object = body.as_object().expect("a JSON object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["description", "limit"]);
    assert_eq!(body["description"], description);
    assert_eq!(body["limit"], 2);

    // The headers are the ones every data command sends, plus what the HTTP
    // library adds. None of them can carry a path or a repository name.
    let cwd = std::env::current_dir().unwrap();
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let repo_name = repo_root.file_name().unwrap().to_str().unwrap();
    for (name, value) in &req.headers {
        assert!(
            [
                "host",
                "content-type",
                "content-length",
                "authorization",
                "x-organization-id",
                "accept",
                "accept-encoding",
                "user-agent",
            ]
            .contains(&name.as_str()),
            "unexpected header {name}: {value}"
        );
        for secret in [
            cwd.to_str().unwrap(),
            repo_root.to_str().unwrap(),
            repo_name,
        ] {
            assert!(
                !value.contains(secret),
                "header {name} carries {secret:?}: {value}"
            );
        }
    }
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(header("authorization"), Some("Bearer pk_test_key"));
    assert_eq!(header("x-organization-id"), Some("org-uuid-1"));
}

#[test]
fn factor_lookup_prints_the_card_text() {
    let server = MockServer::start(vec![(LOOKUP_PATH, 200, LOOKUP_BODY)]);
    let out = lookup_output(&server.client(), "add a retry", 3, None).unwrap();
    // The card comes first, as the server wrote it, then one blank line.
    assert!(
        out.starts_with(
            "CF-0021 Unbounded retry\n\
             Tell: a loop around a network call with no attempt counter.\n\
             Guard: cap the attempts.\n\n"
        ),
        "{out}"
    );
}

#[test]
fn factor_lookup_prints_the_definition_for_an_item_with_no_card() {
    let server = MockServer::start(vec![(LOOKUP_PATH, 200, LOOKUP_BODY)]);
    let out = lookup_output(&server.client(), "add a retry", 3, None).unwrap();
    assert!(
        out.ends_with("\n\nCF-0107 - Stale runbook\nThe runbook is out of date.\n"),
        "{out}"
    );
}

#[test]
fn factor_lookup_prints_the_no_match_line_for_an_empty_list() {
    let server = MockServer::start(vec![(
        LOOKUP_PATH,
        200,
        r#"{"edition":"2026.2","factors":[]}"#,
    )]);
    let out = lookup_output(&server.client(), "rename a variable", 3, None).unwrap();
    assert_eq!(out, "No causal factor matches this description.\n");

    // The server can send null for an empty list.
    let server = MockServer::start(vec![(
        LOOKUP_PATH,
        200,
        r#"{"edition":"2026.2","factors":null}"#,
    )]);
    let out = lookup_output(&server.client(), "rename a variable", 3, None).unwrap();
    assert_eq!(out, "No causal factor matches this description.\n");
}

#[test]
fn factor_lookup_json_is_raw_passthrough() {
    let server = MockServer::start(vec![(LOOKUP_PATH, 200, LOOKUP_BODY)]);
    let out = lookup_output(&server.client(), "add a retry", 3, Some("json")).unwrap();
    assert_eq!(out, format!("{LOOKUP_BODY}\n"));
}

#[test]
fn factor_lookup_error_is_a_runtime_failure_with_the_client_message() {
    let server = MockServer::start(vec![(
        LOOKUP_PATH,
        400,
        r#"{"error":"bad_request","message":"the description is too long"}"#,
    )]);
    let f = lookup_output(&server.client(), "add a retry", 3, None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error: server error (400): bad_request: the description is too long"
    );
}
