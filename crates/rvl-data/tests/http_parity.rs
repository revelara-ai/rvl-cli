//! Hermetic golden-parity tests against a mock HTTP backend: no live API
//! calls, ever. The mock speaks just enough HTTP/1.1 for ureq and records
//! every request (method, path, headers, body) for assertions.

use rvl_data::client::{resolve_organization_id, validate_credentials, Client};
use rvl_data::config::DataConfig;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

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

/// A canned route: exact "METHOD /path?query" -> (status, body).
type Routes = Vec<(&'static str, u16, &'static str)>;

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

    fn recorded(&self) -> Vec<Recorded> {
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

    let key = format!("{method} {path}");
    let (status, resp_body) = routes
        .iter()
        .find(|(route, _, _)| *route == key)
        .map(|(_, s, b)| (*s, *b))
        .unwrap_or((404, ""));

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

// --- slice (a): auth + status ---

#[test]
fn validate_credentials_hits_risks_stats_with_auth_headers() {
    let server = MockServer::start(vec![("GET /api/v1/risks/stats", 200, r#"{"total":0}"#)]);
    let client = server.client();
    validate_credentials(&client).expect("valid credentials");
    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
    assert_eq!(reqs[0].header("X-Organization-ID"), Some("org-uuid-1"));
}

#[test]
fn validate_credentials_maps_401_to_auth_failure() {
    let server = MockServer::start(vec![("GET /api/v1/risks/stats", 401, "{}")]);
    let err = validate_credentials(&server.client()).unwrap_err();
    assert_eq!(err, "authentication failed (status 401)");
}

#[test]
fn org_resolution_matches_case_insensitively() {
    let server = MockServer::start(vec![(
        "GET /api/v1/organizations",
        200,
        r#"{"organizations":[{"id":"org-1","name":"Acme Corp"},{"id":"org-2","name":"Beta"}]}"#,
    )]);
    let cfg = DataConfig {
        api_url: server.base_url.clone(),
        api_key: "pk".into(),
        org_name: "acme corp".into(),
    };
    assert_eq!(
        resolve_organization_id(&cfg).unwrap(),
        Some("org-1".to_string())
    );
    // No org header on the resolution call itself (mirrors rvl-cli).
    let reqs = server.recorded();
    assert_eq!(reqs[0].header("X-Organization-ID"), None);
}

#[test]
fn org_resolution_reports_available_names_on_mismatch() {
    let server = MockServer::start(vec![(
        "GET /api/v1/organizations",
        200,
        r#"{"organizations":[{"id":"org-1","name":"Acme"},{"id":"org-2","name":"Beta"}]}"#,
    )]);
    let cfg = DataConfig {
        api_url: server.base_url.clone(),
        api_key: "pk".into(),
        org_name: "nope".into(),
    };
    let err = resolve_organization_id(&cfg).unwrap_err();
    assert_eq!(
        err,
        "organization \"nope\" not found; available: Acme, Beta"
    );
}

#[test]
fn org_resolution_distinguishes_zero_accessible_orgs() {
    let server = MockServer::start(vec![(
        "GET /api/v1/organizations",
        200,
        r#"{"organizations":[]}"#,
    )]);
    let cfg = DataConfig {
        api_url: server.base_url.clone(),
        api_key: "pk".into(),
        org_name: "acme".into(),
    };
    let err = resolve_organization_id(&cfg).unwrap_err();
    assert!(err.contains("no organizations are accessible"), "{err}");
    assert!(err.contains("support@revelara.ai"), "{err}");
}

#[test]
fn status_output_reports_connected() {
    let server = MockServer::start(vec![("GET /api/v1/risks/stats", 200, "{}")]);
    let cfg = DataConfig {
        api_url: server.base_url.clone(),
        api_key: "pk_test_key_12345".into(),
        org_name: "acme".into(),
    };
    let out = rvl_data::auth::status_output(&cfg, &server.client(), "0.1.0").unwrap();
    assert!(out.contains("Status: Connected"), "{out}");
    assert!(out.contains("Organization: acme"), "{out}");
    assert!(!out.contains("pk_test_key_12345"), "key must be masked");
}

#[test]
fn status_output_connection_failure_exits_1() {
    let server = MockServer::start(vec![("GET /api/v1/risks/stats", 403, "{}")]);
    let cfg = DataConfig {
        api_url: server.base_url.clone(),
        api_key: "pk".into(),
        org_name: String::new(),
    };
    let f = rvl_data::auth::status_output(&cfg, &server.client(), "0.1.0").unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Connection failed: authentication failed (status 403)"
    );
}

// --- slice (b): evidence submit ---

#[test]
fn evidence_submit_resolves_control_then_posts_go_shaped_body() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-uuid-1","control_code":"RC-018","name":"Timeouts","expected_evidence_types":["code","test"]}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","control_id":"ctl-uuid-1","type":"code","name":"CB impl","status":"configured","created_at":"2026-08-04T00:00:00Z","updated_at":"2026-08-04T00:00:00Z"}"#,
        ),
    ]);
    let client = server.client();
    let out = rvl_data::evidence::submit_output(
        &client,
        "RC-018",
        "code",
        "CB impl",
        "https://github.com/x",
        "desc",
        "abc123def",
        "",
        "",
        None,
    )
    .unwrap();
    assert!(out.contains("Evidence submitted successfully."), "{out}");
    assert!(out.contains("Control: RC-018 (Timeouts)"), "{out}");

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[1].method, "POST");
    // The POST body is Go's sorted-key map marshal, byte-identical.
    let body = String::from_utf8(reqs[1].body.clone()).unwrap();
    assert_eq!(
        body,
        r#"{"control_id":"ctl-uuid-1","description":"desc","git_hash":"abc123def","name":"CB impl","type":"code","url_or_identifier":"https://github.com/x"}"#
    );
    assert_eq!(reqs[1].header("Content-Type"), Some("application/json"));
}

#[test]
fn evidence_submit_json_mode_prints_server_body_verbatim() {
    let raw = r#"{"id":"ev-1","type":"code","name":"n","status":"configured"}"#;
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-001",
            200,
            r#"{"id":"ctl-1","name":"C"}"#,
        ),
        ("POST /api/v1/evidence", 200, raw),
    ]);
    let out = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-001",
        "code",
        "n",
        "",
        "",
        "",
        "",
        "",
        Some("json"),
    )
    .unwrap();
    assert_eq!(out, format!("{raw}\n"));
}

#[test]
fn evidence_submit_unknown_control_is_a_runtime_error() {
    let server = MockServer::start(vec![]); // everything 404s
    let f = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-999",
        "code",
        "n",
        "",
        "",
        "",
        "",
        "",
        None,
    )
    .unwrap_err();
    assert_eq!(f.code, 1);
    assert!(
        f.msg.starts_with("Error: control RC-999 not found:"),
        "{}",
        f.msg
    );
}

// --- slice (c): risk / control / knowledge reads ---

#[test]
fn risk_list_json_is_raw_body_passthrough() {
    // Key order in the server body is deliberately non-alphabetical: the
    // passthrough must not re-encode.
    let raw = r#"{"total":1,"risks":[{"id":"a","risk_code":"R-1","title":"T","category":"c","score":5,"status":"applicable","linked_services":[]}],"page":1,"limit":50}"#;
    let server = MockServer::start(vec![("GET /api/v1/risks?limit=50", 200, raw)]);
    let out =
        rvl_data::risk::list_output(&server.client(), None, None, None, 50, Some("json")).unwrap();
    assert_eq!(out, format!("{raw}\n"));
}

#[test]
fn risk_list_encodes_filters_like_go_url_values() {
    let raw = r#"{"risks":[],"total":0,"page":1,"limit":1000}"#;
    let server = MockServer::start(vec![(
        "GET /api/v1/risks?category=fault_tolerance&limit=1000&service=a%26b&status=applicable",
        200,
        raw,
    )]);
    let out = rvl_data::risk::list_output(
        &server.client(),
        Some("applicable"),
        Some("fault_tolerance"),
        Some("a&b"),
        1000,
        None,
    )
    .unwrap();
    assert_eq!(out, "No risks found.\n");
}

#[test]
fn risk_show_json_is_raw_and_code_is_path_escaped() {
    let raw = r#"{"risk_code":"R-001","title":"T"}"#;
    let server = MockServer::start(vec![("GET /api/v1/risks/R-001", 200, raw)]);
    let out = rvl_data::risk::show_output(&server.client(), "R-001", Some("json")).unwrap();
    assert_eq!(out, format!("{raw}\n"));
}

#[test]
fn risk_fetch_error_message_matches_rvl_cli() {
    let server = MockServer::start(vec![(
        "GET /api/v1/risks/R-404",
        500,
        r#"{"error":"internal","message":"boom"}"#,
    )]);
    let f = rvl_data::risk::show_output(&server.client(), "R-404", None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error fetching risk: server error (500): internal: boom"
    );
}

#[test]
fn risk_context_composes_detail_and_coverage() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/risks/R-001",
            200,
            r#"{"risk_code":"R-001","score":10}"#,
        ),
        (
            "GET /api/v1/risks/R-001/context",
            200,
            r#"{"risk":{"risk_code":"R-001"},"controls":[]}"#,
        ),
        (
            "GET /api/v1/risks/stats",
            200,
            r#"{"coverage":{"total_controls":10,"assessed_controls":5,"coverage_percentage":50.0}}"#,
        ),
    ]);
    let out = rvl_data::risk::context_output(&server.client(), "R-001", Some("json")).unwrap();
    // Sorted top-level keys: controls, coverage_gap, detail, risk.
    let want = "{\n  \"controls\": [],\n  \"coverage_gap\": {\n    \"total_controls\": 10,\n    \"assessed_controls\": 5,\n    \"coverage_percentage\": 50\n  },\n  \"detail\": {\n    \"risk_code\": \"R-001\",\n    \"score\": 10\n  },\n  \"risk\": {\n    \"risk_code\": \"R-001\"\n  }\n}\n";
    assert_eq!(out, want);
}

#[test]
fn risk_context_both_fetches_failing_is_a_runtime_error() {
    let server = MockServer::start(vec![("GET /api/v1/risks/stats", 200, "{}")]);
    let f = rvl_data::risk::context_output(&server.client(), "R-9", None).unwrap_err();
    assert_eq!(f.code, 1);
    assert!(
        f.msg.starts_with("Error fetching risk context:"),
        "{}",
        f.msg
    );
}

#[test]
fn risk_resolve_posts_reason_and_reports() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/risks?limit=1000",
            200,
            r#"{"risks":[{"id":"uuid-9","risk_code":"R-009","title":"t","category":"c","score":1,"status":"applicable","linked_services":[]}],"total":1,"page":1,"limit":1000}"#,
        ),
        (
            "POST /api/v1/risks/uuid-9/resolve",
            200,
            r#"{"id":"uuid-9","risk_code":"R-009","status":"mitigated","resolved_at":"2026-08-04T01:02:03Z"}"#,
        ),
    ]);
    let out = rvl_data::risk::resolve_output(&server.client(), "R-009", "Fixed in deploy 42", None)
        .unwrap();
    assert!(out.contains("Risk R-009 resolved successfully."), "{out}");
    assert!(out.contains("Status:      mitigated"), "{out}");
    assert!(out.contains("Resolved At: 2026-08-04T01:02:03Z"), "{out}");
    let reqs = server.recorded();
    let body = String::from_utf8(reqs[1].body.clone()).unwrap();
    assert_eq!(body, r#"{"reason":"Fixed in deploy 42"}"#);
}

#[test]
fn risk_accept_patches_status_with_sorted_keys() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/risks?limit=1000",
            200,
            r#"{"risks":[{"id":"uuid-7","risk_code":"R-007","title":"t","category":"c","score":1,"status":"applicable","linked_services":[]}],"total":1,"page":1,"limit":1000}"#,
        ),
        ("PATCH /api/v1/risks/uuid-7/status", 200, "{}"),
    ]);
    let out = rvl_data::risk::accept_output(&server.client(), "R-007", "known cost").unwrap();
    assert_eq!(out, "Risk R-007 accepted successfully.\n");
    let reqs = server.recorded();
    assert_eq!(reqs[1].method, "PATCH");
    let body = String::from_utf8(reqs[1].body.clone()).unwrap();
    assert_eq!(body, r#"{"reason":"known cost","status":"accepted"}"#);
}

#[test]
fn compound_risk_show_lists_then_fetches_detail() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/compound-risks",
            200,
            r#"[{"id":"cr-uuid","risk_code":"CR-001","title":"Compound","category":"compound_failure","score":95,"status":"applicable","linked_services":["svc"]}]"#,
        ),
        (
            "GET /api/v1/compound-risks/cr-uuid",
            200,
            r#"{"risk":{"id":"cr-uuid","risk_code":"CR-001","title":"Compound","score":95,"status":"applicable","linked_services":["svc"]},"rule":{"id":"r1","name":"No timeouts + no CB","control_codes":["RC-018","RC-012"],"min_control_count":2,"base_interaction_severity":9},"constituents":[{"id":"c1","risk_code":"R-001","title":"No timeout","status":"applicable","control_codes":["RC-018"],"service":"svc","score":70}]}"#,
        ),
    ]);
    let out = rvl_data::risk::show_output(&server.client(), "CR-001", None).unwrap();
    assert!(out.contains("Compound Risk: CR-001"), "{out}");
    assert!(out.contains("No timeouts + no CB"), "{out}");
    assert!(out.contains("R-001"), "{out}");

    // JSON mode prints the raw detail body.
    let out = rvl_data::risk::show_output(&server.client(), "CR-001", Some("json")).unwrap();
    assert!(out.starts_with(r#"{"risk":{"id":"cr-uuid""#), "{out}");
}

#[test]
fn control_list_and_show_json_are_raw_passthrough() {
    let list_raw = r#"{"controls":[{"control_code":"RC-018","name":"Timeouts","category":"fault_tolerance","type":"preventive","weight":9}],"total":1,"page":1,"limit":200}"#;
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#;
    let server = MockServer::start(vec![
        ("GET /api/v1/controls?limit=200", 200, list_raw),
        ("GET /api/v1/controls/by-code/RC-018", 200, show_raw),
    ]);
    let out = rvl_data::control::list_output(&server.client(), None, 200, Some("json")).unwrap();
    assert_eq!(out, format!("{list_raw}\n"));
    let out = rvl_data::control::show_output(&server.client(), "RC-018", None, None, Some("json"))
        .unwrap();
    assert_eq!(out, format!("{show_raw}\n"));
}

#[test]
fn knowledge_search_posts_go_shaped_body_with_min_class() {
    let raw = r#"{"results":[],"total":0}"#;
    let server = MockServer::start(vec![
        ("POST /api/knowledge/search", 200, raw),
        ("POST /api/knowledge/search?min_class=best", 200, raw),
    ]);
    let out = rvl_data::knowledge::search_output(
        &server.client(),
        "circuit breaker",
        20,
        0,
        None,
        Some("json"),
    )
    .unwrap();
    assert_eq!(out, format!("{raw}\n"));
    rvl_data::knowledge::search_output(
        &server.client(),
        "circuit breaker",
        5,
        10,
        Some("best"),
        Some("json"),
    )
    .unwrap();
    let reqs = server.recorded();
    assert_eq!(
        String::from_utf8(reqs[0].body.clone()).unwrap(),
        r#"{"limit":20,"offset":0,"query":"circuit breaker"}"#
    );
    assert_eq!(reqs[1].path, "/api/knowledge/search?min_class=best");
    assert_eq!(
        String::from_utf8(reqs[1].body.clone()).unwrap(),
        r#"{"limit":5,"offset":10,"query":"circuit breaker"}"#
    );
}

#[test]
fn knowledge_procedures_control_filter_reemits_filtered_json() {
    let raw = r#"{"procedures":[{"id":"p1","title":"A","vertical":"v","procedure_type":"runbook","related_controls":["RC-018"],"effectiveness_score":0.9,"applied_count":1,"success_count":1,"confidence":0.8},{"id":"p2","title":"B","vertical":"v","procedure_type":"runbook","related_controls":["RC-043"],"effectiveness_score":0.5,"applied_count":0,"success_count":0,"confidence":0.6}],"total":2}"#;
    let server = MockServer::start(vec![(
        "GET /api/knowledge/procedures?limit=20&q=RC-018",
        200,
        raw,
    )]);
    let out = rvl_data::knowledge::procedures_output(
        &server.client(),
        None,
        None,
        None,
        Some("RC-018"),
        20,
        0,
        Some("json"),
    )
    .unwrap();
    // Filtered to p1 only, re-marshaled Go-style.
    assert!(out.contains("\"id\": \"p1\""), "{out}");
    assert!(!out.contains("\"id\": \"p2\""), "{out}");
    assert!(out.contains("\"total\": 1"), "{out}");
    assert!(out.contains("\"effectiveness_score\": 0.9"), "{out}");
}

#[test]
fn knowledge_facts_builds_sorted_query_and_passes_json_through() {
    let raw = r#"{"facts":[],"total":0}"#;
    let server = MockServer::start(vec![(
        "GET /api/knowledge/facts?limit=20&technology=go&vertical=fault-tolerance",
        200,
        raw,
    )]);
    let out = rvl_data::knowledge::facts_output(
        &server.client(),
        Some("fault-tolerance"),
        Some("go"),
        None,
        20,
        0,
        Some("json"),
    )
    .unwrap();
    assert_eq!(out, format!("{raw}\n"));
}

// --- slice (d): feedback / bugreport (po-av01j.158) ---

fn sample_submission(category: &str) -> rvl_data::feedback::Submission {
    rvl_data::feedback::Submission {
        message: "the scan did not submit data".into(),
        category: category.into(),
        cli_version: "1.2.3".into(),
        diagnostics: Some(rvl_data::feedback::Diagnostics {
            cli_version: "1.2.3".into(),
            os: "linux".into(),
            arch: "amd64".into(),
            api_host: "api.revelara.ai".into(),
            ..rvl_data::feedback::Diagnostics::default()
        }),
    }
}

#[test]
fn feedback_submit_posts_go_shaped_body_and_renders_report_id() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-123"}"#)]);
    let sub = sample_submission("bug");
    let body = rvl_data::feedback::submission_json(&sub);
    let out = rvl_data::feedback::submit_output(&server.client(), &body, "bug", "text").unwrap();
    assert_eq!(
        out,
        "Thanks! Your bug report was sent to Revelara.\nReport id: fb-123\n"
    );

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/feedback");
    assert_eq!(reqs[0].header("Content-Type"), Some("application/json"));
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
    // Byte-parity with Go's feedbackSubmission struct marshal.
    assert_eq!(
        String::from_utf8(reqs[0].body.clone()).unwrap(),
        r#"{"message":"the scan did not submit data","category":"bug","cli_version":"1.2.3","diagnostics":{"cli_version":"1.2.3","os":"linux","arch":"amd64","api_host":"api.revelara.ai"}}"#
    );
}

#[test]
fn feedback_submit_json_mode_matches_go_marshalindent() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-9"}"#)]);
    let sub = sample_submission("feedback");
    let body = rvl_data::feedback::submission_json(&sub);
    let out =
        rvl_data::feedback::submit_output(&server.client(), &body, "feedback", "json").unwrap();
    // Go: MarshalIndent(map[string]string{...}, "", "  ") — sorted keys.
    assert_eq!(
        out,
        "{\n  \"category\": \"feedback\",\n  \"id\": \"fb-9\",\n  \"status\": \"submitted\"\n}\n"
    );
}

#[test]
fn feedback_submit_unexpected_response_is_a_runtime_error() {
    // 200 without an id (and non-JSON bodies) both fail loudly.
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"ok":true}"#)]);
    let sub = sample_submission("feedback");
    let body = rvl_data::feedback::submission_json(&sub);
    let f =
        rvl_data::feedback::submit_output(&server.client(), &body, "feedback", "text").unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error: unexpected response from server: {\"ok\":true}"
    );
}

#[test]
fn feedback_submit_server_error_names_the_category_noun() {
    let server = MockServer::start(vec![(
        "POST /api/v1/feedback",
        500,
        r#"{"error":"db","message":"down"}"#,
    )]);
    let sub = sample_submission("bug");
    let body = rvl_data::feedback::submission_json(&sub);
    let f = rvl_data::feedback::submit_output(&server.client(), &body, "bug", "text").unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(
        f.msg,
        "Error submitting bug report: server error (500): db: down"
    );
}

#[test]
fn auth_error_message_matches_rvl_cli_401_contract() {
    let server = MockServer::start(vec![("GET /api/v1/risks?limit=1000", 401, "{}")]);
    let f =
        rvl_data::risk::list_output(&server.client(), None, None, None, 1000, None).unwrap_err();
    assert_eq!(f.code, 1);
    assert!(
        f.msg
            .contains("authentication failed (401) - run 'rvlscan login' to reconfigure"),
        "{}",
        f.msg
    );
}

// --- incident search ---

#[test]
fn incident_search_encodes_query_and_renders_both_formats() {
    let raw = r#"{"results":[{"short_name":"INC-1234","title":"Redis failover storm","severity":"sev1","incident_date":"2026-01-02T00:00:00Z","mttr_minutes":42,"source_url":"https://example.com/pm","relevance_score":0.87}],"total":1}"#;
    let server = MockServer::start(vec![(
        "GET /api/v1/incidents/search?limit=5&q=payment+timeout",
        200,
        raw,
    )]);

    // JSON mode is a raw body passthrough (exactly what the plugin's
    // scan.md Step 3C invocation consumes).
    let out =
        rvl_data::incident::search_output(&server.client(), "payment timeout", 5, Some("json"))
            .unwrap();
    assert_eq!(out, format!("{raw}\n"));

    // Table mode: header line + parsed rows.
    let out =
        rvl_data::incident::search_output(&server.client(), "payment timeout", 5, None).unwrap();
    assert!(
        out.starts_with("Found 1 result(s) for \"payment timeout\":\n\n"),
        "{out}"
    );
    assert!(out.contains("INC-1234"), "{out}");
    assert!(out.contains("0.87"), "{out}");
    assert!(out.contains("sev1"), "{out}");
    assert!(out.contains("https://example.com/pm"), "{out}");

    // The request path is Go url.Values.Encode parity: sorted keys,
    // space escaped as '+', with auth headers on every call.
    let reqs = server.recorded();
    assert_eq!(reqs.len(), 2);
    for r in &reqs {
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/api/v1/incidents/search?limit=5&q=payment+timeout");
        assert_eq!(r.header("Authorization"), Some("Bearer pk_test_key"));
        assert_eq!(r.header("X-Organization-ID"), Some("org-uuid-1"));
    }
}

#[test]
fn incident_search_server_error_message_matches_rvl_cli() {
    let server = MockServer::start(vec![(
        "GET /api/v1/incidents/search?limit=10&q=kafka",
        500,
        r#"{"error":"internal","message":"boom"}"#,
    )]);
    let f = rvl_data::incident::search_output(&server.client(), "kafka", 10, None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(f.msg, "Error: server error (500): internal: boom");
}

// --- slice (d): knowledge graph-search / foresight / enrich ---

#[test]
fn knowledge_graph_search_posts_go_shaped_body_and_renders_badges() {
    let raw = r#"{"results":[{"type":"fact","id":"fact_a1","title":"Redis timeouts cascade","vertical":"fault-tolerance","similarity":0.91,"discovery_method":"semantic"}],"total":1,"graph_expanded":true}"#;
    let server = MockServer::start(vec![("POST /api/knowledge/graph-search", 200, raw)]);
    let out = rvl_data::knowledge::graph_search_output(
        &server.client(),
        "timeout failures",
        5,
        2,
        Some("causes,depends_on"),
    )
    .unwrap();
    assert!(
        out.starts_with("Found 1 results for \"timeout failures\" (graph-expanded):"),
        "{out}"
    );
    assert!(
        out.contains("fact_a1      [FACT] [SEM] Redis timeouts cascade"),
        "{out}"
    );

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/knowledge/graph-search");
    // Go's sorted-key map marshal, byte-identical.
    assert_eq!(
        String::from_utf8(reqs[0].body.clone()).unwrap(),
        r#"{"expand_depth":2,"expand_types":["causes","depends_on"],"graph_expand":true,"limit":5,"query":"timeout failures"}"#
    );
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
}

#[test]
fn knowledge_graph_search_server_error_is_a_runtime_error() {
    let server = MockServer::start(vec![(
        "POST /api/knowledge/graph-search",
        500,
        r#"{"error":"internal","message":"graph down"}"#,
    )]);
    let f =
        rvl_data::knowledge::graph_search_output(&server.client(), "q", 20, 1, None).unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(f.msg, "Error: server error (500): internal: graph down");
}

#[test]
fn knowledge_foresight_posts_body_and_json_mode_is_raw_passthrough() {
    // Key order in the server body is deliberately non-alphabetical: the
    // passthrough must not re-encode.
    let raw = r#"{"metadata":{"traversal_depth":3,"edges_examined":42,"query_time_ms":12.5},"impact_paths":[]}"#;
    let server = MockServer::start(vec![("POST /api/knowledge/foresight", 200, raw)]);
    let out = rvl_data::knowledge::foresight_output(
        &server.client(),
        "technology",
        "redis",
        3,
        0.3,
        true,
        None,
        Some("json"),
    )
    .unwrap();
    assert_eq!(out, format!("{raw}\n"));

    let reqs = server.recorded();
    assert_eq!(reqs[0].path, "/api/knowledge/foresight");
    assert_eq!(
        String::from_utf8(reqs[0].body.clone()).unwrap(),
        r#"{"depth":3,"entity_id":"redis","entity_type":"technology","include_mitigations":true,"min_strength":0.3}"#
    );
}

#[test]
fn knowledge_foresight_table_renders_impact_chain() {
    let raw = r#"{"impact_paths":[{"chain":[{"entity_type":"pattern","entity_id":"p1","label":"Retry storm","relation_type":"causes","strength":0.8,"depth":1}],"total_strength":0.8}],"metadata":{"traversal_depth":3,"edges_examined":7,"query_time_ms":50}}"#;
    let server = MockServer::start(vec![("POST /api/knowledge/foresight", 200, raw)]);
    let out = rvl_data::knowledge::foresight_output(
        &server.client(),
        "service",
        "checkout-api",
        3,
        0.3,
        false,
        Some("causes,depends_on"),
        None,
    )
    .unwrap();
    assert!(
        out.starts_with("Foresight: service checkout-api (depth 3, 7 edges examined, 50ms)"),
        "{out}"
    );
    assert!(
        out.contains("  -[causes]-> Retry storm [pattern] (strength: 80%)"),
        "{out}"
    );
    let body = String::from_utf8(server.recorded()[0].body.clone()).unwrap();
    assert!(
        body.ends_with(r#""relation_types":["causes","depends_on"]}"#),
        "{body}"
    );
}

#[test]
fn knowledge_foresight_auth_error_matches_rvl_cli() {
    let server = MockServer::start(vec![("POST /api/knowledge/foresight", 401, "{}")]);
    let f = rvl_data::knowledge::foresight_output(
        &server.client(),
        "service",
        "api",
        3,
        0.3,
        false,
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(f.code, 1);
    assert!(f.msg.contains("authentication failed (401)"), "{}", f.msg);
}

#[test]
fn knowledge_enrich_fetches_all_sections_with_go_shaped_urls() {
    let server = MockServer::start(vec![
        (
            "GET /api/knowledge/patterns?limit=10&vertical=fault-tolerance",
            200,
            r#"{"patterns":[{"id":"pat_1","title":"Retry storm","pattern_type":"failure_mode","occurrence_count":2}],"total":1}"#,
        ),
        (
            "GET /api/knowledge/procedures?limit=10&vertical=fault-tolerance&q=RC-018",
            200,
            r#"{"procedures":[{"id":"proc_1","title":"Set timeouts","procedure_type":"runbook","related_controls":["RC-018"]}],"total":1}"#,
        ),
        (
            "GET /api/knowledge/health",
            200,
            r#"{"total_facts":10,"total_procedures":5,"total_patterns":3,"validated_percentage":80,"avg_confidence":0.75}"#,
        ),
        (
            "GET /api/knowledge/facts?limit=10&technology=go&vertical=fault-tolerance",
            200,
            r#"{"facts":[{"id":"fact_1","content":"c","vertical":"fault-tolerance","confidence":0.8,"validation_status":"auto_extracted"}],"total":1}"#,
        ),
        (
            "POST /api/knowledge/search",
            200,
            r#"{"results":[{"type":"fact","id":"fact_2","title":"Timeout budget","similarity":0.88,"vertical":"fault-tolerance"}],"total":1}"#,
        ),
    ]);
    let out = rvl_data::knowledge::enrich_output(
        &server.client(),
        "fault-tolerance",
        Some("RC-018"),
        Some("go"),
        Some("timeout failure"),
        10,
    )
    .unwrap();
    assert!(out.starts_with("=== Patterns (1) ==="), "{out}");
    assert!(out.contains("=== Procedures (1) ==="), "{out}");
    assert!(out.contains("proc_1 [runbook] Set timeouts"), "{out}");
    assert!(out.contains("=== Facts for go (1) ==="), "{out}");
    assert!(
        out.contains("=== Search Results for \"timeout failure\" (1) ==="),
        "{out}"
    );
    assert!(out.contains("Total Items:       18"), "{out}");

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 5);
    // The search fetch posts Go's sorted-key {limit, query} body.
    let search_req = reqs
        .iter()
        .find(|r| r.method == "POST")
        .expect("search POST recorded");
    assert_eq!(
        String::from_utf8(search_req.body.clone()).unwrap(),
        r#"{"limit":10,"query":"timeout failure"}"#
    );
}

#[test]
fn knowledge_enrich_total_fetch_failure_is_a_runtime_error() {
    // Everything 404s: all three attempted fetches fail, so enrich must
    // exit 1 with one Error line per fetch (po-cj4s7 parity).
    let server = MockServer::start(vec![]);
    let f = rvl_data::knowledge::enrich_output(
        &server.client(),
        "fault-tolerance",
        None,
        None,
        None,
        10,
    )
    .unwrap_err();
    assert_eq!(f.code, 1);
    let lines: Vec<&str> = f.msg.lines().collect();
    assert_eq!(lines.len(), 3, "{}", f.msg);
    assert!(lines[0].starts_with("Error: patterns:"), "{}", f.msg);
    assert!(lines[1].starts_with("Error: procedures:"), "{}", f.msg);
    assert!(lines[2].starts_with("Error: health:"), "{}", f.msg);
}

// --- slice (b/c) po-av01j.167: evidence + control scoping ---

#[test]
fn evidence_submit_sends_team_and_service_and_renders_scope() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-uuid-1","control_code":"RC-018","name":"Timeouts"}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","type":"code","name":"CB impl","status":"configured","scope_state":"team","team_slug":"platform","service_name":"shared-postgres"}"#,
        ),
    ]);
    let out = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-018",
        "code",
        "CB impl",
        "",
        "",
        "abc123",
        "platform",
        "shared-postgres",
        None,
    )
    .unwrap();
    assert!(
        out.contains("  Scope:   team=platform service=shared-postgres"),
        "{out}"
    );

    let reqs = server.recorded();
    let body = String::from_utf8(reqs[1].body.clone()).unwrap();
    assert_eq!(
        body,
        r#"{"control_id":"ctl-uuid-1","description":"","git_hash":"abc123","name":"CB impl","service":"shared-postgres","team":"platform","type":"code","url_or_identifier":""}"#
    );
}

#[test]
fn evidence_submit_team_only_omits_service_from_the_wire() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-1","name":"Timeouts"}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","type":"code","name":"n","status":"configured","scope_state":"team","team_slug":"payments"}"#,
        ),
    ]);
    let out = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-018",
        "code",
        "n",
        "",
        "",
        "",
        "payments",
        "",
        None,
    )
    .unwrap();
    assert!(out.contains("  Scope:   team=payments"), "{out}");

    let body = String::from_utf8(server.recorded()[1].body.clone()).unwrap();
    assert!(body.contains(r#""team":"payments""#), "{body}");
    assert!(!body.contains("service"), "{body}");
}

#[test]
fn evidence_submit_service_only_scope_renders() {
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-1","name":"Timeouts"}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","type":"code","name":"n","status":"configured","scope_state":"service","service_name":"checkout-api"}"#,
        ),
    ]);
    let out = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-018",
        "code",
        "n",
        "",
        "",
        "",
        "",
        "checkout-api",
        None,
    )
    .unwrap();
    assert!(out.contains("  Scope:   service=checkout-api"), "{out}");

    let body = String::from_utf8(server.recorded()[1].body.clone()).unwrap();
    assert!(body.contains(r#""service":"checkout-api""#), "{body}");
    assert!(!body.contains("team"), "{body}");
}

#[test]
fn evidence_submit_global_says_org_wide_but_pre_scoping_server_says_nothing() {
    // Server that knows about scoping and reports global.
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-1","name":"Timeouts"}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","type":"code","name":"n","status":"configured","scope_state":"global"}"#,
        ),
    ]);
    let out = rvl_data::evidence::submit_output(
        &server.client(),
        "RC-018",
        "code",
        "n",
        "",
        "",
        "",
        "",
        "",
        None,
    )
    .unwrap();
    assert!(out.contains("  Scope:   org-wide (global)"), "{out}");

    // Older server that predates scoping: no scope_state at all, so no
    // Scope line whatsoever (empty is NOT "unknown").
    let old = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"ctl-1","name":"Timeouts"}"#,
        ),
        (
            "POST /api/v1/evidence",
            200,
            r#"{"id":"ev-1","type":"code","name":"n","status":"configured"}"#,
        ),
    ]);
    let out = rvl_data::evidence::submit_output(
        &old.client(),
        "RC-018",
        "code",
        "n",
        "",
        "",
        "",
        "",
        "",
        None,
    )
    .unwrap();
    assert!(
        !out.contains("Scope:"),
        "pre-scoping server must be silent: {out}"
    );
}

#[test]
fn evidence_list_scope_filters_are_url_values_encoded() {
    let raw = r#"{"evidence":[{"id":"ev-abcdef1234","type":"code","name":"CB impl","status":"verified","scope_state":"team","team_slug":"payments"}],"total":1}"#;
    let server = MockServer::start(vec![(
        "GET /api/v1/evidence?limit=20&scope_state=team&service=checkout+api&team=payments",
        200,
        raw,
    )]);
    let out = rvl_data::evidence::list_output(
        &server.client(),
        None,
        None,
        None,
        Some("payments"),
        Some("checkout api"),
        Some("team"),
        20,
        None,
    )
    .unwrap();
    assert!(out.contains("Found 1 evidence records:"), "{out}");
    assert!(out.contains("    Scope: team=payments"), "{out}");
}

#[test]
fn evidence_list_flags_unknown_scope_and_stays_silent_on_global_and_old_servers() {
    let raw = r#"{"evidence":[
        {"id":"ev-1","type":"code","name":"grandfathered","status":"configured","scope_state":"unknown"},
        {"id":"ev-2","type":"code","name":"org wide","status":"configured","scope_state":"global"},
        {"id":"ev-3","type":"code","name":"pre scoping","status":"configured"}
    ],"total":3}"#;
    let server = MockServer::start(vec![("GET /api/v1/evidence?limit=20", 200, raw)]);
    let out = rvl_data::evidence::list_output(
        &server.client(),
        None,
        None,
        None,
        None,
        None,
        None,
        20,
        None,
    )
    .unwrap();
    assert!(
        out.contains("    Scope: unknown scope (needs re-scoping)"),
        "{out}"
    );
    // Exactly one Scope line: global and pre-scoping rows render nothing.
    assert_eq!(out.matches("    Scope:").count(), 1, "{out}");
}

#[test]
fn control_show_team_scope_breakdown_renders_worst_of() {
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts","category":"fault_tolerance","type":"preventive","weight":9}"#;
    let scope_raw = r#"{"control_code":"RC-018","org_status":"absent","teams":[{"team_slug":"payments","team_name":"Payments","status":"evidenced","direct_evidence":2,"inherited_evidence":1,"global_evidence":0},{"team_slug":"platform","team_name":"Platform","status":"absent","direct_evidence":0,"inherited_evidence":0,"global_evidence":0}],"unknown_evidence":3}"#;
    let server = MockServer::start(vec![
        ("GET /api/v1/controls/by-code/RC-018", 200, show_raw),
        (
            "GET /api/v1/controls/by-code/RC-018/scope-status?team=payments",
            200,
            scope_raw,
        ),
    ]);
    let out =
        rvl_data::control::show_output(&server.client(), "RC-018", Some("payments"), None, None)
            .unwrap();
    assert!(out.contains("Control: RC-018 - Timeouts"), "{out}");
    assert!(out.contains("Scope Status (per team):"), "{out}");
    assert!(out.contains("payments"), "{out}");
    // Worst-of: payments is evidenced but platform is absent -> absent.
    assert!(out.contains("Org status (worst-of): absent"), "{out}");
    assert!(
        out.contains("Note: 3 evidence record(s) have unknown scope"),
        "{out}"
    );

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        reqs[1].path,
        "/api/v1/controls/by-code/RC-018/scope-status?team=payments"
    );
}

#[test]
fn control_show_service_scope_breakdown_encodes_the_filter() {
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#;
    let scope_raw =
        r#"{"control_code":"RC-018","org_status":"evidenced","teams":[],"unknown_evidence":0}"#;
    let server = MockServer::start(vec![
        ("GET /api/v1/controls/by-code/RC-018", 200, show_raw),
        (
            "GET /api/v1/controls/by-code/RC-018/scope-status?service=checkout+api",
            200,
            scope_raw,
        ),
    ]);
    let out = rvl_data::control::show_output(
        &server.client(),
        "RC-018",
        None,
        Some("checkout api"),
        None,
    )
    .unwrap();
    assert!(out.contains("(no teams in scope"), "{out}");
    assert!(out.contains("Org status (worst-of): evidenced"), "{out}");
}

#[test]
fn control_show_scope_json_is_a_combined_envelope() {
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#;
    let scope_raw =
        r#"{"control_code":"RC-018","org_status":"absent","teams":[],"unknown_evidence":1}"#;
    let server = MockServer::start(vec![
        ("GET /api/v1/controls/by-code/RC-018", 200, show_raw),
        (
            "GET /api/v1/controls/by-code/RC-018/scope-status?team=payments",
            200,
            scope_raw,
        ),
    ]);
    let out = rvl_data::control::show_output(
        &server.client(),
        "RC-018",
        Some("payments"),
        None,
        Some("json"),
    )
    .unwrap();
    assert_eq!(
        out,
        format!("{{\"control\":{show_raw},\"scope_status\":{scope_raw}}}\n")
    );
}

#[test]
fn control_show_without_flags_appends_best_effort_org_summary() {
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#;
    let scope_raw = r#"{"control_code":"RC-018","org_status":"absent","teams":[{"team_slug":"payments","status":"evidenced","direct_evidence":2,"inherited_evidence":0,"global_evidence":0}],"unknown_evidence":3}"#;
    let server = MockServer::start(vec![
        ("GET /api/v1/controls/by-code/RC-018", 200, show_raw),
        (
            "GET /api/v1/controls/by-code/RC-018/scope-status",
            200,
            scope_raw,
        ),
    ]);
    let out = rvl_data::control::show_output(&server.client(), "RC-018", None, None, None).unwrap();
    assert!(
        out.contains("Org scope status: absent (worst-of across 1 teams; 3 unknown-scope records; see --team/--service)"),
        "{out}"
    );
    // The full per-team table belongs to the --team/--service path only.
    assert!(!out.contains("Scope Status (per team):"), "{out}");
}

#[test]
fn control_show_degrades_silently_when_scope_status_is_missing() {
    // A server that predates the scope-status endpoint: 404 on the extra
    // best-effort fetch must not disturb the classic output.
    let show_raw = r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#;
    let server = MockServer::start(vec![("GET /api/v1/controls/by-code/RC-018", 200, show_raw)]);
    let out = rvl_data::control::show_output(&server.client(), "RC-018", None, None, None).unwrap();
    assert!(out.contains("Control: RC-018 - Timeouts"), "{out}");
    assert!(!out.contains("Org scope status"), "{out}");
    assert!(!out.contains("Scope Status"), "{out}");
}

#[test]
fn control_show_scope_status_surfaces_the_server_hint_verbatim() {
    // An unknown --team is a 400 whose message lists the known slugs; with
    // scope flags that error is fatal and must pass through.
    let server = MockServer::start(vec![
        (
            "GET /api/v1/controls/by-code/RC-018",
            200,
            r#"{"id":"c1","control_code":"RC-018","name":"Timeouts"}"#,
        ),
        (
            "GET /api/v1/controls/by-code/RC-018/scope-status?team=paymnets",
            400,
            r#"{"error":"bad_request","message":"unknown team \"paymnets\"; known team slugs: payments, platform"}"#,
        ),
    ]);
    let f =
        rvl_data::control::show_output(&server.client(), "RC-018", Some("paymnets"), None, None)
            .unwrap_err();
    assert_eq!(f.code, 1);
    assert!(
        f.msg.contains("known team slugs: payments, platform"),
        "server hint swallowed: {}",
        f.msg
    );
}
// --- slice (e): knowledge relationships / graph / health (po-av01j.161) ---

#[test]
fn knowledge_relationships_path_escapes_entities_and_renders_table() {
    let raw = r#"{"relationships":[{"id":"rel_1","relation_type":"causes","source_type":"fact","source_id":"fact a/b","source_label":"Redis timeout","target_type":"pattern","target_id":"pat_b2","target_label":"Retry storm","strength":0.8,"direction":"outbound","evidence":["INC-1234"],"observation_count":3}],"total":1}"#;
    let server = MockServer::start(vec![(
        // Go url.PathEscape parity (po-4xrz5): space -> %20, slash -> %2F.
        "GET /api/knowledge/entities/fact/fact%20a%2Fb/relationships",
        200,
        raw,
    )]);
    let out = rvl_data::knowledge::relationships_output(&server.client(), "fact", "fact a/b", None)
        .unwrap();
    assert!(
        out.starts_with("Relationships for fact fact a/b (1 total):\n\n"),
        "{out}"
    );
    assert!(
        out.contains("Redis timeout [fact] -> Retry storm [pattern] (strength: 80%, seen 3x)"),
        "{out}"
    );
    assert!(out.contains("    Relation: causes  ID: rel_1"), "{out}");
    assert!(out.contains("    Evidence: INC-1234"), "{out}");

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(
        reqs[0].path,
        "/api/knowledge/entities/fact/fact%20a%2Fb/relationships"
    );
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
    assert_eq!(reqs[0].header("X-Organization-ID"), Some("org-uuid-1"));
}

#[test]
fn knowledge_relationships_json_is_raw_passthrough() {
    // Key order in the server body is deliberately non-alphabetical: the
    // passthrough must not re-encode.
    let raw = r#"{"total":0,"relationships":[]}"#;
    let server = MockServer::start(vec![(
        "GET /api/knowledge/entities/fact/fact_abc12/relationships",
        200,
        raw,
    )]);
    let out = rvl_data::knowledge::relationships_output(
        &server.client(),
        "fact",
        "fact_abc12",
        Some("json"),
    )
    .unwrap();
    assert_eq!(out, format!("{raw}\n"));
}

#[test]
fn knowledge_relationships_server_error_is_a_runtime_error() {
    let server = MockServer::start(vec![(
        "GET /api/knowledge/entities/fact/fact_abc12/relationships",
        500,
        r#"{"error":"internal","message":"boom"}"#,
    )]);
    let f = rvl_data::knowledge::relationships_output(&server.client(), "fact", "fact_abc12", None)
        .unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(f.msg, "Error: server error (500): internal: boom");
}

#[test]
fn knowledge_graph_builds_go_shaped_url_and_renders_depths() {
    let raw = r#"{"results":[{"entity_type":"pattern","entity_id":"pat_b2","entity_label":"Retry storm","relation_type":"causes","strength":0.8,"depth":1},{"entity_type":"service","entity_id":"svc_c3","entity_label":"checkout-api","relation_type":"impacts","strength":0.6,"depth":2}],"total":2}"#;
    let server = MockServer::start(vec![(
        // rvl-cli's fmt.Sprintf URL: entity segments and query values ride
        // unescaped (unlike relationships), commas included.
        "GET /api/knowledge/entities/fact/fact_abc12/graph?max_depth=2&min_strength=0.5&relation_type=causes,mitigates",
        200,
        raw,
    )]);
    let out = rvl_data::knowledge::graph_output(
        &server.client(),
        "fact",
        "fact_abc12",
        2,
        "0.5",
        Some("causes,mitigates"),
    )
    .unwrap();
    assert!(
        out.starts_with("Graph traversal from fact fact_abc12 (2 nodes):\n\n"),
        "{out}"
    );
    assert!(out.contains("  Depth 1:\n"), "{out}");
    assert!(
        out.contains("    -[causes]-> Retry storm [pattern] (strength: 80%)"),
        "{out}"
    );
    assert!(out.contains("  Depth 2:\n"), "{out}");
    assert!(
        out.contains("      -[impacts]-> checkout-api [service] (strength: 60%)"),
        "{out}"
    );

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(
        reqs[0].path,
        "/api/knowledge/entities/fact/fact_abc12/graph?max_depth=2&min_strength=0.5&relation_type=causes,mitigates"
    );
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
}

#[test]
fn knowledge_graph_omits_relation_type_when_not_given() {
    let raw = r#"{"results":[],"total":0}"#;
    let server = MockServer::start(vec![(
        "GET /api/knowledge/entities/fact/fact_abc12/graph?max_depth=3&min_strength=0.3",
        200,
        raw,
    )]);
    let out =
        rvl_data::knowledge::graph_output(&server.client(), "fact", "fact_abc12", 3, "0.3", None)
            .unwrap();
    assert_eq!(out, "No connected nodes found from fact fact_abc12\n");
    assert_eq!(
        server.recorded()[0].path,
        "/api/knowledge/entities/fact/fact_abc12/graph?max_depth=3&min_strength=0.3"
    );
}

#[test]
fn knowledge_graph_server_error_is_a_runtime_error() {
    let server = MockServer::start(vec![(
        "GET /api/knowledge/entities/fact/fact_abc12/graph?max_depth=3&min_strength=0.3",
        500,
        r#"{"error":"internal","message":"graph down"}"#,
    )]);
    let f =
        rvl_data::knowledge::graph_output(&server.client(), "fact", "fact_abc12", 3, "0.3", None)
            .unwrap_err();
    assert_eq!(f.code, 1);
    assert_eq!(f.msg, "Error: server error (500): internal: graph down");
}

#[test]
fn knowledge_health_fetches_and_renders_stats() {
    let server = MockServer::start(vec![(
        "GET /api/knowledge/health",
        200,
        r#"{"total_facts":10,"total_procedures":5,"total_patterns":3,"validated_percentage":80,"avg_confidence":0.75,"stale_count":2}"#,
    )]);
    let out = rvl_data::knowledge::health_output(&server.client()).unwrap();
    assert!(out.starts_with("Knowledge Base Health\n\n"), "{out}");
    assert!(out.contains("  Total Items:       18\n"), "{out}");
    assert!(out.contains("  Validated:         80%\n"), "{out}");
    assert!(out.contains("  Avg Confidence:    75%\n"), "{out}");
    assert!(out.contains("  Stale:             2\n"), "{out}");
    assert!(!out.contains("Contradictions:"), "{out}");

    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "GET");
    assert_eq!(reqs[0].path, "/api/knowledge/health");
    assert_eq!(reqs[0].header("Authorization"), Some("Bearer pk_test_key"));
    assert_eq!(reqs[0].header("X-Organization-ID"), Some("org-uuid-1"));
}

#[test]
fn knowledge_health_auth_error_matches_rvl_cli() {
    let server = MockServer::start(vec![("GET /api/knowledge/health", 401, "{}")]);
    let f = rvl_data::knowledge::health_output(&server.client()).unwrap_err();
    assert_eq!(f.code, 1);
    assert!(f.msg.contains("authentication failed (401)"), "{}", f.msg);
}
