//! Hermetic proof that `rvl stpa submit` hits the SAME six endpoints as
//! rvl-cli's Go implementation, in the same order, with ids from earlier
//! responses feeding the later calls (po-av01j.183). No live API calls.
//!
//! The mock speaks just enough HTTP/1.1 for ureq and serves a scripted
//! sequence of responses (one per connection), recording every request.

use rvl_data::client::Client;
use rvl_data::stpa::{submit_all, StpaFindings};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    body: Vec<u8>,
}

impl Recorded {
    fn line(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

type Scripted = (u16, &'static str);

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    fn start(responses: Vec<Scripted>) -> MockServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests: Arc<Mutex<Vec<Recorded>>> = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        std::thread::spawn(move || {
            let mut script = responses.into_iter();
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let next = script.next().unwrap_or((500, "exhausted"));
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
    (status, resp_body): Scripted,
    reqs: &Arc<Mutex<Vec<Recorded>>>,
) -> std::io::Result<()> {
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
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    reqs.lock().unwrap().push(Recorded { method, path, body });

    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    )?;
    out.write_all(resp_body.as_bytes())?;
    Ok(())
}

/// A representative findings file: one loss, two UCAs, a top-level scenario
/// with an `immediate` child that references both UCAs and a control, plus a
/// control-structure model. Deliberately lists the child scenario FIRST so
/// the level sort has to reorder it before the parent can resolve.
fn findings_fixture() -> StpaFindings {
    serde_json::from_str(
        r#"{
      "losses": [
        {"title": "Customer orders silently dropped",
         "description": "Irrecoverable revenue and trust loss",
         "category": "zero_tolerance"}
      ],
      "findings": [
        {"content": "Checkout does not retry the payment authorize call on 503",
         "uca_type": "not_provided",
         "causal_factors": ["inadequate_feedback"],
         "loss_scenario": "upstream 503 -> no retry -> order dropped",
         "canonical_form": "authorize not retried on 503",
         "confidence": 0.8,
         "control_code": "RC-018"},
        {"content": "Order writer commits before the payment result is known",
         "uca_type": "wrong_timing",
         "causal_factors": ["incorrect_process_model"],
         "loss_scenario": "commit before confirm -> phantom order",
         "canonical_form": "commit precedes confirm",
         "confidence": 0.6}
      ],
      "loss_scenarios": [
        {"title": "Authorize call is dropped under upstream pressure",
         "description": "The immediate mechanism",
         "level": "immediate",
         "parent_title": "Orders are lost",
         "uca_refs": [0, 1],
         "control_links": [{"control_code": "RC-018", "relationship": "mitigates"}]},
        {"title": "Orders are lost",
         "description": "The top-level loss scenario",
         "level": "top_level"}
      ],
      "control_structure": {
        "nodes": [
          {"node_key": "checkout", "name": "Checkout", "hierarchy_level": "controller",
           "source": "design_review", "confidence": 80, "description": "edge service"},
          {"node_key": "payments", "name": "Payments", "hierarchy_level": "controlled_process",
           "source": "design_review", "confidence": 90}
        ],
        "edges": [
          {"from_key": "checkout", "to_key": "payments", "label": "authorize",
           "edge_type": "control_action", "source": "design_review", "confidence": 75}
        ]
      }
    }"#,
    )
    .expect("fixture parses")
}

#[test]
fn submit_walks_all_six_endpoints_in_order() {
    let server = MockServer::start(vec![
        // 1. dedup listing, then the create
        (200, r#"{"loss_definitions":[]}"#),
        (200, r#"{"id":"loss-1"}"#),
        // 2. two UCAs; the second is a repeat detection
        (200, r#"{"uca":{"id":"uca-aaa"},"is_new":true}"#),
        (200, r#"{"uca":{"id":"uca-bbb"},"is_new":false}"#),
        // 3. scenarios, top-down: parent then child
        (200, r#"{"id":"ls-top"}"#),
        (200, r#"{"id":"ls-imm"}"#),
        // 4. UCA links on the child
        (200, r#"{"linked":true}"#),
        (200, r#"{"linked":true}"#),
        // 5. control resolution, then the control link
        (200, r#"{"id":"ctl-018"}"#),
        (200, r#"{"linked":true}"#),
        // 6. control structure model
        (200, r#"{"nodes_upserted":2,"edges_upserted":1}"#),
    ]);
    let client = server.client();

    let stats = submit_all(&client, &findings_fixture(), "github.com/acme/shop");

    let reqs = server.recorded();
    let lines: Vec<String> = reqs.iter().map(|r| r.line()).collect();
    assert_eq!(
        lines,
        vec![
            "GET /api/v1/loss-definitions",
            "POST /api/v1/loss-definitions",
            "POST /api/v1/ucas",
            "POST /api/v1/ucas",
            "POST /api/v1/loss-scenarios",
            "POST /api/v1/loss-scenarios",
            "POST /api/v1/loss-scenarios/ls-imm/ucas",
            "POST /api/v1/loss-scenarios/ls-imm/ucas",
            "GET /api/v1/controls/by-code/RC-018",
            "POST /api/v1/loss-scenarios/ls-imm/controls",
            "POST /api/v1/control-structure/model",
        ],
        "the six endpoints must be walked in rvl-cli's order"
    );

    // The parent scenario is created FIRST even though it was listed second,
    // and the child carries the parent's returned id.
    assert!(reqs[4].body_str().contains(r#""level":"top_level""#));
    assert!(!reqs[4].body_str().contains("parent_id"));
    assert!(reqs[5].body_str().contains(r#""parent_id":"ls-top""#));

    // UCA ids from step 2 feed the step-4 links, by findings index.
    assert_eq!(reqs[6].body_str(), r#"{"uca_id":"uca-aaa"}"#);
    assert_eq!(reqs[7].body_str(), r#"{"uca_id":"uca-bbb"}"#);

    // The control code is resolved to a UUID before linking.
    assert_eq!(
        reqs[9].body_str(),
        r#"{"control_id":"ctl-018","relationship":"mitigates"}"#
    );

    // Every UCA is submitted with source=design_review, which is what puts
    // the finding behind the product's "Design Review" badge.
    assert!(reqs[2].body_str().contains(r#""source":"design_review""#));
    assert!(reqs[3].body_str().contains(r#""source":"design_review""#));
    // Optional control_code is omitted when the finding has none.
    assert!(reqs[2].body_str().contains(r#""control_code":"RC-018""#));
    assert!(!reqs[3].body_str().contains("control_code"));

    // The control structure carries repo_url from --service.
    assert!(reqs[10]
        .body_str()
        .contains(r#""repo_url":"github.com/acme/shop""#));

    assert_eq!(stats.loss_defs_total, 1);
    assert_eq!(stats.loss_defs_new, 1);
    assert_eq!(stats.ucas_total, 2);
    assert_eq!(stats.ucas_new, 1); // the second was a repeat detection
    assert_eq!(stats.scenarios_created, 2);
    assert_eq!(stats.uca_links, 2);
    assert_eq!(stats.control_links, 1);
    assert_eq!(stats.cs_nodes, 2);
    assert_eq!(stats.cs_edges, 1);
    assert_eq!(stats.errors, 0);
}

#[test]
fn existing_loss_titles_are_skipped_case_insensitively() {
    let server = MockServer::start(vec![
        (
            200,
            r#"{"loss_definitions":[{"title":"CUSTOMER ORDERS SILENTLY DROPPED"}]}"#,
        ),
        // No POST /loss-definitions should be attempted; the next scripted
        // response is consumed by the first UCA.
        (200, r#"{"uca":{"id":"uca-aaa"},"is_new":true}"#),
        (200, r#"{"uca":{"id":"uca-bbb"},"is_new":true}"#),
        (200, r#"{"id":"ls-top"}"#),
        (200, r#"{"id":"ls-imm"}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"id":"ctl-018"}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"nodes_upserted":2,"edges_upserted":1}"#),
    ]);
    let stats = submit_all(&server.client(), &findings_fixture(), "repo");
    let lines: Vec<String> = server.recorded().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| *l == "POST /api/v1/loss-definitions")
            .count(),
        0,
        "an existing title must not be re-created"
    );
    assert_eq!(stats.loss_defs_total, 1);
    assert_eq!(stats.loss_defs_new, 0);
}

#[test]
fn a_failed_item_is_a_warning_not_an_abort() {
    let server = MockServer::start(vec![
        (200, r#"{"loss_definitions":[]}"#),
        (500, r#"{"error":"db","message":"down"}"#), // loss definition fails
        (200, r#"{"uca":{"id":"uca-aaa"},"is_new":true}"#),
        (500, r#"{"error":"db","message":"down"}"#), // second UCA fails
        (200, r#"{"id":"ls-top"}"#),
        (200, r#"{"id":"ls-imm"}"#),
        (200, r#"{"linked":true}"#), // ref 0 links
        // ref 1 has no id (its UCA failed) so NO request is made for it;
        // the next response goes to the control lookup.
        (200, r#"{"id":"ctl-018"}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"nodes_upserted":2,"edges_upserted":1}"#),
    ]);
    let stats = submit_all(&server.client(), &findings_fixture(), "repo");

    // The run continued to the last endpoint despite two failures.
    let lines: Vec<String> = server.recorded().iter().map(|r| r.line()).collect();
    assert_eq!(
        lines.last().map(String::as_str),
        Some("POST /api/v1/control-structure/model")
    );
    assert_eq!(stats.errors, 2);
    assert_eq!(stats.loss_defs_new, 0);
    assert_eq!(stats.ucas_total, 2);
    assert_eq!(stats.ucas_new, 1);
    // Only the UCA that was actually created got linked.
    assert_eq!(stats.uca_links, 1);
    assert_eq!(stats.control_links, 1);
    assert_eq!(stats.cs_nodes, 2);
}

#[test]
fn control_structure_is_skipped_without_service() {
    let server = MockServer::start(vec![
        (200, r#"{"loss_definitions":[]}"#),
        (200, r#"{"id":"loss-1"}"#),
        (200, r#"{"uca":{"id":"uca-aaa"},"is_new":true}"#),
        (200, r#"{"uca":{"id":"uca-bbb"},"is_new":true}"#),
        (200, r#"{"id":"ls-top"}"#),
        (200, r#"{"id":"ls-imm"}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"linked":true}"#),
        (200, r#"{"id":"ctl-018"}"#),
        (200, r#"{"linked":true}"#),
    ]);
    let stats = submit_all(&server.client(), &findings_fixture(), "");
    let lines: Vec<String> = server.recorded().iter().map(|r| r.line()).collect();
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("/api/v1/control-structure/model")),
        "without --service the control structure must be skipped, not sent unscoped"
    );
    assert_eq!(stats.cs_nodes, 0);
    assert_eq!(stats.cs_edges, 0);
    // A skip is not an error.
    assert_eq!(stats.errors, 0);
}
