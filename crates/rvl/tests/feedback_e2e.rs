//! End-to-end tests for `rvl feedback` / `rvl bugreport` against a
//! mock HTTP backend: the real binary, real flag parsing, real stdin and
//! confirmation flow. No live API calls, ever.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct MockServer {
    base_url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockServer {
    /// Serve canned routes ("METHOD /path" -> (status, body)) on an
    /// ephemeral port; unmatched requests get 404.
    fn start(routes: Vec<(&'static str, u16, &'static str)>) -> MockServer {
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

    fn recorded(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

fn handle(
    stream: std::net::TcpStream,
    routes: &[(&'static str, u16, &'static str)],
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
        let line = line.trim_end();
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

    let key = format!("{method} {path}");
    let (status, resp_body) = routes
        .iter()
        .find(|(route, _, _)| *route == key)
        .map(|(_, s, b)| (*s, *b))
        .unwrap_or((404, ""));

    reqs.lock().unwrap().push(Recorded { method, path, body });

    let mut out = stream;
    write!(
        out,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_body.len()
    )?;
    out.write_all(resp_body.as_bytes())?;
    Ok(())
}

/// The rvl binary configured for a hermetic run: temp HOME (no
/// ~/.revelara/config.yaml), env-var credentials pointing at the mock, no
/// org name (skips org resolution), cwd outside any git repo.
fn bin(server: &MockServer, home: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rvl"));
    cmd.env("HOME", home)
        .env("RVL_API_KEY", "pk_e2e_key")
        .env("RVL_API_URL", &server.base_url)
        .env_remove("RVL_ORG_NAME")
        .current_dir(home);
    cmd
}

fn run_with_stdin(cmd: &mut Command, input: &str) -> std::process::Output {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rvl");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().expect("wait rvl")
}

#[test]
fn yes_bypasses_confirmation_and_posts_feedback() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-1"}"#)]);
    let home = tempfile::tempdir().unwrap();
    let out = bin(&server, home.path())
        .args(["feedback", "--message", "great tool", "--yes"])
        .output()
        .expect("run rvl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        stdout,
        "Thanks! Your feedback was sent to Revelara.\nReport id: fb-1\n"
    );
    assert!(
        !stdout.contains("About to send"),
        "--yes must skip the preview/confirmation"
    );
    let reqs = server.recorded();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "POST");
    assert_eq!(reqs[0].path, "/api/v1/feedback");
    let body = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(
        body.starts_with(r#"{"message":"great tool","category":"feedback","cli_version":""#),
        "body: {body}"
    );
    assert!(
        body.contains(r#""diagnostics":{"cli_version":"#),
        "diagnostics attached by default: {body}"
    );
}

#[test]
fn bugreport_defaults_bug_category_and_json_output_is_go_shaped() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-2"}"#)]);
    let home = tempfile::tempdir().unwrap();
    let out = bin(&server, home.path())
        .args([
            "bugreport",
            "--message=scan submit returned 500",
            "--attach-diagnostics=false",
            "--yes",
            "--format=json",
        ])
        .output()
        .expect("run rvl");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "{\n  \"category\": \"bug\",\n  \"id\": \"fb-2\",\n  \"status\": \"submitted\"\n}\n"
    );
    // With diagnostics detached the POST body is fully deterministic.
    let reqs = server.recorded();
    assert_eq!(
        String::from_utf8(reqs[0].body.clone()).unwrap(),
        format!(
            r#"{{"message":"scan submit returned 500","category":"bug","cli_version":"{}"}}"#,
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[test]
fn message_dash_reads_stdin_and_trims() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-3"}"#)]);
    let home = tempfile::tempdir().unwrap();
    let out = run_with_stdin(
        bin(&server, home.path()).args(["feedback", "--message", "-", "--yes"]),
        "  piped message\n\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = String::from_utf8(server.recorded()[0].body.clone()).unwrap();
    assert!(
        body.starts_with(r#"{"message":"piped message","category":"feedback""#),
        "stdin message must be trimmed: {body}"
    );
}

#[test]
fn declined_confirmation_sends_nothing() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-4"}"#)]);
    let home = tempfile::tempdir().unwrap();
    let out = run_with_stdin(
        bin(&server, home.path()).args(["feedback", "--message", "hmm"]),
        "n\n",
    );
    assert!(out.status.success(), "declining is exit 0");
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("About to send to Revelara:"), "{stdout}");
    assert!(stdout.contains("Send this to Revelara? [y/N]:"), "{stdout}");
    assert!(stdout.contains("Aborted. Nothing was sent."), "{stdout}");
    assert_eq!(server.recorded().len(), 0, "nothing may reach the API");
}

#[test]
fn confirmed_prompt_sends() {
    let server = MockServer::start(vec![("POST /api/v1/feedback", 200, r#"{"id":"fb-5"}"#)]);
    let home = tempfile::tempdir().unwrap();
    let out = run_with_stdin(
        bin(&server, home.path()).args(["feedback", "--message", "ship it"]),
        "y\n",
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Report id: fb-5"), "{stdout}");
    assert_eq!(server.recorded().len(), 1);
}

#[test]
fn invalid_category_is_a_usage_error_with_help_pointer() {
    let server = MockServer::start(vec![]);
    let home = tempfile::tempdir().unwrap();
    let out = bin(&server, home.path())
        .args(["feedback", "--message=m", "--category=rant", "--yes"])
        .output()
        .expect("run rvl");
    assert_eq!(out.status.code(), Some(2), "usage errors exit 2");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains(r#"Error: invalid --category "rant" (valid: feedback, bug)"#),
        "{stderr}"
    );
    assert!(
        stderr.contains("Run 'rvl feedback --help' for usage."),
        "{stderr}"
    );
    assert_eq!(server.recorded().len(), 0);
}

#[test]
fn missing_message_points_at_stdin_form() {
    let server = MockServer::start(vec![]);
    let home = tempfile::tempdir().unwrap();
    let out = bin(&server, home.path())
        .args(["bugreport", "--yes"])
        .output()
        .expect("run rvl");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Error: --message is required (pass '--message -' to read it from stdin)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Run 'rvl bugreport --help' for usage."),
        "{stderr}"
    );
}

#[test]
fn api_failure_is_a_runtime_error() {
    let server = MockServer::start(vec![(
        "POST /api/v1/feedback",
        500,
        r#"{"error":"db","message":"down"}"#,
    )]);
    let home = tempfile::tempdir().unwrap();
    let out = bin(&server, home.path())
        .args(["bugreport", "--message=broke", "--yes"])
        .output()
        .expect("run rvl");
    assert_eq!(out.status.code(), Some(1), "runtime failures exit 1");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("Error submitting bug report: server error (500): db: down"),
        "{stderr}"
    );
}
