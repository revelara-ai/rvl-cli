//! EMPTY FLAG VALUES, END TO END (po-av01j.192).
//!
//! The unit tests in `empty_flag` prove the argv reaches the consumer intact
//! and that every flag has a declared rule. These prove what the user and the
//! SERVER actually see: the process exit code, and the request that leaves
//! the machine. Both are what diverged from rvl-cli, and neither is visible
//! from a parse test.
//!
//! Every case below was run side by side against a Go rvl-cli built from
//! `origin/main` and pointed at the same stub; the expectations here are that
//! binary's observed behaviour, not a reading of its source.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

/// One request the CLI actually sent.
#[derive(Debug, Clone)]
struct Req {
    method: String,
    target: String,
    body: String,
}

/// A stub API that answers everything with `{}`-ish JSON and records what it
/// was asked for. Enough to let a command reach the wire; the point is the
/// request, never the response.
struct Stub {
    url: String,
    seen: Arc<Mutex<Vec<Req>>>,
    _stop: Receiver<()>,
}

impl Stub {
    fn start() -> Stub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = channel::<()>();
        let sink = Arc::clone(&seen);
        std::thread::spawn(move || {
            // Owning the sender here stops the thread from being reaped as
            // unused; it lives as long as the listener.
            let _tx = tx;
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let sink = Arc::clone(&sink);
                std::thread::spawn(move || serve(stream, &sink));
            }
        });
        Stub {
            url,
            seen,
            _stop: rx,
        }
    }

    fn requests(&self) -> Vec<Req> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve(mut stream: TcpStream, sink: &Arc<Mutex<Vec<Req>>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut start = String::new();
    if reader.read_line(&mut start).is_err() || start.is_empty() {
        return;
    }
    let mut parts = start.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let mut len = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; len];
    if len > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    sink.lock().unwrap().push(Req {
        method,
        target,
        body: String::from_utf8_lossy(&body).into_owned(),
    });

    // A body that satisfies every response type these commands decode.
    let payload = br#"{"organizations":[{"id":"org-1","name":"test-org"}],"risks":[{"id":"risk-uuid-1","risk_code":"R-1","title":"t"}],"total":1,"controls":[],"evidence":[],"results":[],"facts":[],"procedures":[],"patterns":[],"id":"x","status":"resolved"}"#;
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

/// Run the real binary against the stub with a throwaway HOME, so no
/// developer credentials or config can influence the result.
fn run(stub: &Stub, args: &[&str]) -> (i32, String) {
    let home = std::env::temp_dir().join(format!("rvl-empty-flag-{}", std::process::id()));
    std::fs::create_dir_all(&home).expect("home");
    let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
        .args(args)
        .env("HOME", &home)
        .env("RVL_API_KEY", "test-key")
        .env("RVL_API_URL", &stub.url)
        .env("RVL_OFFLINE", "1")
        .env_remove("NO_COLOR")
        .output()
        .expect("run rvl");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The two spellings of an empty value. rvl-cli's `cliutil.FlagValue` returns
/// "" for both, so every case below is run twice and must agree.
fn spellings<'a>(flag: &'a str, equals: &'a mut String) -> [Vec<&'a str>; 2] {
    equals.push_str(flag);
    equals.push('=');
    [vec![equals.as_str()], vec![flag, ""]]
}

/// (a) `--limit=` is a USAGE ERROR, not a silent default. rvl-cli runs
/// `strconv.Atoi("")`, fails, and exits 2 (risk.go:351, control.go:128,
/// incident.go:152, evidence.go:258, knowledge.go:382). The argv strip made
/// this binary apply the default and query the server instead — the user asks
/// for a broken limit and gets a successful, differently-scoped answer.
#[test]
fn an_empty_numeric_flag_exits_2_and_never_reaches_the_wire() {
    let stub = Stub::start();
    for (cmd, flag) in [
        (vec!["risk", "list"], "--limit"),
        (vec!["risk", "ready"], "--limit"),
        (vec!["control", "list"], "--limit"),
        (vec!["incident", "search", "db"], "--limit"),
        (vec!["evidence", "list"], "--limit"),
        (vec!["knowledge", "facts"], "--offset"),
    ] {
        let mut eq = String::new();
        for extra in spellings(flag, &mut eq) {
            let argv: Vec<&str> = cmd.iter().copied().chain(extra).collect();
            let (code, err) = run(&stub, &argv);
            assert_eq!(code, 2, "{argv:?} must exit 2, stderr: {err}");
        }
    }
    assert!(
        stub.requests().is_empty(),
        "a usage error must not talk to the server: {:?}",
        stub.requests()
    );
}

/// (b) A MISSPELLED flag is a usage error whatever its spelling. The argv
/// strip disabled unknown-flag detection for the entire `--x=` shape, so
/// `risk list --serivce=` exited 0 and listed everything, hiding the typo.
#[test]
fn a_misspelled_flag_exits_2_with_or_without_a_trailing_equals() {
    let stub = Stub::start();
    for (cmd, flag) in [
        (vec!["risk", "list"], "--serivce"),
        (vec!["control", "list"], "--catgeory"),
        (vec!["evidence", "list"], "--contorl"),
        (vec!["knowledge", "facts"], "--verticl"),
    ] {
        let mut eq = String::new();
        for extra in spellings(flag, &mut eq) {
            let argv: Vec<&str> = cmd.iter().copied().chain(extra).collect();
            let (code, err) = run(&stub, &argv);
            assert_eq!(code, 2, "{argv:?} must exit 2, stderr: {err}");
            assert!(
                err.contains("unexpected argument") || err.contains("unknown"),
                "{argv:?} must name the unknown flag, got: {err}"
            );
        }
    }
    assert!(stub.requests().is_empty());
}

/// (c) `--reason=` sends the EMPTY reason, not the "Resolved" default. This
/// one is written into the risk register, so a substituted default is a
/// record of a decision nobody made (risk.go:1097/1152).
#[test]
fn an_empty_reason_is_posted_as_empty_and_an_absent_one_defaults() {
    for (extra, want) in [
        (vec!["--reason="], r#"{"reason":""}"#),
        (vec!["--reason", ""], r#"{"reason":""}"#),
        (vec![], r#"{"reason":"Resolved"}"#),
        (vec!["--reason", "fixed"], r#"{"reason":"fixed"}"#),
    ] {
        let stub = Stub::start();
        let argv: Vec<&str> = ["risk", "resolve", "R-1"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let (code, err) = run(&stub, &argv);
        assert_ne!(code, 2, "{argv:?} is not a usage error: {err}");
        let reqs = stub.requests();
        let post = reqs
            .iter()
            .find(|r| r.method == "POST")
            .unwrap_or_else(|| panic!("{argv:?} sent no POST: {reqs:?}"));
        assert_eq!(post.body, want, "{argv:?}");
    }
}

/// The OTHER spelling was wrong in the opposite direction: `--control ''`
/// was passed through as present-and-empty, so `evidence list --control ''`
/// looked up the control code "" — `GET /controls/by-code/` — and 404'd,
/// where rvl-cli guards `!= ""` (evidence.go:304) and just lists everything.
#[test]
fn an_empty_string_filter_is_absent_in_both_spellings() {
    for extra in [vec!["--control="], vec!["--control", ""], vec![]] {
        let stub = Stub::start();
        let argv: Vec<&str> = ["evidence", "list"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let (code, err) = run(&stub, &argv);
        assert_ne!(code, 2, "{argv:?}: {err}");
        let reqs = stub.requests();
        assert!(
            !reqs.iter().any(|r| r.target.contains("/controls/by-code/")),
            "{argv:?} must not resolve the control code \"\": {reqs:?}"
        );
        assert!(
            reqs.iter()
                .any(|r| r.target.starts_with("/api/v1/evidence?")
                    && !r.target.contains("control_id=")),
            "{argv:?} must list evidence unfiltered: {reqs:?}"
        );
    }
}

/// The same rule on the query string: an empty filter must not become an
/// empty query PARAMETER, which is a different request from an absent one.
#[test]
fn an_empty_filter_is_not_sent_as_an_empty_query_parameter() {
    for extra in [vec!["--service="], vec!["--service", ""]] {
        let stub = Stub::start();
        let argv: Vec<&str> = ["risk", "list"]
            .into_iter()
            .chain(extra.iter().copied())
            .collect();
        let (code, err) = run(&stub, &argv);
        assert_ne!(code, 2, "{argv:?}: {err}");
        let reqs = stub.requests();
        assert!(
            reqs.iter().all(|r| !r.target.contains("service=")),
            "{argv:?} must send no service filter: {reqs:?}"
        );
    }
}

/// Not every empty value is absent. These are the consumers rvl-cli leaves
/// UNGUARDED, where the empty string is validated (and rejected) rather than
/// ignored — a class the argv strip erased wholesale.
#[test]
fn the_validators_that_reject_an_empty_value_still_do() {
    let stub = Stub::start();
    for argv in [
        // incident.go:163 — ValidateFormat, not wrapped in `!= ""`.
        vec!["incident", "search", "db", "--format="],
        vec!["incident", "search", "db", "--format", ""],
        // knowledge.go:372 — the switch has no empty case.
        vec!["knowledge", "search", "db", "--min-class="],
        vec!["knowledge", "search", "db", "--min-class", ""],
        // evidence.go:142/146/150 — "is required".
        vec![
            "evidence",
            "submit",
            "--control=",
            "--type=code",
            "--name=n",
        ],
        vec![
            "evidence",
            "submit",
            "--control",
            "",
            "--type=code",
            "--name=n",
        ],
        // feedback.go:195/198/201.
        vec!["feedback", "--message=", "--yes"],
        vec!["feedback", "--message=hi", "--category=", "--yes"],
        vec!["feedback", "--message=hi", "--format=", "--yes"],
    ] {
        let (code, err) = run(&stub, &argv);
        assert_eq!(code, 2, "{argv:?} must exit 2, stderr: {err}");
    }
    assert!(
        stub.requests().is_empty(),
        "usage errors must not reach the server: {:?}",
        stub.requests()
    );
}

/// ...and the guarded ones still accept it. `--format=` renders the default
/// view wherever rvl-cli wraps ValidateFormat in `if format != ""`
/// (control.go:163, evidence.go:276, knowledge.go:413) — the opposite of the
/// command above, on the same flag NAME, which is exactly why this had to
/// move from argv to the consumer.
#[test]
fn the_validators_that_are_guarded_still_accept_an_empty_value() {
    let stub = Stub::start();
    for argv in [
        vec!["control", "list", "--format="],
        vec!["control", "list", "--format", ""],
        vec!["evidence", "list", "--format="],
        vec!["evidence", "list", "--status="],
        vec!["knowledge", "facts", "--format="],
        vec!["risk", "list", "--format="],
    ] {
        let (code, err) = run(&stub, &argv);
        assert_ne!(code, 2, "{argv:?} must not be a usage error: {err}");
    }
}
