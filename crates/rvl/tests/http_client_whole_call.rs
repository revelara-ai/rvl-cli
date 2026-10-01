//! THE WHOLE-CALL BOUND THE ENGINE COULD NOT SEE.
//!
//! Three `net/http.Client` calls were reported as violations while a
//! whole-call bound stood in plain sight, and one was passed with no bound at
//! all (split-resolution pilot, po-av01j.232). Each shape is a Go module
//! scanned through the goindex built from THIS tree, so the wire shape and the
//! verdict are pinned together:
//!
//!   - a handler literal deep inside a long `main` derives a context deadline
//!     and sets only a dial bound on the client: the deadline bounds the call.
//!     The enclosing function was cut at the snippet budget, and the deadline
//!     was in the part that was cut;
//!   - the client is a parameter, and the function is handed around as a
//!     value: every call of it passes a client built with `Timeout`;
//!   - `Timeout` is set from a variable beside a dial-only transport;
//!   - the client is the result of a call into a dependency and the context
//!     is `context.Background()`: nothing in the repository can say whether
//!     that client is bounded, so the site abstains.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate directory, read at run time. `cargo test` sets CARGO_MANIFEST_DIR
/// for every test process; a binary reused from a shared CARGO_TARGET_DIR still
/// carries the compile-time path of whichever checkout built it, which may be gone.
fn manifest_dir() -> std::path::PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

/// The served shape: `Do` is bounded by the client or the request context,
/// `Post` by the client alone; the transport and the dialer bound a phase.
const SPECS: &str = r#"{"apis":[
{"type":"net/http.Client","method":"Do","site_count":1,"blocking":"yes","bounded_by":["client_config","context"],"confidence":1,"rationale":"blocks on network I/O"},
{"type":"net/http.Client","method":"Post","site_count":1,"blocking":"yes","bounded_by":["client_config"],"confidence":1,"rationale":"blocks on network I/O"}],
"configs":[
{"type":"net/http.Client","bounds":"whole_call","scope":"this_client","confidence":1,"fields":["Timeout"],"rationale":"bounded end to end only when Timeout is set"},
{"type":"net/http.Transport","bounds":"phase_only","scope":"this_client","confidence":1,"rationale":"transport timeouts bound a phase"},
{"type":"net.Dialer","bounds":"phase_only","scope":"this_client","confidence":1,"rationale":"the dialer bounds the connect phase"}]}"#;

/// A handler literal at the end of a `main` longer than the retriever's
/// snippet budget (tailscale cmd/tta/tta.go). `deadline` is the statement
/// that derives the request context.
fn long_main(deadline: &str) -> String {
    let padding: String = (0..120)
        .map(|i| format!("\tlog.Printf(\"starting subsystem %d of the agent\", {i})\n"))
        .collect();
    format!(
        r#"package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"
)

var _ = time.Second

func main() {{
{padding}
	http.HandleFunc("/http-get", func(w http.ResponseWriter, r *http.Request) {{
		{deadline}
		req, err := http.NewRequestWithContext(ctx, "GET", r.FormValue("url"), nil)
		if err != nil {{
			return
		}}
		client := &http.Client{{
			Transport: &http.Transport{{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {{
					var d net.Dialer
					return d.DialContext(ctx, network, addr)
				}},
			}},
		}}
		resp, err := client.Do(req)
		if err != nil {{
			return
		}}
		resp.Body.Close()
	}})
	log.Fatal(http.ListenAndServe(":8080", nil))
}}
"#
    )
}

/// The client is a parameter and the function travels as a value
/// (fish2018/pansou plugin/quarkres). The two literals are the clients
/// the callers pass.
fn param_client(response: &str, background: &str) -> String {
    format!(
        r#"package main

import (
	"net/http"
	"time"
)

var (
	responseTimeout   = 4 * time.Second
	processingTimeout = 30 * time.Second
)

type base struct {{
	client           *http.Client
	backgroundClient *http.Client
}}

func newBase() *base {{
	p := &base{{}}
	p.client = &{response}
	p.backgroundClient = &{background}
	return p
}}

type searchFunc func(*http.Client, string) (int, error)

func (p *base) asyncSearch(keyword string, search searchFunc) (int, error) {{
	go p.refresh(keyword, search)
	return search(p.client, keyword)
}}

func (p *base) refresh(keyword string, search searchFunc) {{
	search(p.backgroundClient, keyword)
}}

type plugin struct{{ *base }}

func (p *plugin) Search(keyword string) (int, error) {{
	return p.asyncSearch(keyword, p.doSearch)
}}

func (p *plugin) doSearch(client *http.Client, keyword string) (int, error) {{
	req, err := http.NewRequest("GET", "https://example.com/?q="+keyword, nil)
	if err != nil {{
		return 0, err
	}}
	resp, err := client.Do(req)
	if err != nil {{
		return 0, err
	}}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}}

func main() {{
	(&plugin{{newBase()}}).Search("x")
}}
"#
    )
}

/// `Timeout` from a validated variable, beside a dial-only transport
/// (benbjohnson/litestream cmd/litestream/sync.go).
const TIMEOUT_FROM_VARIABLE: &str = r#"package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"time"
)

func run(args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	timeout := fs.Int("timeout", 30, "seconds")
	socketPath := fs.String("socket", "/var/run/app.sock", "control socket")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}
	clientTimeout := time.Duration(*timeout) * time.Second
	client := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", *socketPath, clientTimeout)
			},
		},
	}
	resp, err := client.Post("http://localhost/sync", "application/json", bytes.NewReader(nil))
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func main() { run(nil) }
"#;

/// The client is built by a dependency and the context is Background
/// (cli/cli pkg/cmd/agent-task/capi/sessions.go).
const DEPENDENCY_CLIENT: &str = r#"package main

import (
	"context"
	"net/http"

	"example.com/ghapi"
)

type capiClient struct{ httpClient *http.Client }

func newCAPIClient(httpClient *http.Client) *capiClient {
	return &capiClient{httpClient: httpClient}
}

func (c *capiClient) listSessions(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://example.com/sessions", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func main() {
	httpClient, err := ghapi.NewHTTPClient(ghapi.ClientOptions{Host: "example.com"})
	if err != nil {
		return
	}
	newCAPIClient(httpClient).listSessions(context.Background())
}
"#;

/// The dependency, outside the scanned repository, the way a module cache is.
const GHAPI_STUB: &str = r#"package ghapi

import "net/http"

type ClientOptions struct{ Host string }

func NewHTTPClient(opts ClientOptions) (*http.Client, error) {
	return &http.Client{}, nil
}
"#;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    for k in [
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

/// goindex built from this tree, or `None` (with the reason printed) when
/// there is no usable Go toolchain. A build FAILURE is a defect where the
/// toolchain is guaranteed (CI), and a skip on a developer machine whose Go
/// install is broken.
fn goindex_binary(dir: &Path) -> Option<PathBuf> {
    let src = manifest_dir().join("../../helpers/goindex");
    let bin = dir.join("goindex");
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".")
        .current_dir(&src)
        .output()
    {
        Ok(out) if out.status.success() => Some(bin),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if std::env::var_os("CI").is_some() {
                panic!("goindex failed to build: {stderr}");
            }
            eprintln!("SKIP: goindex failed to build (set CI=1 to make this fatal): {stderr}");
            None
        }
        Err(e) => {
            eprintln!("SKIP: `go` not available: {e}");
            None
        }
    }
}

/// Scan one module holding `main_go` and return the `(verdict, reason)` of
/// its `net/http.Client` call sites.
fn scan(
    repo: &Path,
    work: &Path,
    goindex: &Path,
    go_mod: &str,
    main_go: &str,
) -> Vec<(String, String)> {
    std::fs::write(repo.join("go.mod"), go_mod).unwrap();
    std::fs::write(repo.join("main.go"), main_go).unwrap();
    let specs = work.join("specs.json");
    std::fs::write(&specs, SPECS).unwrap();
    let out_path = work.join("findings.json");
    let out = bin()
        .arg("scan")
        .arg(repo)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_GOINDEX", goindex)
        .env("RVL_CACHE_DIR", work.join("cache"))
        .output()
        .expect("failed to run rvl");
    assert!(
        out_path.is_file(),
        "scan wrote no --out document: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    doc["sites"]
        .as_array()
        .expect("sites must be a JSON array")
        .iter()
        .filter(|r| {
            r["class"]
                .as_str()
                .is_some_and(|c| c.starts_with("net/http.Client."))
        })
        .map(|r| {
            (
                r["verdict"].as_str().unwrap_or_default().to_string(),
                r["reason"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

const GO_MOD: &str = "module repro\n\ngo 1.22\n";

/// The single `net/http.Client` site of a one-file module.
fn verdict_of(goindex: &Path, main_go: &str) -> (String, String) {
    let repo = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    let rows = scan(repo.path(), work.path(), goindex, GO_MOD, main_go);
    assert_eq!(rows.len(), 1, "want one net/http.Client site: {rows:?}");
    rows.into_iter().next().unwrap()
}

#[test]
fn a_context_deadline_in_a_handler_literal_bounds_a_client_with_only_a_dial_bound() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    let (verdict, reason) = verdict_of(
        &goindex,
        &long_main(
            "ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)\n\t\tdefer cancel()",
        ),
    );
    assert_eq!(verdict, "satisfies", "{reason}");
    assert!(reason.contains("deadline"), "{reason}");

    // The same literal with no deadline is the hang, and the dial bound must
    // not read as more than a phase.
    let (verdict, reason) = verdict_of(&goindex, &long_main("ctx := r.Context()"));
    assert_eq!(verdict, "violates", "{reason}");
}

#[test]
fn a_client_parameter_is_judged_by_the_clients_its_callers_pass() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    let (verdict, reason) = verdict_of(
        &goindex,
        &param_client(
            "http.Client{Timeout: responseTimeout}",
            "http.Client{Timeout: processingTimeout}",
        ),
    );
    assert_eq!(verdict, "satisfies", "{reason}");
    assert!(reason.contains("Timeout"), "{reason}");

    // With no caller passing a bounded client, the same call is the hang.
    let (verdict, reason) = verdict_of(&goindex, &param_client("http.Client{}", "http.Client{}"));
    assert_eq!(verdict, "violates", "{reason}");
}

#[test]
fn a_timeout_set_from_a_variable_bounds_the_call() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    let (verdict, reason) = verdict_of(&goindex, TIMEOUT_FROM_VARIABLE);
    assert_eq!(verdict, "satisfies", "{reason}");
    assert!(reason.contains("Timeout"), "{reason}");
}

#[test]
fn a_client_built_by_a_dependency_under_a_background_context_abstains() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    let repo = tempfile::tempdir().unwrap();
    let dep = tempfile::tempdir().unwrap();
    let work = tempfile::tempdir().unwrap();
    std::fs::write(
        dep.path().join("go.mod"),
        "module example.com/ghapi\n\ngo 1.22\n",
    )
    .unwrap();
    std::fs::write(dep.path().join("ghapi.go"), GHAPI_STUB).unwrap();
    let go_mod = format!(
        "{GO_MOD}\nrequire example.com/ghapi v0.0.0\n\nreplace example.com/ghapi => {}\n",
        dep.path().display()
    );
    let rows = scan(
        repo.path(),
        work.path(),
        &goindex,
        &go_mod,
        DEPENDENCY_CLIENT,
    );
    assert_eq!(rows.len(), 1, "want one net/http.Client site: {rows:?}");
    let (verdict, reason) = &rows[0];
    assert_eq!(verdict, "abstain", "{reason}");
    assert!(
        reason.contains("outside this repository"),
        "the reason must say why the bound cannot be read: {reason}"
    );
}
