//! RC-027 error-reporting facts and verdict: whether a repository that runs a
//! listening server reports its errors to a central system, with alert rules
//! on top.
//!
//! RETRIEVAL ([`observe`]) records presence only, as repo-relative paths: a
//! server entry point, an error-tracker SDK reference, a tracker init, a
//! log-shipping config, an alert-rule file. JUDGEMENT ([`evaluate`]) decides
//! the two cases a tree proves and abstains on the rest. It violates only
//! when the repository reads as a service ([`crate::repo_kind`]: a server
//! entry point and a deployment manifest), a server runs, and the tree holds
//! no tracker SDK and no log shipping at all: a tracker wired in elsewhere is a claim no file here can refute,
//! so every presence the search can see counts against a violation. It
//! satisfies only when a tracker is initialised in service code and an alert
//! rule file is committed.
//!
//! The server entry points are narrower than [`crate::repo_kind`]'s, on
//! purpose: a framework that wraps `ListenAndServe` in a library function
//! has no tracker of its own and is not a service, so a Go listener counts
//! only in `package main` or in a package only a served `main` can build
//! (see [`delegated`]), and a JS listener only as `app.listen(`, a
//! `createServer(...).listen(` chain on one line, or a `next start` script.

use crate::inventory::read_capped;
use crate::repo_kind::{in_service_code, is_test_source};
use crate::{ErrorReportingFacts, RepoStructure, StructureFinding};
use rvl_core::Verdict;
use std::collections::BTreeSet;
use std::path::Path;

/// The paths kept per fact: enough to show, bounded for a large tree.
pub const MAX_PATHS: usize = 5;

/// Build output and vendored code the walk still descends into: the
/// inventory skips `target`, `build`, `dist`, `vendor` and `node_modules`.
const NOT_OURS: &[&str] = &["out", "third_party", "third-party"];

/// Directories of test code. A tracker referenced only here reports nothing.
const TEST_DIRS: &[&str] = &[
    "test",
    "tests",
    "testdata",
    "test-data",
    "test_data",
    "testing",
    "testutil",
    "testutils",
    "mock",
    "mocks",
    "fixtures",
    "__tests__",
];

/// Error-tracker SDKs, as they appear in an import or a manifest, lowercased.
/// Each matches as a whole word (see [`has_sdk`]).
const TRACKER_SDKS: &[&str] = &[
    "getsentry/sentry-go",
    "sentry_sdk",
    "sentry-sdk",
    "@sentry/",
    "bugsnag",
    "rollbar",
    "honeybadger",
    "airbrake",
    "gobrake",
];

/// The calls that initialise a tracker, by source extension.
const TRACKER_INITS: &[(&[&str], &[&str])] = &[
    (
        &["go"],
        &[
            "sentry.Init(",
            "bugsnag.Configure(",
            "rollbar.SetToken(",
            "rollbar.New(",
            "honeybadger.Configure(",
            "gobrake.NewNotifier",
        ],
    ),
    (
        &["py"],
        &["sentry_sdk.init(", "bugsnag.configure(", "rollbar.init("],
    ),
    (
        JS_EXTS,
        &[
            "Sentry.init(",
            "Bugsnag.start(",
            "new Rollbar(",
            "Rollbar.init(",
        ],
    ),
];

const JS_EXTS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx"];

/// Dependency manifests that name a tracker SDK as well as an import does.
const MANIFESTS: &[&str] = &["go.mod", "package.json", "pyproject.toml", "Pipfile"];

/// File-name markers of a log shipper's config, lowercased.
const SHIPPER_NAMES: &[&str] = &[
    "fluent-bit",
    "fluentbit",
    "fluentd",
    "fluent.conf",
    "td-agent",
    "promtail",
    "otel-collector",
    "otelcol",
];

/// Log-shipper images a manifest or compose file runs.
const SHIPPER_IMAGES: &[&str] = &[
    "fluent/fluent-bit",
    "fluent/fluentd",
    "timberio/vector",
    "grafana/promtail",
    "otel/opentelemetry-collector",
];

/// Terraform resources of the Sentry provider that define an alert.
const SENTRY_ALERTS: &[&str] = &[
    "\"sentry_issue_alert\"",
    "\"sentry_metric_alert\"",
    "\"sentry_alert_rule\"",
];

/// The error-reporting facts, accumulated over the walk.
#[derive(Default)]
pub(crate) struct Acc {
    listeners: BTreeSet<String>,
    tracker_sdks: BTreeSet<String>,
    tracker_inits: BTreeSet<String>,
    log_shipping: BTreeSet<String>,
    alert_rules: BTreeSet<String>,
    /// Directories holding a Go `package main` file in service code.
    go_mains: BTreeSet<String>,
    /// Go files outside `package main` that start a server.
    go_servers: BTreeSet<String>,
}

impl Acc {
    pub(crate) fn finish(mut self) -> ErrorReportingFacts {
        for rp in &self.go_servers {
            if delegated(rp, &self.go_mains) {
                self.listeners.insert(rp.clone());
            }
        }
        let cap = |s: BTreeSet<String>| s.into_iter().take(MAX_PATHS).collect();
        ErrorReportingFacts {
            listeners: cap(self.listeners),
            tracker_sdks: cap(self.tracker_sdks),
            tracker_inits: cap(self.tracker_inits),
            log_shipping: cap(self.log_shipping),
            alert_rules: cap(self.alert_rules),
        }
    }
}

/// Whether repo-relative `rp` sits under a directory of `names`.
/// Whether the file at `rp` is build output or vendored code the walk
/// still descends into.
pub(crate) fn not_ours(rp: &str) -> bool {
    under(rp, NOT_OURS)
}

fn under(rp: &str, names: &[&str]) -> bool {
    let mut dirs: Vec<&str> = rp.split('/').collect();
    dirs.pop();
    dirs.iter()
        .any(|d| names.contains(&d.to_ascii_lowercase().as_str()))
}

/// Record what the file at repo-relative `rp` says about error reporting.
pub(crate) fn observe(path: &Path, rp: &str, name: &str, ext: &str, acc: &mut Acc) {
    if under(rp, NOT_OURS) || under(rp, TEST_DIRS) || is_test_source(name) {
        return;
    }
    let lower = name.to_ascii_lowercase();
    let service = in_service_code(rp);
    if MANIFESTS.contains(&name) || (lower.starts_with("requirements") && ext == "txt") {
        let text = read_capped(path);
        if has_sdk(&text) {
            acc.tracker_sdks.insert(rp.to_string());
        }
        if service && name == "package.json" && next_server(&text, path) {
            acc.listeners.insert(rp.to_string());
        }
        return;
    }
    if service && lower.starts_with("gunicorn") && ext == "py" {
        acc.listeners.insert(rp.to_string());
    }
    if SHIPPER_NAMES.iter().any(|s| lower.contains(s))
        || (lower.starts_with("vector.") && matches!(ext, "toml" | "yaml" | "yml"))
    {
        acc.log_shipping.insert(rp.to_string());
    }
    match ext {
        "go" | "py" => source(path, rp, ext, service, acc),
        _ if JS_EXTS.contains(&ext) && !name.ends_with(".d.ts") => {
            source(path, rp, ext, service, acc)
        }
        "yaml" | "yml" => {
            let text = read_capped(path);
            if SHIPPER_IMAGES.iter().any(|i| text.contains(i)) {
                acc.log_shipping.insert(rp.to_string());
            }
            if service && alert_rules(&text) {
                acc.alert_rules.insert(rp.to_string());
            }
        }
        "tf" if service => {
            let text = read_capped(path);
            if SENTRY_ALERTS.iter().any(|r| text.contains(r)) {
                acc.alert_rules.insert(rp.to_string());
            }
        }
        _ => {}
    }
}

/// Whether `text` names a tracker SDK. A name that starts or ends with a
/// letter or digit must not run on into another there: `rollbar` is not in
/// `scrollbar`, a CSS and UI word.
fn has_sdk(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    TRACKER_SDKS.iter().any(|s| {
        let (first, last) = (s.chars().next(), s.chars().last());
        text.match_indices(s).any(|(i, _)| {
            !(word(first) && word(text[..i].chars().last()))
                && !(word(last) && word(text[i + s.len()..].chars().next()))
        })
    })
}

fn source(path: &Path, rp: &str, ext: &str, service: bool, acc: &mut Acc) {
    let text = read_capped(path);
    if has_sdk(&text) {
        acc.tracker_sdks.insert(rp.to_string());
        let inits = TRACKER_INITS
            .iter()
            .filter(|(exts, _)| exts.contains(&ext))
            .flat_map(|(_, calls)| calls.iter());
        if service && inits.into_iter().any(|c| text.contains(c)) {
            acc.tracker_inits.insert(rp.to_string());
        }
    }
    if ext == "go" && !go_built(&text) {
        return;
    }
    if service && listens(&text, ext) {
        acc.listeners.insert(rp.to_string());
    }
    if ext == "go" {
        if !go_main(&text) {
            // An httptest server is a test helper's, not the binary's.
            if go_serves(&text) && !text.contains("httptest.") {
                acc.go_servers.insert(rp.to_string());
            }
        } else if service {
            let dir = rp.rsplit_once('/').map_or("", |(d, _)| d);
            acc.go_mains.insert(dir.to_string());
        }
    }
}

/// A server entry point in a source file of extension `ext`.
fn listens(text: &str, ext: &str) -> bool {
    match ext {
        "go" => go_main(text) && go_serves(text),
        "py" => {
            text.contains("uvicorn.run(")
                || (text.contains("app.run(")
                    && (text.contains("Flask(") || text.contains("FastAPI(")))
                || ((text.contains("from http.server import")
                    || text.contains("import http.server"))
                    && (text.contains("HTTPServer((") || text.contains(".serve_forever(")))
        }
        _ => text.lines().any(|l| {
            l.contains("app.listen(") || (l.contains("createServer(") && l.contains(".listen("))
        }),
    }
}

/// Whether a Go source is ever built: `//go:build ignore` or `none` keeps a
/// file (a dev helper, a generator) out of every build.
fn go_built(text: &str) -> bool {
    !text
        .lines()
        .any(|l| matches!(l.trim(), "//go:build ignore" | "//go:build none"))
}

fn go_main(text: &str) -> bool {
    text.lines().any(|l| l.trim() == "package main")
}

/// A Go source that starts a server.
fn go_serves(text: &str) -> bool {
    text.contains("ListenAndServe(")
        || text.contains("ListenAndServeTLS(")
        || text.contains("net.Listen(")
        || ((text.contains("grpc.NewServer(") || text.contains("http.Server{"))
            && text.contains(".Serve("))
}

/// Whether the Go server outside `package main` at `rp` is a served
/// binary's own, given the directories of `package main` files in service
/// code (`mains`). It is when it sits below a `main` under a `cmd/<name>/`
/// directory (the command's own packages), or under an `internal/`
/// directory in service code whose parent's tree holds a `main`: Go lets
/// only that tree import an `internal/` package, so its server is not a
/// library's API for others.
fn delegated(rp: &str, mains: &BTreeSet<String>) -> bool {
    let in_cmd = mains.iter().any(|m| {
        let parts: Vec<&str> = m.split('/').collect();
        parts.len() >= 2 && parts[parts.len() - 2] == "cmd" && rp.starts_with(&format!("{m}/"))
    });
    let dirs: Vec<&str> = rp.split('/').collect();
    let in_internal = in_service_code(rp)
        && dirs[..dirs.len() - 1]
            .iter()
            .position(|d| *d == "internal")
            .is_some_and(|i| {
                let root = dirs[..i].join("/");
                mains
                    .iter()
                    .any(|m| root.is_empty() || *m == root || m.starts_with(&format!("{root}/")))
            });
    in_cmd || in_internal
}

/// A `package.json` whose `start` script runs `next start`: a Next.js
/// server. A sibling `next.config.*` with `output: 'export'` builds static
/// files that `next start` does not serve, so it does not count.
fn next_server(text: &str, path: &Path) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    let start = v
        .pointer("/scripts/start")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    if !start.contains("next start") {
        return false;
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    !["js", "mjs", "cjs", "ts"].iter().any(|e| {
        let config: String = read_capped(&dir.join(format!("next.config.{e}")))
            .split_whitespace()
            .collect();
        config.contains("output:'export'") || config.contains("output:\"export\"")
    })
}

/// A Prometheus alerting-rule file: a `PrometheusRule` resource, or a rule
/// file with `groups:` and an `alert:` rule.
fn alert_rules(text: &str) -> bool {
    let line_is = |p: &str| {
        text.lines()
            .any(|l| l.trim_start().trim_start_matches("- ").starts_with(p))
    };
    text.lines().any(|l| l.trim_end() == "kind: PrometheusRule")
        || (line_is("groups:") && line_is("alert:"))
}

const CONTROL: &str = "RC-027";
const CONTROL_NAME: &str = "error reporting";

/// What the violation's absence claim searched.
const SEARCHED: &str = "no error-tracker SDK (sentry, bugsnag, rollbar, honeybadger, airbrake) \
                        in non-test source or dependency manifests, and no log-shipping config \
                        (fluent-bit, fluentd, vector, promtail, otel-collector)";

/// RC-027 from the facts. Satisfies (partially: alert rules on new or
/// spiking error patterns are not read) on a tracker init and an alert rule
/// file; violates on a server with no tracker and no log shipping in a
/// completely walked tree of a repository read as a service; abstains
/// otherwise.
pub(crate) fn evaluate(facts: &RepoStructure) -> StructureFinding {
    crate::only_in_a_service(from_the_tree(facts), &facts.repo_kind)
}

/// RC-027 from the tree's error-reporting facts alone, before the
/// repository's kind is read.
fn from_the_tree(facts: &RepoStructure) -> StructureFinding {
    let e = &facts.error_reporting;
    let mk = |verdict, reason: String, evidence: Vec<String>| StructureFinding {
        control: CONTROL,
        control_name: CONTROL_NAME,
        verdict,
        reason,
        evidence,
        fix: "initialise an error tracker (Sentry, Bugsnag, Rollbar) in each service's entry \
              point and commit alert rules on new or spiking errors"
            .into(),
        severity: "medium",
        weak: false,
    };
    if !e.tracker_inits.is_empty() && !e.alert_rules.is_empty() {
        return mk(
            Verdict::Satisfies,
            format!(
                "partial: an error tracker is initialised ({}) and alert rule files are \
                 committed ({}); whether the rules alert on new or spiking errors is not read",
                e.tracker_inits.join(", "),
                e.alert_rules.join(", ")
            ),
            [e.tracker_inits.clone(), e.alert_rules.clone()].concat(),
        );
    }
    if e.listeners.is_empty() {
        return mk(
            Verdict::Abstain,
            "no listening server in non-test code: a library or a CLI".into(),
            vec![],
        );
    }
    if !e.tracker_sdks.is_empty() || !e.log_shipping.is_empty() {
        let mut seen = Vec::new();
        if !e.tracker_sdks.is_empty() {
            seen.push(format!("error-tracker SDK ({})", e.tracker_sdks.join(", ")));
        }
        if !e.log_shipping.is_empty() {
            seen.push(format!(
                "log-shipping config ({})",
                e.log_shipping.join(", ")
            ));
        }
        let rules = if e.alert_rules.is_empty() {
            "no alert rule file"
        } else {
            "alert rule files but no tracker init in service code"
        };
        return mk(
            Verdict::Abstain,
            format!("{} present, {rules}", seen.join(" and ")),
            vec![],
        );
    }
    if !facts.walk_complete {
        return mk(
            Verdict::Abstain,
            "walk truncated: absence of an error tracker is not evidence".into(),
            vec![],
        );
    }
    mk(
        Verdict::Violates,
        format!(
            "a listening server in non-test code ({}) and {SEARCHED}",
            e.listeners.join(", ")
        ),
        e.listeners.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inventory of a tree of `(path, text)` files.
    fn facts(files: &[(&str, &str)]) -> RepoStructure {
        let dir = tempfile::tempdir().unwrap();
        for (rp, text) in files {
            let path = dir.path().join(rp);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        crate::inventory(dir.path())
    }

    /// RC-027 on a tree, read from its error-reporting facts alone: what the
    /// tree says before the repository's kind gates a violation.
    fn judge(files: &[(&str, &str)]) -> StructureFinding {
        from_the_tree(&facts(files))
    }

    fn assert_verdict(want: Verdict, files: &[(&str, &str)]) {
        let f = judge(files);
        assert_eq!(f.verdict, want, "{:?}: {}", files[0].0, f.reason);
    }

    const GO_MOD: (&str, &str) = ("go.mod", "module example.com/svc\n\ngo 1.22\n");

    const SERVER: (&str, &str) = (
        "main.go",
        "package main\n\nfunc main() { http.ListenAndServe(\":8080\", nil) }\n",
    );
    const DOCKERFILE: (&str, &str) = ("Dockerfile", "FROM scratch\nEXPOSE 8080\n");

    /// A violation stands only in a repository read as a service: a server
    /// entry point and a deployment manifest.
    #[test]
    fn only_a_deployed_service_violates() {
        let f = evaluate(&facts(&[GO_MOD, SERVER, DOCKERFILE]));
        assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
        assert_eq!(f.evidence, ["main.go"]);

        // A server and no deployment manifest: not read as a service.
        let f = evaluate(&facts(&[GO_MOD, SERVER]));
        assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
        assert!(
            f.reason.starts_with("no deployment manifest found"),
            "{f:?}"
        );
        assert!(f.reason.contains("main.go"), "{f:?}");

        // A CLI main only.
        let cli = ("main.go", "package main\n\nfunc main() { flag.Parse() }\n");
        let f = evaluate(&facts(&[GO_MOD, cli, DOCKERFILE]));
        assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");

        // A tool by its own account, deployed or not.
        let readme = ("README.md", "A vulnerability scanner for Go modules.\n");
        let f = evaluate(&facts(&[GO_MOD, SERVER, DOCKERFILE, readme]));
        assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
        assert!(
            f.reason
                .starts_with("the repository reads as a tool (README says"),
            "{f:?}"
        );

        // A satisfied repository stays satisfied whatever its kind.
        let f = evaluate(&facts(&[
            GO_MOD,
            (
                "main.go",
                "package main\n\nimport \"github.com/getsentry/sentry-go\"\n\nfunc main() { sentry.Init(o) }\n",
            ),
            ("deploy/rules.yaml", "groups:\n  - rules:\n      - alert: Errors\n"),
        ]));
        assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
    }

    #[test]
    fn an_sdk_name_matches_as_a_whole_word() {
        for text in [
            "<ScrollAreaPrimitive.ScrollAreaScrollbar>",
            "<nav className=\"scrollbar-none flex h-11\">",
            "// add right margin so scrollbar doesn't touch browser panel",
        ] {
            assert!(!has_sdk(text), "{text}");
        }
        for text in [
            "import * as Rollbar from \"rollbar\";",
            "\"rollbar\": \"^2.26.0\",",
            "rollbar.init(\"token\")",
            "\"@sentry/node\": \"^8\"",
            "import sentry_sdk",
            "github.com/getsentry/sentry-go v0.27.0",
            "github.com/airbrake/gobrake/v5",
            "@bugsnag/js",
        ] {
            assert!(has_sdk(text), "{text}");
        }
    }

    #[test]
    fn a_scrollbar_beside_a_server_is_not_a_tracker() {
        // A Go server with a web UI (graphjin).
        assert_verdict(
            Verdict::Violates,
            &[
                (
                    "serv/web/src/components/ui/scroll-area.jsx",
                    "<ScrollAreaPrimitive.ScrollAreaScrollbar>\n</ScrollAreaPrimitive.ScrollAreaScrollbar>\n",
                ),
                (
                    "serv/web/src/components/Layout/Header.jsx",
                    "<nav className=\"scrollbar-none flex h-11\">\n",
                ),
                GO_MOD,
                (
                    "main.go",
                    "package main\n\nfunc main() { http.ListenAndServe(\":8080\", nil) }\n",
                ),
            ],
        );
        // A Python server with a TypeScript front end (magentic-ui).
        assert_verdict(
            Verdict::Violates,
            &[
                (
                    "frontend/src/components/chat/ChatView.tsx",
                    "// In expanded mode, add right margin so scrollbar doesn't touch browser panel\n",
                ),
                (
                    "src/magentic_ui/backend/cli.py",
                    "import uvicorn\n\ndef run():\n    uvicorn.run(\"app:app\")\n",
                ),
            ],
        );
    }

    #[test]
    fn a_go_main_that_delegates_its_listener_is_a_service() {
        // tusd: cmd/tusd/main.go calls cli.Serve().
        assert_verdict(
            Verdict::Violates,
            &[
                (
                    "cmd/tusd/main.go",
                    "package main\n\nimport (\n\t\"github.com/tus/tusd/v2/cmd/tusd/cli\"\n)\n\n\
                     func main() {\n\tcli.ParseFlags()\n\tcli.CreateComposer()\n\tcli.Serve()\n}\n",
                ),
                (
                    "cmd/tusd/cli/listener.go",
                    "package cli\n\nfunc NewListener(addr string) (net.Listener, error) {\n\
                     \treturn net.Listen(\"tcp\", addr)\n}\n",
                ),
                ("cmd/tusd/cli/serve.go", "package cli\n\nfunc Serve() {}\n"),
                GO_MOD,
            ],
        );
        // gluetun: the server runs in an internal package.
        assert_verdict(
            Verdict::Violates,
            &[
                (
                    "cmd/gluetun/main.go",
                    "package main\n\nfunc main() { run() }\n",
                ),
                (
                    "internal/httpserver/run.go",
                    "package httpserver\n\nfunc (s *Server) Run(ctx context.Context) {\n\
                     \tserver := http.Server{\n\t\tAddr: s.address,\n\t\tHandler: s.handler,\n\t}\n\
                     \terr = server.Serve(listener)\n}\n",
                ),
                GO_MOD,
            ],
        );
    }

    #[test]
    fn a_go_library_still_abstains() {
        let server = "package lib\n\nfunc (e *Engine) Run() { http.ListenAndServe(a, e) }\n";
        for files in [
            // A framework's listen helper, no main (gin, resty, cobra).
            &[GO_MOD, ("gin.go", server)][..],
            // A main in examples/ only (bubbletea).
            &[
                GO_MOD,
                ("lib.go", server),
                ("examples/demo/main.go", "package main\n"),
            ],
            // A CLI main beside a public package that serves (gosec).
            &[
                GO_MOD,
                ("cmd/gosec/main.go", "package main\n"),
                ("server/server.go", server),
            ],
            // An internal server no main in its tree can import.
            &[
                GO_MOD,
                ("cmd/tool/main.go", "package main\n"),
                ("pkg/internal/srv/srv.go", server),
            ],
            // A dev helper no build compiles (rclone).
            &[
                GO_MOD,
                (
                    "fs/rc/js/serve.go",
                    "//go:build none\n\npackage main\n\nfunc main() { http.ListenAndServe(\":3000\", m) }\n",
                ),
            ],
            // An httptest helper in an internal package (minio).
            &[
                GO_MOD,
                ("main.go", "package main\n"),
                (
                    "internal/grid/debug.go",
                    "package grid\n\nfunc start() { l, _ := net.Listen(\"tcp\", a); httptest.NewUnstartedServer(h) }\n",
                ),
            ],
            // A test server below a command.
            &[
                GO_MOD,
                ("cmd/tool/main.go", "package main\n"),
                ("cmd/tool/serve_test.go", server),
            ],
        ] {
            assert_verdict(Verdict::Abstain, files);
        }
    }

    #[test]
    fn an_http_server_from_the_standard_library_listens() {
        // hermes-webui.
        assert_verdict(
            Verdict::Violates,
            &[(
                "server.py",
                "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n\n\
                 class QuietHTTPServer(ThreadingHTTPServer):\n    pass\n\n\
                 def main():\n    _abort_if_already_serving(HOST, PORT)\n\
                 \x20   httpd = QuietHTTPServer((HOST, PORT), Handler)\n",
            )],
        );
        assert!(listens(
            "import http.server\ns = http.server.HTTPServer(addr, H)\ns.serve_forever()\n",
            "py"
        ));
        assert!(!listens(
            "from http.server import BaseHTTPRequestHandler\n",
            "py"
        ));
    }

    #[test]
    fn next_start_is_a_server_unless_exported() {
        let morphic = r#"{"scripts": {"dev": "next dev", "build": "next build", "start": "next start"},
            "dependencies": {"next": "^16.2.6"}}"#;
        let nextchat = r#"{"scripts": {"dev": "concurrently -r \"yarn run mask:watch\" \"next dev\"",
            "start": "next start"}, "dependencies": {"next": "^14.1.1"}}"#;
        for pkg in [morphic, nextchat] {
            assert_verdict(Verdict::Violates, &[("package.json", pkg)]);
        }
        assert_verdict(
            Verdict::Abstain,
            &[
                ("package.json", morphic),
                (
                    "next.config.mjs",
                    "export default {\n  output: 'export',\n}\n",
                ),
            ],
        );
        // With a tracker in the manifest it is not a violation.
        let tracked =
            r#"{"scripts": {"start": "next start"}, "dependencies": {"@sentry/nextjs": "^8"}}"#;
        assert_verdict(Verdict::Abstain, &[("package.json", tracked)]);
        // A library's dev script is not a server.
        let lib = r#"{"scripts": {"dev": "next dev", "start": "node dist/cli.js"}}"#;
        assert_verdict(Verdict::Abstain, &[("package.json", lib)]);
    }

    #[test]
    fn a_go_listener_counts_only_in_package_main() {
        let main = "package main\n\nfunc main() { http.ListenAndServe(\":80\", nil) }\n";
        assert!(listens(main, "go"));
        let lib = "package gin\n\nfunc (e *Engine) Run() { http.ListenAndServe(a, e) }\n";
        assert!(!listens(lib, "go"));
        let grpc = "package main\nfunc main() { s := grpc.NewServer(); s.Serve(l) }\n";
        assert!(listens(grpc, "go"));
    }

    #[test]
    fn python_and_js_listeners() {
        assert!(listens("import uvicorn\nuvicorn.run(app)\n", "py"));
        assert!(listens("app = Flask(__name__)\napp.run()\n", "py"));
        assert!(
            !listens("app.run()\n", "py"),
            "app.run alone is not a server"
        );
        assert!(listens("app.listen(3000)\n", "ts"));
        assert!(listens("http.createServer(h).listen(80)\n", "js"));
        // A framework's listen helper splits the two: not a service entry point.
        assert!(!listens(
            "const server = http.createServer(this.callback());\nreturn server.listen(...args);\n",
            "js"
        ));
    }

    #[test]
    fn alert_rule_files() {
        assert!(alert_rules(
            "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\n"
        ));
        assert!(alert_rules(
            "groups:\n  - name: api\n    rules:\n      - alert: HighErrorRate\n"
        ));
        assert!(!alert_rules(
            "groups:\n  - name: api\n    rules:\n      - record: x\n"
        ));
    }
}
