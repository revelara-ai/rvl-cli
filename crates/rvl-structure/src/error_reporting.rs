//! RC-027 error-reporting facts and verdict: whether a repository that runs a
//! listening server reports its errors to a central system, with alert rules
//! on top.
//!
//! RETRIEVAL ([`observe`]) records presence only, as repo-relative paths: a
//! server entry point, an error-tracker SDK reference, a tracker init, a
//! log-shipping config, an alert-rule file. JUDGEMENT ([`evaluate`]) decides
//! the two cases a tree proves and abstains on the rest. It violates only
//! when a server runs and the tree holds no tracker SDK and no log shipping
//! at all: a tracker wired in elsewhere is a claim no file here can refute,
//! so every presence the search can see counts against a violation. It
//! satisfies only when a tracker is initialised in service code and an alert
//! rule file is committed.
//!
//! The server entry points are narrower than [`crate::repo_kind`]'s, on
//! purpose: a framework that wraps `ListenAndServe` in a library function
//! has no tracker of its own and is not a service, so a Go listener counts
//! only in `package main`, and a JS listener only as `app.listen(` or a
//! `createServer(...).listen(` chain on one line.

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
}

impl Acc {
    pub(crate) fn finish(self) -> ErrorReportingFacts {
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
        if has_sdk(&read_capped(path)) {
            acc.tracker_sdks.insert(rp.to_string());
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

fn has_sdk(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    TRACKER_SDKS.iter().any(|s| text.contains(s))
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
    if service && listens(&text, ext) {
        acc.listeners.insert(rp.to_string());
    }
}

/// A server entry point in a source file of extension `ext`.
fn listens(text: &str, ext: &str) -> bool {
    match ext {
        "go" => {
            text.lines().any(|l| l.trim() == "package main")
                && (text.contains("ListenAndServe(")
                    || text.contains("ListenAndServeTLS(")
                    || text.contains("net.Listen(")
                    || (text.contains("grpc.NewServer(") && text.contains(".Serve(")))
        }
        "py" => {
            text.contains("uvicorn.run(")
                || (text.contains("app.run(")
                    && (text.contains("Flask(") || text.contains("FastAPI(")))
        }
        _ => text.lines().any(|l| {
            l.contains("app.listen(") || (l.contains("createServer(") && l.contains(".listen("))
        }),
    }
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
/// completely walked tree; abstains otherwise.
pub(crate) fn evaluate(facts: &RepoStructure) -> StructureFinding {
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
