//! Liveness probe joined to its handler (po-6c0v8.5): a Kubernetes liveness
//! probe whose HTTP handler calls a dependency.
//!
//! A liveness probe that fails restarts the container. When its handler calls
//! a database or another service, an outage of that dependency restarts every
//! replica at once, and a restart does not bring the dependency back.
//!
//! What this detects, and nothing more: a liveness probe `httpGet` path from
//! a manifest IN THIS REPOSITORY, joined to a route registered IN THIS
//! REPOSITORY, whose handler function holds a G1 I/O call site. Both sides
//! are retrieval facts, so no spec is consulted.
//!
//! The join abstains whenever a link is not resolved:
//!   * no route with a literal path matches the probe path (the handler is in
//!     another repository, or its path is not a literal)
//!   * more than one registration matches
//!   * the handler is an inline function, or not a plain reference
//!   * call sites in a function of that name are found in more than one file
//!   * the handler holds no inventoried I/O call site. This is NOT a pass:
//!     only direct containment is read, so I/O the handler reaches through
//!     another function is not seen.

use crate::server_entry::{is_middleware_attachment, route_paths};
use rvl_core::{Site, Verdict, SITE_KIND_SERVER_ENTRY};
use std::collections::{BTreeMap, BTreeSet};

/// A liveness probe's `httpGet` path, as the config lane resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessProbe {
    /// Repo-relative manifest the probe was read from.
    pub file_path: String,
    /// The container it belongs to, in the config packet `unit` vocabulary.
    pub unit: String,
    /// The path the kubelet requests.
    pub path: String,
}

/// The function a route registration hands requests to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handler {
    /// A named function, with the `file:line` of each G1 I/O call site it
    /// holds (none when the inventory has no call site in it).
    Named { name: String, io_sites: Vec<String> },
    /// The handler could not be tied to one function. Carries the reason.
    Unresolved(String),
}

/// One route registration with a literal path, and its handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHandler {
    /// `file:line` of the registration.
    pub site: String,
    /// The literal route paths the registration carries.
    pub paths: Vec<String>,
    pub handler: Handler,
}

/// The outcome of the join for one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHandlerFinding {
    pub probe: LivenessProbe,
    /// `Violates` when the resolved handler holds an I/O call site, `Abstain`
    /// otherwise. There is no `Satisfies`: see the module comment.
    pub verdict: Verdict,
    pub reason: String,
    /// On a violation: the handler's I/O call sites, `file:line`.
    pub evidence: Vec<String>,
}

/// The ladder class of a violation, and its waiver key.
pub const CLASS_RULE: &str = "server_entry.liveness-probe-handler-io";
/// The control a violation is reported on: health checks.
pub const CONTROL: &str = "RC-020";
/// Base severity of a violation. Advisory, like the rest of the server-entry
/// lane: the join reads one function and cannot see a timeout or a cache.
pub const SEVERITY: &str = "medium";
/// Suggested fix for a violation.
pub const FIX: &str = "keep the liveness handler free of calls to a database or another \
    service: an outage of the dependency restarts every replica, and a restart does not \
    bring the dependency back. Check dependencies in the readiness probe";

/// Every violation in one scan, as the single class the ladder shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeHandlerClass {
    pub description: String,
    /// The handlers' I/O call sites, `file:line`, sorted, each once.
    pub sites: Vec<String>,
}

/// Collapse the violations among `findings` into one class, however many
/// probes and handlers repeat it. `None` when nothing violates: an
/// abstention never surfaces.
pub fn class_of(findings: &[ProbeHandlerFinding]) -> Option<ProbeHandlerClass> {
    let hits: Vec<&ProbeHandlerFinding> = findings
        .iter()
        .filter(|f| f.verdict == Verdict::Violates)
        .collect();
    let first = hits.first()?;
    let sites: BTreeSet<&String> = hits.iter().flat_map(|f| &f.evidence).collect();
    let more = match hits.len() - 1 {
        0 => String::new(),
        n => format!(" (and {n} more probe(s))"),
    };
    Some(ProbeHandlerClass {
        description: format!(
            "liveness probe handler calls a dependency \u{2014} {} [{} ({})]{more}",
            first.reason, first.probe.file_path, first.probe.unit
        ),
        sites: sites.into_iter().cloned().collect(),
    })
}

/// Inventory every route registration that carries a literal path, with the
/// handler it names. `registrations` holds the server-entry records, and
/// `call_sites` the G1 call sites a handler is checked for. A record of
/// another kind in either slice is ignored.
pub fn route_handlers(registrations: &[Site], call_sites: &[Site]) -> Vec<RouteHandler> {
    // Indexed once: a repository has thousands of routes and many more calls.
    let mut by_symbol: BTreeMap<&str, Vec<&Site>> = BTreeMap::new();
    for s in call_sites.iter().filter(|s| s.is_call_site()) {
        by_symbol.entry(s.symbol.as_str()).or_default().push(s);
    }
    registrations
        .iter()
        .filter(|s| s.site_kind == SITE_KIND_SERVER_ENTRY && !is_middleware_attachment(s))
        .filter_map(|reg| {
            let paths = route_paths(reg);
            (!paths.is_empty()).then(|| RouteHandler {
                site: reg.id(),
                handler: resolve_handler(reg, &paths, &by_symbol),
                paths,
            })
        })
        .collect()
}

/// Tie a registration to one named function and the I/O call sites in it.
fn resolve_handler(
    reg: &Site,
    paths: &[String],
    by_symbol: &BTreeMap<&str, Vec<&Site>>,
) -> Handler {
    // A decorator registers the function it decorates, and the retriever
    // stamps that function as the record's symbol. It is in the same file.
    let decorated = reg.snippet.trim_start().starts_with('@');
    let name = if decorated {
        reg.symbol.clone()
    } else {
        handler_reference(&reg.snippet, paths).unwrap_or_default()
    };
    if name.is_empty() {
        return Handler::Unresolved(
            "the registration does not name its handler as a plain reference".into(),
        );
    }
    let io: Vec<&Site> = by_symbol
        .get(name.as_str())
        .into_iter()
        .flatten()
        .copied()
        .filter(|s| s.lang.is_empty() || reg.lang.is_empty() || s.lang == reg.lang)
        .filter(|s| !decorated || s.file_path == reg.file_path)
        .collect();
    // The symbol is a bare name. Two functions of that name in two files
    // cannot be told apart, and one of them is not the handler.
    let files: BTreeSet<&str> = io.iter().map(|s| s.file_path.as_str()).collect();
    if files.len() > 1 {
        return Handler::Unresolved(format!(
            "call sites in a function named {name} are in more than one file"
        ));
    }
    let io_sites: BTreeSet<String> = io.iter().map(|s| s.id()).collect();
    Handler::Named {
        name,
        io_sites: io_sites.into_iter().collect(),
    }
}

/// The name of the function a call-form registration hands requests to: the
/// last positional argument of the call that carries the route path, when it
/// is a plain reference (`health`, `h.Health`) or a one-argument wrapper
/// around one (`http.HandlerFunc(health)`, `get(health)`). `None` for an
/// inline function, a call that builds a handler, or a snippet in which the
/// path literal is not in exactly one argument list.
fn handler_reference(snippet: &str, paths: &[String]) -> Option<String> {
    let is_path = |arg: &str| {
        let lit = arg.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        lit.len() < arg.len() && paths.iter().any(|p| p == lit)
    };
    let mut carrying = call_argument_lists(snippet)
        .into_iter()
        .filter(|args| args.iter().any(|a| is_path(a)));
    let args = carrying.next()?;
    if carrying.next().is_some() {
        return None;
    }
    let last = args.iter().rev().find(|a| !is_keyword_argument(a))?;
    match last.strip_suffix(')').and_then(|l| l.split_once('(')) {
        Some((wrapper, inner)) => {
            reference_name(wrapper)?;
            reference_name(inner.trim())
        }
        None => reference_name(last),
    }
}

/// The last segment of a dotted identifier path, or `None` when `text` is
/// anything else.
fn reference_name(text: &str) -> Option<String> {
    let is_ident = |seg: &str| {
        let mut chars = seg.chars();
        chars
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_' || c == '$')
            && chars.all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    };
    let segments: Vec<&str> = text.split('.').flat_map(|s| s.split("::")).collect();
    segments
        .iter()
        .all(|s| is_ident(s))
        .then(|| segments[segments.len() - 1].to_string())
}

/// `name=value`, as Python writes a keyword argument.
fn is_keyword_argument(arg: &str) -> bool {
    arg.split_once('=').is_some_and(|(name, rest)| {
        reference_name(name.trim()).is_some() && !rest.starts_with(['=', '>'])
    })
}

/// The arguments of every call in `text` that is not nested in another call,
/// each trimmed and split at its top-level commas. String literals and
/// bracketed groups are kept whole.
fn call_argument_lists(text: &str) -> Vec<Vec<String>> {
    let mut lists = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let mut arg = String::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            arg.push(c);
            if c == '\\' {
                arg.extend(chars.next());
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' | '`' => quote = Some(c),
            '(' | '[' | '{' => {
                depth += 1;
                if depth == 1 && c == '(' {
                    arg.clear();
                    continue;
                }
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if c == ')' {
                        args.push(std::mem::take(&mut arg));
                        lists.push(
                            std::mem::take(&mut args)
                                .iter()
                                .map(|a| a.trim().to_string())
                                .filter(|a| !a.is_empty())
                                .collect(),
                        );
                    }
                    continue;
                }
            }
            ',' if depth == 1 => {
                args.push(std::mem::take(&mut arg));
                continue;
            }
            _ => {}
        }
        if depth > 0 {
            arg.push(c);
        }
    }
    lists
}

/// A path with its query, fragment and outer slashes removed.
fn normalized(path: &str) -> &str {
    let end = path.find(['?', '#']).unwrap_or(path.len());
    path[..end].trim_matches('/')
}

/// Join each liveness probe to the route that serves its path. One finding
/// per probe, in probe order.
pub fn join(probes: &[LivenessProbe], routes: &[RouteHandler]) -> Vec<ProbeHandlerFinding> {
    probes
        .iter()
        .map(|probe| {
            let (verdict, reason, evidence) = judge(&probe.path, routes);
            ProbeHandlerFinding {
                probe: probe.clone(),
                verdict,
                reason,
                evidence,
            }
        })
        .collect()
}

fn judge(path: &str, routes: &[RouteHandler]) -> (Verdict, String, Vec<String>) {
    let want = normalized(path);
    let serving = |serves: &dyn Fn(&str) -> bool| -> Vec<&RouteHandler> {
        routes
            .iter()
            .filter(|r| r.paths.iter().any(|p| serves(normalized(p))))
            .collect()
    };
    let mut matched = serving(&|p| p == want);
    if matched.is_empty() {
        // A router mounted under a prefix: a whole-segment suffix, so
        // `/healthz` serves `/api/healthz` and does not serve `/myhealthz`.
        matched = serving(&|p| {
            !p.is_empty() && want.strip_suffix(p).is_some_and(|rest| rest.ends_with('/'))
        });
    }
    let abstain = |reason: String| (Verdict::Abstain, reason, Vec::new());
    let route = match matched.as_slice() {
        [] => {
            return abstain(format!(
                "no route with a literal path serves {path}; the handler is in another \
                 repository or its path is not a literal"
            ))
        }
        [one] => one,
        many => {
            return abstain(format!(
                "{} route registrations serve {path}; the handler is not determined",
                many.len()
            ))
        }
    };
    match &route.handler {
        Handler::Unresolved(why) => abstain(format!(
            "the handler of {} is not resolved: {why}",
            route.site
        )),
        Handler::Named { name, io_sites } if io_sites.is_empty() => abstain(format!(
            "no inventoried I/O call site in handler {name} ({}); I/O that it reaches \
             through another function is not traced",
            route.site
        )),
        Handler::Named { name, io_sites } => (
            Verdict::Violates,
            format!(
                "liveness probe path {path} is served by {name} ({}), which holds {} I/O \
                 call site(s)",
                route.site,
                io_sites.len()
            ),
            io_sites.clone(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_core::ConstArg;

    fn route(file: &str, line: u32, symbol: &str, snippet: &str) -> Site {
        Site {
            file_path: file.into(),
            line_number: line,
            symbol: symbol.into(),
            method: "HandleFunc".into(),
            client_type: "net/http.ServeMux".into(),
            snippet: snippet.into(),
            site_kind: SITE_KIND_SERVER_ENTRY.into(),
            lang: "go".into(),
            ..Default::default()
        }
    }

    fn io(file: &str, line: u32, symbol: &str) -> Site {
        Site {
            file_path: file.into(),
            line_number: line,
            symbol: symbol.into(),
            method: "PingContext".into(),
            client_type: "database/sql.DB".into(),
            snippet: "db.PingContext(ctx)".into(),
            lang: "go".into(),
            ..Default::default()
        }
    }

    fn probe(path: &str) -> LivenessProbe {
        LivenessProbe {
            file_path: "k8s/deploy.yaml".into(),
            unit: "container:deployment/web/app".into(),
            path: path.into(),
        }
    }

    fn one(path: &str, sites: &[Site]) -> ProbeHandlerFinding {
        let mut got = join(&[probe(path)], &route_handlers(sites, sites));
        assert_eq!(got.len(), 1);
        got.remove(0)
    }

    #[test]
    fn a_liveness_handler_that_holds_an_io_site_is_a_finding() {
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            io("handlers.go", 22, "healthHandler"),
            io("handlers.go", 40, "usersHandler"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Violates, "{}", f.reason);
        assert_eq!(f.evidence, vec!["handlers.go:22"]);
        assert!(f.reason.contains("healthHandler"), "{}", f.reason);
        assert!(f.reason.contains("routes.go:10"), "{}", f.reason);
    }

    #[test]
    fn violations_collapse_into_one_class_and_abstentions_do_not_surface() {
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            io("handlers.go", 22, "healthHandler"),
        ];
        let routes = route_handlers(&sites, &sites);
        let got = join(
            &[probe("/healthz"), probe("/api/healthz"), probe("/x")],
            &routes,
        );
        let class = class_of(&got).unwrap();
        assert_eq!(class.sites, vec!["handlers.go:22"]);
        assert!(
            class.description.contains("k8s/deploy.yaml")
                && class.description.contains("1 more probe"),
            "{}",
            class.description
        );
        assert_eq!(class_of(&join(&[probe("/x")], &routes)), None);
    }

    #[test]
    fn a_probe_path_no_route_serves_abstains() {
        // The handler may be in another repository, or behind a path that is
        // not a literal. Neither is evidence about this repository's code.
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/users", usersHandler)"#,
            ),
            route("routes.go", 11, "routes", "mux.HandleFunc(cfg.Health, h)"),
            io("handlers.go", 40, "usersHandler"),
            io("handlers.go", 50, "h"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("no route"), "{}", f.reason);
        assert!(f.evidence.is_empty());
    }

    #[test]
    fn no_server_entry_inventory_abstains() {
        let f = one("/healthz", &[io("handlers.go", 22, "healthHandler")]);
        assert_eq!(f.verdict, Verdict::Abstain);
    }

    #[test]
    fn an_inline_handler_abstains() {
        // The I/O site's symbol is the registering function, which holds
        // every other closure too. Nothing ties the call to this route.
        let sites = vec![
            route(
                "main.go",
                10,
                "main",
                r#"mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { db.Ping() })"#,
            ),
            io("main.go", 10, "main"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("handler"), "{}", f.reason);
    }

    #[test]
    fn a_handler_with_no_io_site_abstains_and_is_not_a_pass() {
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            io("handlers.go", 40, "usersHandler"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("healthHandler"), "{}", f.reason);
    }

    #[test]
    fn a_handler_name_found_in_two_files_abstains() {
        // `h.Health` names a method, and two types can each have one.
        let sites = vec![
            route("routes.go", 10, "routes", r#"r.Get("/healthz", h.Health)"#),
            io("api/handlers.go", 22, "Health"),
            io("admin/handlers.go", 9, "Health"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("more than one file"), "{}", f.reason);
    }

    #[test]
    fn two_registrations_for_the_path_abstain() {
        let sites = vec![
            route(
                "a/routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthA)"#,
            ),
            route(
                "b/routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthB)"#,
            ),
            io("a/h.go", 3, "healthA"),
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("2 route registrations"), "{}", f.reason);
    }

    #[test]
    fn the_last_reference_is_the_handler_and_wrappers_and_methods_resolve() {
        // Middleware comes before the handler.
        let sites = vec![
            route(
                "r.go",
                1,
                "routes",
                r#"r.GET("/livez", authMiddleware, h.Live)"#,
            ),
            io("h.go", 5, "Live"),
            io("mw.go", 7, "authMiddleware"),
        ];
        assert_eq!(one("/livez", &sites).evidence, vec!["h.go:5"]);

        // A one-argument conversion wraps the handler.
        let sites = vec![
            route(
                "r.go",
                1,
                "routes",
                r#"mux.Handle("/livez", http.HandlerFunc(live))"#,
            ),
            io("h.go", 5, "live"),
        ];
        assert_eq!(one("/livez", &sites).verdict, Verdict::Violates);

        // A keyword argument is not the handler (django).
        let mut django = route(
            "urls.py",
            3,
            "",
            r#"path("livez/", views.live, name="live")"#,
        );
        django.lang = "python".into();
        let mut call = io("views.py", 12, "live");
        call.lang = "python".into();
        assert_eq!(one("/livez", &[django, call]).verdict, Verdict::Violates);

        // A call that builds a handler is not a reference to one.
        let sites = vec![
            route(
                "r.go",
                1,
                "routes",
                r#"mux.Handle("/livez", newLive(db, cache))"#,
            ),
            io("h.go", 5, "newLive"),
        ];
        assert_eq!(one("/livez", &sites).verdict, Verdict::Abstain);
    }

    #[test]
    fn a_decorated_handler_is_the_function_in_the_same_file() {
        // The Python helper stamps the decorated function as the symbol.
        let mut dec = route("app.py", 8, "livez", "@app.get('/livez')");
        dec.lang = "python".into();
        dec.const_args = vec![ConstArg {
            index: 0,
            name: String::new(),
            value: "'/livez'".into(),
            how: "literal".into(),
        }];
        let mut same = io("app.py", 10, "livez");
        same.lang = "python".into();
        let mut other = io("other.py", 4, "livez");
        other.lang = "python".into();
        let f = one("/livez", &[dec, same, other]);
        assert_eq!(f.verdict, Verdict::Violates, "{}", f.reason);
        assert_eq!(f.evidence, vec!["app.py:10"]);
    }

    #[test]
    fn a_call_site_in_another_language_is_not_the_handler() {
        let mut py = io("tools/health.py", 4, "healthHandler");
        py.lang = "python".into();
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            py,
        ];
        assert_eq!(one("/healthz", &sites).verdict, Verdict::Abstain);
    }

    #[test]
    fn a_prefix_mounted_route_serves_the_longer_probe_path() {
        let sites = vec![
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            io("handlers.go", 22, "healthHandler"),
        ];
        assert_eq!(one("/api/healthz", &sites).verdict, Verdict::Violates);
        assert_eq!(one("/healthz?full=1", &sites).verdict, Verdict::Violates);
        assert_eq!(one("/myhealthz", &sites).verdict, Verdict::Abstain);
    }

    #[test]
    fn middleware_and_non_io_records_are_never_the_handler_evidence() {
        let mut job = io("handlers.go", 22, "healthHandler");
        job.site_kind = "background_job".into();
        let mut mw = route("routes.go", 9, "routes", r#"r.Use("/healthz", limiter)"#);
        mw.method = "Use".into();
        let sites = vec![
            mw,
            route(
                "routes.go",
                10,
                "routes",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
            ),
            job,
        ];
        let f = one("/healthz", &sites);
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
        assert!(f.reason.contains("healthHandler"), "{}", f.reason);
    }
}
