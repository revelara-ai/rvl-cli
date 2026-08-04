//! G2 server-entry lane: evaluate the server-entry inventory against the
//! controls that ride it (po-av01j.3).
//!
//! The typed retrievers inventory HTTP handler registrations, route
//! definitions, and middleware-chain attachments as `Site` records stamped
//! `site_kind: "server_entry"`. This module maps that inventory to per-control
//! verdicts, spec-driven like the G1 lane: which route paths count as a
//! health endpoint and which middleware identities rate-limit are JUDGEMENT,
//! carried by `ServerSpec`s in the cache, never hard-coded here.
//!
//! Controls, per the granularity map:
//!   RC-020 health checks           [S] decidable from route paths
//!   RC-069 rate limiting           [S] decidable from middleware identities
//!   RC-018 graceful degradation    [J] the degraded-response half; presence
//!                                      of degradation middleware satisfies,
//!                                      absence is NEVER a violation (whether
//!                                      handlers degrade internally is a
//!                                      per-handler judgement)
//!
//! Abstention philosophy matches the structure lane: an absence is a
//! decidable negative only when the inventory could have contained the thing.
//! A route registered under a non-literal path could be the health endpoint,
//! so RC-020 abstains while any route path is unresolved.

use rvl_core::{Site, Verdict, SITE_KIND_SERVER_ENTRY};
use rvl_spec::{
    SpecCache, SERVER_KIND_DEGRADED_RESPONSE, SERVER_KIND_HEALTH_PATH, SERVER_KIND_RATE_LIMIT,
};

/// One control-mapped conclusion drawn from the server-entry inventory. The
/// evaluator emits one per control every time; the renderer decides what to
/// surface (mirrors `rvl_structure::StructureFinding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntryFinding {
    /// Control code, e.g. "RC-020".
    pub control: &'static str,
    /// Control name for display.
    pub control_name: &'static str,
    pub verdict: Verdict,
    pub reason: String,
    /// `file:line` evidence sites.
    pub evidence: Vec<String>,
    /// Suggested fix (shown on violates).
    pub fix: String,
    /// Base severity when this control violates ("medium"; empty for
    /// controls that never violate).
    pub severity: &'static str,
}

/// Registration verbs that attach middleware / mount sub-routers rather than
/// registering a path-bearing route. A mechanical fact about the method NAME
/// the retriever reported, used only to keep middleware attachments out of
/// RC-020's "every route path resolved" completeness question.
const MIDDLEWARE_METHODS: &[&str] = &[
    "use",
    "add_middleware",
    "middleware",
    "addhook",
    "register",
    "include_router",
    "mount",
    "before_request",
    "after_request",
];

fn is_middleware_attachment(site: &Site) -> bool {
    MIDDLEWARE_METHODS.contains(&site.method.to_ascii_lowercase().as_str())
}

/// A string literal that reads as a route path: leading-slash paths
/// (flask/fastapi/express/Go) or django's trailing-slash convention
/// (`path("users/", ...)`). A bare word is NOT a path — accepting one would
/// let a `name="health"` keyword argument satisfy RC-020, the false pass we
/// refuse.
fn is_pathish(s: &str) -> bool {
    s.starts_with('/') || (s.len() > 1 && s.ends_with('/'))
}

/// The literal route paths a registration carries. Primary source: the
/// schema-v2 constant arguments (each language's quoting stripped). Fallback
/// when no const arg resolved: quoted path strings in the snippet, so a
/// stream from a retriever without const-arg support still yields paths.
fn route_paths(site: &Site) -> Vec<String> {
    let mut out: Vec<String> = site
        .const_args
        .iter()
        .filter_map(|a| {
            let v = a.value.trim().trim_matches(|c| c == '"' || c == '\'');
            is_pathish(v).then(|| v.to_string())
        })
        .collect();
    if out.is_empty() {
        out = quoted_paths_in(&site.snippet);
    }
    out
}

/// Quoted string literals in `text` that read as route paths.
fn quoted_paths_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let q = bytes[i];
        if q == b'"' || q == b'\'' {
            if let Some(end) = text[i + 1..].find(q as char) {
                let inner = &text[i + 1..i + 1 + end];
                if is_pathish(inner) {
                    out.push(inner.to_string());
                }
                i += end + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Whether a route path counts as `pattern`. Case-insensitive over
/// slash-normalized forms (so django's `healthz/` matches `/healthz`);
/// equality or a SEGMENT-suffix match so a router mounted under a prefix
/// still counts (`/api/healthz` matches `/healthz`) while `/myhealthz` does
/// not.
fn path_matches(path: &str, pattern: &str) -> bool {
    let p = path.trim_matches('/').to_ascii_lowercase();
    let pat = pattern.trim_matches('/').to_ascii_lowercase();
    !pat.is_empty() && (p == pat || p.ends_with(&format!("/{pat}")))
}

/// The registration's identity text for middleware-pattern matching: the call
/// snippet plus the resolved framework type and method. Deliberately NOT the
/// enclosing function body — a comment or unrelated code near the
/// registration must not satisfy a control (a false pass on a reliability
/// property is the one error we refuse).
fn identity_text(site: &Site) -> String {
    format!("{} {} {}", site.snippet, site.client_type, site.method).to_ascii_lowercase()
}

/// Patterns of one spec kind, lowercased, from every usable server spec for
/// `control`.
fn patterns_for(specs: &SpecCache, control: &str, kind: &str) -> Vec<String> {
    specs
        .server_specs()
        .filter(|s| s.control == control && s.kind == kind)
        .flat_map(|s| s.patterns.iter())
        .map(|p| p.to_ascii_lowercase())
        .collect()
}

/// Map the server-entry inventory to per-control verdicts. Deterministic, no
/// model calls. Always returns one finding per control, in stable order:
/// RC-020, RC-069, RC-018. Sites whose `site_kind` is not `server_entry` are
/// ignored — the applicability filter in the other direction, so a G1 call
/// site can never satisfy a server-entry control.
pub fn evaluate(sites: &[Site], specs: &SpecCache) -> Vec<ServerEntryFinding> {
    let entries: Vec<&Site> = sites
        .iter()
        .filter(|s| s.site_kind == SITE_KIND_SERVER_ENTRY)
        .collect();
    vec![
        eval_health(&entries, specs),
        eval_rate_limit(&entries, specs),
        eval_degraded(&entries, specs),
    ]
}

fn eval_health(entries: &[&Site], specs: &SpecCache) -> ServerEntryFinding {
    let mk = |verdict, reason: String, evidence| ServerEntryFinding {
        control: "RC-020",
        control_name: "health checks",
        verdict,
        reason,
        evidence,
        fix: "expose a health-check endpoint (e.g. /healthz for liveness, /readyz for \
              readiness) and wire it into the deploy/orchestrator probes"
            .to_string(),
        severity: "medium",
    };
    if entries.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no server-entry points inventoried".into(),
            vec![],
        );
    }
    let patterns = patterns_for(specs, "RC-020", SERVER_KIND_HEALTH_PATH);
    if patterns.is_empty() {
        return mk(
            Verdict::Abstain,
            "no health_path server specs in the cache; the control cannot be judged".into(),
            vec![],
        );
    }
    let routes: Vec<&&Site> = entries
        .iter()
        .filter(|s| !is_middleware_attachment(s))
        .collect();
    let mut matched = Vec::new();
    let mut unresolved = 0usize;
    for site in &routes {
        let paths = route_paths(site);
        if paths.is_empty() {
            unresolved += 1;
            continue;
        }
        if paths
            .iter()
            .any(|p| patterns.iter().any(|pat| path_matches(p, pat)))
        {
            matched.push(site.id());
        }
    }
    if !matched.is_empty() {
        return mk(
            Verdict::Satisfies,
            "health-check endpoint registered".into(),
            matched,
        );
    }
    if routes.is_empty() {
        return mk(
            Verdict::Abstain,
            "only middleware attachments inventoried; the route surface is unknown".into(),
            vec![],
        );
    }
    if unresolved > 0 {
        return mk(
            Verdict::Abstain,
            format!(
                "{unresolved} route registration(s) carry no resolvable path; a health \
                 endpoint may be among them"
            ),
            vec![],
        );
    }
    mk(
        Verdict::Violates,
        format!(
            "{} route(s) inventoried, no health-check endpoint among them",
            routes.len()
        ),
        routes.iter().take(3).map(|s| s.id()).collect(),
    )
}

fn eval_rate_limit(entries: &[&Site], specs: &SpecCache) -> ServerEntryFinding {
    let mk = |verdict, reason: String, evidence| ServerEntryFinding {
        control: "RC-069",
        control_name: "rate limiting",
        verdict,
        reason,
        evidence,
        fix: "attach rate-limiting middleware to the server's ingress routes (or, if \
              limiting is enforced at a gateway the scanner cannot see, waive this \
              finding with that provenance)"
            .to_string(),
        severity: "medium",
    };
    if entries.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no server-entry points inventoried".into(),
            vec![],
        );
    }
    let patterns = patterns_for(specs, "RC-069", SERVER_KIND_RATE_LIMIT);
    if patterns.is_empty() {
        return mk(
            Verdict::Abstain,
            "no rate_limit_middleware server specs in the cache; the control cannot be judged"
                .into(),
            vec![],
        );
    }
    let matched: Vec<String> = entries
        .iter()
        .filter(|s| {
            let t = identity_text(s);
            patterns.iter().any(|p| t.contains(p))
        })
        .map(|s| s.id())
        .collect();
    if !matched.is_empty() {
        return mk(
            Verdict::Satisfies,
            "rate-limiting middleware attached".into(),
            matched,
        );
    }
    mk(
        Verdict::Violates,
        format!(
            "no rate-limiting middleware among {} server-entry registration(s); a \
             gateway/infra-layer limiter is invisible here",
            entries.len()
        ),
        entries.iter().take(3).map(|s| s.id()).collect(),
    )
}

fn eval_degraded(entries: &[&Site], specs: &SpecCache) -> ServerEntryFinding {
    let mk = |verdict, reason: String, evidence| ServerEntryFinding {
        control: "RC-018",
        control_name: "graceful degradation (degraded response)",
        verdict,
        reason,
        evidence,
        fix: "add a degraded-response path for overload/dependency failure (load-shedding \
              or circuit-breaking middleware, fallback responses)"
            .to_string(),
        // Never violates: whether handlers degrade internally is a per-handler
        // judgement ([J] in the granularity map), so there is no blockable
        // absence to grade.
        severity: "",
    };
    if entries.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no server-entry points inventoried".into(),
            vec![],
        );
    }
    let patterns = patterns_for(specs, "RC-018", SERVER_KIND_DEGRADED_RESPONSE);
    if patterns.is_empty() {
        return mk(
            Verdict::Abstain,
            "no degraded_response server specs in the cache; the control cannot be judged".into(),
            vec![],
        );
    }
    let matched: Vec<String> = entries
        .iter()
        .filter(|s| {
            let t = identity_text(s);
            patterns.iter().any(|p| t.contains(p))
        })
        .map(|s| s.id())
        .collect();
    if !matched.is_empty() {
        return mk(
            Verdict::Satisfies,
            "degradation middleware attached".into(),
            matched,
        );
    }
    mk(
        Verdict::Abstain,
        "degraded-response behavior is a per-handler judgement; no recognizable \
         degradation middleware inventoried"
            .into(),
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_core::ConstArg;
    use rvl_spec::{ServerSpec, SpecCache, SpecFile};

    fn seed_specs() -> SpecCache {
        SpecCache::from_file(SpecFile {
            apis: vec![],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            emissions: vec![],
            server: vec![
                ServerSpec {
                    control: "RC-020".into(),
                    kind: SERVER_KIND_HEALTH_PATH.into(),
                    patterns: vec!["/healthz".into(), "/health".into(), "/readyz".into()],
                    confidence: 0.9,
                    rationale: "seed".into(),
                },
                ServerSpec {
                    control: "RC-069".into(),
                    kind: SERVER_KIND_RATE_LIMIT.into(),
                    patterns: vec!["ratelimit".into(), "throttle".into(), "limiter".into()],
                    confidence: 0.9,
                    rationale: "seed".into(),
                },
                ServerSpec {
                    control: "RC-018".into(),
                    kind: SERVER_KIND_DEGRADED_RESPONSE.into(),
                    patterns: vec!["circuitbreaker".into(), "fallback".into()],
                    confidence: 0.9,
                    rationale: "seed".into(),
                },
            ],
        })
    }

    fn entry(file: &str, line: u32, method: &str, snippet: &str, path: Option<&str>) -> Site {
        Site {
            file_path: file.into(),
            line_number: line,
            method: method.into(),
            client_type: "net/http.ServeMux".into(),
            snippet: snippet.into(),
            site_kind: SITE_KIND_SERVER_ENTRY.into(),
            const_args: path
                .map(|p| {
                    vec![ConstArg {
                        index: 0,
                        name: String::new(),
                        value: format!("{p:?}"),
                        how: "literal".into(),
                    }]
                })
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    fn by_control<'a>(fs: &'a [ServerEntryFinding], c: &str) -> &'a ServerEntryFinding {
        fs.iter().find(|f| f.control == c).unwrap()
    }

    #[test]
    fn g1_sites_are_invisible_to_the_server_lane() {
        // The applicability filter in the other direction: a G1 call site
        // whose snippet happens to contain "/healthz" must not satisfy RC-020.
        let g1 = Site {
            file_path: "a.go".into(),
            line_number: 3,
            method: "Get".into(),
            snippet: r#"client.Get("/healthz")"#.into(),
            ..Default::default()
        };
        let fs = evaluate(&[g1], &seed_specs());
        assert_eq!(by_control(&fs, "RC-020").verdict, Verdict::NotApplicable);
        assert_eq!(by_control(&fs, "RC-069").verdict, Verdict::NotApplicable);
    }

    #[test]
    fn a_registered_health_endpoint_satisfies_with_evidence() {
        let sites = vec![
            entry(
                "routes.go",
                10,
                "HandleFunc",
                r#"mux.HandleFunc("/healthz", healthHandler)"#,
                Some("/healthz"),
            ),
            entry(
                "routes.go",
                11,
                "HandleFunc",
                r#"mux.HandleFunc("/users", usersHandler)"#,
                Some("/users"),
            ),
        ];
        let f = evaluate(&sites, &seed_specs());
        let h = by_control(&f, "RC-020");
        assert_eq!(h.verdict, Verdict::Satisfies);
        assert_eq!(h.evidence, vec!["routes.go:10"]);
    }

    #[test]
    fn django_trailing_slash_paths_match_and_bare_words_do_not() {
        // django registers `path("healthz/", ...)` — trailing-slash, no
        // leading slash — and it must match the seed's "/healthz". A bare
        // keyword like name="health" must NOT be read as a path (false pass).
        let mut s = entry("urls.py", 3, "path", "", None);
        s.client_type = "django.urls".into();
        s.snippet = r#"path("healthz/", views.health, name="health")"#.into();
        s.const_args = vec![
            ConstArg {
                index: 0,
                name: String::new(),
                value: "'healthz/'".into(),
                how: "literal".into(),
            },
            ConstArg {
                index: 2,
                name: "name".into(),
                value: "'health'".into(),
                how: "literal".into(),
            },
        ];
        assert_eq!(
            by_control(&evaluate(&[s], &seed_specs()), "RC-020").verdict,
            Verdict::Satisfies
        );

        // The bare word alone (no pathish literal) is not a resolvable path.
        let mut bare = entry("urls.py", 4, "path", "", None);
        bare.client_type = "django.urls".into();
        bare.snippet = r#"path(prefix, views.users, name="health")"#.into();
        bare.const_args = vec![ConstArg {
            index: 2,
            name: "name".into(),
            value: "'health'".into(),
            how: "literal".into(),
        }];
        let f = by_control(&evaluate(&[bare], &seed_specs()), "RC-020").clone();
        assert_eq!(
            f.verdict,
            Verdict::Abstain,
            "a name= keyword must not satisfy the health control: {}",
            f.reason
        );
    }

    #[test]
    fn a_prefix_mounted_health_route_still_matches() {
        let sites = vec![entry(
            "routes.go",
            10,
            "HandleFunc",
            r#"mux.HandleFunc("/api/healthz", h)"#,
            Some("/api/healthz"),
        )];
        assert_eq!(
            by_control(&evaluate(&sites, &seed_specs()), "RC-020").verdict,
            Verdict::Satisfies
        );
    }

    #[test]
    fn all_paths_resolved_and_no_health_endpoint_is_a_violation() {
        let sites = vec![
            entry(
                "r.go",
                1,
                "HandleFunc",
                r#"m.HandleFunc("/users", h)"#,
                Some("/users"),
            ),
            entry(
                "r.go",
                2,
                "HandleFunc",
                r#"m.HandleFunc("/orders", h)"#,
                Some("/orders"),
            ),
        ];
        let f = by_control(&evaluate(&sites, &seed_specs()), "RC-020").clone();
        assert_eq!(f.verdict, Verdict::Violates);
        assert!(f.reason.contains("2 route(s)"), "{}", f.reason);
    }

    #[test]
    fn an_unresolved_route_path_abstains_rather_than_asserting_absence() {
        // A route registered under a variable path COULD be the health
        // endpoint; absence is only decidable when every path resolved.
        let sites = vec![
            entry(
                "r.go",
                1,
                "HandleFunc",
                r#"m.HandleFunc("/users", h)"#,
                Some("/users"),
            ),
            entry(
                "r.go",
                2,
                "HandleFunc",
                "m.HandleFunc(cfg.HealthPath, h)",
                None,
            ),
        ];
        let f = by_control(&evaluate(&sites, &seed_specs()), "RC-020").clone();
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("no resolvable path"), "{}", f.reason);
    }

    #[test]
    fn a_middleware_only_inventory_does_not_grade_the_route_surface() {
        let sites = vec![entry("r.go", 1, "Use", "r.Use(logging)", None)];
        assert_eq!(
            by_control(&evaluate(&sites, &seed_specs()), "RC-020").verdict,
            Verdict::Abstain
        );
    }

    #[test]
    fn rate_limit_middleware_satisfies_and_absence_violates() {
        let limited = vec![
            entry("r.go", 1, "Use", "r.Use(middleware.Throttle(100))", None),
            entry(
                "r.go",
                2,
                "HandleFunc",
                r#"m.HandleFunc("/u", h)"#,
                Some("/u"),
            ),
        ];
        let f = by_control(&evaluate(&limited, &seed_specs()), "RC-069").clone();
        assert_eq!(f.verdict, Verdict::Satisfies);
        assert_eq!(f.evidence, vec!["r.go:1"]);

        let unlimited = vec![entry(
            "r.go",
            2,
            "HandleFunc",
            r#"m.HandleFunc("/u", h)"#,
            Some("/u"),
        )];
        let f = by_control(&evaluate(&unlimited, &seed_specs()), "RC-069").clone();
        assert_eq!(f.verdict, Verdict::Violates);
        assert!(f.reason.contains("gateway"), "{}", f.reason);
    }

    #[test]
    fn degraded_response_absence_abstains_never_violates() {
        // RC-018 is a judgement control: presence of degradation middleware
        // satisfies, absence proves nothing about per-handler behavior.
        let sites = vec![entry(
            "r.go",
            1,
            "HandleFunc",
            r#"m.HandleFunc("/u", h)"#,
            Some("/u"),
        )];
        let f = by_control(&evaluate(&sites, &seed_specs()), "RC-018").clone();
        assert_eq!(f.verdict, Verdict::Abstain);

        let breaker = vec![entry(
            "r.go",
            1,
            "Use",
            "r.Use(circuitbreaker.New(cfg))",
            None,
        )];
        assert_eq!(
            by_control(&evaluate(&breaker, &seed_specs()), "RC-018").verdict,
            Verdict::Satisfies
        );
    }

    #[test]
    fn without_server_specs_every_control_abstains_or_reports_no_entries() {
        let empty = SpecCache::from_file(SpecFile::default());
        // With entries but no specs: abstain (corpus pending), never a guess.
        let sites = vec![entry(
            "r.go",
            1,
            "HandleFunc",
            r#"m.HandleFunc("/u", h)"#,
            Some("/u"),
        )];
        for f in evaluate(&sites, &empty) {
            assert_eq!(f.verdict, Verdict::Abstain, "{}: {}", f.control, f.reason);
        }
        // With no entries at all: not applicable.
        for f in evaluate(&[], &empty) {
            assert_eq!(f.verdict, Verdict::NotApplicable);
        }
    }

    #[test]
    fn snippet_quoted_paths_are_the_fallback_when_no_const_arg_resolved() {
        // A retriever without const-arg support still yields judgable paths.
        let mut s = entry("app.py", 4, "route", "", None);
        s.snippet = "@app.route('/healthz')".into();
        assert_eq!(
            by_control(&evaluate(&[s], &seed_specs()), "RC-020").verdict,
            Verdict::Satisfies
        );
    }
}
