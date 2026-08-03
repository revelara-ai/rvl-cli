//! Deterministic propagation: apply specs to every call site, no inference.
//!
//! This is the half of the pipeline that runs locally with zero model calls,
//! and it is why the scanner can ship as a Rust binary plus a JSON cache rather
//! than as a model. On the reference Go repo, 76 spec answers decided 1525 sites and agreed
//! with the far more expensive per-site LLM panel on 94.0% of the sites where
//! both committed, while abstaining on none that the panel decided.
//!
//! Nothing here decides reliability semantics. It looks up what the specs say
//! and combines them mechanically. Every rule below traces to a measurement or
//! to a human adjudication, not to intuition.

use rvl_core::{scope_of, CtxEvidence, Site, Verdict};
use rvl_spec::{spec_gate, Bounds, Mechanism, Scope, ServedBound, SpecCache};

/// Evidence of a bound, and how much of the call it covers.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub site_id: String,
    pub verdict: Verdict,
    pub reason: String,
}

fn has_deadline_call(src: &str) -> bool {
    src.contains("context.WithTimeout")
        || src.contains("context.WithDeadline")
        || src.contains("asyncio.wait_for")
        || src.contains("asyncio.timeout")
        || src.contains("anyio.fail_after")
}

/// A deadline imposed by the database session rather than by the language.
///
/// `SET lock_timeout` and `SET statement_timeout` bound work that no
/// language-level construct touches, and a migration harness that sets
/// lock_timeout is bounded by the canon's own rule -- DDL runs under a small
/// lock_timeout with bounded acquisition retries, while statement_timeout is
/// deliberately relaxed so index builds can run long. Propagation saw neither
/// and reported a violation on a correctly-bounded migration.
fn has_session_bound(src: &str) -> bool {
    let lower = src.to_ascii_lowercase();
    [
        "lock_timeout",
        "statement_timeout",
        "idle_in_transaction_session_timeout",
    ]
    .iter()
    .any(|k| lower.contains(k))
        && lower.contains("set")
}

fn has_timeout_arg(call: &str) -> bool {
    let lower = call.to_ascii_lowercase();
    ["timeout=", "timeout:", "deadline=", "deadline:"]
        .iter()
        .any(|k| lower.contains(k))
}

/// A decorator or annotation carrying a time bound. Looks at the decorators the
/// retriever reported on chain roots and at the enclosing source, since a
/// decorator sits textually above the function it bounds.
fn has_bounding_decorator(site: &Site) -> bool {
    const KEYS: [&str; 4] = ["time_limit", "soft_time_limit", "timeout", "deadline"];
    let decorated = site
        .provenance
        .chain_roots
        .iter()
        .flat_map(|r| r.decorators.iter())
        .any(|d| KEYS.iter().any(|k| d.contains(k)));
    decorated
        || site
            .enclosing_function_body
            .lines()
            .take_while(|l| l.trim_start().starts_with('@') || l.trim().is_empty())
            .any(|l| KEYS.iter().any(|k| l.contains(k)))
}

fn is_served_request_root(site: &Site) -> bool {
    site.provenance
        .chain_roots
        .iter()
        .any(|r| r.signature.contains("http.ResponseWriter"))
}

/// Apply the specs to one site.
pub fn propagate(
    site: &Site,
    specs: &SpecCache,
    served: &ServedBound,
    // Repo-level client bound: computed and threaded, but NOT yet applied.
    // Sound broadening requires family-scoping (po-3t3oj.30); until then only
    // exact-type client-config matches satisfy. Kept in the signature so the
    // family-scoped increment is a body change, not an API churn.
    _client: &ServedBound,
) -> Finding {
    let id = site.id();
    let key = site.api_key();
    let spec = specs.api(&key);

    if let Some((verdict, reason)) = spec_gate(spec) {
        return Finding {
            site_id: id,
            verdict,
            reason,
        };
    }

    // Scope is checked AFTER the API gate so a non-I/O call in an exempt scope
    // still reports as not_applicable rather than as a scope pass: those are
    // different facts and collapsing them hides extractor errors.
    let scope = scope_of(&site.file_path);
    if let Some(sp) = specs.scope_exempt(scope.as_str()) {
        return Finding {
            site_id: id,
            verdict: Verdict::Satisfies,
            reason: format!(
                "scope {} is not governed by this control: {}",
                scope.as_str(),
                sp.rationale
            ),
        };
    }
    let spec = spec.expect("spec_gate returns None only when a spec exists");

    let mut whole: Vec<String> = Vec::new();
    let mut phase: Vec<String> = Vec::new();
    let mut served_unresolved = false;

    // AMBIENT mechanisms are checked for every blocking API, regardless of what
    // the spec lists. The distinction the first version missed: bounded_by
    // conflates two different kinds of mechanism.
    //
    //   API-specific  does THIS API take a timeout argument? does its client
    //                 carry timeout config? Only the spec knows.
    //   Ambient       a supervising deadline bounds whatever runs under it. A
    //                 database call inside @shared_task(time_limit=120) is
    //                 bounded whether or not the DB API "supports decorators",
    //                 because the bound is a property of the SITE's context,
    //                 not of the callee.
    //
    // Gating ambient mechanisms on a per-API list scored app/reports.py wrong:
    // the spec for the DB call had no reason to mention celery, so a real
    // decorator bound was invisible.
    let scope_src = site.scope_source();
    // The ancestry FACTS are emitted by the retriever and are genuinely useful
    // to a reader, but they are too coarse to drive a verdict, and two
    // adjudicated sites proved it. risk_class_backfill.go:33 has two traced
    // callers, NewServer and main, both flagged as deriving a deadline -- and
    // both merely CONTAIN a context.WithTimeout somewhere in a large body,
    // established for something else entirely. The backfill receives a
    // different ctx. Treating "this function contains WithTimeout" as "the ctx
    // it passes is bounded" turned two real violations into passes.
    //
    // Answering it properly needs local dataflow: at the call
    // `runRiskClassBackfill(ctx, ...)`, is that `ctx` the variable assigned
    // from context.WithTimeout? That is tractable in go/ast and is the next
    // increment. Until then the counts inform the packet and do not decide.
    if has_deadline_call(&scope_src) {
        whole.push("deadline derived in scope".into());
    }
    // Dataflow, not body presence. The earlier coarse fact ("this caller
    // contains a WithTimeout somewhere") turned two adjudicated violations into
    // passes because main() contains one in almost every Go program. This asks
    // whether the ctx ARRIVING at the call was assigned from WithTimeout, and
    // on those same two sites it correctly reports unbounded.
    match site.provenance.ctx_evidence() {
        CtxEvidence::AllBounded => {
            whole.push("every direct caller passes a ctx traced to a deadline".into());
        }
        CtxEvidence::Mixed { bounded, total } => {
            // One unbounded path is real exposure even when others are bounded.
            phase.push(format!(
                "{} of {total} direct callers pass an unbounded ctx",
                total - bounded
            ));
        }
        CtxEvidence::NoneBounded | CtxEvidence::Unknown => {}
    }
    // A session bound established BY this very call does not bound it. The call
    // site at analyst_pool.go:72 is literally `SET statement_timeout`, and
    // crediting it produced a false pass on a site a human confirmed as a
    // violation. Only bounds set elsewhere in scope count.
    if has_session_bound(&scope_src) && !has_session_bound(&site.snippet) {
        whole.push("database session bound set in scope".into());
    }
    if has_bounding_decorator(site) {
        whole.push("bounding decorator on the enclosing function".into());
    }
    for m in &spec.bounded_by {
        match m {
            Mechanism::CallArg if has_timeout_arg(&site.snippet) => {
                whole.push("timeout argument at the call".into());
            }
            // ServerConfig looked ambient and is not. Whether a server's
            // deadline reaches a call depends on the call's cancellation
            // semantics: http.Server's WriteTimeout deadlines the connection
            // write and never cancels the request context, so it does not bound
            // a pgx query running in that handler. Treating it as ambient sent
            // 867 reference-repo sites to abstain on a server-spec conflict that was
            // irrelevant to almost all of them.
            Mechanism::ServerConfig if is_served_request_root(site) => match served {
                ServedBound::Conflict(_) => served_unresolved = true,
                ServedBound::Agreed(Bounds::WholeCall) => {
                    whole.push("server config bounds served requests".into())
                }
                ServedBound::Agreed(Bounds::PhaseOnly) => {
                    phase.push("server config bounds only a phase of served requests".into())
                }
                _ => {}
            },
            Mechanism::ClientConfig => {
                // EXACT (a): the client is constructed at this site with a
                // config the specs recognise.
                for c in &site.client_construction {
                    match specs.config(&c.symbol).map(|s| s.bounds) {
                        Some(Bounds::WholeCall) => {
                            whole.push(format!("client config {}", c.symbol))
                        }
                        Some(Bounds::PhaseOnly) => {
                            phase.push(format!("client config {} bounds only a phase", c.symbol))
                        }
                        _ => {}
                    }
                }
                // EXACT (b): the call's own client_type carries a this_client
                // config, even when the construction is not at this site.
                if let Some(s) = specs.config(&site.client_type) {
                    if s.scope == Scope::ThisClient && s.confidence >= rvl_spec::MIN_CONFIDENCE {
                        match s.bounds {
                            Bounds::WholeCall => {
                                whole.push(format!("client config {}", site.client_type))
                            }
                            Bounds::PhaseOnly => phase.push(format!(
                                "client config {} bounds only a phase",
                                site.client_type
                            )),
                            _ => {}
                        }
                    }
                }
                // GUARDED BROADENING is DELIBERATELY DISABLED pending a
                // family-scoped design. The repo-level `client_bound` is
                // computed and threaded (`_client`), but applying a single
                // whole-call config across ALL client_config calls is UNSOUND:
                // a repo can construct several unrelated clients with timeouts
                // (measured on immich: an ExifTool `taskTimeoutMillis` and a
                // Kysely DB pool with NO timeout), and broadening the ExifTool
                // bound to the DB queries is exactly the false negative the
                // soundness pin forbids. Sound broadening must match the config
                // to the call's client FAMILY; until that lands, only EXACT-type
                // matches (above) satisfy, and everything else stays a finding
                // for a human. See po-3t3oj.30 (family-scoped config lane).
            }
            _ => {}
        }
    }

    if !whole.is_empty() {
        return Finding {
            site_id: id,
            verdict: Verdict::Satisfies,
            reason: whole.join("; "),
        };
    }
    if served_unresolved {
        return Finding {
            site_id: id,
            verdict: Verdict::Abstain,
            reason: "conflicting server-config specs".into(),
        };
    }
    // A phase-only bound is worse than no bound found, not better: it means the
    // connection setup is bounded and the response read is not, which is
    // exactly the case a naive "a timeout exists nearby" reading gets wrong.
    if !phase.is_empty() {
        return Finding {
            site_id: id,
            verdict: Verdict::Violates,
            reason: format!("only phase bounds: {}", phase.join("; ")),
        };
    }
    if !site.provenance.complete() {
        return Finding {
            site_id: id,
            verdict: Verdict::Abstain,
            reason: "no bound found and the search was truncated".into(),
        };
    }
    Finding {
        site_id: id,
        verdict: Verdict::Violates,
        reason: "no bound anywhere and the search was complete".into(),
    }
}

pub fn propagate_all(
    sites: &[Site],
    specs: &SpecCache,
    served: &ServedBound,
    client: &ServedBound,
) -> Vec<Finding> {
    sites
        .iter()
        .map(|s| propagate(s, specs, served, client))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_core::{Provenance, RootFact, Snippet};
    use rvl_spec::{ApiSpec, Blocking, ConfigSpec, Scope, ScopeSpec, SpecFile};

    fn cache(bounded_by: Vec<Mechanism>, configs: Vec<ConfigSpec>) -> SpecCache {
        SpecCache::from_file(SpecFile {
            apis: vec![ApiSpec {
                type_name: "db.Pool".into(),
                method: "Query".into(),
                blocking: Blocking::Yes,
                bounded_by,
                confidence: 0.9,
                rationale: String::new(),
                site_count: 1,
            }],
            configs,
            scopes: vec![],
        })
    }

    fn site() -> Site {
        Site {
            file_path: "a.go".into(),
            line_number: 1,
            method: "Query".into(),
            client_type: "db.Pool".into(),
            ..Default::default()
        }
    }

    #[test]
    fn complete_search_with_no_bound_is_a_violation() {
        let f = propagate(
            &site(),
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Violates);
        assert!(f.reason.contains("complete"));
    }

    fn client_cfg(bounds: Bounds) -> ConfigSpec {
        ConfigSpec {
            type_name: "db.Pool".into(),
            bounds,
            scope: Scope::ThisClient,
            confidence: 0.9,
            rationale: String::new(),
        }
    }

    #[test]
    fn client_config_exact_type_satisfies() {
        // The call's own client_type carries a whole-call this_client config,
        // even without a per-site construction. Exact match needs no broadening.
        let f = propagate(
            &site(),
            &cache(
                vec![Mechanism::ClientConfig],
                vec![client_cfg(Bounds::WholeCall)],
            ),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn repo_level_broadening_is_disabled_until_family_scoped() {
        // SOUNDNESS: a repo-level whole-call client config must NOT satisfy a
        // call whose exact type has no config. Global broadening would let one
        // client's timeout (e.g. immich's ExifTool) mask another client's
        // genuinely-unbounded calls (immich's DB) -- the false negative the
        // pin forbids. Until family-scoping lands, this stays a Violation.
        let f = propagate(
            &site(),
            &cache(vec![Mechanism::ClientConfig], vec![]),
            &ServedBound::None,
            &ServedBound::Agreed(Bounds::WholeCall),
        );
        assert_eq!(f.verdict, Verdict::Violates);
    }

    #[test]
    fn client_config_with_no_bound_still_violates_the_soundness_guard() {
        // THE false-negative guard: a client_config-bounded call with no exact
        // config must NOT be silently satisfied.
        let f = propagate(
            &site(),
            &cache(vec![Mechanism::ClientConfig], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Violates);
    }

    #[test]
    fn truncated_search_abstains_instead_of_asserting() {
        let mut s = site();
        s.provenance = Provenance {
            hit_caller_budget: true,
            ..Default::default()
        };
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(
            f.verdict,
            Verdict::Abstain,
            "absence is only evidence when the search was complete"
        );
    }

    #[test]
    fn body_presence_of_a_deadline_still_decides_nothing() {
        // The regression this guards: both callers CONTAIN a WithTimeout and
        // neither passes it here. Only the dataflow counts may move a verdict.
        let mut s = site();
        s.provenance = Provenance {
            ancestors_traced: 2,
            ancestors_with_deadline: 2,
            direct_callers: 2,
            direct_callers_passing_bounded_ctx: 0,
            enclosing_takes_context: true,
            ..Default::default()
        };
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::Context], vec![]),
                &ServedBound::None,
                &ServedBound::None
            )
            .verdict,
            Verdict::Violates
        );
    }

    #[test]
    fn dataflow_confirmed_bounded_ctx_satisfies() {
        let mut s = site();
        s.provenance = Provenance {
            direct_callers: 3,
            direct_callers_passing_bounded_ctx: 3,
            ..Default::default()
        };
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::Context], vec![]),
                &ServedBound::None,
                &ServedBound::None
            )
            .verdict,
            Verdict::Satisfies
        );
    }

    #[test]
    fn one_unbounded_path_among_several_is_not_a_pass() {
        let mut s = site();
        s.provenance = Provenance {
            direct_callers: 4,
            direct_callers_passing_bounded_ctx: 3,
            ..Default::default()
        };
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Violates);
        assert!(f.reason.contains("1 of 4"));
    }

    #[test]
    fn deadline_in_a_callee_counts_the_same_as_one_in_a_caller() {
        let mut s = site();
        s.callees = vec![Snippet {
            source: "ctx, cancel := context.WithTimeout(ctx, d)".into(),
            ..Default::default()
        }];
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn an_api_specific_mechanism_the_spec_omits_is_never_searched_for() {
        // call_arg is API-specific: only the spec knows whether this API takes
        // a timeout argument, so a timeout-looking argument must not be
        // credited when the spec does not list it. This is what stops
        // propagation inventing bounds.
        let mut s = site();
        s.snippet = "pool.Query(sql, timeout=5)".into();
        let f = propagate(
            &s,
            &cache(vec![Mechanism::ClientConfig], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Violates);
    }

    #[test]
    fn ambient_bounds_apply_even_when_the_spec_omits_them() {
        // A DB call inside @shared_task(time_limit=120) is bounded whether or
        // not the DB API's spec mentions decorators: the bound belongs to the
        // site's context, not to the callee.
        let mut s = site();
        s.enclosing_function_body =
            "@shared_task(time_limit=120)\ndef build():\n    pool.Query(q)".into();
        let f = propagate(
            &s,
            &cache(vec![Mechanism::ClientConfig], vec![]),
            &ServedBound::None,
            &ServedBound::None,
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn phase_only_client_config_is_a_violation_not_a_pass() {
        let mut s = site();
        s.client_construction = vec![Snippet {
            symbol: "redis.Options".into(),
            ..Default::default()
        }];
        let specs = cache(
            vec![Mechanism::ClientConfig],
            vec![ConfigSpec {
                type_name: "redis.Options".into(),
                bounds: Bounds::PhaseOnly,
                scope: Scope::ThisClient,
                confidence: 0.9,
                rationale: String::new(),
            }],
        );
        let f = propagate(&s, &specs, &ServedBound::None, &ServedBound::None);
        assert_eq!(f.verdict, Verdict::Violates);
        assert!(f.reason.contains("phase"));
    }

    #[test]
    fn a_bounding_decorator_satisfies_when_the_spec_allows_it() {
        // @shared_task(time_limit=120) bounds every call in the task. The
        // fixture gold set scored app/reports.py wrong until Decorator existed.
        let mut s = site();
        s.enclosing_function_body =
            "@shared_task(time_limit=120)\ndef build_report():\n    db.query()".into();
        let specs = cache(vec![Mechanism::Decorator], vec![]);
        assert_eq!(
            propagate(&s, &specs, &ServedBound::None, &ServedBound::None).verdict,
            Verdict::Satisfies
        );
    }

    #[test]
    fn a_session_level_bound_counts_as_a_bound() {
        // migrations/env.py sets lock_timeout, which is exactly what the canon
        // asks of DDL. No language-level construct is involved, so the
        // language-only detector called a correctly-bounded migration a
        // violation.
        let mut s = site();
        s.file_path = "migrations/env.py".into();
        s.enclosing_function_body =
            "def run_migrations():\n    conn.execute(\"SET lock_timeout = '2s'\")".into();
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::ClientConfig], vec![]),
                &ServedBound::None,
                &ServedBound::None
            )
            .verdict,
            Verdict::Satisfies
        );
    }

    #[test]
    fn the_statement_that_sets_the_bound_is_not_bounded_by_it() {
        let mut s = site();
        s.snippet = "tx.Exec(ctx, \"SET statement_timeout = '30s'\")".into();
        s.enclosing_function_body = s.snippet.clone();
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::ClientConfig], vec![]),
                &ServedBound::None,
                &ServedBound::None
            )
            .verdict,
            Verdict::Violates,
            "crediting the bound-setter with its own bound is circular"
        );
    }

    #[test]
    fn a_server_conflict_does_not_reach_apis_that_no_server_bounds() {
        // The spec does not list ServerConfig, so a server-spec conflict is
        // irrelevant to this call and must not force an abstention.
        let mut s = site();
        s.provenance = Provenance {
            chain_roots: vec![RootFact {
                signature: "func(w http.ResponseWriter, r *http.Request)".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let conflict = ServedBound::Conflict(vec!["a=WholeCall".into(), "b=PhaseOnly".into()]);
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::ClientConfig], vec![]),
                &conflict,
                &ServedBound::None
            )
            .verdict,
            Verdict::Violates
        );
    }

    #[test]
    fn a_timeout_word_without_a_set_is_not_a_session_bound() {
        // "# TODO: add a statement_timeout" must not count as having one.
        let mut s = site();
        s.enclosing_function_body = "# TODO: add a statement_timeout here\npool.Query(q)".into();
        assert_eq!(
            propagate(
                &s,
                &cache(vec![Mechanism::ClientConfig], vec![]),
                &ServedBound::None,
                &ServedBound::None
            )
            .verdict,
            Verdict::Violates
        );
    }

    #[test]
    fn an_exempt_scope_satisfies_by_non_applicability() {
        let mut s = site();
        s.file_path = "scripts/seed_dev_data.py".into();
        let mut f = SpecFile {
            apis: vec![ApiSpec {
                type_name: "db.Pool".into(),
                method: "Query".into(),
                blocking: Blocking::Yes,
                bounded_by: vec![Mechanism::Context],
                confidence: 0.9,
                rationale: String::new(),
                site_count: 1,
            }],
            configs: vec![],
            scopes: vec![ScopeSpec {
                scope: "dev_only".into(),
                applies: false,
                confidence: 0.9,
                rationale: "local tooling fails open".into(),
            }],
        };
        let specs = SpecCache::from_file(f.clone());
        assert_eq!(
            propagate(&s, &specs, &ServedBound::None, &ServedBound::None).verdict,
            Verdict::Satisfies
        );

        // A low-confidence exemption must NOT fire: silently exempting a scope
        // is how a real violation disappears.
        f.scopes[0].confidence = 0.3;
        let weak = SpecCache::from_file(f);
        assert_eq!(
            propagate(&s, &weak, &ServedBound::None, &ServedBound::None).verdict,
            Verdict::Violates
        );
    }

    #[test]
    fn conflicting_server_specs_abstain_on_served_sites_only() {
        let mut served_site = site();
        served_site.provenance = Provenance {
            chain_roots: vec![RootFact {
                signature: "func(w http.ResponseWriter, r *http.Request)".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let specs = cache(vec![Mechanism::ServerConfig], vec![]);
        let conflict = ServedBound::Conflict(vec!["a=WholeCall".into(), "b=PhaseOnly".into()]);
        assert_eq!(
            propagate(&served_site, &specs, &conflict, &ServedBound::None).verdict,
            Verdict::Abstain
        );
        // A site not reached through a handler is unaffected by the conflict.
        assert_eq!(
            propagate(&site(), &specs, &conflict, &ServedBound::None).verdict,
            Verdict::Violates
        );
    }
}
