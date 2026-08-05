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

use rvl_core::{scope_of, ConstArg, CtxEvidence, Site, Verdict};
use rvl_spec::{
    client_family, spec_gate, Bounds, Family, Mechanism, Scope, ServedBound, SpecCache,
};
use std::collections::HashMap;

pub mod server_entry;

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

/// A schema-v2 constant argument whose KEYWORD NAME says it is a timeout.
/// Name-keyed only: a bare positional constant says nothing about being a
/// timeout — that would take the API's signature, which is spec knowledge.
/// Mirrors the `timeout=`/`deadline=` text heuristic over structured evidence.
fn const_timeout_arg(site: &Site) -> Option<&ConstArg> {
    site.const_args.iter().find(|a| {
        let name = a.name.to_ascii_lowercase();
        name.contains("timeout") || name.contains("deadline")
    })
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
    // Repo-level client bounds, resolved per I/O family. A call is broadened
    // only by its OWN family's bound (po-3t3oj.34), so one client's timeout can
    // never mask another family's unbounded calls.
    client: &HashMap<Family, ServedBound>,
) -> Finding {
    let id = site.id();
    // Site kinds with their OWN lane are never a client-call question: a
    // server-entry registration (po-av01j.3) is judged by the server-entry
    // lane even when a G1 spec is keyed to the same (type, method) — scoring
    // a route registration as an unbounded call would be a category error.
    // Kinds that RIDE this lane's judgment machinery (background_job,
    // po-av01j.4) fall through to the applicability gate below instead.
    if site.site_kind == rvl_core::SITE_KIND_SERVER_ENTRY {
        return Finding {
            site_id: id,
            verdict: Verdict::NotApplicable,
            reason: format!(
                "site_kind {} is judged by its own lane, not the client-call lane",
                site.site_kind
            ),
        };
    }
    // Same for G4 emission points (po-av01j.5): an API spec judges CALLS. An
    // emission-point aggregate is routed to the emission lane by the scan
    // pipeline; if one reaches here anyway (eval harness, a stream fed
    // straight in), it is out of this control's scope by construction —
    // never a blocking call, never an abstention that pollutes the no-spec
    // mint queue.
    if site.is_emission_point() {
        return Finding {
            site_id: id,
            verdict: Verdict::NotApplicable,
            reason: format!(
                "{} site: not a client-call surface, API specs do not apply",
                site.site_kind
            ),
        };
    }
    let key = site.api_key();
    let spec = specs.api(&key);

    // Any other kinded site WITHOUT a client-call spec is likewise not this
    // lane's question; with a spec it reaches the applicability gate, so a
    // spec declaring job-altitude coverage flows through ordinary judgment.
    if !site.site_kind.is_empty() && spec.is_none() {
        return Finding {
            site_id: id,
            verdict: Verdict::NotApplicable,
            reason: format!(
                "site_kind {} is judged by its own lane, not the client-call lane",
                site.site_kind
            ),
        };
    }

    // Applicability by site kind (G3, po-av01j.4). A spec governs only the
    // site kinds it declares (empty = the classic G1 call site), so a
    // call-site judgment is never silently re-applied at job altitude, nor a
    // job-altitude spec to classic calls. Wrong-altitude specs ABSTAIN — the
    // site routes to a spec author, exactly like a missing spec, because a
    // spec error is multiplied across every site using the API at once.
    if let Some(s) = spec {
        if !s.applies_to(&site.site_kind) {
            let kind = if site.site_kind.is_empty() {
                "call_site"
            } else {
                &site.site_kind
            };
            return Finding {
                site_id: id,
                verdict: Verdict::Abstain,
                reason: format!("spec does not declare applicability to site kind {kind}"),
            };
        }
    }

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
    let mut client_unresolved = false;

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
            Mechanism::CallArg => {
                // v2 evidence first: a constant-valued timeout argument
                // carries its RESOLVED VALUE and provenance into the reason
                // (the config-lane resolved-value principle), so the finding
                // is auditable back to what the retriever actually saw. The
                // snippet-text heuristic remains the v1 fallback.
                if let Some(a) = const_timeout_arg(site) {
                    whole.push(format!(
                        "timeout argument at the call ({}={}, {})",
                        a.name, a.value, a.how
                    ));
                } else if has_timeout_arg(&site.snippet) {
                    whole.push("timeout argument at the call".into());
                }
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
                let before = whole.len() + phase.len();
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
                            // A declared (.revelara.yaml) bound carries its
                            // policy provenance into the reason: the finding
                            // must be auditable back to the declaration.
                            Bounds::WholeCall if s.declared => {
                                whole.push(format!("bound {}", s.rationale))
                            }
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
                // FAMILY-SCOPED GUARDED BROADENING (po-3t3oj.34): only when no
                // exact bound was found, and only from the call's OWN I/O
                // family's repo-level config. A DB query is broadened by a DB
                // pool's whole-call timeout, never by an image tool's timeout
                // (immich: ExifTool vs an unbounded Kysely pool). A call whose
                // type has no recognised family, or whose family has no config,
                // stays a finding. Conflicting configs within the family abstain
                // to a human — never a guess.
                if whole.len() + phase.len() == before {
                    if let Some(bound) =
                        client_family(&site.client_type).and_then(|f| client.get(&f))
                    {
                        match bound {
                            ServedBound::Agreed(Bounds::WholeCall) => whole.push(
                                "repo constructs this client's family with a single, unconflicted whole-call timeout".into(),
                            ),
                            ServedBound::Agreed(Bounds::PhaseOnly) => {
                                phase.push("repo client config bounds only a phase".into())
                            }
                            ServedBound::Conflict(_) => client_unresolved = true,
                            _ => {}
                        }
                    }
                }
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
    if client_unresolved {
        return Finding {
            site_id: id,
            verdict: Verdict::Abstain,
            reason: "conflicting client-config specs in this family".into(),
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
    client: &HashMap<Family, ServedBound>,
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
    use std::collections::HashMap;

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
                site_kinds: vec![],
            }],
            configs,
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
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

    // --- G3 background-job sites: spec applicability by site_kind (po-av01j.4) ---

    /// A job-altitude spec: the same timeout-judgment machinery, declared
    /// applicable to background_job sites (RC-060 / job-altitude re-application).
    fn job_cache(bounded_by: Vec<Mechanism>) -> SpecCache {
        SpecCache::from_file(SpecFile {
            apis: vec![ApiSpec {
                type_name: "github.com/robfig/cron/v3.Cron".into(),
                method: "AddFunc".into(),
                blocking: Blocking::Yes,
                bounded_by,
                confidence: 0.9,
                rationale: "RC-060: a registered job runs unattended; the run bound must exist at registration altitude".into(),
                site_count: 1,
                site_kinds: vec!["background_job".into()],
            }],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
        })
    }

    fn job_site() -> Site {
        Site {
            file_path: "internal/jobs/cron.go".into(),
            line_number: 12,
            method: "AddFunc".into(),
            client_type: "github.com/robfig/cron/v3.Cron".into(),
            site_kind: "background_job".into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_classic_spec_never_decides_a_background_job_site() {
        // The applicability guard: the cache holds only a G1 call-site spec
        // for this api key. A background-job registration must ABSTAIN and
        // route to a spec author, never inherit a judgment authored for a
        // different altitude — spec error is multiplied, not isolated.
        let mut s = site();
        s.site_kind = "background_job".into();
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(
            f.reason.contains("site kind"),
            "the reason must name the applicability gap: {}",
            f.reason
        );
    }

    #[test]
    fn a_job_altitude_spec_never_leaks_onto_classic_call_sites() {
        // The reverse guard: a spec declared for background_job only must not
        // decide a classic call site with the same api key.
        let mut s = site();
        s.method = "AddFunc".into();
        s.client_type = "github.com/robfig/cron/v3.Cron".into();
        let f = propagate(
            &s,
            &job_cache(vec![Mechanism::Context]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("site kind"), "{}", f.reason);
    }

    #[test]
    fn an_unbounded_job_registration_with_complete_search_violates() {
        // Job-altitude re-application of the EXISTING judgment: no bound
        // anywhere, complete search -> violation, exactly as at G1 altitude.
        let f = propagate(
            &job_site(),
            &job_cache(vec![Mechanism::Context]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Violates);
    }

    #[test]
    fn a_deadline_derived_in_the_registered_closure_satisfies_at_job_altitude() {
        // The registered closure derives its own deadline; the ambient
        // deadline machinery (unchanged) must see it through the enclosing
        // body, the same way it would for a G1 call site.
        let mut s = job_site();
        s.enclosing_function_body =
            "func run() {\n  c.AddFunc(\"@hourly\", func() {\n    ctx, cancel := context.WithTimeout(context.Background(), time.Minute)\n    defer cancel()\n    work(ctx)\n  })\n}"
                .into();
        let f = propagate(
            &s,
            &job_cache(vec![Mechanism::Context]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn a_bounding_decorator_on_the_task_satisfies_at_job_altitude() {
        // Celery's idiom: @shared_task(time_limit=120) IS the job bound. The
        // existing Decorator mechanism applies unchanged at job altitude.
        let mut s = Site {
            file_path: "app/tasks.py".into(),
            line_number: 8,
            method: "shared_task".into(),
            client_type: "celery".into(),
            site_kind: "background_job".into(),
            ..Default::default()
        };
        s.enclosing_function_body =
            "@shared_task(time_limit=120)\ndef rebuild_index():\n    walk()".into();
        let specs = SpecCache::from_file(SpecFile {
            apis: vec![ApiSpec {
                type_name: "celery".into(),
                method: "shared_task".into(),
                blocking: Blocking::Yes,
                bounded_by: vec![Mechanism::Decorator],
                confidence: 0.9,
                rationale: String::new(),
                site_count: 1,
                site_kinds: vec!["background_job".into()],
            }],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
        });
        let f = propagate(&s, &specs, &ServedBound::None, &HashMap::new());
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn a_server_entry_site_is_never_judged_by_the_client_call_lane() {
        // G2 (po-av01j.3): even with a G1 spec keyed to the same (type,
        // method), a server-entry registration is not a blocking-call
        // question. It reports NotApplicable here and is judged by the
        // server-entry lane instead.
        let mut s = site();
        s.site_kind = rvl_core::SITE_KIND_SERVER_ENTRY.into();
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::NotApplicable);
        assert!(
            f.reason.contains("server_entry"),
            "the reason must name the kind that was routed away: {}",
            f.reason
        );
    }

    #[test]
    fn emission_point_sites_are_never_judged_by_g1_specs() {
        // G4 (po-av01j.5): spec applicability filters on site_kind. An
        // emission aggregate whose (client_type, method) happens to collide
        // with a G1 API spec must NOT be judged as a blocking call — the G1
        // control does not govern emission points. The scan pipeline also
        // partitions emission sites out before propagation; this guard is the
        // defense for every other caller (eval harness, future lanes).
        let mut s = site();
        s.site_kind = rvl_core::SITE_KIND_EMISSION.into();
        let f = propagate(
            &s,
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(
            f.verdict,
            Verdict::NotApplicable,
            "an emission point is not a client-call surface: {}",
            f.reason
        );
        assert!(
            f.reason.contains("emission"),
            "the reason must name the routing: {}",
            f.reason
        );
    }

    #[test]
    fn complete_search_with_no_bound_is_a_violation() {
        let f = propagate(
            &site(),
            &cache(vec![Mechanism::Context], vec![]),
            &ServedBound::None,
            &HashMap::new(),
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
            declared: false,
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
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    // A ClientConfig-bounded call on a recognised DB client type, no exact config.
    fn db_call() -> (Site, SpecCache) {
        let cache = SpecCache::from_file(SpecFile {
            apis: vec![ApiSpec {
                type_name: "typeorm.QueryRunner".into(),
                method: "query".into(),
                blocking: Blocking::Yes,
                bounded_by: vec![Mechanism::ClientConfig],
                confidence: 0.9,
                rationale: String::new(),
                site_count: 1,
                site_kinds: vec![],
            }],
            configs: vec![],
            scopes: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
        });
        let site = Site {
            file_path: "a.ts".into(),
            line_number: 1,
            method: "query".into(),
            client_type: "typeorm.QueryRunner".into(),
            ..Default::default()
        };
        (site, cache)
    }

    #[test]
    fn family_broadening_satisfies_within_the_same_family() {
        // A DB call is broadened by the Database family's single whole-call bound.
        let (s, cache) = db_call();
        let client = HashMap::from([(Family::Database, ServedBound::Agreed(Bounds::WholeCall))]);
        let f = propagate(&s, &cache, &ServedBound::None, &client);
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn family_broadening_never_crosses_families_the_immich_guard() {
        // THE cross-family false-negative guard: a DB call must NOT be satisfied
        // by an HTTP client's whole-call timeout. (immich: an ExifTool/HTTP
        // timeout must never mask the unbounded Kysely DB queries.)
        let (s, cache) = db_call();
        let client = HashMap::from([(Family::Http, ServedBound::Agreed(Bounds::WholeCall))]);
        let f = propagate(&s, &cache, &ServedBound::None, &client);
        assert_eq!(f.verdict, Verdict::Violates);
    }

    #[test]
    fn family_conflict_abstains_never_guesses() {
        let (s, cache) = db_call();
        let client = HashMap::from([(
            Family::Database,
            ServedBound::Conflict(vec!["a".into(), "b".into()]),
        )]);
        let f = propagate(&s, &cache, &ServedBound::None, &client);
        assert_eq!(f.verdict, Verdict::Abstain);
    }

    #[test]
    fn client_config_with_no_bound_still_violates_the_soundness_guard() {
        // THE false-negative guard: a client_config-bounded call with no exact
        // config must NOT be silently satisfied.
        let f = propagate(
            &site(),
            &cache(vec![Mechanism::ClientConfig], vec![]),
            &ServedBound::None,
            &HashMap::new(),
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
            &HashMap::new(),
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
                &HashMap::new()
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
                &HashMap::new()
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
            &HashMap::new(),
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
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    #[test]
    fn a_const_timeout_arg_carries_its_resolved_value_into_the_reason() {
        // Schema v2 evidence: the retriever resolved the timeout argument's
        // VALUE, so the finding cites it with provenance (config-lane
        // resolved-value principle) instead of a bare substring claim.
        let mut s = site();
        s.snippet = "pool.Query(sql, timeout=DEFAULT_TIMEOUT)".into();
        s.const_args = vec![ConstArg {
            index: 1,
            name: "timeout".into(),
            value: "5".into(),
            how: "named_constant".into(),
        }];
        let f = propagate(
            &s,
            &cache(vec![Mechanism::CallArg], vec![]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
        assert!(
            f.reason.contains("timeout=5") && f.reason.contains("named_constant"),
            "the reason must cite the resolved value and how it was determined: {}",
            f.reason
        );
    }

    #[test]
    fn a_positional_const_arg_without_a_name_is_not_credited_as_a_timeout() {
        // A bare positional constant says nothing about BEING a timeout —
        // only the spec knows the API's signature. Without a timeout-ish
        // keyword name (and no timeout text in the snippet) CallArg finds
        // nothing.
        let mut s = site();
        s.snippet = "pool.Query(sql, 5)".into();
        s.const_args = vec![ConstArg {
            index: 1,
            name: String::new(),
            value: "5".into(),
            how: "literal".into(),
        }];
        let f = propagate(
            &s,
            &cache(vec![Mechanism::CallArg], vec![]),
            &ServedBound::None,
            &HashMap::new(),
        );
        assert_eq!(f.verdict, Verdict::Violates);
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
            &HashMap::new(),
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
            &HashMap::new(),
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
                declared: false,
            }],
        );
        let f = propagate(&s, &specs, &ServedBound::None, &HashMap::new());
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
            propagate(&s, &specs, &ServedBound::None, &HashMap::new()).verdict,
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
                &HashMap::new()
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
                &HashMap::new()
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
                &HashMap::new()
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
                &HashMap::new()
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
                site_kinds: vec![],
            }],
            configs: vec![],
            config_keys: vec![],
            server: vec![],
            emissions: vec![],
            scopes: vec![ScopeSpec {
                scope: "dev_only".into(),
                applies: false,
                confidence: 0.9,
                rationale: "local tooling fails open".into(),
            }],
        };
        let specs = SpecCache::from_file(f.clone());
        assert_eq!(
            propagate(&s, &specs, &ServedBound::None, &HashMap::new()).verdict,
            Verdict::Satisfies
        );

        // A low-confidence exemption must NOT fire: silently exempting a scope
        // is how a real violation disappears.
        f.scopes[0].confidence = 0.3;
        let weak = SpecCache::from_file(f);
        assert_eq!(
            propagate(&s, &weak, &ServedBound::None, &HashMap::new()).verdict,
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
            propagate(&served_site, &specs, &conflict, &HashMap::new()).verdict,
            Verdict::Abstain
        );
        // A site not reached through a handler is unaffected by the conflict.
        assert_eq!(
            propagate(&site(), &specs, &conflict, &HashMap::new()).verdict,
            Verdict::Violates
        );
    }
}
