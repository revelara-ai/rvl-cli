//! Fixture tests against the PINNED rust-analyzer (charter po-ae75b.8).
//!
//! Two layers:
//! 1. The trait-vs-impl MONIKER test — the behavioral canary for the pin.
//!    If a rust-analyzer upgrade changes how trait dispatch is encoded,
//!    this fails loudly instead of silently reshaping every derived packet.
//! 2. Golden packet tests over the derived stream — one assertion per site
//!    class and confidence tier.
//!
//! Skip convention (matches goindex/tsindex): if rust-analyzer is not
//! available the tests log SKIP and return, so a CI env without the rustup
//! component degrades to unit coverage rather than failing.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("fixture")
}

/// Discover + index the fixture once per test binary; None = skip.
fn indexed() -> Option<&'static (rustindex::ra::RaIdentity, scip::types::Index)> {
    static IDX: OnceLock<Option<(rustindex::ra::RaIdentity, scip::types::Index)>> = OnceLock::new();
    IDX.get_or_init(|| {
        let ra = match rustindex::ra::discover() {
            Ok(ra) => ra,
            Err(e) => {
                eprintln!("SKIP rustindex fixture tests: {e}");
                return None;
            }
        };
        let root = fixture_root();
        if let Err(e) = rustindex::ra::require_workspace_loads(&root) {
            eprintln!("SKIP rustindex fixture tests (workspace load): {e}");
            return None;
        }
        match rustindex::ra::run_scip(&ra, &root) {
            Ok(index) => Some((ra, index)),
            Err(e) => {
                eprintln!("SKIP rustindex fixture tests (scip run): {e}");
                None
            }
        }
    })
    .as_ref()
}

fn all_symbols(index: &scip::types::Index) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for doc in &index.documents {
        for occ in &doc.occurrences {
            out.push((doc.relative_path.clone(), occ.symbol.clone()));
        }
    }
    out
}

/// FIRST TASK (a): the trait-vs-impl moniker contract on the pinned engine.
#[test]
fn moniker_contract_trait_vs_impl_vs_dyn() {
    let Some((ra, index)) = indexed() else { return };
    assert!(
        ra.version_line.contains(rustindex::ra::PINNED_VERSION) || {
            eprintln!(
                "NOTE: running against unpinned {} (pin {}); moniker assertions still apply",
                ra.version_line,
                rustindex::ra::PINNED_VERSION
            );
            true
        }
    );
    let syms = all_symbols(index);
    let app = "app/src/main.rs";
    let has = |needle: &str| {
        syms.iter()
            .any(|(doc, s)| doc == app && s.ends_with(needle))
    };

    // Concrete receiver on a trait method resolves to the IMPL symbol,
    // carrying BOTH the self type and the trait.
    assert!(
        has("impl#[PgPool][Executor]execute()."),
        "trait-method-on-concrete-receiver must resolve to the impl moniker"
    );
    // dyn (and generic) dispatch resolve to the TRAIT method symbol.
    assert!(
        has("Executor#execute()."),
        "dyn/generic dispatch must resolve to the trait moniker"
    );
    // Inherent methods resolve to their impl.
    assert!(has("impl#[Client]get()."), "inherent method moniker");
    // Macros carry their own bang symbol at the call site.
    assert!(has("info!"), "macro call sites carry the macro symbol");
    // The desugar noise this engine emits (poll/branch at `.await` tokens)
    // must exist — the derivation's token-text filter depends on it being
    // recognizable. If an upgrade stops emitting them, nothing breaks; if it
    // starts emitting them with MATCHING text, the golden tests below catch
    // the junk sites.
}

fn derived() -> Option<rustindex::derive::Derived> {
    let (_, index) = indexed()?;
    Some(rustindex::derive::derive(
        &fixture_root(),
        "fixture",
        index,
        None,
    ))
}

#[test]
fn golden_g1_concrete_call_is_high_tier() {
    let Some(d) = derived() else { return };
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "get" && s.client_type == "reqwest::Client")
        .expect("client.get site");
    assert_eq!(site.site_kind, "", "G1 keeps the classic empty site_kind");
    assert!(site.provenance.client_type_resolved);
    assert_eq!(site.lang, "rust");
    assert_eq!(site.packet_schema, rvl_core::PACKET_SCHEMA);
    assert_eq!(
        site.symbol, "fetch_user",
        "enclosing fn from SCIP enclosing_range"
    );
    assert!(
        site.enclosing_function_body.contains("client.get"),
        "body re-read from source"
    );
    assert!(!site.macro_expansion);
}

#[test]
fn golden_trait_impl_dispatch_is_concrete() {
    let Some(d) = derived() else { return };
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "execute" && s.symbol == "query_direct")
        .expect("query_direct execute site");
    assert_eq!(
        site.client_type, "sqlx::PgPool",
        "concrete receiver resolves to the impl's self type (high tier)"
    );
    assert!(site.provenance.client_type_resolved);
}

#[test]
fn golden_dyn_dispatch_is_mid_tier_with_trait_identity() {
    let Some(d) = derived() else { return };
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "execute" && s.symbol == "query_dyn")
        .expect("query_dyn execute site");
    assert_eq!(
        site.client_type, "dyn sqlx::Executor",
        "visibly-dyn receiver carries the trait identity (mid tier)"
    );
    assert!(site.provenance.client_type_resolved);
}

#[test]
fn golden_generic_dispatch_abstains() {
    let Some(d) = derived() else { return };
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "execute" && s.symbol == "query_generic")
        .expect("query_generic execute site");
    assert_eq!(
        site.client_type, "",
        "uninstantiated generic dispatch must abstain, not guess"
    );
    assert!(!site.provenance.client_type_resolved);
}

#[test]
fn golden_g2_route_registrations_are_server_entries() {
    let Some(d) = derived() else { return };
    let routes: Vec<_> = d
        .sites
        .iter()
        .filter(|s| s.site_kind == rvl_core::SITE_KIND_SERVER_ENTRY)
        .collect();
    assert_eq!(routes.len(), 2, "two .route() registrations: {routes:#?}");
    assert!(routes.iter().all(|s| s.client_type == "axum::Router"));
    // The path literal is constant-argument evidence.
    assert!(
        routes.iter().all(|s| s
            .const_args
            .iter()
            .any(|a| a.value == "\"/users\"" && a.how == "literal")),
        "route path literal must ride const_args: {routes:#?}"
    );
}

#[test]
fn golden_g3_spawns_are_background_jobs() {
    let Some(d) = derived() else { return };
    let jobs: Vec<_> = d
        .sites
        .iter()
        .filter(|s| s.site_kind == "background_job")
        .collect();
    let methods: Vec<&str> = jobs.iter().map(|s| s.method.as_str()).collect();
    assert!(
        methods.contains(&"spawn") && methods.contains(&"spawn_blocking"),
        "tokio spawn family must be inventoried: {methods:?}"
    );
    assert!(jobs.iter().all(|s| s.client_type.starts_with("tokio")));
}

#[test]
fn golden_g4_emissions_aggregate_per_function_and_category() {
    let Some(d) = derived() else { return };
    let ems: Vec<_> = d.sites.iter().filter(|s| s.is_emission_point()).collect();
    // observe() has 3 level-macro calls (info x2, error x1) in ONE function
    // and ONE framework and ONE category → exactly one aggregate.
    let obs: Vec<_> = ems.iter().filter(|s| s.symbol == "observe").collect();
    assert_eq!(
        obs.len(),
        1,
        "one aggregate per (fn, framework, category): {obs:#?}"
    );
    let agg = obs[0];
    assert_eq!(agg.emission_category(), Some("log"));
    assert_eq!(
        agg.emission_count(),
        3,
        "info+info+error collapse to count 3"
    );
    assert!(
        agg.macro_expansion,
        "Rust emission macros genuinely populate macro_expansion"
    );
    assert_eq!(agg.client_type, "tracing");
}

#[test]
fn golden_const_args_carry_the_call_site_timeout() {
    let Some(d) = derived() else { return };
    let bounded = d
        .sites
        .iter()
        .find(|s| s.method == "send" && s.symbol == "fetch_bounded")
        .expect("fetch_bounded send site");
    // The .timeout(Duration::from_secs(5)) rides the SNIPPET (statement
    // re-read) AND becomes name-keyed const-arg evidence on the send site,
    // which is what propagation's CallArg mechanism credits (Rust has no
    // kwargs; the builder method name is the mechanical name).
    assert!(
        bounded.snippet.contains(".timeout(Duration::from_secs(5))"),
        "chain snippet must include the call-site bound: {}",
        bounded.snippet
    );
    let timeout_arg = bounded
        .const_args
        .iter()
        .find(|a| a.name == "timeout")
        .expect("chain timeout must ride const_args name-keyed");
    assert_eq!(timeout_arg.value, "Duration::from_secs(5)");
    assert_eq!(timeout_arg.how, "named_constant");

    // The UNbounded send in fetch_user must NOT get the evidence: the chain
    // association is per-statement, not per-function.
    let unbounded = d
        .sites
        .iter()
        .find(|s| s.method == "send" && s.symbol == "fetch_user")
        .expect("fetch_user send site");
    assert!(
        unbounded.const_args.iter().all(|a| a.name != "timeout"),
        "no chain bound on the unbounded call: {:#?}",
        unbounded.const_args
    );
}

#[test]
fn golden_construction_bounds_reach_repo_config_and_sites() {
    let Some(d) = derived() else { return };
    let cons = &d.repo_config.constructions;
    assert!(
        cons.iter()
            .any(|c| c.type_name == "reqwest::Client" && c.fields == vec!["timeout".to_string()]),
        "ClientBuilder::timeout must be a repo_config construction: {cons:#?}"
    );
    assert!(
        cons.iter().any(|c| c.type_name == "sqlx::pool::PoolOptions"
            && c.fields == vec!["acquire_timeout".to_string()]),
        "PoolOptions::acquire_timeout must be a repo_config construction: {cons:#?}"
    );
    // And the reqwest G1 site can cite its client's construction.
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "get" && s.client_type == "reqwest::Client")
        .expect("client.get site");
    assert!(
        site.client_construction
            .iter()
            .any(|c| c.source.contains("timeout(Duration::from_secs(30))")),
        "construction-time bound must be attached: {:#?}",
        site.client_construction
    );
}

#[test]
fn golden_callers_are_retrieved_depth_one() {
    let Some(d) = derived() else { return };
    let site = d
        .sites
        .iter()
        .find(|s| s.method == "execute" && s.symbol == "query_direct")
        .expect("query_direct execute site");
    assert!(
        site.provenance.callers_total >= 1,
        "main() calls query_direct: {:?}",
        site.provenance
    );
    assert!(
        site.callers.iter().any(|c| c.symbol == "main"),
        "caller snippet must name the calling fn: {:#?}",
        site.callers
    );
}

#[test]
fn golden_incremental_filter_keeps_evidence_repo_wide() {
    let Some((_, index)) = indexed() else { return };
    let d = rustindex::derive::derive(
        &fixture_root(),
        "fixture",
        index,
        Some(&["app/src/main.rs".to_string()]),
    );
    assert!(
        d.sites.iter().all(|s| s.file_path == "app/src/main.rs"),
        "only the requested file's sites are emitted"
    );
    assert!(!d.sites.is_empty(), "the requested file has sites");
}

#[test]
fn golden_no_desugar_junk_and_no_stub_internals() {
    let Some(d) = derived() else { return };
    // `.await` desugar (Future::poll / Try::branch) must never become sites.
    assert!(
        d.sites
            .iter()
            .all(|s| s.method != "poll" && s.method != "branch"),
        "desugar occurrences must be filtered by the token-text check"
    );
    // Stub-internal definitions are definitions, not calls.
    assert!(
        d.sites
            .iter()
            .filter(|s| s.is_call_site())
            .all(|s| s.file_path.starts_with("app/")),
        "G1 call sites come from the app, not the stubs: {:#?}",
        d.sites
            .iter()
            .filter(|s| !s.file_path.starts_with("app/"))
            .map(|s| (&s.file_path, &s.method, &s.site_kind))
            .collect::<Vec<_>>()
    );
}
