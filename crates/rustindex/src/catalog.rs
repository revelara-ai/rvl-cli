//! The G1–G4 site-class catalogs for Rust.
//!
//! RETRIEVAL knowledge only: which crate identities mark a client call, a
//! server-entry registration, a background-job registration, or an emission
//! point. Whether a control governs a matched site is spec-layer judgment.

use crate::symbol::{ParsedSymbol, SymbolKind};

/// What kind of site (or evidence) a matched occurrence yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteClass {
    /// G1: a client call site (classic empty `site_kind`).
    ClientCall,
    /// G2: an HTTP route/handler registration (`site_kind: server_entry`).
    ServerEntry,
    /// G3: a spawn/scheduler/queue registration (`site_kind: background_job`).
    BackgroundJob,
    /// G4: an emission call, aggregated per (function, framework, category).
    Emission { category: &'static str },
    /// Not a site: construction-time bound evidence (a builder timeout), fed
    /// into `client_construction` and the repo_config record.
    Construction {
        /// The constructed client family's type path (e.g. `reqwest::Client`).
        type_name: &'static str,
        /// The bound-carrying field, when this construction call sets one.
        bound_field: Option<&'static str>,
    },
    /// Not a site: a call-level bound set in the SAME statement chain as a
    /// client call (`.timeout(d).send()`). Rust has no keyword arguments, so
    /// this is how a call-site timeout becomes name-keyed const-arg evidence.
    CallBound {
        /// The bound's name as the mechanism knows it (`timeout`).
        name: &'static str,
    },
}

/// G1 client-call methods per crate. A method name must resolve to one of
/// these crates to match; name collisions in user code never match because
/// the moniker carries the defining crate.
const G1: &[(&str, &[&str])] = &[
    (
        "reqwest",
        &[
            "get", "post", "put", "delete", "patch", "head", "execute", "request", "send",
        ],
    ),
    (
        "reqwest-middleware",
        &[
            "get", "post", "put", "delete", "patch", "head", "execute", "request", "send",
        ],
    ),
    ("hyper", &["request", "send_request", "get"]),
    (
        "sqlx",
        &[
            "execute",
            "fetch",
            "fetch_one",
            "fetch_all",
            "fetch_optional",
            "acquire",
            "begin",
        ],
    ),
    (
        "tokio-postgres",
        &[
            "query",
            "query_one",
            "query_opt",
            "execute",
            "batch_execute",
            "prepare",
        ],
    ),
    (
        "redis",
        &[
            "get",
            "set",
            "del",
            "incr",
            "expire",
            "publish",
            "query",
            "query_async",
        ],
    ),
    (
        "lapin",
        &[
            "basic_publish",
            "basic_consume",
            "basic_ack",
            "create_channel",
        ],
    ),
    ("rdkafka", &["send", "poll", "commit", "flush"]),
    (
        "tonic",
        &[
            "ready",
            "unary",
            "streaming",
            "server_streaming",
            "client_streaming",
        ],
    ),
];

/// G2 server-entry registrations: (crate, self/owner type or "" for free
/// functions, method).
const G2: &[(&str, &str, &str)] = &[
    ("axum", "Router", "route"),
    ("axum", "Router", "nest"),
    ("actix-web", "App", "route"),
    ("actix-web", "App", "service"),
    ("actix-web", "Scope", "route"),
    ("actix-web", "Scope", "service"),
    ("actix-web", "", "resource"),
    ("warp", "", "serve"),
    ("rocket", "Rocket", "mount"),
    ("rocket", "", "mount"),
];

/// G3 background-job registrations: (crate, self/owner type or "", method).
/// Every spawn-family registration is INVENTORIED; whether a given spawn is a
/// governed job is spec-side judgment (retrieval-only rule).
const G3: &[(&str, &str, &str)] = &[
    ("tokio", "", "spawn"),
    ("tokio", "", "spawn_blocking"),
    ("tokio", "", "spawn_local"),
    ("std", "", "spawn"),
    ("async-std", "", "spawn"),
    ("tokio-cron-scheduler", "Job", "new"),
    ("tokio-cron-scheduler", "Job", "new_async"),
    ("tokio-cron-scheduler", "JobScheduler", "add"),
];

/// G4 emission identities: (crate, macro?, name, category). Categories follow
/// the G4 convention: `log` | `trace` | `error_capture`.
const G4: &[(&str, bool, &str, &str)] = &[
    ("tracing", true, "trace", "log"),
    ("tracing", true, "debug", "log"),
    ("tracing", true, "info", "log"),
    ("tracing", true, "warn", "log"),
    ("tracing", true, "error", "log"),
    ("tracing", true, "span", "trace"),
    ("tracing", true, "info_span", "trace"),
    ("tracing", false, "info_span", "trace"),
    ("tracing", false, "span", "trace"),
    ("log", true, "trace", "log"),
    ("log", true, "debug", "log"),
    ("log", true, "info", "log"),
    ("log", true, "warn", "log"),
    ("log", true, "error", "log"),
    ("sentry", false, "capture_error", "error_capture"),
    ("sentry", false, "capture_message", "error_capture"),
    ("sentry", false, "capture_event", "error_capture"),
    ("opentelemetry", false, "start", "trace"),
];

/// Construction-time bound evidence: (crate, self type, method, family type
/// path, bound field). `bound_field: Some` marks a call that SETS a bound;
/// `None` marks a plain constructor worth citing as construction provenance.
const CONSTRUCTIONS: &[(&str, &str, &str, &str, Option<&str>)] = &[
    (
        "reqwest",
        "ClientBuilder",
        "timeout",
        "reqwest::Client",
        Some("timeout"),
    ),
    (
        "reqwest",
        "ClientBuilder",
        "connect_timeout",
        "reqwest::Client",
        Some("connect_timeout"),
    ),
    ("reqwest", "Client", "builder", "reqwest::Client", None),
    ("reqwest", "ClientBuilder", "build", "reqwest::Client", None),
    (
        "sqlx",
        "PoolOptions",
        "acquire_timeout",
        "sqlx::pool::PoolOptions",
        Some("acquire_timeout"),
    ),
    (
        "sqlx",
        "PoolOptions",
        "new",
        "sqlx::pool::PoolOptions",
        None,
    ),
    ("redis", "Client", "open", "redis::Client", None),
    (
        "tokio-postgres",
        "Config",
        "connect_timeout",
        "tokio_postgres::Config",
        Some("connect_timeout"),
    ),
];

/// Call-level bounds set on a request/statement chain: (crate, self type,
/// method, bound name). Matched per-statement in derivation and surfaced as
/// name-keyed const-arg evidence on the sibling call site.
const CALL_BOUNDS: &[(&str, &str, &str, &str)] = &[
    ("reqwest", "RequestBuilder", "timeout", "timeout"),
    ("reqwest-middleware", "RequestBuilder", "timeout", "timeout"),
];

/// The type a method call resolved against: the concrete self type when the
/// impl is known, otherwise the declaring type/trait.
fn resolved_type(sym: &ParsedSymbol) -> Option<&str> {
    sym.self_type.as_deref().or(sym.owner_type.as_deref())
}

/// Classify a parsed symbol against the catalogs. Constructions are checked
/// first (a builder's `timeout` must not be mistaken for a client call), then
/// G2/G3/G4, then the broad G1 method lists.
pub fn classify(sym: &ParsedSymbol) -> Option<SiteClass> {
    match sym.kind {
        SymbolKind::Method | SymbolKind::Function => {}
        SymbolKind::Macro => {
            for (krate, is_macro, name, category) in G4 {
                if *is_macro && sym.crate_name == *krate && sym.name == *name {
                    return Some(SiteClass::Emission { category });
                }
            }
            return None;
        }
        SymbolKind::Type => return None,
    }

    let rtype = resolved_type(sym).unwrap_or("");

    for (krate, self_ty, method, family, field) in CONSTRUCTIONS {
        if sym.crate_name == *krate && sym.name == *method && rtype == *self_ty {
            return Some(SiteClass::Construction {
                type_name: family,
                bound_field: *field,
            });
        }
    }
    for (krate, self_ty, method, name) in CALL_BOUNDS {
        if sym.crate_name == *krate && sym.name == *method && rtype == *self_ty {
            return Some(SiteClass::CallBound { name });
        }
    }
    for (krate, owner, method) in G2 {
        if sym.crate_name == *krate && sym.name == *method && (owner.is_empty() || rtype == *owner)
        {
            return Some(SiteClass::ServerEntry);
        }
    }
    for (krate, owner, method) in G3 {
        if sym.crate_name == *krate && sym.name == *method && (owner.is_empty() || rtype == *owner)
        {
            return Some(SiteClass::BackgroundJob);
        }
    }
    for (krate, is_macro, name, category) in G4 {
        if !*is_macro && sym.crate_name == *krate && sym.name == *name {
            return Some(SiteClass::Emission { category });
        }
    }
    for (krate, methods) in G1 {
        if sym.crate_name == *krate && methods.contains(&sym.name.as_str()) {
            return Some(SiteClass::ClientCall);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbol::parse;

    #[test]
    fn reqwest_get_is_a_client_call() {
        let s = parse("rust-analyzer cargo reqwest 0.11.0 impl#[Client]get().").unwrap();
        assert_eq!(classify(&s), Some(SiteClass::ClientCall));
    }

    #[test]
    fn a_user_crate_get_never_matches() {
        // The catalog is crate-keyed: `get` on the user's own type is not a
        // reqwest call, whatever it is named.
        let s = parse("rust-analyzer cargo myapp 0.1.0 impl#[Cache]get().").unwrap();
        assert_eq!(classify(&s), None);
    }

    #[test]
    fn builder_timeout_is_construction_evidence_not_a_call() {
        let s = parse("rust-analyzer cargo reqwest 0.11.0 impl#[ClientBuilder]timeout().").unwrap();
        assert_eq!(
            classify(&s),
            Some(SiteClass::Construction {
                type_name: "reqwest::Client",
                bound_field: Some("timeout"),
            })
        );
    }

    #[test]
    fn pool_acquire_timeout_is_bound_evidence() {
        let s = parse("rust-analyzer cargo sqlx 0.7.0 pool/impl#[PoolOptions]acquire_timeout().")
            .unwrap();
        assert_eq!(
            classify(&s),
            Some(SiteClass::Construction {
                type_name: "sqlx::pool::PoolOptions",
                bound_field: Some("acquire_timeout"),
            })
        );
    }

    #[test]
    fn axum_route_is_server_entry() {
        let s = parse("rust-analyzer cargo axum 0.7.0 impl#[Router]route().").unwrap();
        assert_eq!(classify(&s), Some(SiteClass::ServerEntry));
    }

    #[test]
    fn tokio_spawn_family_is_background_job() {
        let spawn = parse("rust-analyzer cargo tokio 1.0.0 spawn().").unwrap();
        assert_eq!(classify(&spawn), Some(SiteClass::BackgroundJob));
        let blocking = parse("rust-analyzer cargo tokio 1.0.0 task/spawn_blocking().").unwrap();
        assert_eq!(classify(&blocking), Some(SiteClass::BackgroundJob));
        let thread = parse(
            "rust-analyzer cargo std https://github.com/rust-lang/rust/library/std thread/spawn().",
        )
        .unwrap();
        assert_eq!(classify(&thread), Some(SiteClass::BackgroundJob));
    }

    #[test]
    fn tracing_macros_are_emissions() {
        let s = parse("rust-analyzer cargo tracing 0.1.0 info!").unwrap();
        assert_eq!(classify(&s), Some(SiteClass::Emission { category: "log" }));
        let e = parse("rust-analyzer cargo tracing 0.1.0 error!").unwrap();
        assert_eq!(classify(&e), Some(SiteClass::Emission { category: "log" }));
    }

    #[test]
    fn trait_level_execute_still_matches_g1() {
        // dyn/generic dispatch resolves to the trait method; the catalog must
        // still recognize it (the TIER decision happens in derivation).
        let s = parse("rust-analyzer cargo sqlx 0.7.0 Executor#execute().").unwrap();
        assert_eq!(classify(&s), Some(SiteClass::ClientCall));
    }
}
