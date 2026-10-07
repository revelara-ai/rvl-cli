//! Unsized-construction lane: an object that takes a bound was constructed,
//! and no bound was set on it in the same scope. Four lens classes share the
//! shape: M6 (a connection pool with no maximum), D2 (a queue with no
//! capacity), F2 (a cache with no size cap or TTL) and F3 (a read of a whole
//! body with no size limit).
//!
//! It is the question the client-call lane answers for timeouts, asked about
//! a different bound, and the retrieval/judgment split is the same. A
//! retriever emits one packet per construction
//! ([`rvl_core::SITE_KIND_UNSIZED`]) and lists the setters and options it
//! OBSERVED in the constructing function. Which of those names is a bound,
//! which values mean "no limit", and which control is violated are spec
//! knowledge ([`rvl_spec::ConstructionBoundSpec`]). A construction no spec
//! names is not judged.
//!
//! A bound set through a non-constant (`pool.SetMaxOpenConns(cfg.Max)`) is a
//! name, not a value. It is credited as a bound and never resolved: a value
//! the engine cannot see is not compared against anything and is not
//! reported.

use rvl_core::{ConstArg, ScopeClass, Site, Verdict, BOUND_HOW_TYPE};
use rvl_spec::{ConstructionBoundSpec, MIN_CONFIDENCE};
use std::collections::BTreeMap;

/// How many evidence sites a finding carries, as in the emission lane.
const MAX_EVIDENCE: usize = 5;

/// One conclusion per (class, control) that at least one spec'd runtime
/// construction falls under. Satisfies and abstain outcomes are part of the
/// record; the caller decides what to surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundFinding {
    /// `pool` | `queue` | `cache` | `read`.
    pub class: String,
    /// The control the matched spec names, e.g. "RC-055".
    pub control: String,
    pub verdict: Verdict,
    pub reason: String,
    /// `file:line` evidence sites (capped at [`MAX_EVIDENCE`]).
    pub evidence: Vec<String>,
    /// Suggested fix (shown on violates).
    pub fix: String,
    /// Never "high": the retriever reads one function, so the lane is
    /// advisory by design.
    pub severity: &'static str,
}

/// What one construction's observations prove under one spec.
enum SiteBound {
    Bounded,
    /// No bound, with the reason in words.
    Unbounded(String),
    /// The retriever could not see enough to say.
    Unknown,
}

/// Whether the retriever resolved the observation's VALUE. Everything else
/// that is in scope (a non-constant, a wrapping call, a label this consumer
/// does not know) says a bound is set and says nothing about its value.
fn value_known(obs: &ConstArg) -> bool {
    matches!(obs.how.as_str(), "literal" | "named_constant")
}

fn judge(site: &Site, spec: &ConstructionBoundSpec) -> SiteBound {
    let names = |obs: &&ConstArg| spec.bounded_by.contains(&obs.name);
    let (elsewhere, in_scope): (Vec<&ConstArg>, Vec<&ConstArg>) = site
        .bound_observations()
        .filter(names)
        .partition(|obs| obs.how == BOUND_HOW_TYPE);

    let no_limit = |obs: &&ConstArg| value_known(obs) && spec.unbounded_values.contains(&obs.value);
    if in_scope.iter().any(|obs| !no_limit(obs)) {
        return SiteBound::Bounded;
    }
    if let Some(obs) = in_scope.first() {
        return SiteBound::Unbounded(format!(
            "{} is set to {}, which means no limit",
            obs.name, obs.value
        ));
    }
    if spec.default_bounded {
        return SiteBound::Bounded;
    }
    if site.bound_opaque() {
        return SiteBound::Unknown;
    }
    if !site.bound_escapes() {
        return SiteBound::Unbounded("no bound is set where it is constructed".into());
    }
    if elsewhere.is_empty() {
        SiteBound::Unbounded(
            "no bound is set where it is constructed or on this type anywhere in the \
             repository"
                .into(),
        )
    } else {
        SiteBound::Unknown
    }
}

/// The spec that governs a construction: same type, same class, at or above
/// the confidence floor.
fn matching_spec<'a>(
    specs: &'a [ConstructionBoundSpec],
    site: &Site,
) -> Option<&'a ConstructionBoundSpec> {
    let class = site.bound_class()?;
    specs.iter().find(|s| {
        s.confidence >= MIN_CONFIDENCE && s.type_name == site.client_type && s.class == class
    })
}

/// The class in words, and the fix for it.
fn describe(class: &str) -> (&'static str, &'static str) {
    match class {
        "pool" => (
            "connection pool",
            "set a maximum size on the pool, and an idle limit or a connection lifetime where \
             the library has one",
        ),
        "queue" => (
            "queue",
            "give the queue a finite capacity, so that a slow consumer pushes back on the \
             producer and memory does not grow without limit",
        ),
        "cache" => (
            "cache",
            "give the cache a size limit or an expiry, so that it cannot grow for the life of \
             the process",
        ),
        "read" => (
            "whole-body read",
            "limit the size of the read (a limited reader, a maximum body size, or a row \
             limit) before the whole body is held in memory",
        ),
        _ => (
            "construction",
            "set the bound that the library provides for this object",
        ),
    }
}

#[derive(Default)]
struct Group<'a> {
    total: usize,
    unbounded: Vec<(&'a Site, String)>,
    unknown: Vec<&'a Site>,
}

/// Judge every unsized-construction packet in runtime scope that a spec
/// names. Deterministic, no model calls. Packets of another kind, packets
/// outside runtime scope and packets no spec names produce nothing.
pub fn evaluate(sites: &[Site], specs: &[ConstructionBoundSpec]) -> Vec<BoundFinding> {
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    for site in sites {
        if !site.is_unsized_construction() || site.scope() != ScopeClass::Runtime {
            continue;
        }
        let Some(spec) = matching_spec(specs, site) else {
            continue;
        };
        let group = groups
            .entry((spec.class.clone(), spec.control.clone()))
            .or_default();
        group.total += 1;
        match judge(site, spec) {
            SiteBound::Bounded => {}
            SiteBound::Unbounded(why) => group.unbounded.push((site, why)),
            SiteBound::Unknown => group.unknown.push(site),
        }
    }

    groups
        .into_iter()
        .map(|((class, control), g)| {
            let (noun, fix) = describe(&class);
            let (verdict, reason, evidence) = if let Some((_, why)) = g.unbounded.first() {
                (
                    Verdict::Violates,
                    format!(
                        "{} of {} {noun}(s) have no bound: {why}",
                        g.unbounded.len(),
                        g.total
                    ),
                    g.unbounded.iter().map(|(s, _)| s.id()).collect::<Vec<_>>(),
                )
            } else if !g.unknown.is_empty() {
                (
                    Verdict::Abstain,
                    format!(
                        "{} of {} {noun}(s) may be bounded where the retriever cannot see: the \
                         value leaves the constructing function and a bound is set on its type \
                         elsewhere, or the constructor takes options that are not written out",
                        g.unknown.len(),
                        g.total
                    ),
                    g.unknown.iter().map(|s| s.id()).collect(),
                )
            } else {
                (
                    Verdict::Satisfies,
                    format!("all {} {noun}(s) set a bound", g.total),
                    vec![],
                )
            };
            BoundFinding {
                fix: format!("{fix} ({control})"),
                class,
                control,
                verdict,
                reason,
                evidence: evidence.into_iter().take(MAX_EVIDENCE).collect(),
                severity: "medium",
            }
        })
        .collect()
}
