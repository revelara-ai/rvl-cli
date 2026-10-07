//! Misuse lane: error-handling and async shapes that are wrong where they
//! stand. Six lens classes share it: H2 (a catch of the root exception type),
//! H3 (an error value assigned to a discard), G5 (a synchronous wait on async
//! work), G6 (a blocking call lexically inside an async function), E5 (an
//! async task started and never held) and E6 (an async call that is never
//! awaited). All six are local: one function is enough to see them.
//!
//! H1, the swallowed error, is not here. It ships through the emission lane
//! (`rvl-emission`, RC-027), and a retriever leaves a handler that lane
//! counts as a swallow out of this one.
//!
//! The retrieval/judgment split is the one every lane keeps. A retriever
//! emits an AGGREGATE packet ([`rvl_core::SITE_KIND_MISUSE`]): one per
//! (enclosing function, class, identity), with a count. Which control a shape
//! violates, and which identities are legitimate, are spec knowledge
//! ([`rvl_spec::MisuseSpec`]). A shape whose class no spec names is not
//! judged.
//!
//! VOLUME is the constraint the lane is built around. These shapes are common,
//! and a report that lists each one is a report nobody reads. So detection
//! stays complete and the lane is quiet in three other ways: one finding per
//! (class, control), a cap on the evidence it carries, and a severity that is
//! never "high" and that the corpus can lower per class.

use rvl_core::{ScopeClass, Site};
use rvl_spec::{MisuseSpec, MIN_CONFIDENCE};
use std::collections::{BTreeMap, BTreeSet};

/// The one role that makes a finding (see [`rvl_spec::MisuseSpec`]). The
/// other known role, `allowed`, is the legitimate-suppression list: like a
/// role this consumer does not know, it produces nothing.
const ROLE_VIOLATES: &str = "violates";

/// A spec `type` that names every identity of its class.
const ANY_IDENTITY: &str = "*";

/// How many evidence sites a finding carries, as in the emission lane.
const MAX_EVIDENCE: usize = 5;

/// One violation: every runtime occurrence of a class that the specs map to
/// one control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MisuseFinding {
    /// The shape's class, e.g. `discarded_error`.
    pub class: String,
    /// The control the matched spec names.
    pub control: String,
    pub reason: String,
    /// The total number of occurrences, across every packet. This is the
    /// exposure of the class, and it is not capped.
    pub occurrences: usize,
    /// `file:line` evidence sites (capped at [`MAX_EVIDENCE`]).
    pub evidence: Vec<String>,
    pub fix: String,
    /// `low` or `medium`, never "high": the retriever reads one function, so
    /// the lane is advisory by design.
    pub severity: &'static str,
}

/// The class in words, its default severity, and the fix for it.
fn describe(class: &str) -> (&'static str, &'static str, &'static str) {
    match class {
        "overbroad_catch" => (
            "handler(s) catch the root exception type and do not re-raise",
            "low",
            "catch the exception types that this code can handle, and let the others propagate",
        ),
        "discarded_error" => (
            "error value(s) are assigned to a discard",
            "low",
            "handle the error, return it, or log it; where the error cannot matter, say why in \
             a comment",
        ),
        "sync_over_async" => (
            "synchronous wait(s) on async work inside an async function",
            "medium",
            "await the async work; a synchronous wait holds the thread that must complete it",
        ),
        "blocking_in_async" => (
            "blocking call(s) inside an async function",
            "medium",
            "use the async form of the call, or move the call to a worker thread; a blocking \
             call stops every task on the event loop",
        ),
        "fire_and_forget" => (
            "async task(s) are started and the result is not held",
            "low",
            "keep a reference to the task and handle its failure; a task with no reference can \
             be collected before it completes, and its exception is lost",
        ),
        "missing_await" => (
            "async call(s) are never awaited",
            "medium",
            "await the call; without an await the work does not run and its failure is not seen",
        ),
        _ => (
            "occurrence(s) of the shape",
            "low",
            "correct the shape at each site",
        ),
    }
}

/// The spec that governs a packet: an exact identity before a class-wide
/// entry, at or above the confidence floor.
fn matching_spec<'a>(specs: &'a [MisuseSpec], site: &Site) -> Option<&'a MisuseSpec> {
    let class = site.misuse_class()?;
    let usable = |s: &&MisuseSpec| s.class == class && s.confidence >= MIN_CONFIDENCE;
    specs
        .iter()
        .filter(usable)
        .find(|s| s.type_name == site.client_type)
        .or_else(|| {
            specs
                .iter()
                .filter(usable)
                .find(|s| s.type_name == ANY_IDENTITY)
        })
}

#[derive(Default)]
struct Group<'a> {
    sites: Vec<&'a Site>,
    /// Whether any matched spec leaves a site at `medium`.
    medium: bool,
}

/// Judge every misuse-shape packet in runtime scope that a `violates` spec
/// names. Deterministic, no model calls. Packets of another kind, packets
/// outside runtime scope, packets an `allowed` spec names and packets no spec
/// names produce nothing.
pub fn evaluate(sites: &[Site], specs: &[MisuseSpec]) -> Vec<MisuseFinding> {
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    for site in sites {
        if !site.is_misuse_shape() || site.scope() != ScopeClass::Runtime {
            continue;
        }
        let Some(spec) = matching_spec(specs, site) else {
            continue;
        };
        // A `violates` entry that names no control produces nothing either:
        // a finding is born control-mapped or not at all.
        if spec.role != ROLE_VIOLATES || spec.control.is_empty() {
            continue;
        }
        let group = groups
            .entry((spec.class.clone(), spec.control.clone()))
            .or_default();
        group.sites.push(site);
        // The spec tunes the severity, and anything it does not say (or
        // says and this lane does not allow, like "high") is the default of
        // the class. Where two specs of one group disagree, the louder one
        // holds.
        let severity = match spec.severity.as_str() {
            s @ ("low" | "medium") => s,
            _ => describe(&spec.class).1,
        };
        group.medium |= severity == "medium";
    }

    groups
        .into_iter()
        .map(|((class, control), mut g)| {
            let (what, _, fix) = describe(&class);
            g.sites
                .sort_by(|a, b| (&a.file_path, a.line_number).cmp(&(&b.file_path, b.line_number)));
            let occurrences: usize = g.sites.iter().map(|s| s.misuse_count() as usize).sum();
            let functions: BTreeSet<(&str, &str)> = g
                .sites
                .iter()
                .map(|s| (s.file_path.as_str(), s.symbol.as_str()))
                .collect();
            MisuseFinding {
                reason: format!("{occurrences} {what}, in {} function(s)", functions.len()),
                occurrences,
                evidence: g.sites.iter().take(MAX_EVIDENCE).map(|s| s.id()).collect(),
                fix: format!("{fix} ({control})"),
                severity: if g.medium { "medium" } else { "low" },
                class,
                control,
            }
        })
        .collect()
}
