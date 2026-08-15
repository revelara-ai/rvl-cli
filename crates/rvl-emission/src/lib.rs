//! G4 emission-point lane (po-av01j.5): evaluate the emission inventory —
//! log statements, span/trace instrumentation, error-handling sites — against
//! the observability controls RC-027 (centralized error monitoring), RC-046
//! (distributed tracing), and RC-061 (LLM observability, the emission half;
//! the call-site half rides G1).
//!
//! The retrieval/judgment split, unchanged: the per-language emitters report
//! AGGREGATE facts ("this function contains 17 slog.Logger log calls", "this
//! function has 2 except blocks that emit nothing"), one packet per
//! (enclosing function, framework, category) — never one per log line. What a
//! matched aggregate MEANS is spec knowledge ([`rvl_spec::EmissionSpec`]),
//! consumed as data here and authored by the factory + a human.
//!
//! Abstention philosophy, mirroring rvl-structure: a verdict rests on
//! POSITIVE evidence wherever possible (a swallow aggregate present, a trace
//! emission present). Reasoning from absence — "no span instrumentation
//! anywhere" — is licensed only when the stream carries at least one
//! emission-point packet, proving a G4-capable emitter ran; a pre-G4 stream
//! abstains instead of minting false violations.

use rvl_core::{ScopeClass, Site, Verdict};
use rvl_spec::{EmissionSpec, MIN_CONFIDENCE};
use std::collections::BTreeSet;

/// Emission spec roles (see [`rvl_spec::EmissionSpec`]).
const ROLE_SATISFIES: &str = "satisfies";
const ROLE_VIOLATES: &str = "violates";
const ROLE_ANCHOR: &str = "anchor";

/// How many evidence sites a finding carries. Volume control at the finding
/// layer, matching the triage `example_sites` cap order of magnitude.
const MAX_EVIDENCE: usize = 5;

/// One control-mapped conclusion drawn from the emission inventory. Emitted
/// one per control, every time — satisfies/abstain outcomes are part of the
/// record; the renderer decides what to surface (only violations, advisory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmissionFinding {
    /// Control code, e.g. "RC-027".
    pub control: &'static str,
    /// Control name for display.
    pub control_name: &'static str,
    pub verdict: Verdict,
    pub reason: String,
    /// `file:line` evidence sites (capped at [`MAX_EVIDENCE`]).
    pub evidence: Vec<String>,
    /// Suggested fix (shown on violates).
    pub fix: String,
    /// Base severity when this control violates. Never "high": emission
    /// findings are advisory by design — an observability gap warrants a
    /// conversation, not a blocked commit.
    pub severity: &'static str,
}

/// Match an emission aggregate against the spec corpus: exact identity match,
/// same category, minimum confidence. Unrecognized frameworks match nothing —
/// the emitter abstained from judging them and so does the evaluator.
fn matching_spec<'a>(
    specs: &'a [EmissionSpec],
    site: &Site,
    control: &str,
    role: &str,
) -> Option<&'a EmissionSpec> {
    let category = site.emission_category()?;
    specs.iter().find(|s| {
        s.control == control
            && s.role == role
            && s.confidence >= MIN_CONFIDENCE
            && s.type_name == site.client_type
            && s.category == category
    })
}

/// Runtime-scope filter: emissions and anchors in test support, migrations,
/// or dev tooling neither satisfy nor violate an observability control for
/// the production surface.
fn runtime(site: &Site) -> bool {
    site.scope() == ScopeClass::Runtime
}

/// The (file, enclosing function) identity used to ask "does this function
/// also emit?". Function granularity is the aggregation contract the
/// emitters uphold, so it is the finest join available — and it is enough:
/// an emission anywhere in the enclosing function counts as "surrounding".
fn function_key(site: &Site) -> (String, String) {
    (site.file_path.clone(), site.symbol.clone())
}

/// Evaluate the emission inventory against RC-027, RC-046, and RC-061.
/// `call_sites` are the G1 packets (the I/O anchors); `emission_sites` are
/// the G4 aggregates. Deterministic, no model calls.
pub fn evaluate(
    call_sites: &[Site],
    emission_sites: &[Site],
    specs: &[EmissionSpec],
) -> Vec<EmissionFinding> {
    vec![
        eval_error_monitoring(emission_sites, specs),
        eval_tracing(call_sites, emission_sites, specs),
        eval_llm_observability(call_sites, emission_sites, specs),
    ]
}

/// RC-027 — centralized error monitoring. The seed question: do error paths
/// CAPTURE (a sentry-style capture, a log emission on the handler path) or
/// SWALLOW (an except/catch/recover with no emission at all)? Swallow
/// aggregates are positive evidence of a gap; capture aggregates are positive
/// evidence of the control. No inventory at all abstains.
fn eval_error_monitoring(emission_sites: &[Site], specs: &[EmissionSpec]) -> EmissionFinding {
    let control = "RC-027";
    let control_name = "centralized error monitoring";
    let fix = "capture or log the error on every handled path (error tracker capture or a \
               structured log emission), and aggregate errors centrally with alerting (RC-027)"
        .to_string();
    let mk = |verdict, reason: String, evidence| EmissionFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "medium",
    };

    if !specs.iter().any(|s| s.control == control) {
        return mk(
            Verdict::Abstain,
            "no error-monitoring emission specs loaded".into(),
            vec![],
        );
    }

    // Swallowed error paths: aggregates a `violates` spec recognizes
    // (except_handler / catch_clause / recover_block — error-handling sites
    // with no capture or log emission inside them).
    let swallows: Vec<&Site> = emission_sites
        .iter()
        .filter(|s| runtime(s))
        .filter(|s| matching_spec(specs, s, control, ROLE_VIOLATES).is_some())
        .collect();
    if !swallows.is_empty() {
        let paths: u32 = swallows.iter().map(|s| s.emission_count()).sum();
        let functions = swallows.len();
        return mk(
            Verdict::Violates,
            format!(
                "{paths} error path(s) across {functions} function(s) swallow errors with no \
                 capture or log emission"
            ),
            swallows.iter().take(MAX_EVIDENCE).map(|s| s.id()).collect(),
        );
    }

    let captures: Vec<&Site> = emission_sites
        .iter()
        .filter(|s| runtime(s))
        .filter(|s| matching_spec(specs, s, control, ROLE_SATISFIES).is_some())
        .collect();
    if !captures.is_empty() {
        return mk(
            Verdict::Satisfies,
            format!(
                "error paths emit: {} capture/log aggregate(s) on handled-error paths",
                captures.len()
            ),
            captures.iter().take(MAX_EVIDENCE).map(|s| s.id()).collect(),
        );
    }

    mk(
        Verdict::Abstain,
        "no error-handling sites inventoried (no error paths in runtime scope, or the stream \
         predates the G4 emitter)"
            .into(),
        vec![],
    )
}

/// RC-046 — distributed tracing at I/O boundaries. Anchors are the G1 call
/// sites (each is a boundary a span should cover). A violation needs the
/// stream to carry emission inventory at all — otherwise a pre-G4 stream
/// would read as "no tracing anywhere".
fn eval_tracing(
    call_sites: &[Site],
    emission_sites: &[Site],
    specs: &[EmissionSpec],
) -> EmissionFinding {
    let control = "RC-046";
    let control_name = "distributed tracing";
    let fix = "instrument I/O boundaries with OpenTelemetry (or equivalent) spans and propagate \
               trace context across service calls (RC-046)"
        .to_string();
    let mk = |verdict, reason: String, evidence| EmissionFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "medium",
    };

    if !specs.iter().any(|s| s.control == control) {
        return mk(
            Verdict::Abstain,
            "no tracing emission specs loaded".into(),
            vec![],
        );
    }
    let anchors: Vec<&Site> = call_sites.iter().filter(|s| runtime(s)).collect();
    if anchors.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no runtime I/O call sites to trace".into(),
            vec![],
        );
    }
    if emission_sites.is_empty() {
        return mk(
            Verdict::Abstain,
            "no emission inventory in the stream (a pre-G4 retriever): absence of spans is not \
             evidence"
                .into(),
            vec![],
        );
    }

    let traced_functions: BTreeSet<(String, String)> = emission_sites
        .iter()
        .filter(|s| matching_spec(specs, s, control, ROLE_SATISFIES).is_some())
        .map(function_key)
        .collect();
    let anchor_functions: BTreeSet<(String, String)> =
        anchors.iter().map(|s| function_key(s)).collect();

    if traced_functions.is_empty() {
        return mk(
            Verdict::Violates,
            format!(
                "no span instrumentation found at any of {} I/O function(s)",
                anchor_functions.len()
            ),
            anchors.iter().take(MAX_EVIDENCE).map(|s| s.id()).collect(),
        );
    }
    let uncovered: Vec<&(String, String)> = anchor_functions
        .iter()
        .filter(|k| !traced_functions.contains(*k))
        .collect();
    if !uncovered.is_empty() {
        return mk(
            Verdict::Violates,
            format!(
                "tracing is adopted but {} of {} I/O function(s) have no span instrumentation",
                uncovered.len(),
                anchor_functions.len()
            ),
            uncovered
                .iter()
                .take(MAX_EVIDENCE)
                .map(|(f, sym)| format!("{f} ({sym})"))
                .collect(),
        );
    }
    mk(
        Verdict::Satisfies,
        format!(
            "all {} I/O function(s) carry span instrumentation",
            anchor_functions.len()
        ),
        vec![],
    )
}

/// RC-061 — LLM observability, the emission half. Anchors are G1 call sites
/// whose client type an `anchor` spec names as an LLM SDK surface; each such
/// call's enclosing function must emit SOMETHING (span, log, or capture — any
/// satisfies-spec'd emission, any control) for the call to be observable.
fn eval_llm_observability(
    call_sites: &[Site],
    emission_sites: &[Site],
    specs: &[EmissionSpec],
) -> EmissionFinding {
    let control = "RC-061";
    let control_name = "LLM observability (emission)";
    let fix = "wrap every LLM call in a telemetry span (OTel GenAI semantic conventions) or, \
               minimally, a structured log emission carrying model/tokens/latency (RC-061)"
        .to_string();
    let mk = |verdict, reason: String, evidence| EmissionFinding {
        control,
        control_name,
        verdict,
        reason,
        evidence,
        fix: fix.clone(),
        severity: "medium",
    };

    let anchor_specs: Vec<&EmissionSpec> = specs
        .iter()
        .filter(|s| s.control == control && s.role == ROLE_ANCHOR && s.confidence >= MIN_CONFIDENCE)
        .collect();
    if anchor_specs.is_empty() {
        return mk(
            Verdict::Abstain,
            "no LLM anchor specs loaded".into(),
            vec![],
        );
    }
    let anchors: Vec<&Site> = call_sites
        .iter()
        .filter(|s| runtime(s))
        .filter(|s| anchor_specs.iter().any(|a| a.type_name == s.client_type))
        .collect();
    if anchors.is_empty() {
        return mk(
            Verdict::NotApplicable,
            "no LLM call sites recognized".into(),
            vec![],
        );
    }
    if emission_sites.is_empty() {
        return mk(
            Verdict::Abstain,
            "no emission inventory in the stream (a pre-G4 retriever): absence of telemetry is \
             not evidence"
                .into(),
            vec![],
        );
    }

    // Any recognized emission (any control, role satisfies) in the anchor's
    // enclosing function counts as surrounding telemetry.
    let emitting_functions: BTreeSet<(String, String)> = emission_sites
        .iter()
        .filter(|s| {
            ["RC-027", "RC-046", "RC-061"]
                .iter()
                .any(|c| matching_spec(specs, s, c, ROLE_SATISFIES).is_some())
        })
        .map(function_key)
        .collect();

    let uncovered: Vec<&&Site> = anchors
        .iter()
        .filter(|s| !emitting_functions.contains(&function_key(s)))
        .collect();
    if !uncovered.is_empty() {
        return mk(
            Verdict::Violates,
            format!(
                "{} of {} LLM call site(s) have no surrounding emission (no span, log, or \
                 capture in the enclosing function)",
                uncovered.len(),
                anchors.len()
            ),
            uncovered
                .iter()
                .take(MAX_EVIDENCE)
                .map(|s| s.id())
                .collect(),
        );
    }
    mk(
        Verdict::Satisfies,
        format!(
            "all {} LLM call site(s) have surrounding emission",
            anchors.len()
        ),
        vec![],
    )
}
