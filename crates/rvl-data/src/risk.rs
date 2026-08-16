//! Slice (c): `risk` commands, ported from rvl-cli
//! `internal/commands/risk.go`.
//!
//! JSON parity map:
//! - `list --format=json`, `show --format=json`: raw server body verbatim.
//! - `ready --format=json`: client-side filter + re-marshal — golden-tested
//!   against Go's `json.MarshalIndent` on the exact rvl-cli structs.
//! - `context --format=json`: the composed map (context body + `detail` +
//!   `coverage_gap`) — golden-tested against Go's map re-marshal (sorted
//!   keys) with the coverage struct keeping its field order.
//! - compound risks (CR-XXX) live at /api/v1/compound-risks and print the
//!   raw detail body in JSON mode.

use crate::client::Client;
use crate::display;
use crate::gojson::{compact, path_escape, pretty, query_encode, G};
use crate::risk_context_render as render;
use crate::{CmdResult, Failure, BIN};
use rvl_core::flag::EmptyFlag;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum RiskCmd {
    /// List all risks in the register
    List {
        /// Filter by status (e.g. applicable, accepted, mitigated)
        #[arg(long)]
        status: Option<String>,
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
        /// Filter by linked service
        #[arg(long)]
        service: Option<String>,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
        /// Number of results (default: 1000, the server cap)
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },
    /// Top unresolved risks ranked by score (highest value first)
    Ready {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,
        /// Filter by linked service
        #[arg(long)]
        service: Option<String>,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
        /// Number of results (default: 10)
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },
    /// Show detailed information about a specific risk
    Show {
        /// Risk code (R-XXX or CR-XXX)
        code: String,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// Show full context (controls, knowledge, service history)
    Context {
        /// Risk code (R-XXX or CR-XXX)
        code: String,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// List risks marked as stale
    Stale,
    /// Mark a risk as resolved
    Resolve {
        /// Risk code (R-XXX or CR-XXX)
        code: String,
        /// Resolution reason
        #[arg(long)]
        reason: Option<String>,
        /// Output format: json for the raw server response
        #[arg(long)]
        format: Option<String>,
    },
    /// Accept a risk (intentional decision to retain)
    Accept {
        /// Risk code (R-XXX)
        code: String,
        /// Acceptance reason
        #[arg(long)]
        reason: Option<String>,
    },
}

/// A risk row — the exact typed subset rvl-cli carries (field order here
/// IS the JSON field order on the re-marshal path).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Risk {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub risk_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub status: String,
    /// `linked_services` has no omitempty in Go: absent/null stays null,
    /// `[]` stays `[]`. Option distinguishes the two.
    #[serde(default)]
    pub linked_services: Option<Vec<String>>,
    #[serde(default)]
    pub control_codes: Vec<String>,
    #[serde(default)]
    pub stale_since: String,
    #[serde(default)]
    pub last_seen_at: String,
    #[serde(default)]
    pub resolved_at: String,
    #[serde(default)]
    pub uca_type: String,
    #[serde(default)]
    pub causal_factors: Vec<String>,
    #[serde(default)]
    pub loss_scenario: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListRisksResponse {
    #[serde(default)]
    pub risks: Vec<Risk>,
    #[serde(default)]
    pub total: i64,
}

#[derive(Debug, Default, Deserialize)]
pub struct RiskDetail {
    #[serde(flatten)]
    pub risk: Risk,
    #[serde(default)]
    pub mapped_controls: Vec<MappedControl>,
    #[serde(default)]
    pub narrative: String,

    // Parity fields for the full `risk context` table (po-p3xur on the Go
    // side, po-av01j.185 item 4 here). Additive and render-only: `show
    // --format=json` still echoes the raw server body, so typing them here
    // narrows nothing.
    #[serde(default)]
    pub likelihood: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub trend: String,
    #[serde(default)]
    pub plain_summary: String,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub source_intelligence_tier: String,
    #[serde(default)]
    pub risk_class: String,
    #[serde(default)]
    pub resolution_reason: String,
    #[serde(default)]
    pub constraint_type: String,
    #[serde(default)]
    pub evidence_status: String,
    #[serde(default)]
    pub graph_multiplier: f64,
    #[serde(default)]
    pub created_at: String,
    #[serde(default)]
    pub updated_at: String,
    #[serde(default)]
    pub related_findings: Vec<render::RelatedFindingItem>,
    /// Free-form on the wire (oneOf array/object): kept raw and decoded
    /// only by the renderer, which tolerates a shape it cannot read.
    #[serde(default)]
    pub substantiation: Option<Box<serde_json::value::RawValue>>,
    #[serde(default)]
    pub corroborating_incidents: Vec<render::CorroboratingIncidentItem>,
    #[serde(default)]
    pub score_breakdown: Option<render::ScoreBreakdown>,
    #[serde(default)]
    pub latest_dismissal: Option<render::LatestDismissal>,
    #[serde(default)]
    pub stpa_provenance: Option<render::StpaProvenanceData>,
    #[serde(default)]
    pub generated_matcher: Option<render::GeneratedMatcherRef>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct MappedControl {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default, rename = "type")]
    pub control_type: String,
}

// --- compound risks (CR-XXX) ---

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CompoundRiskSummary {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub risk_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub narrative: String,
    #[serde(default, rename = "linked_services")]
    pub services: Vec<String>,
    #[serde(default)]
    pub last_seen_at: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct CompoundRuleDetail {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub control_codes: Vec<String>,
    #[serde(default)]
    pub min_control_count: i64,
    #[serde(default)]
    pub rationale: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ConstituentRiskSummary {
    #[serde(default)]
    pub risk_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub control_codes: Vec<String>,
    #[serde(default)]
    pub score: i64,
}

#[derive(Debug, Default, Deserialize)]
pub struct CompoundRiskDetailResponse {
    #[serde(default)]
    pub risk: CompoundRiskSummary,
    #[serde(default)]
    pub rule: CompoundRuleDetail,
    #[serde(default)]
    pub constituents: Vec<ConstituentRiskSummary>,
}

// --- coverage (risk context's coverage_gap) ---

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CoverageStats {
    #[serde(default)]
    pub total_controls: i64,
    #[serde(default)]
    pub assessed_controls: i64,
    #[serde(default)]
    pub coverage_percentage: f64,
    #[serde(default)]
    pub by_category: Vec<CategoryCoverage>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct CategoryCoverage {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub assessed: i64,
}

/// EMPTY-FLAG SEMANTICS (po-av01j.192): every field is destructured by name
/// here — no `..` — so a flag added to `RiskCmd` later cannot reach the wire
/// without its author deciding, at this site, what an empty value means. The
/// decisions below are read off `internal/commands/risk.go`.
pub fn run(cmd: RiskCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            RiskCmd::List {
                status,
                category,
                service,
                format,
                limit,
            } => {
                // risk.go:417/420/423 — each filter is guarded `!= ""`, so an
                // empty one is simply not a filter. `--limit=` is rejected by
                // clap's typed parse, as `strconv.Atoi("")` is at risk.go:351.
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(
                    &client,
                    status.empty_is_absent(),
                    category.empty_is_absent(),
                    service.empty_is_absent(),
                    limit,
                    format.empty_is_absent(),
                )
            }
            RiskCmd::Ready {
                category,
                service,
                format,
                limit,
            } => {
                // risk.go:532/535.
                let (_, client) = crate::client::load_and_resolve()?;
                ready_output(
                    &client,
                    category.empty_is_absent(),
                    service.empty_is_absent(),
                    limit as usize,
                    format.empty_is_absent(),
                )
            }
            RiskCmd::Show { code, format } => {
                // risk.go:751 only ever compares `format == "json"`.
                let (_, client) = crate::client::load_and_resolve()?;
                show_output(&client, &code, format.empty_is_absent())
            }
            RiskCmd::Context { code, format } => {
                // risk.go:920, same comparison.
                let (_, client) = crate::client::load_and_resolve()?;
                context_output(&client, &code, format.empty_is_absent())
            }
            RiskCmd::Stale => {
                let (_, client) = crate::client::load_and_resolve()?;
                stale_output(&client)
            }
            RiskCmd::Resolve {
                code,
                reason,
                format,
            } => {
                // risk.go:1097/1152: `--reason=` OVERRIDES the "Resolved"
                // default and is POSTed as {"reason":""}. Falling back to the
                // default would write a sentence into the risk register that
                // the operator did not type.
                let (_, client) = crate::client::load_and_resolve()?;
                resolve_output(
                    &client,
                    &code,
                    reason.empty_is_value().unwrap_or("Resolved"),
                    format.empty_is_absent(),
                )
            }
            RiskCmd::Accept { code, reason } => {
                // risk.go:1205 — same, with "" as the default reason.
                let (_, client) = crate::client::load_and_resolve()?;
                accept_output(&client, &code, reason.empty_is_value().unwrap_or(""))
            }
        }
    })();
    crate::finish(res)
}

fn is_compound_code(code: &str) -> bool {
    code.starts_with("CR-")
}

// --- list ---

pub fn list_output(
    client: &Client,
    status: Option<&str>,
    category: Option<&str>,
    service: Option<&str>,
    limit: u32,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![("limit", limit.to_string())];
    if let Some(s) = status {
        pairs.push(("status", s.to_string()));
    }
    if let Some(c) = category {
        pairs.push(("category", c.to_string()));
    }
    if let Some(s) = service {
        pairs.push(("service", s.to_string()));
    }
    let url = format!("{}/api/v1/risks?{}", client.api_url, query_encode(&pairs));
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error fetching risks: {e}")))?;
    let resp: ListRisksResponse = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let mut out = String::new();
    if resp.risks.is_empty() {
        let _ = writeln!(out, "No risks found.");
        return Ok(out);
    }
    let _ = writeln!(out, "Total Risks: {}\n", resp.total);
    let _ = writeln!(
        out,
        "{:<10} {:<12} {:<8} {:<20} {:<50}",
        "CODE", "STATUS", "SCORE", "CATEGORY", "TITLE"
    );
    let _ = writeln!(out, "{}", "-".repeat(110));
    for r in &resp.risks {
        let _ = writeln!(
            out,
            "{:<10} {:<12} {:<8} {:<20} {:<50}",
            r.risk_code,
            display::format_status(&r.status),
            r.score,
            r.category,
            display::truncate_title(&r.title, 47)
        );
    }
    if resp.total > resp.risks.len() as i64 {
        eprintln!(
            "\nNote: showing first {} of {} total risks. Raise --limit or use --status / --category / --service to narrow.",
            resp.risks.len(),
            resp.total
        );
    }
    Ok(out)
}

// --- ready ---

pub fn ready_output(
    client: &Client,
    category: Option<&str>,
    service: Option<&str>,
    limit: usize,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![
        ("limit", "1000".to_string()),
        ("sort_by", "score".to_string()),
        ("sort_order", "desc".to_string()),
    ];
    if let Some(c) = category {
        pairs.push(("category", c.to_string()));
    }
    if let Some(s) = service {
        pairs.push(("service", s.to_string()));
    }
    let url = format!("{}/api/v1/risks?{}", client.api_url, query_encode(&pairs));
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error fetching risks: {e}")))?;
    let resp: ListRisksResponse = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    if resp.total > resp.risks.len() as i64 {
        eprintln!(
            "Warning: tenant has {} risks but the server returned only {} (capped at limit=1000). 'ready' ranking may be incomplete; tighten --category/--service to narrow.",
            resp.total,
            resp.risks.len()
        );
    }

    let ready: Vec<&Risk> = resp
        .risks
        .iter()
        .filter(|r| r.status == "applicable")
        .collect();

    if format == Some("json") {
        return Ok(ready_json(&ready, limit));
    }

    let mut out = String::new();
    if ready.is_empty() {
        let _ = writeln!(out, "No unresolved risks ready for remediation.");
        return Ok(out);
    }
    let showing = ready.len().min(limit);
    let _ = writeln!(
        out,
        "Ready Risks: showing top {showing} of {} unresolved\n",
        ready.len()
    );
    let _ = writeln!(
        out,
        "{:<6} {:<10} {:<5} {:<14} {:<18} TITLE",
        "#", "CODE", "SCORE", "PRIORITY", "CATEGORY"
    );
    let _ = writeln!(out, "{}", "-".repeat(100));
    for (i, r) in ready.iter().take(limit).enumerate() {
        let cat = display::format_category(&r.category);
        let cat = display::cut_at_boundary(&cat, 18);
        let _ = writeln!(
            out,
            "{:<6} {:<10} {:<5} {:<14} {:<18} {}",
            i + 1,
            r.risk_code,
            r.score,
            classify_priority(r.score),
            cat,
            display::truncate_title(&r.title, 42)
        );
    }
    if ready.len() > limit {
        let _ = writeln!(
            out,
            "\n  ... {} more unresolved risks (use --limit to see more)",
            ready.len() - limit
        );
    }
    Ok(out)
}

/// The `risk ready --format=json` body: the wrapped `{risks, total, page,
/// limit}` shape rvl-cli emits (po-9a07e), byte-identical to Go's
/// `json.MarshalIndent` — including the nil-slice-as-null behavior when no
/// risk is applicable.
pub fn ready_json(ready: &[&Risk], limit: usize) -> String {
    let risks_g = if ready.is_empty() {
        G::Null
    } else {
        G::Arr(ready.iter().take(limit).map(|r| risk_g(r)).collect())
    };
    let wrapped = G::Obj(vec![
        ("risks".to_string(), risks_g),
        ("total".to_string(), G::Int(ready.len() as i64)),
        ("page".to_string(), G::Int(1)),
        ("limit".to_string(), G::Int(limit as i64)),
    ]);
    format!("{}\n", pretty(&wrapped))
}

/// One risk in Go struct-field order with Go omitempty semantics.
fn risk_g(r: &Risk) -> G {
    let mut f: Vec<(String, G)> = vec![
        ("id".into(), G::Str(r.id.clone())),
        ("risk_code".into(), G::Str(r.risk_code.clone())),
        ("title".into(), G::Str(r.title.clone())),
        ("category".into(), G::Str(r.category.clone())),
        ("score".into(), G::Int(r.score)),
        ("status".into(), G::Str(r.status.clone())),
        (
            "linked_services".into(),
            match &r.linked_services {
                None => G::Null,
                Some(v) => G::Arr(v.iter().map(|s| G::Str(s.clone())).collect()),
            },
        ),
    ];
    if !r.control_codes.is_empty() {
        f.push((
            "control_codes".into(),
            G::Arr(r.control_codes.iter().map(|s| G::Str(s.clone())).collect()),
        ));
    }
    let opt = |key: &str, val: &str, f: &mut Vec<(String, G)>| {
        if !val.is_empty() {
            f.push((key.to_string(), G::Str(val.to_string())));
        }
    };
    opt("stale_since", &r.stale_since, &mut f);
    opt("last_seen_at", &r.last_seen_at, &mut f);
    opt("resolved_at", &r.resolved_at, &mut f);
    opt("uca_type", &r.uca_type, &mut f);
    if !r.causal_factors.is_empty() {
        f.push((
            "causal_factors".into(),
            G::Arr(r.causal_factors.iter().map(|s| G::Str(s.clone())).collect()),
        ));
    }
    opt("loss_scenario", &r.loss_scenario, &mut f);
    G::Obj(f)
}

fn classify_priority(score: i64) -> &'static str {
    match score {
        s if s >= 80 => "CRITICAL",
        s if s >= 60 => "HIGH",
        s if s >= 40 => "MEDIUM",
        _ => "LOW",
    }
}

// --- show ---

pub fn show_output(client: &Client, code: &str, format: Option<&str>) -> CmdResult {
    if is_compound_code(code) {
        let (detail, raw) = fetch_compound_detail(client, code)
            .map_err(|e| Failure::runtime(format!("Error fetching compound risk: {e}")))?;
        if format == Some("json") {
            return Ok(format!("{}\n", String::from_utf8_lossy(&raw)));
        }
        return Ok(render_compound_show(&detail));
    }

    let url = format!("{}/api/v1/risks/{}", client.api_url, path_escape(code));
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error fetching risk: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let detail: RiskDetail = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_risk_show(&detail))
}

fn render_risk_show(d: &RiskDetail) -> String {
    let r = &d.risk;
    let mut out = String::new();
    let _ = writeln!(out, "\nRisk: {}", r.risk_code);
    let _ = writeln!(out, "{}", "=".repeat(80));
    let _ = writeln!(out, "Title:    {}", r.title);
    let _ = writeln!(out, "Status:   {}", display::format_status(&r.status));
    let _ = writeln!(out, "Category: {}", r.category);
    let _ = writeln!(out, "Score:    {}", r.score);
    if let Some(services) = &r.linked_services {
        if !services.is_empty() {
            let _ = writeln!(out, "Services: {}", services.join(", "));
        }
    }
    if !r.last_seen_at.is_empty() {
        let _ = writeln!(out, "Last Seen: {}", r.last_seen_at);
    }
    if !r.stale_since.is_empty() {
        let _ = writeln!(out, "Stale Since: {}", r.stale_since);
    }
    if !r.resolved_at.is_empty() {
        let _ = writeln!(out, "Resolved At: {}", r.resolved_at);
    }

    let has_stpa =
        !r.uca_type.is_empty() || !r.causal_factors.is_empty() || !r.loss_scenario.is_empty();
    if has_stpa {
        let _ = writeln!(out, "\nSTPA Causal Analysis:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        if !r.uca_type.is_empty() {
            let _ = write!(
                out,
                "  Unsafe Control Action: {}",
                display::format_uca_type(&r.uca_type)
            );
            let cat = display::format_uca_category(&r.uca_type);
            if !cat.is_empty() {
                let _ = write!(out, "  ({cat})");
            }
            let _ = writeln!(out);
        }
        if !r.loss_scenario.is_empty() {
            let _ = writeln!(out, "  Loss Scenario: {}", r.loss_scenario);
        }
        if !r.causal_factors.is_empty() {
            let _ = writeln!(out, "  Causal Factors:");
            for f in &r.causal_factors {
                let _ = writeln!(out, "    > {}", display::wrap_text(f, 74, "      "));
            }
        }
    }

    if !d.narrative.is_empty() {
        let _ = writeln!(out, "\nNarrative:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        let _ = writeln!(out, "{}", display::wrap_text(&d.narrative, 80, ""));
    }

    if !d.mapped_controls.is_empty() {
        let _ = writeln!(out, "\nMapped Controls:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        for c in &d.mapped_controls {
            let _ = writeln!(out, "  [{}] {}", c.control_code, c.name);
            let _ = writeln!(
                out,
                "    Category: {} | Type: {}",
                c.category,
                display::format_control_type(&c.control_type)
            );
            if !c.description.is_empty() {
                for line in display::wrap_text(&c.description, 76, "").lines() {
                    let _ = writeln!(out, "    {line}");
                }
            }
            let _ = writeln!(out);
        }
    }
    out
}

// --- context ---

pub fn context_output(client: &Client, code: &str, format: Option<&str>) -> CmdResult {
    if is_compound_code(code) {
        let (detail, raw) = fetch_compound_detail(client, code)
            .map_err(|e| Failure::runtime(format!("Error fetching risk context: {e}")))?;
        if format == Some("json") {
            return Ok(format!("{}\n", String::from_utf8_lossy(&raw)));
        }
        return Ok(render_compound_context(&detail));
    }

    let base = format!("{}/api/v1/risks/{}", client.api_url, path_escape(code));

    // po-av01j.200: the three fetches run CONCURRENTLY, mirroring rvl-cli's
    // sync.WaitGroup (internal/commands/risk.go). This is load-bearing, not a
    // micro-optimization: `risk context` is the richest read in the CLI and the
    // command `/rvl:fix` runs to ground a remediation, so serializing three
    // round trips roughly triples the latency a developer waits on. Scoped
    // threads rather than an async runtime because the HTTP client is blocking
    // (ureq) and the workspace has no executor; three threads for one call site
    // is a far smaller change than adopting one.
    //
    // Shape matches Go exactly: fire all three, wait for all three, then decide.
    // No cancel-on-first-error, and no shared deadline — each request keeps its
    // own per-request timeout. The decision below reads the three results in a
    // fixed order, so the outcome cannot depend on which reply lands first.
    fn join_fetch(
        h: std::thread::ScopedJoinHandle<'_, Result<Vec<u8>, String>>,
    ) -> Result<Vec<u8>, String> {
        h.join().unwrap_or_else(|p| std::panic::resume_unwind(p))
    }
    let (detail_res, ctx_res, stats_res) = std::thread::scope(|s| {
        let detail = s.spawn(|| client.request("GET", &base, None));
        let ctx = s.spawn(|| client.request("GET", &format!("{base}/context"), None));
        let stats = s.spawn(|| {
            client.request(
                "GET",
                &format!("{}/api/v1/risks/stats", client.api_url),
                None,
            )
        });
        (join_fetch(detail), join_fetch(ctx), join_fetch(stats))
    });

    if let (Err(de), Err(_)) = (&detail_res, &ctx_res) {
        return Err(Failure::runtime(format!(
            "Error fetching risk context: {de}"
        )));
    }
    let coverage = stats_res.ok().and_then(|b| coverage_from(&b));
    let ctx_body = ctx_res.as_deref().unwrap_or(&[]);
    let detail_body = detail_res.as_deref().unwrap_or(&[]);

    if format == Some("json") {
        return Ok(
            match compose_context_json(ctx_body, detail_body, coverage.as_ref()) {
                Some(s) => format!("{s}\n"),
                // Mirrors Go: on a compose failure, print the raw context
                // body (empty when the context fetch itself failed).
                None => format!("{}\n", String::from_utf8_lossy(ctx_body)),
            },
        );
    }

    render_context_human(ctx_body, detail_body, coverage.as_ref())
}

/// Decode the coverage slice from a risk-stats response body.
pub fn coverage_from(body: &[u8]) -> Option<CoverageStats> {
    #[derive(Deserialize)]
    struct RiskStatsResponse {
        #[serde(default)]
        coverage: Option<CoverageStats>,
    }
    if body.is_empty() {
        return None;
    }
    let s: RiskStatsResponse = serde_json::from_slice(body).ok()?;
    s.coverage
}

/// The composed `risk context --format=json` body: the context object's
/// keys verbatim plus `detail` and `coverage_gap`, re-marshaled the way Go
/// re-marshals a `map[string]any` (sorted keys, floats) — except
/// `coverage_gap`, which Go marshals as a typed struct (field order kept).
pub fn compose_context_json(
    ctx_body: &[u8],
    detail_body: &[u8],
    coverage: Option<&CoverageStats>,
) -> Option<String> {
    let mut merged: BTreeMap<String, G> = BTreeMap::new();
    if !ctx_body.is_empty() {
        let v: Value = serde_json::from_slice(ctx_body).ok()?;
        let Value::Object(map) = v else {
            return None;
        };
        for (k, val) in map {
            merged.insert(k, G::Dyn(val));
        }
    }
    if !detail_body.is_empty() {
        if let Ok(v) = serde_json::from_slice::<Value>(detail_body) {
            merged.insert("detail".to_string(), G::Dyn(v));
        }
    }
    if let Some(c) = coverage {
        merged.insert("coverage_gap".to_string(), coverage_g(c));
    }
    let fields: Vec<(String, G)> = merged.into_iter().collect();
    Some(pretty(&G::Obj(fields)))
}

/// CoverageStats in Go struct-field order (by_category has omitempty).
fn coverage_g(c: &CoverageStats) -> G {
    let mut f = vec![
        ("total_controls".to_string(), G::Int(c.total_controls)),
        ("assessed_controls".to_string(), G::Int(c.assessed_controls)),
        (
            "coverage_percentage".to_string(),
            G::Float(c.coverage_percentage),
        ),
    ];
    if !c.by_category.is_empty() {
        f.push((
            "by_category".to_string(),
            G::Arr(
                c.by_category
                    .iter()
                    .map(|cat| {
                        G::Obj(vec![
                            ("category".to_string(), G::Str(cat.category.clone())),
                            ("total".to_string(), G::Int(cat.total)),
                            ("assessed".to_string(), G::Int(cat.assessed)),
                        ])
                    })
                    .collect(),
            ),
        ));
    }
    G::Obj(f)
}

/// Human context view: the FULL rvl-cli render (po-av01j.185 item 4).
///
/// The first port shipped a 3-section summary here while `--format=json`
/// stayed complete, so agents were unaffected and humans (and `/rvl:fix`)
/// lost the evidence grounding. The section set, ordering and formatting
/// now live in [`crate::risk_context_render`], one function per Go
/// function, so the two files diff by eye.
fn render_context_human(
    ctx_body: &[u8],
    detail_body: &[u8],
    coverage: Option<&CoverageStats>,
) -> CmdResult {
    let view = render::view_from_bodies(ctx_body, detail_body, coverage.cloned())
        .ok_or_else(|| Failure::runtime("Error parsing risk context response"))?;
    Ok(render::render_risk_context(&view))
}

// --- stale ---

pub fn stale_output(client: &Client) -> CmdResult {
    let url = format!("{}/api/v1/risks/stale", client.api_url);
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error fetching stale risks: {e}")))?;
    let resp: ListRisksResponse = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    let mut out = String::new();
    if resp.risks.is_empty() {
        let _ = writeln!(out, "No stale risks found.");
        return Ok(out);
    }
    let _ = writeln!(out, "Stale Risks: {}\n", resp.risks.len());
    let _ = writeln!(
        out,
        "{:<10} {:<20} {:<20} {:<50}",
        "CODE", "CATEGORY", "STALE SINCE", "TITLE"
    );
    let _ = writeln!(out, "{}", "-".repeat(110));
    for r in &resp.risks {
        let stale_since = if r.stale_since.is_empty() {
            "N/A"
        } else {
            &r.stale_since
        };
        let _ = writeln!(
            out,
            "{:<10} {:<20} {:<20} {:<50}",
            r.risk_code,
            r.category,
            stale_since,
            display::truncate_title(&r.title, 47)
        );
    }
    Ok(out)
}

// --- resolve / accept ---

pub fn resolve_output(
    client: &Client,
    code: &str,
    reason: &str,
    format: Option<&str>,
) -> CmdResult {
    let reason_body = compact(&G::Obj(vec![(
        "reason".to_string(),
        G::Str(reason.to_string()),
    )]));

    // Compound risks auto-resolve when all constituents are mitigated;
    // resolve each applicable constituent individually.
    if is_compound_code(code) {
        let (detail, _) = fetch_compound_detail(client, code)
            .map_err(|e| Failure::runtime(format!("Error fetching compound risk: {e}")))?;
        let mut out = String::new();
        let mut resolved = 0;
        for c in &detail.constituents {
            if c.status != "applicable" {
                continue;
            }
            let url = format!(
                "{}/api/v1/risks/{}/resolve",
                client.api_url,
                path_escape(&c.risk_code)
            );
            match client.request("POST", &url, Some(reason_body.as_bytes())) {
                Ok(_) => {
                    let _ = writeln!(out, "  Resolved constituent: {} - {}", c.risk_code, c.title);
                    resolved += 1;
                }
                Err(e) => eprintln!("Warning: failed to resolve {}: {e}", c.risk_code),
            }
        }
        let _ = writeln!(
            out,
            "\nResolved {resolved} of {} constituents for {code}.",
            detail.constituents.len()
        );
        let _ = writeln!(
            out,
            "The compound risk will auto-resolve when all applicable constituents are mitigated."
        );
        return Ok(out);
    }

    let risk_id = find_risk_id_by_code(client, code)
        .map_err(|e| Failure::runtime(format!("Error finding risk: {e}")))?;
    let url = format!("{}/api/v1/risks/{risk_id}/resolve", client.api_url);
    let resp = client
        .request("POST", &url, Some(reason_body.as_bytes()))
        .map_err(|e| Failure::runtime(format!("Error resolving risk: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let mut out = String::new();
    let _ = writeln!(out, "Risk {code} resolved successfully.");
    if let Ok(r) = serde_json::from_slice::<Risk>(&resp) {
        if !r.status.is_empty() {
            let _ = writeln!(out, "  Status:      {}", r.status);
        }
        if !r.resolved_at.is_empty() {
            let _ = writeln!(out, "  Resolved At: {}", r.resolved_at);
        }
    }
    Ok(out)
}

pub fn accept_output(client: &Client, code: &str, reason: &str) -> CmdResult {
    let risk_id = find_risk_id_by_code(client, code)
        .map_err(|e| Failure::runtime(format!("Error finding risk: {e}")))?;
    let url = format!("{}/api/v1/risks/{risk_id}/status", client.api_url);
    // Go marshals map[string]string{"status", "reason"} — sorted keys.
    let body = compact(&G::Obj(vec![
        ("reason".to_string(), G::Str(reason.to_string())),
        ("status".to_string(), G::Str("accepted".to_string())),
    ]));
    client
        .request("PATCH", &url, Some(body.as_bytes()))
        .map_err(|e| Failure::runtime(format!("Error accepting risk: {e}")))?;
    Ok(format!("Risk {code} accepted successfully.\n"))
}

/// Resolve a risk UUID from its R-XXX code via the list endpoint.
pub fn find_risk_id_by_code(client: &Client, code: &str) -> Result<String, String> {
    let url = format!("{}/api/v1/risks?limit=1000", client.api_url);
    let body = client.request("GET", &url, None)?;
    let resp: ListRisksResponse =
        serde_json::from_slice(&body).map_err(|e| format!("error parsing response: {e}"))?;
    for r in &resp.risks {
        if r.risk_code == code {
            return Ok(r.id.clone());
        }
    }
    Err(format!("risk not found: {code}"))
}

// --- compound fetch + renders ---

/// Look up a compound risk by CR-XXX code: list to resolve the UUID, then
/// fetch the detail. Returns the parsed detail plus the raw detail body
/// (the JSON mode prints it verbatim).
pub fn fetch_compound_detail(
    client: &Client,
    code: &str,
) -> Result<(CompoundRiskDetailResponse, Vec<u8>), String> {
    let list_url = format!("{}/api/v1/compound-risks", client.api_url);
    let list_body = client.request("GET", &list_url, None)?;
    let list: Vec<CompoundRiskSummary> = serde_json::from_slice(&list_body)
        .map_err(|e| format!("parsing compound risk list: {e}"))?;
    let id = list
        .iter()
        .find(|r| r.risk_code == code)
        .map(|r| r.id.clone())
        .ok_or_else(|| {
            format!("compound risk not found: {code} (run `{BIN} risk list` to verify the code)")
        })?;
    let detail_url = format!("{}/api/v1/compound-risks/{id}", client.api_url);
    let detail_body = client.request("GET", &detail_url, None)?;
    let detail: CompoundRiskDetailResponse = serde_json::from_slice(&detail_body)
        .map_err(|e| format!("parsing compound risk detail: {e}"))?;
    Ok((detail, detail_body))
}

fn render_compound_show(d: &CompoundRiskDetailResponse) -> String {
    let r = &d.risk;
    let mut out = String::new();
    let _ = writeln!(out, "\nCompound Risk: {}", r.risk_code);
    let _ = writeln!(out, "{}", "=".repeat(80));
    let _ = writeln!(out, "Title:    {}", r.title);
    let _ = writeln!(out, "Status:   {}", display::format_status(&r.status));
    let _ = writeln!(out, "Category: compound_failure");
    let _ = writeln!(
        out,
        "Score:    {} (CRITICAL - interaction amplification)",
        r.score
    );
    if !r.services.is_empty() {
        let _ = writeln!(out, "Services: {}", r.services.join(", "));
    }
    if !r.last_seen_at.is_empty() {
        let _ = writeln!(out, "Last Seen: {}", r.last_seen_at);
    }

    let _ = writeln!(out, "\nTriggering Rule:");
    let _ = writeln!(out, "{}", "-".repeat(80));
    let _ = writeln!(out, "  Name:     {}", d.rule.name);
    let _ = writeln!(
        out,
        "  Controls: {} (min {} matched)",
        d.rule.control_codes.join(", "),
        d.rule.min_control_count
    );
    if let Some(desc) = &d.rule.description {
        if !desc.is_empty() {
            let _ = writeln!(
                out,
                "  Why:      {}",
                display::wrap_text(desc, 74, "            ")
            );
        }
    }

    if !r.narrative.is_empty() {
        let _ = writeln!(out, "\nNarrative:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        let _ = writeln!(out, "{}", display::wrap_text(&r.narrative, 80, ""));
    }

    if !d.constituents.is_empty() {
        let _ = writeln!(out, "\nConstituent Risks:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        let _ = writeln!(out, "{:<10} {:<5} {:<12} TITLE", "CODE", "SCORE", "STATUS");
        let _ = writeln!(out, "{}", "-".repeat(80));
        for c in &d.constituents {
            let _ = writeln!(
                out,
                "{:<10} {:<5} {:<12} {}",
                c.risk_code,
                c.score,
                c.status,
                display::truncate_title(&c.title, 52)
            );
        }
    }
    out
}

fn render_compound_context(d: &CompoundRiskDetailResponse) -> String {
    let r = &d.risk;
    let mut out = String::new();
    let _ = writeln!(out, "\nCompound Risk Context: {}", r.risk_code);
    let _ = writeln!(out, "{}", "=".repeat(80));
    let _ = writeln!(out, "Title:    {}", r.title);
    let _ = writeln!(out, "Status:   {}", display::format_status(&r.status));
    let _ = writeln!(
        out,
        "Score:    {} (CRITICAL - interaction amplification)",
        r.score
    );
    if !r.services.is_empty() {
        let _ = writeln!(out, "Services: {}", r.services.join(", "));
    }

    let _ = writeln!(out, "\nTriggering Rule:");
    let _ = writeln!(out, "{}", "-".repeat(80));
    let _ = writeln!(out, "  Name:            {}", d.rule.name);
    let _ = writeln!(
        out,
        "  Control Pattern: {}",
        d.rule.control_codes.join(", ")
    );
    let _ = writeln!(
        out,
        "  Minimum Matched: {} of {} controls",
        d.rule.min_control_count,
        d.rule.control_codes.len()
    );
    if let Some(rationale) = &d.rule.rationale {
        if !rationale.is_empty() {
            let _ = writeln!(out, "\n  Rationale:");
            let _ = writeln!(out, "  {}", display::wrap_text(rationale, 76, "  "));
        }
    }

    if !r.narrative.is_empty() {
        let _ = writeln!(out, "\nNarrative:");
        let _ = writeln!(out, "{}", "-".repeat(80));
        let _ = writeln!(out, "{}", display::wrap_text(&r.narrative, 80, ""));
    }

    if !d.constituents.is_empty() {
        let _ = writeln!(
            out,
            "\nConstituent Risks (all must be addressed to clear this compound risk):"
        );
        let _ = writeln!(out, "{}", "-".repeat(80));
        let _ = writeln!(
            out,
            "{:<10} {:<5} {:<15} TITLE",
            "CODE", "SCORE", "CONTROLS"
        );
        let _ = writeln!(out, "{}", "-".repeat(80));
        for c in &d.constituents {
            let mut controls = c.control_codes.join(", ");
            if controls.len() > 15 {
                controls = format!("{}+", display::cut_at_boundary(&controls, 14));
            }
            let _ = writeln!(
                out,
                "{:<10} {:<5} {:<15} {}",
                c.risk_code,
                c.score,
                controls,
                display::truncate_title(&c.title, 48)
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "  Tip: run `{BIN} risk context <R-XXX>` on any constituent for full remediation context."
        );
        let _ = writeln!(
            out,
            "  Tip: run `{BIN} risk resolve {}` to resolve all applicable constituents.",
            r.risk_code
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn testdata(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
    }

    /// The pure core of `ready --format=json`: parse the list body, filter
    /// to applicable, emit the wrapped shape. Mirrors the fixture flow the
    /// Go generator runs.
    fn ready_json_from_body(body: &[u8], limit: usize) -> String {
        let resp: ListRisksResponse = serde_json::from_slice(body).unwrap();
        let ready: Vec<&Risk> = resp
            .risks
            .iter()
            .filter(|r| r.status == "applicable")
            .collect();
        ready_json(&ready, limit)
    }

    #[test]
    fn ready_json_matches_go_golden() {
        // Byte-identical to Go's json.MarshalIndent on rvl-cli's structs:
        // unknown fields dropped, HTML escaping, absent linked_services as
        // null, omitempty on control_codes/uca_type/..., limit applied to
        // risks but total = all applicable.
        let got = ready_json_from_body(&testdata("ready_input.json"), 2);
        let want = String::from_utf8(testdata("ready_golden.txt")).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn ready_json_empty_set_is_null_matching_go_nil_slice() {
        let got = ready_json_from_body(&testdata("ready_empty_input.json"), 10);
        let want = String::from_utf8(testdata("ready_empty_golden.txt")).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn context_compose_matches_go_golden() {
        let ctx = testdata("context_ctx_input.json");
        let detail = testdata("context_detail_input.json");
        let stats = testdata("context_stats_input.json");
        let coverage = coverage_from(&stats).expect("stats fixture has coverage");
        let got = compose_context_json(&ctx, &detail, Some(&coverage)).unwrap() + "\n";
        let want = String::from_utf8(testdata("context_composed_golden.txt")).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn context_compose_without_detail_or_coverage_matches_go() {
        let ctx = testdata("context_ctx_input.json");
        let got = compose_context_json(&ctx, &[], None).unwrap() + "\n";
        let want = String::from_utf8(testdata("context_composed_noextras_golden.txt")).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn context_compose_rejects_non_object_context() {
        // Go's json.Unmarshal into map[string]any errors on an array; the
        // caller then falls back to printing the raw body.
        assert!(compose_context_json(b"[1,2]", &[], None).is_none());
        assert!(compose_context_json(b"not json", &[], None).is_none());
    }

    #[test]
    fn context_compose_detail_key_collision_overwrites() {
        // A context body that already carries "detail" is overwritten by
        // the fetched detail payload, exactly like Go's map assignment.
        let ctx = br#"{"detail":"from-ctx","a":1}"#;
        let detail = br#"{"real":true}"#;
        let got = compose_context_json(ctx, detail, None).unwrap();
        assert!(got.contains("\"real\": true"), "{got}");
        assert!(!got.contains("from-ctx"), "{got}");
    }

    #[test]
    fn priority_classification() {
        assert_eq!(classify_priority(80), "CRITICAL");
        assert_eq!(classify_priority(60), "HIGH");
        assert_eq!(classify_priority(40), "MEDIUM");
        assert_eq!(classify_priority(39), "LOW");
    }

    #[test]
    fn compound_code_detection() {
        assert!(is_compound_code("CR-001"));
        assert!(!is_compound_code("R-001"));
        assert!(!is_compound_code("RC-018"));
    }
}
