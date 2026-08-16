//! The full `risk context` table, ported from rvl-cli
//! `internal/commands/risk_context_render.go` (po-av01j.185 item 4).
//!
//! WHY THE DEPTH MATTERS: `--format=json` was always complete, so agents
//! never lost anything — but the human table and `/rvl:fix` read THIS, and
//! the first port collapsed 15 sections into 3. The dropped ones (Score
//! Math, Grounding, Causal Analysis, Corroborating Incidents, Control
//! Coverage, Defense-Layer Coverage, Incident Patterns/Procedures/Facts)
//! are the evidence-grounding that separates the product from a linter: a
//! reader who cannot see why a score is 90, which incident corroborates
//! it, or which defense layer is missing has a severity label and nothing
//! to act on.
//!
//! Section set and ordering follow `renderRiskContext` exactly; the
//! per-section functions keep the Go names so the two files diff by eye.

use crate::display;
use crate::risk::{CategoryCoverage, CoverageStats, MappedControl, RiskDetail};
use serde::Deserialize;
use std::fmt::Write as _;

// --- wire types (rvl-cli risk.go / risk_context_render.go) ---

/// A past incident that corroborates the risk.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct CorroboratingIncidentItem {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub short_name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub incident_date: String,
    #[serde(default)]
    pub mttr_minutes: Option<i64>,
    #[serde(default)]
    pub relevance: f64,
    #[serde(default)]
    pub source_url: String,
}

/// The Path5Breakdown L x I score-math receipt.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ScoreBreakdown {
    #[serde(default)]
    pub likelihood_factor: i64,
    #[serde(default)]
    pub likelihood_source: String,
    #[serde(default)]
    pub likelihood_notes: String,
    #[serde(default)]
    pub impact_factor: i64,
    #[serde(default)]
    pub impact_source: String,
    #[serde(default)]
    pub impact_notes: String,
    #[serde(default)]
    pub base_score: i64,
    #[serde(default)]
    pub business_multiplier: f64,
    #[serde(default)]
    pub adjusted_score: i64,
}

/// The auto-generated matcher backing a risk.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct GeneratedMatcherRef {
    #[serde(default)]
    pub slug: String,
    #[serde(default)]
    pub source_pattern_ids: Vec<String>,
}

/// The most recent dismissal record on a risk.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct LatestDismissal {
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub explanation: String,
}

/// Another risk sharing controls with this one.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct RelatedFindingItem {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub risk_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub plain_summary: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub shared_controls: i64,
}

/// A UCA/loss-scenario edge to a control.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ProvenanceEdge {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub control_name: String,
    #[serde(default)]
    pub strength: f64,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct UcaRef {
    #[serde(default, rename = "type")]
    pub uca_type: String,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub control_edges: Vec<ProvenanceEdge>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct LossScenarioRef {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub control_edges: Vec<ProvenanceEdge>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct StpaProvenanceData {
    #[serde(default)]
    pub ucas: Vec<UcaRef>,
    #[serde(default)]
    pub loss_scenarios: Vec<LossScenarioRef>,
}

/// One code/config finding substantiating a risk. The wire shape is
/// free-form (oneOf array/object); this models the per-finding element.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct SubstantiationFinding {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub line: i64,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: String,
}

/// A control with its evidence context.
#[derive(Debug, Default, Deserialize)]
pub struct ControlContextItem {
    #[serde(default)]
    pub control: MappedControl,
    #[serde(default)]
    pub existing_evidence: Vec<ContextEvidenceItem>,
    #[serde(default)]
    pub evidence_gaps: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ContextEvidenceItem {
    #[serde(default, rename = "type")]
    pub evidence_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "url_or_identifier")]
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct KnowledgeContextResp {
    #[serde(default)]
    pub patterns: Vec<PatternItem>,
    #[serde(default)]
    pub procedures: Vec<ProcedureItem>,
    #[serde(default)]
    pub facts: Vec<FactItem>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PatternItem {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub pattern_type: String,
    #[serde(default)]
    pub causal_chain: Vec<ChainLink>,
    #[serde(default)]
    pub trigger_event: String,
    #[serde(default)]
    pub occurrence_count: i64,
    #[serde(default)]
    pub typical_mttr: String,
    #[serde(default)]
    pub typical_blast_radius: String,
    #[serde(default)]
    pub prevention_strategies: Vec<String>,
    #[serde(default)]
    pub score: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct ChainLink {
    #[serde(default)]
    pub order: i64,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub typical_delay: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ProcedureItem {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub effectiveness_score: f64,
    #[serde(default)]
    pub applied_count: i64,
    #[serde(default)]
    pub success_count: i64,
    #[serde(default)]
    pub related_controls: Vec<String>,
    #[serde(default)]
    pub score: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct FactItem {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub validation_status: String,
    #[serde(default)]
    pub score: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServiceContextResp {
    #[serde(default)]
    pub service_name: String,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub incidents: Option<IncidentHistoryResp>,
}

#[derive(Debug, Default, Deserialize)]
pub struct IncidentHistoryResp {
    #[serde(default)]
    pub total_incidents: i64,
    #[serde(default)]
    pub last_30_days: i64,
    #[serde(default)]
    pub last_90_days: i64,
    #[serde(default)]
    pub critical_count: i64,
    #[serde(default)]
    pub high_count: i64,
    #[serde(default)]
    pub most_recent_title: String,
    #[serde(default)]
    pub average_mttr: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScoreFactorResp {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub points: i64,
    #[serde(default)]
    pub source: String,
}

/// The `/context` payload.
#[derive(Debug, Default, Deserialize)]
pub struct RiskContextResponse {
    #[serde(default)]
    pub risk: RiskDetail,
    #[serde(default)]
    pub controls: Vec<ControlContextItem>,
    #[serde(default)]
    pub knowledge: KnowledgeContextResp,
    #[serde(default)]
    pub service_context: Option<ServiceContextResp>,
    #[serde(default)]
    pub score_factors: Vec<ScoreFactorResp>,
    /// pre-po-foyko alias for `score_factors`.
    #[serde(default, rename = "score_breakdown")]
    pub score_factors_old: Vec<ScoreFactorResp>,
    #[serde(default)]
    pub grounding_provenance: String,
}

/// The three payloads that back the render: detail (primary), context
/// (grounding, service context, score factors, knowledge), and the
/// coverage slice from risk stats.
#[derive(Default)]
pub struct RiskContextView {
    pub detail: Option<RiskDetail>,
    pub context: Option<RiskContextResponse>,
    pub coverage: Option<CoverageStats>,
}

impl RiskContextView {
    /// The best available risk object: the richer detail payload, falling
    /// back to the context response's embedded risk.
    fn risk(&self) -> Option<&RiskDetail> {
        self.detail
            .as_ref()
            .or_else(|| self.context.as_ref().map(|c| &c.risk))
    }
}

/// Priority label for a score (rvl-cli `classifyPriority`).
pub fn classify_priority(score: i64) -> &'static str {
    match score {
        s if s >= 80 => "CRITICAL",
        s if s >= 60 => "HIGH",
        s if s >= 40 => "MEDIUM",
        _ => "LOW",
    }
}

/// Trim an RFC3339 timestamp to its date component.
fn date_only(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 10 && b[4] == b'-' && b[7] == b'-' {
        &s[..10]
    } else {
        s
    }
}

const RULE: &str =
    "--------------------------------------------------------------------------------";
const HEAVY: &str =
    "================================================================================";
const STPA_DISCLAIMER: &str =
    "Adapted from Systems-Theoretic Process Analysis (Leveson, MIT). Findings are candidates.";

/// The full textual risk context view.
pub fn render_risk_context(v: &RiskContextView) -> String {
    let mut sb = String::new();
    let Some(r) = v.risk() else {
        return sb;
    };

    let _ = writeln!(sb, "\nRisk Context: {}", r.risk.risk_code);
    let _ = writeln!(sb, "{HEAVY}");
    let _ = writeln!(sb, "Title:    {}", r.risk.title);
    let _ = writeln!(sb, "Status:   {}", display::format_status(&r.risk.status));
    let _ = writeln!(sb, "Category: {}", r.risk.category);
    let _ = writeln!(sb, "Score:    {}", r.risk.score);
    render_header_extras(&mut sb, r);

    render_score_math(&mut sb, r);
    render_grounding_and_narrative(&mut sb, v);
    render_stpa_causal(&mut sb, r);
    render_services_line(&mut sb, r);
    render_related_findings(&mut sb, r);
    render_corroborating(&mut sb, r);
    render_score_factors(&mut sb, v.context.as_ref());
    render_service_context(&mut sb, v.context.as_ref());
    render_control_coverage(&mut sb, v);
    render_substantiation(&mut sb, r);
    render_defense_layers(&mut sb, v);
    render_stpa_provenance(&mut sb, r);
    render_knowledge(&mut sb, v.context.as_ref());
    render_history(&mut sb, r);
    render_coverage_gap(&mut sb, v);

    sb
}

fn render_header_extras(sb: &mut String, r: &RiskDetail) {
    if !r.plain_summary.is_empty() && r.plain_summary != r.risk.title {
        let _ = writeln!(sb, "Summary:  {}", r.plain_summary);
    }
    if !r.trend.is_empty() {
        let _ = writeln!(sb, "Trend:    {}", r.trend);
    }
    if !r.likelihood.is_empty() && !r.impact.is_empty() {
        let _ = writeln!(
            sb,
            "Severity: {} (likelihood {} x impact {})",
            classify_priority(r.risk.score),
            r.likelihood,
            r.impact
        );
    }
    if let Some(m) = r.generated_matcher.as_ref().filter(|m| !m.slug.is_empty()) {
        let _ = write!(sb, "Matcher:  {}", m.slug);
        if !m.source_pattern_ids.is_empty() {
            let _ = write!(sb, " (from {} pattern(s))", m.source_pattern_ids.len());
        }
        sb.push('\n');
    }
    if !r.risk_class.is_empty() {
        let _ = writeln!(sb, "Class:    {}", r.risk_class);
    }
    if r.read_only {
        if !r.source_intelligence_tier.is_empty() {
            let _ = writeln!(
                sb,
                "Note:     read-only ({} intelligence)",
                r.source_intelligence_tier
            );
        } else {
            sb.push_str("Note:     read-only\n");
        }
    }
}

fn render_score_math(sb: &mut String, r: &RiskDetail) {
    let Some(b) = r.score_breakdown.as_ref() else {
        return;
    };
    let _ = writeln!(sb, "\nScore Math:\n{RULE}");
    let _ = write!(sb, "  Likelihood: {}", b.likelihood_factor);
    if !b.likelihood_source.is_empty() {
        let _ = write!(sb, " ({})", b.likelihood_source);
    }
    sb.push('\n');
    if !b.likelihood_notes.is_empty() {
        let _ = writeln!(
            sb,
            "    {}",
            display::wrap_text(&b.likelihood_notes, 74, "    ")
        );
    }
    let _ = write!(sb, "  Impact:     {}", b.impact_factor);
    if !b.impact_source.is_empty() {
        let _ = write!(sb, " ({})", b.impact_source);
    }
    sb.push('\n');
    if !b.impact_notes.is_empty() {
        let _ = writeln!(
            sb,
            "    {}",
            display::wrap_text(&b.impact_notes, 74, "    ")
        );
    }
    let _ = writeln!(sb, "  Base score: {}", b.base_score);
    if b.business_multiplier != 0.0 && b.business_multiplier != 1.0 {
        let _ = writeln!(sb, "  Business x:  {:.2}", b.business_multiplier);
    }
    let _ = writeln!(sb, "  Adjusted:   {}", b.adjusted_score);
    if r.graph_multiplier > 1.0 {
        let _ = writeln!(
            sb,
            "  Graph amplification: x{:.2} -> {}",
            r.graph_multiplier, r.risk.score
        );
    }
}

fn render_grounding_and_narrative(sb: &mut String, v: &RiskContextView) {
    if let Some(g) = v
        .context
        .as_ref()
        .map(|c| c.grounding_provenance.as_str())
        .filter(|g| !g.is_empty())
    {
        let _ = writeln!(sb, "\nGrounding:\n{RULE}");
        let _ = writeln!(sb, "{}", display::wrap_text(g, 80, ""));
    }
    let Some(r) = v.risk().filter(|r| !r.narrative.is_empty()) else {
        return;
    };
    let mut text = r.narrative.as_str();
    let stpa = display::parse_stpa_context(&r.narrative);
    if let Some(s) = stpa.as_ref().filter(|s| !s.clean_narrative.is_empty()) {
        text = &s.clean_narrative;
    }
    let text = text.trim();
    if text.is_empty() {
        return;
    }
    let _ = writeln!(sb, "\nNarrative:\n{RULE}");
    let _ = writeln!(sb, "{}", display::wrap_text(text, 80, ""));
}

fn render_services_line(sb: &mut String, r: &RiskDetail) {
    let services = r.risk.linked_services.as_deref().unwrap_or(&[]);
    if !services.is_empty() {
        let _ = writeln!(sb, "\nServices: {}", services.join(", "));
    }
}

fn render_related_findings(sb: &mut String, r: &RiskDetail) {
    if r.related_findings.is_empty() {
        return;
    }
    let _ = writeln!(sb, "\nRelated Findings:\n{RULE}");
    for rf in &r.related_findings {
        let title = if rf.title.is_empty() {
            &rf.plain_summary
        } else {
            &rf.title
        };
        let _ = writeln!(
            sb,
            "  {}  {} (score {}, {} shared control(s))",
            rf.risk_code, title, rf.score, rf.shared_controls
        );
    }
}

fn render_corroborating(sb: &mut String, r: &RiskDetail) {
    if r.corroborating_incidents.is_empty() {
        return;
    }
    let _ = writeln!(sb, "\nCorroborating Incidents:\n{RULE}");
    for inc in &r.corroborating_incidents {
        if !inc.short_name.is_empty() {
            let _ = writeln!(sb, "\n{}  {}", inc.short_name, inc.title);
        } else {
            let _ = writeln!(sb, "\n{}", inc.title);
        }
        let mut meta: Vec<String> = Vec::new();
        if !inc.severity.is_empty() {
            meta.push(format!("severity {}", inc.severity));
        }
        let d = date_only(&inc.incident_date);
        if !d.is_empty() {
            meta.push(d.to_string());
        }
        if let Some(m) = inc.mttr_minutes {
            meta.push(format!("MTTR {m}m"));
        }
        if inc.relevance > 0.0 {
            meta.push(format!("relevance {:.2}", inc.relevance));
        }
        if !meta.is_empty() {
            let _ = writeln!(sb, "  {}", meta.join(" | "));
        }
        if !inc.source_url.is_empty() {
            let _ = writeln!(sb, "  source: {}", inc.source_url);
        }
    }
}

fn render_substantiation(sb: &mut String, r: &RiskDetail) {
    let Some(raw) = r.substantiation.as_ref() else {
        return;
    };
    let Ok(findings) = serde_json::from_str::<Vec<SubstantiationFinding>>(raw.get()) else {
        return;
    };
    if findings.is_empty() {
        return;
    }
    let _ = writeln!(sb, "\nSubstantiation Evidence:\n{RULE}");
    for f in &findings {
        let loc = if f.line > 0 {
            format!("{}:{}", f.path, f.line)
        } else {
            f.path.clone()
        };
        if !f.severity.is_empty() {
            let _ = writeln!(sb, "\n[{}] {}", f.severity, loc);
        } else {
            let _ = writeln!(sb, "\n{loc}");
        }
        if !f.description.is_empty() {
            let _ = writeln!(sb, "  {}", display::wrap_text(&f.description, 76, "  "));
        }
        if !f.snippet.is_empty() {
            let lines: Vec<&str> = f.snippet.split('\n').collect();
            for (i, line) in lines.iter().enumerate() {
                if i >= 5 {
                    let _ = writeln!(sb, "    ... ({} more line(s))", lines.len() - 5);
                    break;
                }
                let _ = writeln!(sb, "    {line}");
            }
        }
    }
}

/// Control types from the context payload, falling back to the detail's
/// mapped controls.
fn control_types(v: &RiskContextView) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    if let Some(ctx) = v.context.as_ref() {
        for c in &ctx.controls {
            if !c.control.control_type.is_empty() {
                out.push(&c.control.control_type);
            }
        }
    }
    if out.is_empty() {
        if let Some(d) = v.detail.as_ref() {
            for c in &d.mapped_controls {
                if !c.control_type.is_empty() {
                    out.push(&c.control_type);
                }
            }
        }
    }
    out
}

fn render_defense_layers(sb: &mut String, v: &RiskContextView) {
    let types = control_types(v);
    if types.is_empty() {
        return;
    }
    let (mut prevention, mut detection, mut correction) = (0, 0, 0);
    for t in &types {
        match t.to_lowercase().as_str() {
            "preventive" => prevention += 1,
            "detective" => detection += 1,
            "corrective" => correction += 1,
            _ => {}
        }
    }
    let covered = [prevention, detection, correction]
        .iter()
        .filter(|n| **n > 0)
        .count();
    let _ = writeln!(sb, "\nDefense-Layer Coverage:\n{RULE}");
    let _ = writeln!(sb, "  Prevention: {prevention} control(s)");
    let _ = writeln!(sb, "  Detection:  {detection} control(s)");
    let _ = writeln!(sb, "  Correction: {correction} control(s)");
    let _ = writeln!(sb, "  Layers covered: {covered}/3");
    if covered == 1 {
        sb.push_str("  WARNING: single point of failure (only one defense layer)\n");
    }
}

fn render_stpa_provenance(sb: &mut String, r: &RiskDetail) {
    let Some(p) = r
        .stpa_provenance
        .as_ref()
        .filter(|p| !(p.ucas.is_empty() && p.loss_scenarios.is_empty()))
    else {
        return;
    };
    let _ = writeln!(sb, "\nSTPA Provenance (STPA-inspired):\n{RULE}");
    let _ = writeln!(sb, "{STPA_DISCLAIMER}");
    for u in &p.ucas {
        let _ = writeln!(
            sb,
            "\n  UCA ({}): {}",
            display::format_uca_type(&u.uca_type),
            display::wrap_text(&u.content, 72, "    ")
        );
        render_provenance_edges(sb, &u.control_edges);
    }
    for ls in &p.loss_scenarios {
        let _ = writeln!(sb, "\n  Loss scenario: {}", ls.title);
        if !ls.description.is_empty() {
            let _ = writeln!(
                sb,
                "    {}",
                display::wrap_text(&ls.description, 72, "    ")
            );
        }
        render_provenance_edges(sb, &ls.control_edges);
    }
}

fn render_provenance_edges(sb: &mut String, edges: &[ProvenanceEdge]) {
    for e in edges {
        let _ = write!(sb, "    -> {}", e.control_code);
        if !e.control_name.is_empty() {
            let _ = write!(sb, " {}", e.control_name);
        }
        if e.strength > 0.0 {
            let _ = write!(sb, " (strength {:.2})", e.strength);
        }
        sb.push('\n');
    }
}

fn render_history(sb: &mut String, r: &RiskDetail) {
    let has_resolution = !r.resolution_reason.is_empty();
    let has_dismissal = r.latest_dismissal.is_some();
    let has_stale = !r.risk.stale_since.is_empty();
    let has_meta = !r.created_at.is_empty() || !r.updated_at.is_empty();
    if !has_resolution && !has_dismissal && !has_stale && !has_meta {
        return;
    }
    let _ = writeln!(sb, "\nContext & History:\n{RULE}");
    if has_resolution {
        let _ = write!(sb, "  Resolution: {}", r.resolution_reason);
        let d = date_only(&r.risk.resolved_at);
        if !d.is_empty() {
            let _ = write!(sb, " ({d})");
        }
        sb.push('\n');
    }
    if let Some(d) = r.latest_dismissal.as_ref() {
        let _ = writeln!(sb, "  Previously dismissed: {}", d.reason);
        if !d.explanation.is_empty() {
            let _ = writeln!(sb, "    {}", display::wrap_text(&d.explanation, 74, "    "));
        }
    }
    if has_stale {
        let _ = writeln!(sb, "  Stale since: {}", date_only(&r.risk.stale_since));
    }
    if has_meta {
        let _ = writeln!(
            sb,
            "  Created: {} | Updated: {}",
            date_only(&r.created_at),
            date_only(&r.updated_at)
        );
    }
}

fn render_coverage_gap(sb: &mut String, v: &RiskContextView) {
    let (Some(cov), Some(detail)) = (v.coverage.as_ref(), v.detail.as_ref()) else {
        return;
    };
    let Some(cc) = cov
        .by_category
        .iter()
        .find(|cc: &&CategoryCoverage| cc.category.eq_ignore_ascii_case(&detail.risk.category))
    else {
        return;
    };
    let unconfigured = (cc.total - cc.assessed).max(0);
    let _ = writeln!(sb, "\nAssessment Coverage:\n{RULE}");
    let _ = writeln!(
        sb,
        "  {}: {} of {} controls assessed ({} not yet configured)",
        display::format_category(&cc.category),
        cc.assessed,
        cc.total,
        unconfigured
    );
}

fn render_stpa_causal(sb: &mut String, r: &RiskDetail) {
    let structured = !r.risk.uca_type.is_empty()
        || !r.risk.causal_factors.is_empty()
        || !r.risk.loss_scenario.is_empty();
    if structured {
        let _ = writeln!(sb, "\nCausal Analysis (STPA-inspired):\n{RULE}");
        let _ = writeln!(sb, "{STPA_DISCLAIMER}");
        if !r.risk.uca_type.is_empty() {
            let _ = write!(
                sb,
                "  Unsafe Control Action: {}",
                display::format_uca_type(&r.risk.uca_type)
            );
            let cat = display::format_uca_category(&r.risk.uca_type);
            if !cat.is_empty() {
                let _ = write!(sb, "  ({cat})");
            }
            sb.push('\n');
        }
        if !r.risk.loss_scenario.is_empty() {
            let _ = writeln!(sb, "  Loss Scenario: {}", r.risk.loss_scenario);
        }
        if !r.constraint_type.is_empty() {
            let _ = writeln!(sb, "  Constraint Type: {}", r.constraint_type);
        }
        if !r.risk.causal_factors.is_empty() {
            sb.push_str("  Causal Factors:\n");
            for f in &r.risk.causal_factors {
                let _ = writeln!(sb, "    > {}", display::wrap_text(f, 74, "      "));
            }
        }
        return;
    }
    let Some(stpa) = display::parse_stpa_context(&r.narrative) else {
        return;
    };
    let _ = writeln!(sb, "\nCausal Analysis (STPA-inspired):\n{RULE}");
    let _ = writeln!(sb, "{STPA_DISCLAIMER}");
    if !stpa.uca_type.is_empty() {
        let _ = write!(
            sb,
            "  Unsafe Control Action: {}",
            display::format_uca_type(&stpa.uca_type)
        );
        let cat = display::format_uca_category(&stpa.uca_type);
        if !cat.is_empty() {
            let _ = write!(sb, "  ({cat})");
        }
        sb.push('\n');
    }
    if !stpa.loss_scenario.is_empty() {
        let _ = writeln!(sb, "  Loss Scenario: {}", stpa.loss_scenario);
    }
    if !stpa.causal_factors.is_empty() {
        sb.push_str("  Causal Factors:\n");
        for f in &stpa.causal_factors {
            let _ = writeln!(sb, "    > {}", display::wrap_text(f, 74, "      "));
        }
    }
}

fn render_score_factors(sb: &mut String, ctx: Option<&RiskContextResponse>) {
    let Some(ctx) = ctx else { return };
    let factors = if ctx.score_factors.is_empty() {
        &ctx.score_factors_old
    } else {
        &ctx.score_factors
    };
    if factors.is_empty() {
        return;
    }
    let _ = writeln!(sb, "\nScore Factors:\n{RULE}");
    for f in factors {
        // Go's "%+3d": sign always shown, width 3, space-padded.
        let _ = writeln!(
            sb,
            "  [{:>3}] {} (Source: {})",
            format!("{:+}", f.points),
            f.description,
            f.source
        );
    }
}

fn render_service_context(sb: &mut String, ctx: Option<&RiskContextResponse>) {
    let Some(sc) = ctx.and_then(|c| c.service_context.as_ref()) else {
        return;
    };
    let _ = writeln!(sb, "\nService Context:\n{RULE}");
    let _ = write!(sb, "Service: {}", sc.service_name);
    if !sc.tier.is_empty() {
        let _ = write!(sb, " (Tier: {})", sc.tier);
    }
    sb.push('\n');
    if let Some(inc) = sc.incidents.as_ref() {
        let _ = writeln!(
            sb,
            "  Incidents: {} total ({} in last 30d, {} in last 90d)",
            inc.total_incidents, inc.last_30_days, inc.last_90_days
        );
        let _ = writeln!(
            sb,
            "  Severity: {} critical, {} high",
            inc.critical_count, inc.high_count
        );
        if let Some(mttr) = inc.average_mttr {
            let _ = writeln!(sb, "  Average MTTR: {mttr} minutes");
        }
        if !inc.most_recent_title.is_empty() {
            let _ = writeln!(sb, "  Most Recent: {}", inc.most_recent_title);
        }
    }
}

fn render_control_coverage(sb: &mut String, v: &RiskContextView) {
    let Some(ctx) = v.context.as_ref().filter(|c| !c.controls.is_empty()) else {
        return;
    };
    let _ = writeln!(sb, "\nControl Coverage:\n{RULE}");
    if let Some(status) = v
        .risk()
        .map(|r| r.evidence_status.as_str())
        .filter(|s| !s.is_empty())
    {
        let _ = writeln!(
            sb,
            "Evidence status: {}",
            display::format_evidence_status(status)
        );
    }
    for item in &ctx.controls {
        let ctrl = &item.control;
        let _ = writeln!(sb, "\n[{}] {}", ctrl.control_code, ctrl.name);
        let _ = writeln!(
            sb,
            "  Category: {} | Type: {}",
            ctrl.category,
            display::format_control_type(&ctrl.control_type)
        );

        if !item.existing_evidence.is_empty() {
            sb.push_str("  Existing Evidence:\n");
            for ev in &item.existing_evidence {
                let _ = write!(sb, "    - [{}] {}", ev.evidence_type, ev.name);
                if !ev.status.is_empty() {
                    let _ = write!(sb, " (Status: {})", ev.status);
                }
                sb.push('\n');
                if !ev.description.is_empty() {
                    for line in display::wrap_text(&ev.description, 76, "").split('\n') {
                        let _ = writeln!(sb, "      {line}");
                    }
                }
                if !ev.url.is_empty() {
                    let _ = writeln!(sb, "      url: {}", ev.url);
                }
            }
        }

        if !item.evidence_gaps.is_empty() {
            sb.push_str("  Evidence Gaps:\n");
            for gap in &item.evidence_gaps {
                let _ = writeln!(sb, "    - {gap}");
            }
        }
    }
}

/// Descending sort by `score`, matching Go's `sort.Slice` (which is NOT
/// stable — but the comparator is the same, and the inputs are already
/// server-ordered by score, so the two agree on real payloads).
fn sort_by_score_desc<T>(items: &mut [T], score: impl Fn(&T) -> f64) {
    items.sort_by(|a, b| {
        score(b)
            .partial_cmp(&score(a))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
}

fn render_knowledge(sb: &mut String, ctx: Option<&RiskContextResponse>) {
    let Some(ctx) = ctx else { return };

    if !ctx.knowledge.patterns.is_empty() {
        let _ = writeln!(sb, "\nRelevant Incident Patterns:\n{RULE}");
        let mut patterns: Vec<&PatternItem> = ctx.knowledge.patterns.iter().collect();
        sort_by_score_desc(&mut patterns, |p| p.score);

        for pat in patterns {
            let _ = writeln!(sb, "\n{} (Type: {})", pat.title, pat.pattern_type);
            let _ = writeln!(
                sb,
                "  Occurrences: {} | Relevance: {:.2}",
                pat.occurrence_count, pat.score
            );
            if !pat.typical_mttr.is_empty() {
                let _ = writeln!(sb, "  Typical MTTR: {}", pat.typical_mttr);
            }
            if !pat.typical_blast_radius.is_empty() {
                let _ = writeln!(sb, "  Typical Blast Radius: {}", pat.typical_blast_radius);
            }
            if !pat.causal_chain.is_empty() {
                sb.push_str("  Causal Chain:\n");
                let mut chain: Vec<&ChainLink> = pat.causal_chain.iter().collect();
                chain.sort_by_key(|l| l.order);
                for link in chain {
                    let _ = write!(sb, "    {}. {}", link.order, link.event);
                    if !link.typical_delay.is_empty() {
                        let _ = write!(sb, " (delay: {})", link.typical_delay);
                    }
                    sb.push('\n');
                }
            }
            if !pat.trigger_event.is_empty() {
                let _ = writeln!(sb, "  Trigger: {}", pat.trigger_event);
            }
            if !pat.prevention_strategies.is_empty() {
                sb.push_str("  Prevention Strategies:\n");
                for strat in &pat.prevention_strategies {
                    for line in display::wrap_text(strat, 76, "").split('\n') {
                        let _ = writeln!(sb, "    - {line}");
                    }
                }
            }
        }
    }

    if !ctx.knowledge.procedures.is_empty() {
        let _ = writeln!(sb, "\nRelevant Procedures:\n{RULE}");
        let mut procedures: Vec<&ProcedureItem> = ctx.knowledge.procedures.iter().collect();
        sort_by_score_desc(&mut procedures, |p| p.score);

        for proc in procedures {
            let _ = writeln!(sb, "\n{}", proc.title);
            let _ = writeln!(
                sb,
                "  Effectiveness: {:.2} | Applied: {} times ({} successful)",
                proc.effectiveness_score, proc.applied_count, proc.success_count
            );
            let _ = writeln!(sb, "  Relevance: {:.2}", proc.score);
            if !proc.related_controls.is_empty() {
                let _ = writeln!(
                    sb,
                    "  Related Controls: {}",
                    proc.related_controls.join(", ")
                );
            }
        }
    }

    if !ctx.knowledge.facts.is_empty() {
        let _ = writeln!(sb, "\nRelevant Facts:\n{RULE}");
        let mut facts: Vec<&FactItem> = ctx.knowledge.facts.iter().collect();
        sort_by_score_desc(&mut facts, |f| f.score);

        for fact in facts {
            let _ = writeln!(sb, "\n- {}", display::wrap_text(&fact.content, 76, ""));
            let _ = writeln!(
                sb,
                "  Confidence: {:.2} | Validation: {} | Relevance: {:.2}",
                fact.confidence, fact.validation_status, fact.score
            );
        }
    }
}

/// Decode the three bodies into a view. `Ok(None)` when neither the
/// context nor the detail body parses (the caller reports the error).
pub fn view_from_bodies(
    ctx_body: &[u8],
    detail_body: &[u8],
    coverage: Option<CoverageStats>,
) -> Option<RiskContextView> {
    let context: Option<RiskContextResponse> = serde_json::from_slice(ctx_body).ok();
    let detail: Option<RiskDetail> = serde_json::from_slice(detail_body).ok();
    if context.is_none() && detail.is_none() {
        return None;
    }
    Some(RiskContextView {
        detail,
        context,
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Risk;

    fn detail() -> RiskDetail {
        RiskDetail {
            risk: Risk {
                risk_code: "R-046".into(),
                title: "Fanned-out goroutines lack panic recovery".into(),
                category: "fault_tolerance".into(),
                score: 90,
                status: "applicable".into(),
                linked_services: Some(vec!["checkout-api/backend".into()]),
                ..Default::default()
            },
            trend: "stable".into(),
            likelihood: "medium".into(),
            impact: "high".into(),
            created_at: "2026-08-11T00:00:00Z".into(),
            updated_at: "2026-08-11T00:00:00Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn header_carries_the_extras_the_short_render_dropped() {
        let v = RiskContextView {
            detail: Some(detail()),
            ..Default::default()
        };
        let out = render_risk_context(&v);
        assert!(out.contains("Trend:    stable"), "{out}");
        assert!(
            out.contains("Severity: CRITICAL (likelihood medium x impact high)"),
            "{out}"
        );
        assert!(out.contains("\nServices: checkout-api/backend\n"), "{out}");
        assert!(out.contains("\nContext & History:\n"), "{out}");
    }

    #[test]
    fn score_math_reproduces_the_receipt() {
        let mut d = detail();
        d.score_breakdown = Some(ScoreBreakdown {
            likelihood_factor: 7,
            likelihood_source: "severity".into(),
            likelihood_notes: "from severity=medium".into(),
            impact_factor: 10,
            impact_source: "severity".into(),
            impact_notes: "from severity=high".into(),
            base_score: 70,
            business_multiplier: 1.285_714_3,
            adjusted_score: 90,
        });
        let v = RiskContextView {
            detail: Some(d),
            ..Default::default()
        };
        let out = render_risk_context(&v);
        assert!(out.contains("\nScore Math:\n"), "{out}");
        assert!(
            out.contains("  Likelihood: 7 (severity)\n    from severity=medium\n"),
            "{out}"
        );
        assert!(
            out.contains("  Impact:     10 (severity)\n    from severity=high\n"),
            "{out}"
        );
        assert!(out.contains("  Base score: 70\n"), "{out}");
        assert!(out.contains("  Business x:  1.29\n"), "{out}");
        assert!(out.contains("  Adjusted:   90\n"), "{out}");
    }

    #[test]
    fn a_multiplier_of_one_is_not_printed() {
        let mut d = detail();
        d.score_breakdown = Some(ScoreBreakdown {
            base_score: 70,
            business_multiplier: 1.0,
            adjusted_score: 70,
            ..Default::default()
        });
        let out = render_risk_context(&RiskContextView {
            detail: Some(d),
            ..Default::default()
        });
        assert!(!out.contains("Business x:"), "{out}");
    }

    #[test]
    fn defense_layers_warn_on_a_single_layer() {
        let ctx = RiskContextResponse {
            controls: vec![ControlContextItem {
                control: MappedControl {
                    control_code: "RC-060".into(),
                    name: "Background Process Safety".into(),
                    category: "fault_tolerance".into(),
                    control_type: "preventive".into(),
                    ..Default::default()
                },
                evidence_gaps: vec!["code".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let out = render_risk_context(&RiskContextView {
            detail: Some(detail()),
            context: Some(ctx),
            coverage: None,
        });
        assert!(out.contains("  Prevention: 1 control(s)"), "{out}");
        assert!(out.contains("  Layers covered: 1/3"), "{out}");
        assert!(
            out.contains("  WARNING: single point of failure (only one defense layer)"),
            "{out}"
        );
        // Control Coverage renders the per-control block, not a count line.
        assert!(out.contains("[RC-060] Background Process Safety"), "{out}");
        assert!(
            out.contains("  Category: fault_tolerance | Type: [PREVENTIVE]"),
            "{out}"
        );
        assert!(out.contains("  Evidence Gaps:\n    - code"), "{out}");
    }

    #[test]
    fn score_factors_use_gos_signed_width_three() {
        let ctx = RiskContextResponse {
            score_factors: vec![
                ScoreFactorResp {
                    description: "Pattern match".into(),
                    points: 29,
                    source: "pattern_match".into(),
                },
                ScoreFactorResp {
                    description: "Mitigated".into(),
                    points: -5,
                    source: "evidence".into(),
                },
            ],
            ..Default::default()
        };
        let out = render_risk_context(&RiskContextView {
            detail: Some(detail()),
            context: Some(ctx),
            coverage: None,
        });
        assert!(
            out.contains("  [+29] Pattern match (Source: pattern_match)"),
            "{out}"
        );
        assert!(
            out.contains("  [ -5] Mitigated (Source: evidence)"),
            "{out}"
        );
    }

    #[test]
    fn corroborating_incidents_render_meta_and_source() {
        let mut d = detail();
        d.corroborating_incidents = vec![CorroboratingIncidentItem {
            short_name: "inc-lmm".into(),
            title: "GitHub availability report".into(),
            severity: "critical".into(),
            incident_date: "2026-02-02T00:00:00Z".into(),
            mttr_minutes: Some(120),
            relevance: 0.91,
            source_url: "https://example.test/x".into(),
            ..Default::default()
        }];
        let out = render_risk_context(&RiskContextView {
            detail: Some(d),
            ..Default::default()
        });
        assert!(
            out.contains("\ninc-lmm  GitHub availability report\n"),
            "{out}"
        );
        assert!(
            out.contains("  severity critical | 2026-02-02 | MTTR 120m | relevance 0.91"),
            "{out}"
        );
        assert!(out.contains("  source: https://example.test/x"), "{out}");
    }

    #[test]
    fn causal_analysis_prefers_structured_fields_over_the_narrative() {
        let mut d = detail();
        d.risk.uca_type = "not_provided".into();
        d.risk.loss_scenario = "process crash".into();
        d.risk.causal_factors = vec!["missing defer".into()];
        d.constraint_type = "primary".into();
        let out = render_risk_context(&RiskContextView {
            detail: Some(d),
            ..Default::default()
        });
        assert!(
            out.contains("\nCausal Analysis (STPA-inspired):\n"),
            "{out}"
        );
        assert!(out.contains(STPA_DISCLAIMER), "{out}");
        assert!(
            out.contains("  Unsafe Control Action: Not Provided  (What control is missing?)"),
            "{out}"
        );
        assert!(out.contains("  Loss Scenario: process crash"), "{out}");
        assert!(out.contains("  Constraint Type: primary"), "{out}");
        assert!(
            out.contains("  Causal Factors:\n    > missing defer"),
            "{out}"
        );
    }

    #[test]
    fn coverage_gap_matches_the_risk_category_case_insensitively() {
        let out = render_risk_context(&RiskContextView {
            detail: Some(detail()),
            context: None,
            coverage: Some(CoverageStats {
                total_controls: 70,
                assessed_controls: 0,
                coverage_percentage: 0.0,
                by_category: vec![CategoryCoverage {
                    category: "Fault_Tolerance".into(),
                    total: 12,
                    assessed: 0,
                }],
            }),
        });
        assert!(
            out.contains("  Fault Tolerance: 0 of 12 controls assessed (12 not yet configured)"),
            "{out}"
        );
    }

    #[test]
    fn an_empty_view_renders_nothing() {
        assert_eq!(render_risk_context(&RiskContextView::default()), "");
    }

    #[test]
    fn every_go_section_heading_is_reachable() {
        // The regression this test exists for: 15 sections collapsed to 3.
        // Build one payload that lights up all of them and assert each
        // heading by name, in Go's order.
        let mut d = detail();
        d.plain_summary = "Panic recovery is missing".into();
        d.risk_class = "code".into();
        d.read_only = true;
        d.source_intelligence_tier = "public".into();
        d.generated_matcher = Some(GeneratedMatcherRef {
            slug: "goroutine-no-recover".into(),
            source_pattern_ids: vec!["p1".into()],
        });
        d.score_breakdown = Some(ScoreBreakdown {
            base_score: 70,
            adjusted_score: 90,
            business_multiplier: 1.29,
            ..Default::default()
        });
        d.graph_multiplier = 1.5;
        d.risk.uca_type = "not_provided".into();
        d.related_findings = vec![RelatedFindingItem {
            risk_code: "R-015".into(),
            title: "No safety net".into(),
            score: 58,
            shared_controls: 2,
            ..Default::default()
        }];
        d.corroborating_incidents = vec![CorroboratingIncidentItem {
            title: "an incident".into(),
            ..Default::default()
        }];
        d.substantiation = Some(
            serde_json::value::RawValue::from_string(
                r#"[{"path":"main.go","line":10,"severity":"high","description":"no recover","snippet":"go f()"}]"#
                    .into(),
            )
            .unwrap(),
        );
        d.stpa_provenance = Some(StpaProvenanceData {
            ucas: vec![UcaRef {
                uca_type: "not_provided".into(),
                content: "no recover".into(),
                control_edges: vec![ProvenanceEdge {
                    control_code: "RC-060".into(),
                    control_name: "Background Process Safety".into(),
                    strength: 0.8,
                }],
            }],
            loss_scenarios: vec![LossScenarioRef {
                title: "crash".into(),
                description: "process dies".into(),
                control_edges: vec![],
            }],
        });
        d.latest_dismissal = Some(LatestDismissal {
            reason: "false positive".into(),
            explanation: "handled upstream".into(),
        });
        d.risk.stale_since = "2026-07-01T00:00:00Z".into();
        d.evidence_status = "missing".into();

        let ctx = RiskContextResponse {
            grounding_provenance: "Grounded in the public incident corpus.".into(),
            score_factors: vec![ScoreFactorResp {
                description: "Pattern".into(),
                points: 29,
                source: "pattern_match".into(),
            }],
            service_context: Some(ServiceContextResp {
                service_name: "checkout-api/backend".into(),
                tier: "1".into(),
                incidents: Some(IncidentHistoryResp {
                    total_incidents: 3,
                    last_30_days: 1,
                    last_90_days: 2,
                    critical_count: 1,
                    high_count: 1,
                    most_recent_title: "outage".into(),
                    average_mttr: Some(42),
                }),
            }),
            controls: vec![ControlContextItem {
                control: MappedControl {
                    control_code: "RC-060".into(),
                    name: "Background Process Safety".into(),
                    category: "fault_tolerance".into(),
                    control_type: "preventive".into(),
                    ..Default::default()
                },
                existing_evidence: vec![ContextEvidenceItem {
                    evidence_type: "code".into(),
                    name: "safego".into(),
                    url: "https://example.test/e".into(),
                    description: "the wrapper".into(),
                    status: "verified".into(),
                }],
                evidence_gaps: vec!["dashboard".into()],
            }],
            knowledge: KnowledgeContextResp {
                patterns: vec![PatternItem {
                    title: "Retry storm".into(),
                    pattern_type: "causal_chain".into(),
                    causal_chain: vec![ChainLink {
                        order: 1,
                        event: "retries".into(),
                        typical_delay: "< 1 minute".into(),
                    }],
                    trigger_event: "deploy".into(),
                    occurrence_count: 89,
                    typical_mttr: "60-120 minutes".into(),
                    typical_blast_radius: "multiple regions".into(),
                    prevention_strategies: vec!["budget retries".into()],
                    score: 0.57,
                }],
                procedures: vec![ProcedureItem {
                    title: "Failover".into(),
                    effectiveness_score: 0.5,
                    applied_count: 6,
                    success_count: 3,
                    related_controls: vec!["RC-060".into()],
                    score: 0.53,
                }],
                facts: vec![FactItem {
                    content: "panics kill the process".into(),
                    confidence: 0.9,
                    validation_status: "analyst_validated".into(),
                    score: 0.5,
                }],
            },
            ..Default::default()
        };

        let out = render_risk_context(&RiskContextView {
            detail: Some(d),
            context: Some(ctx),
            coverage: Some(CoverageStats {
                by_category: vec![CategoryCoverage {
                    category: "fault_tolerance".into(),
                    total: 12,
                    assessed: 1,
                }],
                ..Default::default()
            }),
        });

        let ordered = [
            "\nRisk Context: R-046\n",
            "\nScore Math:\n",
            "\nGrounding:\n",
            "\nCausal Analysis (STPA-inspired):\n",
            "\nServices: ",
            "\nRelated Findings:\n",
            "\nCorroborating Incidents:\n",
            "\nScore Factors:\n",
            "\nService Context:\n",
            "\nControl Coverage:\n",
            "\nSubstantiation Evidence:\n",
            "\nDefense-Layer Coverage:\n",
            "\nSTPA Provenance (STPA-inspired):\n",
            "\nRelevant Incident Patterns:\n",
            "\nRelevant Procedures:\n",
            "\nRelevant Facts:\n",
            "\nContext & History:\n",
            "\nAssessment Coverage:\n",
        ];
        let mut cursor = 0usize;
        for heading in ordered {
            let at = out[cursor..]
                .find(heading)
                .unwrap_or_else(|| panic!("missing (or out of order): {heading:?}\n---\n{out}"));
            cursor += at + heading.len();
        }
        // Header extras and the graph-amplification line.
        assert!(out.contains("Summary:  Panic recovery is missing"), "{out}");
        assert!(
            out.contains("Matcher:  goroutine-no-recover (from 1 pattern(s))"),
            "{out}"
        );
        assert!(out.contains("Class:    code"), "{out}");
        assert!(
            out.contains("Note:     read-only (public intelligence)"),
            "{out}"
        );
        assert!(out.contains("  Graph amplification: x1.50 -> 90"), "{out}");
        assert!(
            out.contains("    -> RC-060 Background Process Safety (strength 0.80)"),
            "{out}"
        );
        assert!(
            out.contains("  Previously dismissed: false positive"),
            "{out}"
        );
        assert!(out.contains("  Stale since: 2026-07-01"), "{out}");
    }
}
