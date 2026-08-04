//! Slice (c): `knowledge` read commands ported from rvl-cli
//! `internal/commands/knowledge.go`: `search`, `facts`, `procedures`,
//! `patterns`. The remaining subcommands (enrich, graph, graph-search,
//! relationships, foresight, health) are follow-up work — see the beads
//! filed on the parent epic.
//!
//! JSON parity: search/facts/patterns print the server body verbatim;
//! `procedures --control=RC-XXX --format=json` re-marshals after the
//! client-side control filter (golden-tested against Go's MarshalIndent).

use crate::client::Client;
use crate::display;
use crate::gojson::{compact, pretty, query_encode, query_escape, G};
use crate::{CmdResult, Failure};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum KnowledgeCmd {
    /// Semantic search across all knowledge types
    Search {
        /// Search query (words are joined with spaces)
        #[arg(required = true)]
        query: Vec<String>,
        /// Maximum results (default 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Result offset for paging
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Minimum practice class: best, good, or emerging
        #[arg(long)]
        min_class: Option<String>,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// List or search facts
    Facts {
        /// Filter by SRE vertical (e.g., fault-tolerance)
        #[arg(long)]
        vertical: Option<String>,
        /// Filter by technology (e.g., redis, kafka, go)
        #[arg(long)]
        technology: Option<String>,
        /// Filter by validation status (auto_extracted, analyst_validated)
        #[arg(long)]
        status: Option<String>,
        /// Maximum results (default 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Result offset for paging
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// List or search procedures (with control mappings)
    Procedures {
        /// Filter by SRE vertical
        #[arg(long)]
        vertical: Option<String>,
        /// Filter by technology
        #[arg(long)]
        technology: Option<String>,
        /// Filter by procedure type (troubleshooting, runbook, best_practice, workflow)
        #[arg(long = "type")]
        proc_type: Option<String>,
        /// Filter procedures related to a specific control (RC-XXX)
        #[arg(long)]
        control: Option<String>,
        /// Maximum results (default 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Result offset for paging
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// List or search failure patterns
    Patterns {
        /// Filter by SRE vertical
        #[arg(long)]
        vertical: Option<String>,
        /// Filter by pattern type (causal_chain, correlation, anti_pattern, failure_mode)
        #[arg(long = "type")]
        pattern_type: Option<String>,
        /// Minimum occurrence count
        #[arg(long, default_value_t = 0)]
        min_occurrences: u32,
        /// Maximum results (default 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Result offset for paging
        #[arg(long, default_value_t = 0)]
        offset: u32,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
}

#[derive(Debug, Default, Deserialize)]
struct SearchResult {
    #[serde(default, rename = "type")]
    result_type: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    vertical: String,
    #[serde(default)]
    similarity: f64,
    #[serde(default)]
    practice_class: String,
    #[serde(default)]
    consensus: String,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SearchResponse {
    #[serde(default)]
    results: Vec<SearchResult>,
    #[serde(default)]
    total: i64,
}

#[derive(Debug, Default, Deserialize)]
struct Fact {
    #[serde(default)]
    id: String,
    #[serde(default)]
    content: String,
    #[serde(default)]
    vertical: String,
    #[serde(default)]
    technologies: Vec<String>,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    validation_status: String,
}

#[derive(Debug, Default, Deserialize)]
struct FactsResponse {
    #[serde(default)]
    facts: Vec<Fact>,
    #[serde(default)]
    total: i64,
}

/// A procedure — the exact typed subset rvl-cli carries; field order here
/// IS the JSON field order on the filtered re-marshal path.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Procedure {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub vertical: String,
    #[serde(default)]
    pub procedure_type: String,
    #[serde(default)]
    pub related_controls: Vec<String>,
    #[serde(default)]
    pub technologies: Vec<String>,
    #[serde(default)]
    pub effectiveness_score: f64,
    #[serde(default)]
    pub applied_count: i64,
    #[serde(default)]
    pub success_count: i64,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub score: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct ProceduresResponse {
    #[serde(default)]
    pub procedures: Vec<Procedure>,
    #[serde(default)]
    pub total: i64,
}

#[derive(Debug, Default, Deserialize)]
struct Pattern {
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    pattern_type: String,
    #[serde(default)]
    occurrence_count: i64,
    #[serde(default)]
    typical_blast_radius: String,
    #[serde(default)]
    typical_mttr: String,
    #[serde(default)]
    related_controls: Vec<String>,
    #[serde(default)]
    prevention_strategies: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PatternsResponse {
    #[serde(default)]
    patterns: Vec<Pattern>,
    #[serde(default)]
    total: i64,
}

pub fn run(cmd: KnowledgeCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            KnowledgeCmd::Search {
                query,
                limit,
                offset,
                min_class,
                format,
            } => {
                validate_format(&format)?;
                validate_min_class(&min_class)?;
                let query = query.join(" ");
                if query.is_empty() {
                    return Err(Failure::usage("Error: search query required"));
                }
                let (_, client) = crate::client::load_and_resolve()?;
                search_output(
                    &client,
                    &query,
                    limit,
                    offset,
                    min_class.as_deref(),
                    format.as_deref(),
                )
            }
            KnowledgeCmd::Facts {
                vertical,
                technology,
                status,
                limit,
                offset,
                format,
            } => {
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                facts_output(
                    &client,
                    vertical.as_deref(),
                    technology.as_deref(),
                    status.as_deref(),
                    limit,
                    offset,
                    format.as_deref(),
                )
            }
            KnowledgeCmd::Procedures {
                vertical,
                technology,
                proc_type,
                control,
                limit,
                offset,
                format,
            } => {
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                procedures_output(
                    &client,
                    vertical.as_deref(),
                    technology.as_deref(),
                    proc_type.as_deref(),
                    control.as_deref(),
                    limit,
                    offset,
                    format.as_deref(),
                )
            }
            KnowledgeCmd::Patterns {
                vertical,
                pattern_type,
                min_occurrences,
                limit,
                offset,
                format,
            } => {
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                patterns_output(
                    &client,
                    vertical.as_deref(),
                    pattern_type.as_deref(),
                    min_occurrences,
                    limit,
                    offset,
                    format.as_deref(),
                )
            }
        }
    })();
    crate::finish(res)
}

fn validate_format(format: &Option<String>) -> Result<(), Failure> {
    match format.as_deref() {
        None | Some("table") | Some("json") => Ok(()),
        Some(f) => Err(Failure::usage(format!(
            "Error: invalid --format \"{f}\" (valid: table, json)"
        ))),
    }
}

fn validate_min_class(min_class: &Option<String>) -> Result<(), Failure> {
    match min_class.as_deref() {
        None | Some("best") | Some("good") | Some("emerging") => Ok(()),
        Some(mc) => Err(Failure::usage(format!(
            "Error: --min-class expects best, good, or emerging, got \"{mc}\""
        ))),
    }
}

/// The POST /api/knowledge/search body: Go's `map[string]interface{}`
/// marshal (sorted keys: limit, offset, query).
pub fn search_body(query: &str, limit: u32, offset: u32) -> String {
    compact(&G::Obj(vec![
        ("limit".to_string(), G::Int(limit as i64)),
        ("offset".to_string(), G::Int(offset as i64)),
        ("query".to_string(), G::Str(query.to_string())),
    ]))
}

pub fn search_output(
    client: &Client,
    query: &str,
    limit: u32,
    offset: u32,
    min_class: Option<&str>,
    format: Option<&str>,
) -> CmdResult {
    let body = search_body(query, limit, offset);
    let mut endpoint = format!("{}/api/knowledge/search", client.api_url);
    if let Some(mc) = min_class {
        endpoint.push_str(&format!("?min_class={}", query_escape(mc)));
    }
    let resp = client
        .request("POST", &endpoint, Some(body.as_bytes()))
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let parsed: SearchResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    let mut out = String::new();
    if parsed.total == 0 {
        let _ = writeln!(out, "No knowledge found matching query.");
        return Ok(out);
    }
    let _ = writeln!(out, "Found {} results for \"{query}\":\n", parsed.total);
    for r in &parsed.results {
        let title = if r.title.is_empty() {
            display::truncate_text(&r.content, 80)
        } else {
            r.title.clone()
        };
        let _ = writeln!(
            out,
            "  {:<12} [{}] {}",
            r.id,
            r.result_type.to_uppercase(),
            title
        );
        if !r.practice_class.is_empty() {
            let mut line = format!(
                "               Practice: {}",
                r.practice_class.to_uppercase()
            );
            if !r.consensus.is_empty() {
                line.push_str(&format!(" ({})", r.consensus));
            }
            if !r.sources.is_empty() {
                line.push_str(&format!("  {} source(s)", r.sources.len()));
            }
            let _ = writeln!(out, "{line}");
        }
        if r.similarity > 0.0 {
            let _ = writeln!(
                out,
                "               Similarity: {:.2}  Vertical: {}",
                r.similarity, r.vertical
            );
        }
    }
    Ok(out)
}

pub fn facts_output(
    client: &Client,
    vertical: Option<&str>,
    technology: Option<&str>,
    status: Option<&str>,
    limit: u32,
    offset: u32,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![("limit", limit.to_string())];
    if offset > 0 {
        pairs.push(("offset", offset.to_string()));
    }
    if let Some(v) = vertical {
        pairs.push(("vertical", v.to_string()));
    }
    if let Some(t) = technology {
        pairs.push(("technology", t.to_string()));
    }
    if let Some(s) = status {
        pairs.push(("status", s.to_string()));
    }
    let url = format!(
        "{}/api/knowledge/facts?{}",
        client.api_url,
        query_encode(&pairs)
    );
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let parsed: FactsResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    let mut out = String::new();
    if parsed.total == 0 {
        let _ = writeln!(out, "No facts found.");
        return Ok(out);
    }
    let _ = writeln!(out, "Found {} facts:\n", parsed.total);
    for f in &parsed.facts {
        let _ = writeln!(
            out,
            "  {} {} [{}] (confidence: {:.0}%)",
            f.id,
            display::format_validation_status(&f.validation_status),
            f.vertical,
            f.confidence * 100.0
        );
        let _ = writeln!(out, "    {}", display::truncate_text(&f.content, 80));
        if !f.technologies.is_empty() {
            let _ = writeln!(out, "    Technologies: {}", f.technologies.join(", "));
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn procedures_output(
    client: &Client,
    vertical: Option<&str>,
    technology: Option<&str>,
    proc_type: Option<&str>,
    control: Option<&str>,
    limit: u32,
    offset: u32,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![("limit", limit.to_string())];
    if offset > 0 {
        pairs.push(("offset", offset.to_string()));
    }
    if let Some(v) = vertical {
        pairs.push(("vertical", v.to_string()));
    }
    if let Some(t) = technology {
        pairs.push(("technology", t.to_string()));
    }
    if let Some(t) = proc_type {
        pairs.push(("type", t.to_string()));
    }
    // Control filter rides as query text; the API has no direct param.
    if let Some(c) = control {
        pairs.push(("q", c.to_string()));
    }
    let url = format!(
        "{}/api/knowledge/procedures?{}",
        client.api_url,
        query_encode(&pairs)
    );
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    // Raw-body short-circuit only when no client-side --control filter
    // applies (po-x7pk0): the filter must run before the JSON is emitted.
    if format == Some("json") && control.is_none() {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let mut parsed: ProceduresResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    let mut out = String::new();
    if parsed.total == 0 {
        let _ = writeln!(out, "No procedures found.");
        return Ok(out);
    }

    if let Some(code) = control {
        parsed
            .procedures
            .retain(|p| p.related_controls.iter().any(|rc| rc == code));
        parsed.total = parsed.procedures.len() as i64;
        if parsed.procedures.is_empty() {
            let _ = writeln!(out, "No procedures matching control {code}.");
            return Ok(out);
        }
    }

    if format == Some("json") {
        return Ok(procedures_json(&parsed));
    }

    let _ = writeln!(out, "Found {} procedures:\n", parsed.total);
    for p in &parsed.procedures {
        let effectiveness = if p.applied_count > 0 {
            format!(
                " (effectiveness: {:.0}%, applied: {})",
                p.effectiveness_score * 100.0,
                p.applied_count
            )
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {} [{}] {}{effectiveness}",
            p.id, p.procedure_type, p.title
        );
        if !p.description.is_empty() {
            let _ = writeln!(out, "    {}", display::truncate_text(&p.description, 78));
        }
        if !p.related_controls.is_empty() {
            let _ = writeln!(out, "    Controls: {}", p.related_controls.join(", "));
        }
        if !p.technologies.is_empty() {
            let _ = writeln!(out, "    Technologies: {}", p.technologies.join(", "));
        }
    }
    Ok(out)
}

/// The post-filter `procedures --format=json` body: Go's MarshalIndent on
/// KnowledgeProceduresResponse (struct field order, omitempty semantics).
pub fn procedures_json(resp: &ProceduresResponse) -> String {
    let procedures = G::Arr(resp.procedures.iter().map(procedure_g).collect());
    let wrapped = G::Obj(vec![
        ("procedures".to_string(), procedures),
        ("total".to_string(), G::Int(resp.total)),
    ]);
    format!("{}\n", pretty(&wrapped))
}

fn procedure_g(p: &Procedure) -> G {
    let mut f: Vec<(String, G)> = vec![
        ("id".into(), G::Str(p.id.clone())),
        ("title".into(), G::Str(p.title.clone())),
    ];
    if !p.description.is_empty() {
        f.push(("description".into(), G::Str(p.description.clone())));
    }
    f.push(("vertical".into(), G::Str(p.vertical.clone())));
    f.push(("procedure_type".into(), G::Str(p.procedure_type.clone())));
    if !p.related_controls.is_empty() {
        f.push((
            "related_controls".into(),
            G::Arr(
                p.related_controls
                    .iter()
                    .map(|s| G::Str(s.clone()))
                    .collect(),
            ),
        ));
    }
    if !p.technologies.is_empty() {
        f.push((
            "technologies".into(),
            G::Arr(p.technologies.iter().map(|s| G::Str(s.clone())).collect()),
        ));
    }
    f.push((
        "effectiveness_score".into(),
        G::Float(p.effectiveness_score),
    ));
    f.push(("applied_count".into(), G::Int(p.applied_count)));
    f.push(("success_count".into(), G::Int(p.success_count)));
    f.push(("confidence".into(), G::Float(p.confidence)));
    if p.score != 0.0 {
        f.push(("score".into(), G::Float(p.score)));
    }
    G::Obj(f)
}

#[allow(clippy::too_many_arguments)]
pub fn patterns_output(
    client: &Client,
    vertical: Option<&str>,
    pattern_type: Option<&str>,
    min_occurrences: u32,
    limit: u32,
    offset: u32,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![("limit", limit.to_string())];
    if offset > 0 {
        pairs.push(("offset", offset.to_string()));
    }
    if let Some(v) = vertical {
        pairs.push(("vertical", v.to_string()));
    }
    if let Some(t) = pattern_type {
        pairs.push(("type", t.to_string()));
    }
    if min_occurrences > 0 {
        pairs.push(("min_occurrences", min_occurrences.to_string()));
    }
    let url = format!(
        "{}/api/knowledge/patterns?{}",
        client.api_url,
        query_encode(&pairs)
    );
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let parsed: PatternsResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    let mut out = String::new();
    if parsed.total == 0 {
        let _ = writeln!(out, "No patterns found.");
        return Ok(out);
    }
    let _ = writeln!(out, "Found {} patterns:\n", parsed.total);
    for p in &parsed.patterns {
        let occurrences = if p.occurrence_count > 0 {
            let mut s = format!(" (seen {}x", p.occurrence_count);
            if !p.typical_blast_radius.is_empty() {
                s.push_str(&format!(", blast: {}", p.typical_blast_radius));
            }
            if !p.typical_mttr.is_empty() {
                s.push_str(&format!(", MTTR: {}", p.typical_mttr));
            }
            s.push(')');
            s
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "  {} [{}] {}{occurrences}",
            p.id, p.pattern_type, p.title
        );
        if !p.description.is_empty() {
            let _ = writeln!(out, "    {}", display::truncate_text(&p.description, 78));
        }
        if !p.related_controls.is_empty() {
            let _ = writeln!(out, "    Controls: {}", p.related_controls.join(", "));
        }
        if !p.prevention_strategies.is_empty() {
            let _ = writeln!(
                out,
                "    Prevention: {}",
                p.prevention_strategies.join("; ")
            );
        }
    }
    Ok(out)
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

    #[test]
    fn search_body_matches_go_golden() {
        let want = String::from_utf8(testdata("search_body_golden.txt")).unwrap();
        assert_eq!(search_body("circuit breaker & <timeouts>", 20, 0), want);
    }

    #[test]
    fn procedures_control_filter_json_matches_go_golden() {
        // Parse the fixture, apply the client-side RC-018 filter, and
        // re-marshal: byte-identical to Go's MarshalIndent (omitempty on
        // description/technologies/score; floats Go-formatted).
        let mut parsed: ProceduresResponse =
            serde_json::from_slice(&testdata("procedures_input.json")).unwrap();
        parsed
            .procedures
            .retain(|p| p.related_controls.iter().any(|rc| rc == "RC-018"));
        parsed.total = parsed.procedures.len() as i64;
        let got = procedures_json(&parsed);
        let want = String::from_utf8(testdata("procedures_filtered_golden.txt")).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn min_class_is_validated() {
        assert!(validate_min_class(&None).is_ok());
        assert!(validate_min_class(&Some("best".into())).is_ok());
        let f = validate_min_class(&Some("bogus".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: --min-class expects best, good, or emerging, got \"bogus\""
        );
    }
}
