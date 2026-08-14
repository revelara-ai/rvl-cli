//! Slice (c): `knowledge` read commands ported from rvl-cli
//! `internal/commands/knowledge.go`: `search`, `facts`, `procedures`,
//! `patterns`, plus (po-av01j.160) `graph-search`, `foresight`, and
//! `enrich`, plus (po-av01j.161) `relationships`, `graph`, and `health` —
//! the full read surface is now ported.
//!
//! JSON parity: search/facts/patterns print the server body verbatim, as
//! does `foresight --format=json`; `procedures --control=RC-XXX
//! --format=json` re-marshals after the client-side control filter
//! (golden-tested against Go's MarshalIndent). POST bodies are Go's
//! sorted-key map marshal, byte-identical.

use crate::client::Client;
use crate::display;
use crate::gojson::{compact, path_escape, pretty, query_encode, query_escape, G};
use crate::{CmdResult, Failure, BIN};
use serde::Deserialize;
use std::fmt::Write as _;
use std::time::Duration;

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
    /// List relationships for a knowledge entity
    Relationships {
        /// Entity type: fact, procedure, pattern, service, technology, control
        entity_type: String,
        /// Entity ID (e.g. fact_abc12)
        entity_id: String,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// Traverse the knowledge graph from an entity
    Graph {
        /// Entity type: fact, procedure, pattern, service, technology, control
        entity_type: String,
        /// Entity ID (e.g. fact_abc12)
        entity_id: String,
        /// Traversal depth (default 3)
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..))]
        depth: u32,
        /// Minimum edge strength (default 0.3); passed to the server verbatim
        #[arg(long, default_value = "0.3")]
        min_strength: String,
        /// Comma-separated relation types to follow (e.g. causes,mitigates)
        #[arg(long = "type")]
        relation_type: Option<String>,
    },
    /// Graph-expanded semantic search (search + graph neighbors)
    GraphSearch {
        /// Search query (words are joined with spaces)
        #[arg(required = true)]
        query: Vec<String>,
        /// Maximum results (default 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Graph expansion depth (default 1)
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
        depth: u32,
        /// Comma-separated relation types to expand (e.g. causes,mitigates)
        #[arg(long)]
        types: Option<String>,
    },
    /// Explore causal impact chains with mitigations
    Foresight {
        /// Starting entity type (service, fact, procedure, pattern, technology, control, incident, risk)
        #[arg(long)]
        entity_type: Option<String>,
        /// Starting entity ID
        #[arg(long)]
        entity_id: Option<String>,
        /// Traversal depth (default 3; the server caps at 7)
        #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..))]
        depth: u32,
        /// Minimum edge strength between 0 and 1 (default 0.3)
        #[arg(long, default_value_t = 0.3)]
        min_strength: f64,
        /// Include mitigating controls and procedures per impact path
        #[arg(long)]
        include_mitigations: bool,
        /// Comma-separated relation types to traverse (e.g. causes,depends_on)
        #[arg(long)]
        relation_types: Option<String>,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// Fetch patterns, procedures, and health in one call
    Enrich {
        /// Filter by SRE vertical (default: fault-tolerance)
        #[arg(long, default_value = "fault-tolerance")]
        vertical: String,
        /// Include procedures for a specific control (RC-XXX)
        #[arg(long)]
        control: Option<String>,
        /// Include facts for a specific technology
        #[arg(long)]
        technology: Option<String>,
        /// Include semantic search results for a query
        #[arg(long)]
        query: Option<String>,
        /// Maximum results per section (default 10)
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
    },
    /// Show knowledge base health statistics
    Health,
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

/// A graph-expanded search hit — search fields plus graph discovery
/// metadata (rvl-cli's KnowledgeGraphSearchResult).
#[derive(Debug, Default, Deserialize)]
struct GraphSearchResult {
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
    discovery_method: String,
    #[serde(default)]
    graph_path: String,
}

#[derive(Debug, Default, Deserialize)]
struct GraphSearchResponse {
    #[serde(default)]
    results: Vec<GraphSearchResult>,
    #[serde(default)]
    total: i64,
}

/// A single entity in a foresight impact path.
#[derive(Debug, Default, Deserialize)]
struct ForesightNode {
    #[serde(default)]
    entity_type: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    relation_type: String,
    #[serde(default)]
    delay_seconds: Option<i64>,
    #[serde(default)]
    strength: f64,
    #[serde(default)]
    depth: i64,
}

/// A control or procedure that mitigates a node on an impact path.
#[derive(Debug, Default, Deserialize)]
struct ForesightMitigation {
    #[serde(default)]
    control_code: String,
    #[serde(default)]
    control_name: String,
    #[serde(default)]
    procedure_title: String,
    #[serde(default)]
    entity_type: String,
    #[serde(default)]
    entity_label: String,
    #[serde(default)]
    edge_strength: f64,
}

/// A single causal chain from the starting entity.
#[derive(Debug, Default, Deserialize)]
struct ForesightPath {
    #[serde(default)]
    chain: Vec<ForesightNode>,
    #[serde(default)]
    mitigations: Vec<ForesightMitigation>,
}

#[derive(Debug, Default, Deserialize)]
struct ForesightMetadata {
    #[serde(default)]
    traversal_depth: i64,
    #[serde(default)]
    edges_examined: i64,
    #[serde(default)]
    query_time_ms: f64,
}

#[derive(Debug, Default, Deserialize)]
struct ForesightResponse {
    #[serde(default)]
    impact_paths: Vec<ForesightPath>,
    #[serde(default)]
    metadata: ForesightMetadata,
}

/// A relationship from the knowledge API (rvl-cli's
/// KnowledgeRelationship; only the fields the table render reads).
#[derive(Debug, Default, Deserialize)]
struct Relationship {
    #[serde(default)]
    id: String,
    #[serde(default)]
    relation_type: String,
    #[serde(default)]
    source_type: String,
    #[serde(default)]
    source_label: String,
    #[serde(default)]
    target_type: String,
    #[serde(default)]
    target_label: String,
    #[serde(default)]
    strength: f64,
    #[serde(default)]
    direction: String,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    observation_count: i64,
}

#[derive(Debug, Default, Deserialize)]
struct RelationshipsResponse {
    #[serde(default)]
    relationships: Vec<Relationship>,
    #[serde(default)]
    total: i64,
}

/// A node from graph traversal (rvl-cli's KnowledgeTraversalResult).
#[derive(Debug, Default, Deserialize)]
struct TraversalNode {
    #[serde(default)]
    entity_type: String,
    #[serde(default)]
    entity_id: String,
    #[serde(default)]
    entity_label: String,
    #[serde(default)]
    relation_type: String,
    #[serde(default)]
    strength: f64,
    #[serde(default)]
    depth: i64,
}

#[derive(Debug, Default, Deserialize)]
struct TraversalResponse {
    #[serde(default)]
    results: Vec<TraversalNode>,
    #[serde(default)]
    total: i64,
}

/// Knowledge base health stats (rvl-cli's KnowledgeHealth).
#[derive(Debug, Default, Deserialize)]
struct Health {
    #[serde(default)]
    total_facts: i64,
    #[serde(default)]
    total_procedures: i64,
    #[serde(default)]
    total_patterns: i64,
    #[serde(default)]
    validated_percentage: f64,
    #[serde(default)]
    avg_confidence: f64,
    #[serde(default)]
    stale_count: i64,
    #[serde(default)]
    contradiction_count: i64,
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
            KnowledgeCmd::Relationships {
                entity_type,
                entity_id,
                format,
            } => {
                let (_, client) = crate::client::load_and_resolve()?;
                relationships_output(&client, &entity_type, &entity_id, format.as_deref())
            }
            KnowledgeCmd::Graph {
                entity_type,
                entity_id,
                depth,
                min_strength,
                relation_type,
            } => {
                let (_, client) = crate::client::load_and_resolve()?;
                graph_output(
                    &client,
                    &entity_type,
                    &entity_id,
                    depth,
                    &min_strength,
                    relation_type.as_deref(),
                )
            }
            KnowledgeCmd::GraphSearch {
                query,
                limit,
                depth,
                types,
            } => {
                let query = query.join(" ");
                if query.is_empty() {
                    return Err(Failure::usage("Error: search query required"));
                }
                let (_, client) = crate::client::load_and_resolve()?;
                graph_search_output(&client, &query, limit, depth, types.as_deref())
            }
            KnowledgeCmd::Foresight {
                entity_type,
                entity_id,
                depth,
                min_strength,
                include_mitigations,
                relation_types,
                format,
            } => {
                let (entity_type, entity_id) =
                    validate_foresight_args(&entity_type, &entity_id, min_strength)?;
                let (_, client) = crate::client::load_and_resolve()?;
                foresight_output(
                    &client,
                    &entity_type,
                    &entity_id,
                    depth,
                    min_strength,
                    include_mitigations,
                    relation_types.as_deref(),
                    format.as_deref(),
                )
            }
            KnowledgeCmd::Enrich {
                vertical,
                control,
                technology,
                query,
                limit,
            } => {
                let (_, client) = crate::client::load_and_resolve()?;
                enrich_output(
                    &client,
                    &vertical,
                    control.as_deref(),
                    technology.as_deref(),
                    query.as_deref(),
                    limit,
                )
            }
            KnowledgeCmd::Health => {
                let (_, client) = crate::client::load_and_resolve()?;
                health_output(&client)
            }
        }
    })();
    crate::finish(res)
}

/// Foresight's Go-side validations: `--min-strength` in [0,1] (checked in
/// rvl-cli's flag loop), then the `--entity-type`/`--entity-id` required
/// pair with its three-line usage message.
fn validate_foresight_args(
    entity_type: &Option<String>,
    entity_id: &Option<String>,
    min_strength: f64,
) -> Result<(String, String), Failure> {
    if !(0.0..=1.0).contains(&min_strength) {
        return Err(Failure::usage(format!(
            "Error: --min-strength expects a number between 0 and 1, got \"{min_strength}\""
        )));
    }
    match (entity_type.as_deref(), entity_id.as_deref()) {
        (Some(et), Some(eid)) if !et.is_empty() && !eid.is_empty() => {
            Ok((et.to_string(), eid.to_string()))
        }
        _ => Err(Failure::usage(format!(
            "Error: --entity-type and --entity-id are required\n\
             Usage: {BIN} knowledge foresight --entity-type=<type> --entity-id=<id> [options]\n\
             Entity types: service, fact, procedure, pattern, technology, control, incident, risk"
        ))),
    }
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
        write_pattern_item(&mut out, p);
    }
    Ok(out)
}

/// The POST /api/knowledge/graph-search body: Go's `map[string]interface{}`
/// marshal (sorted keys: expand_depth, expand_types, graph_expand, limit,
/// query; expand_types only when `--types` was given).
pub fn graph_search_body(query: &str, limit: u32, depth: u32, types: Option<&str>) -> String {
    let mut f: Vec<(String, G)> = vec![("expand_depth".to_string(), G::Int(depth as i64))];
    if let Some(t) = types {
        f.push((
            "expand_types".to_string(),
            G::Arr(t.split(',').map(|s| G::Str(s.to_string())).collect()),
        ));
    }
    f.push(("graph_expand".to_string(), G::Bool(true)));
    f.push(("limit".to_string(), G::Int(limit as i64)));
    f.push(("query".to_string(), G::Str(query.to_string())));
    compact(&G::Obj(f))
}

pub fn graph_search_output(
    client: &Client,
    query: &str,
    limit: u32,
    depth: u32,
    types: Option<&str>,
) -> CmdResult {
    let body = graph_search_body(query, limit, depth, types);
    let url = format!("{}/api/knowledge/graph-search", client.api_url);
    let resp = client
        .request("POST", &url, Some(body.as_bytes()))
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let parsed: GraphSearchResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_graph_search(&parsed, query))
}

fn render_graph_search(resp: &GraphSearchResponse, query: &str) -> String {
    let mut out = String::new();
    if resp.total == 0 {
        let _ = writeln!(out, "No knowledge found matching query.");
        return out;
    }
    let _ = writeln!(
        out,
        "Found {} results for \"{query}\" (graph-expanded):\n",
        resp.total
    );
    for r in &resp.results {
        let type_badge = format!("[{}]", r.result_type.to_uppercase());
        let title = if r.title.is_empty() {
            display::truncate_text(&r.content, 80)
        } else {
            r.title.clone()
        };
        let method_badge = match r.discovery_method.as_str() {
            "semantic" => " [SEM]",
            "graph" => " [GRAPH]",
            "both" => " [SEM+GRAPH]",
            _ => "",
        };
        let _ = writeln!(out, "  {:<12} {type_badge}{method_badge} {title}", r.id);
        if r.similarity > 0.0 {
            let _ = write!(out, "               Score: {:.2}", r.similarity);
            if !r.vertical.is_empty() {
                let _ = write!(out, "  Vertical: {}", r.vertical);
            }
            out.push('\n');
        }
        if !r.graph_path.is_empty() {
            let _ = writeln!(out, "               Path: {}", r.graph_path);
        }
    }
    out
}

pub fn relationships_output(
    client: &Client,
    entity_type: &str,
    entity_id: &str,
    format: Option<&str>,
) -> CmdResult {
    // po-4xrz5 (carried from rvl-cli): URL-encode the path segments so
    // entity ids with /, ?, # don't smuggle.
    let url = format!(
        "{}/api/knowledge/entities/{}/{}/relationships",
        client.api_url,
        path_escape(entity_type),
        path_escape(entity_id)
    );
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    // rvl-cli only compares --format against "json"; any other value
    // falls through to the table render, unvalidated. Mirror that quirk.
    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let parsed: RelationshipsResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_relationships(&parsed, entity_type, entity_id))
}

fn render_relationships(
    resp: &RelationshipsResponse,
    entity_type: &str,
    entity_id: &str,
) -> String {
    let mut out = String::new();
    if resp.total == 0 {
        let _ = writeln!(out, "No relationships found for {entity_type} {entity_id}");
        return out;
    }
    let _ = writeln!(
        out,
        "Relationships for {entity_type} {entity_id} ({} total):\n",
        resp.total
    );
    for rel in &resp.relationships {
        let dir_icon = if rel.direction == "bidirectional" {
            " <-> "
        } else {
            " -> "
        };
        let _ = write!(
            out,
            "  {} [{}]{dir_icon}{} [{}] (strength: {:.0}%",
            rel.source_label,
            rel.source_type,
            rel.target_label,
            rel.target_type,
            rel.strength * 100.0
        );
        if rel.observation_count > 1 {
            let _ = write!(out, ", seen {}x", rel.observation_count);
        }
        out.push_str(")\n");
        let _ = writeln!(out, "    Relation: {}  ID: {}", rel.relation_type, rel.id);
        if let Some(ev) = rel.evidence.first() {
            let _ = writeln!(out, "    Evidence: {ev}");
        }
    }
    out
}

pub fn graph_output(
    client: &Client,
    entity_type: &str,
    entity_id: &str,
    depth: u32,
    min_strength: &str,
    relation_type: Option<&str>,
) -> CmdResult {
    // rvl-cli builds this URL with fmt.Sprintf and — unlike relationships
    // (po-4xrz5) — does NOT path-escape the entity segments or the
    // min_strength/relation_type values. Mirror that byte-for-byte.
    let mut url = format!(
        "{}/api/knowledge/entities/{entity_type}/{entity_id}/graph?max_depth={depth}&min_strength={min_strength}",
        client.api_url
    );
    if let Some(rt) = relation_type {
        if !rt.is_empty() {
            let _ = write!(url, "&relation_type={rt}");
        }
    }
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let parsed: TraversalResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_graph(&parsed, entity_type, entity_id))
}

fn render_graph(resp: &TraversalResponse, entity_type: &str, entity_id: &str) -> String {
    let mut out = String::new();
    if resp.total == 0 {
        let _ = writeln!(
            out,
            "No connected nodes found from {entity_type} {entity_id}"
        );
        return out;
    }
    let _ = writeln!(
        out,
        "Graph traversal from {entity_type} {entity_id} ({} nodes):\n",
        resp.total
    );

    // Group by depth for readability, exactly like the Go render: a
    // "Depth N:" header per level from 1 to the max observed depth.
    let max_depth = resp.results.iter().map(|n| n.depth).max().unwrap_or(0);
    for d in 1..=max_depth {
        let _ = writeln!(out, "  Depth {d}:");
        for n in resp.results.iter().filter(|n| n.depth == d) {
            let indent = "  ".repeat(d.max(0) as usize);
            let _ = writeln!(
                out,
                "  {indent}-[{}]-> {} [{}] (strength: {:.0}%)",
                n.relation_type,
                n.entity_label,
                n.entity_type,
                n.strength * 100.0
            );
            let _ = writeln!(out, "  {indent}         ID: {}", n.entity_id);
        }
    }
    out
}

pub fn health_output(client: &Client) -> CmdResult {
    let url = format!("{}/api/knowledge/health", client.api_url);
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let parsed: Health = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_health(&parsed))
}

fn render_health(health: &Health) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Knowledge Base Health\n");
    write_health_lines(&mut out, health);
    out
}

/// The health stat lines; rvl-cli renders them identically in both the
/// `health` command and the `enrich` Knowledge Health section.
fn write_health_lines(out: &mut String, health: &Health) {
    let total = health.total_facts + health.total_procedures + health.total_patterns;
    let _ = writeln!(out, "  Total Items:       {total}");
    let _ = writeln!(out, "    Facts:           {}", health.total_facts);
    let _ = writeln!(out, "    Procedures:      {}", health.total_procedures);
    let _ = writeln!(out, "    Patterns:        {}", health.total_patterns);
    let _ = writeln!(
        out,
        "  Validated:         {:.0}%",
        health.validated_percentage
    );
    let _ = writeln!(
        out,
        "  Avg Confidence:    {:.0}%",
        health.avg_confidence * 100.0
    );
    if health.stale_count > 0 {
        let _ = writeln!(out, "  Stale:             {}", health.stale_count);
    }
    if health.contradiction_count > 0 {
        let _ = writeln!(out, "  Contradictions:    {}", health.contradiction_count);
    }
}

/// The POST /api/knowledge/foresight body: Go's `map[string]interface{}`
/// marshal (sorted keys: depth, entity_id, entity_type,
/// include_mitigations, min_strength, relation_types; relation_types only
/// when `--relation-types` was given).
pub fn foresight_body(
    entity_type: &str,
    entity_id: &str,
    depth: u32,
    min_strength: f64,
    include_mitigations: bool,
    relation_types: Option<&str>,
) -> String {
    let mut f: Vec<(String, G)> = vec![
        ("depth".to_string(), G::Int(depth as i64)),
        ("entity_id".to_string(), G::Str(entity_id.to_string())),
        ("entity_type".to_string(), G::Str(entity_type.to_string())),
        (
            "include_mitigations".to_string(),
            G::Bool(include_mitigations),
        ),
        ("min_strength".to_string(), G::Float(min_strength)),
    ];
    if let Some(rt) = relation_types {
        f.push((
            "relation_types".to_string(),
            G::Arr(rt.split(',').map(|s| G::Str(s.to_string())).collect()),
        ));
    }
    compact(&G::Obj(f))
}

#[allow(clippy::too_many_arguments)]
pub fn foresight_output(
    client: &Client,
    entity_type: &str,
    entity_id: &str,
    depth: u32,
    min_strength: f64,
    include_mitigations: bool,
    relation_types: Option<&str>,
    format: Option<&str>,
) -> CmdResult {
    let body = foresight_body(
        entity_type,
        entity_id,
        depth,
        min_strength,
        include_mitigations,
        relation_types,
    );
    // po-8eld4 (carried from rvl-cli): foresight at depth>=3 walks a
    // meaningful slice of the knowledge graph and can take well beyond
    // the default 30s timeout on a populated KB. Give it a 5-minute
    // budget; the server itself caps depth at 7.
    let url = format!("{}/api/knowledge/foresight", client.api_url);
    let resp = client
        .request_with_timeout(
            "POST",
            &url,
            Some(body.as_bytes()),
            Duration::from_secs(300),
        )
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let parsed: ForesightResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_foresight(&parsed, entity_type, entity_id))
}

/// Seconds to a human-readable delay (45s / 3m / 2h), truncating like Go
/// integer division.
fn format_foresight_delay(seconds: i64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / 3600)
    }
}

fn render_foresight(resp: &ForesightResponse, entity_type: &str, entity_id: &str) -> String {
    let mut out = String::new();
    if resp.impact_paths.is_empty() {
        let _ = writeln!(out, "No impact paths found from {entity_type} {entity_id}");
        return out;
    }

    let _ = writeln!(
        out,
        "Foresight: {entity_type} {entity_id} (depth {}, {} edges examined, {:.0}ms)\n",
        resp.metadata.traversal_depth, resp.metadata.edges_examined, resp.metadata.query_time_ms
    );

    for (i, path) in resp.impact_paths.iter().enumerate() {
        for node in &path.chain {
            let indent = "  ".repeat(node.depth.max(0) as usize);
            let delay = match node.delay_seconds {
                Some(s) => format!(" ({})", format_foresight_delay(s)),
                None => String::new(),
            };
            let _ = writeln!(
                out,
                "  {indent}-[{}]-> {} [{}] (strength: {:.0}%){delay}",
                node.relation_type,
                node.label,
                node.entity_type,
                node.strength * 100.0
            );
        }

        if !path.mitigations.is_empty() {
            let _ = writeln!(out, "    Mitigations:");
            for mit in &path.mitigations {
                let label = if !mit.control_code.is_empty() {
                    format!("{}: {}", mit.control_code, mit.control_name)
                } else if !mit.procedure_title.is_empty() {
                    mit.procedure_title.clone()
                } else {
                    mit.entity_label.clone()
                };
                let _ = writeln!(
                    out,
                    "      [{}] {label} (strength: {:.0}%)",
                    mit.entity_type,
                    mit.edge_strength * 100.0
                );
            }
        }

        if i < resp.impact_paths.len() - 1 {
            out.push('\n');
        }
    }
    out
}

/// Fetch patterns, procedures, health, and optionally facts and search
/// results, printing combined output. rvl-cli fires the fetches in
/// parallel goroutines; sequential here keeps the same output and error
/// semantics with a deterministic stderr order. Total fetch failure (e.g.
/// expired API key) is a runtime error (exit 1); partial failure degrades
/// to stderr warnings (po-cj4s7).
pub fn enrich_output(
    client: &Client,
    vertical: &str,
    control: Option<&str>,
    technology: Option<&str>,
    query: Option<&str>,
    limit: u32,
) -> CmdResult {
    let mut attempted = 3; // patterns, procedures, health
    if technology.is_some() {
        attempted += 1;
    }
    if query.is_some() {
        attempted += 1;
    }

    let mut errs: Vec<String> = Vec::new();

    // Query strings below concatenate values unencoded, exactly as the Go
    // CLI builds them with fmt.Sprintf.
    let mut patterns = PatternsResponse::default();
    let url = format!(
        "{}/api/knowledge/patterns?limit={limit}&vertical={vertical}",
        client.api_url
    );
    match client.request("GET", &url, None) {
        Err(e) => errs.push(format!("patterns: {e}")),
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(p) => patterns = p,
            Err(e) => errs.push(format!("patterns parse: {e}")),
        },
    }

    let mut procs = ProceduresResponse::default();
    let mut url = format!(
        "{}/api/knowledge/procedures?limit={limit}&vertical={vertical}",
        client.api_url
    );
    if let Some(c) = control {
        let _ = write!(url, "&q={c}");
    }
    match client.request("GET", &url, None) {
        Err(e) => errs.push(format!("procedures: {e}")),
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(p) => procs = p,
            Err(e) => errs.push(format!("procedures parse: {e}")),
        },
    }

    let mut health = Health::default();
    let url = format!("{}/api/knowledge/health", client.api_url);
    match client.request("GET", &url, None) {
        Err(e) => errs.push(format!("health: {e}")),
        Ok(b) => match serde_json::from_slice(&b) {
            Ok(h) => health = h,
            Err(e) => errs.push(format!("health parse: {e}")),
        },
    }

    let mut facts = FactsResponse::default();
    if let Some(t) = technology {
        let mut url = format!(
            "{}/api/knowledge/facts?limit={limit}&technology={t}",
            client.api_url
        );
        if !vertical.is_empty() {
            let _ = write!(url, "&vertical={vertical}");
        }
        match client.request("GET", &url, None) {
            Err(e) => errs.push(format!("facts: {e}")),
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(f) => facts = f,
                Err(e) => errs.push(format!("facts parse: {e}")),
            },
        }
    }

    let mut search = SearchResponse::default();
    if let Some(q) = query {
        let body = compact(&G::Obj(vec![
            ("limit".to_string(), G::Int(limit as i64)),
            ("query".to_string(), G::Str(q.to_string())),
        ]));
        let url = format!("{}/api/knowledge/search", client.api_url);
        match client.request("POST", &url, Some(body.as_bytes())) {
            Err(e) => errs.push(format!("search: {e}")),
            Ok(b) => match serde_json::from_slice(&b) {
                Ok(s) => search = s,
                Err(e) => errs.push(format!("search parse: {e}")),
            },
        }
    }

    if errs.len() >= attempted {
        return Err(Failure::runtime(
            errs.iter()
                .map(|e| format!("Error: {e}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    if !errs.is_empty() {
        for e in &errs {
            eprintln!("Warning: {e}");
        }
        eprintln!();
    }

    Ok(render_enrich(
        &patterns, procs, &health, &facts, &search, control, technology, query,
    ))
}

#[allow(clippy::too_many_arguments)]
fn render_enrich(
    patterns: &PatternsResponse,
    mut procs: ProceduresResponse,
    health: &Health,
    facts: &FactsResponse,
    search: &SearchResponse,
    control: Option<&str>,
    technology: Option<&str>,
    query: Option<&str>,
) -> String {
    let mut out = String::new();

    // --- Patterns ---
    let _ = writeln!(out, "=== Patterns ({}) ===\n", patterns.total);
    for p in &patterns.patterns {
        write_pattern_item(&mut out, p);
    }

    // --- Procedures ---
    let _ = writeln!(out, "\n=== Procedures ({}) ===\n", procs.total);
    // Client-side control filter; the Go CLI keeps the unfiltered list
    // when nothing matches, so mirror that quirk.
    if let Some(code) = control {
        let filtered: Vec<Procedure> = procs
            .procedures
            .iter()
            .filter(|p| p.related_controls.iter().any(|rc| rc == code))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            procs.procedures = filtered;
        }
    }
    for p in &procs.procedures {
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
    }

    // --- Facts (optional) ---
    if let Some(t) = technology {
        let _ = writeln!(out, "\n=== Facts for {t} ({}) ===\n", facts.total);
        for f in &facts.facts {
            let _ = writeln!(
                out,
                "  {} {} [{}] (confidence: {:.0}%)",
                f.id,
                display::format_validation_status(&f.validation_status),
                f.vertical,
                f.confidence * 100.0
            );
            let _ = writeln!(out, "    {}", display::truncate_text(&f.content, 80));
        }
    }

    // --- Search (optional) ---
    if let Some(q) = query {
        let _ = writeln!(
            out,
            "\n=== Search Results for \"{q}\" ({}) ===\n",
            search.total
        );
        for r in &search.results {
            let type_badge = format!("[{}]", r.result_type.to_uppercase());
            let title = if r.title.is_empty() {
                display::truncate_text(&r.content, 80)
            } else {
                r.title.clone()
            };
            let _ = writeln!(out, "  {:<12} {type_badge} {title}", r.id);
            if r.similarity > 0.0 {
                let _ = writeln!(
                    out,
                    "               Similarity: {:.2}  Vertical: {}",
                    r.similarity, r.vertical
                );
            }
        }
    }

    // --- Health ---
    let _ = writeln!(out, "\n=== Knowledge Health ===\n");
    write_health_lines(&mut out, health);
    out
}

/// One pattern line-item; rvl-cli renders it identically in both the
/// `patterns` table and the `enrich` Patterns section.
fn write_pattern_item(out: &mut String, p: &Pattern) {
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

    // --- graph-search ---

    #[test]
    fn graph_search_body_matches_go_sorted_map_marshal() {
        // Keys sorted like Go's map marshal; expand_types only with --types.
        assert_eq!(
            graph_search_body("timeout failures", 5, 2, Some("causes,depends_on")),
            r#"{"expand_depth":2,"expand_types":["causes","depends_on"],"graph_expand":true,"limit":5,"query":"timeout failures"}"#
        );
        assert_eq!(
            graph_search_body("cache stampede", 20, 1, None),
            r#"{"expand_depth":1,"graph_expand":true,"limit":20,"query":"cache stampede"}"#
        );
    }

    #[test]
    fn graph_search_render_badges_and_paths() {
        let resp: GraphSearchResponse = serde_json::from_str(
            r#"{"results":[
                {"type":"fact","id":"fact_a1","title":"Redis timeouts cascade","vertical":"fault-tolerance","similarity":0.91,"discovery_method":"semantic"},
                {"type":"pattern","id":"pat_b2","content":"Connection pool exhaustion under retry storms","discovery_method":"graph","graph_path":"fact_a1 -[causes]-> pat_b2"},
                {"type":"procedure","id":"proc_c3","title":"Tune pool limits","similarity":0.55,"discovery_method":"both"}
            ],"total":3}"#,
        )
        .unwrap();
        let out = render_graph_search(&resp, "timeout failures");
        let want = "Found 3 results for \"timeout failures\" (graph-expanded):\n\n  \
            fact_a1      [FACT] [SEM] Redis timeouts cascade\n               \
            Score: 0.91  Vertical: fault-tolerance\n  \
            pat_b2       [PATTERN] [GRAPH] Connection pool exhaustion under retry storms\n               \
            Path: fact_a1 -[causes]-> pat_b2\n  \
            proc_c3      [PROCEDURE] [SEM+GRAPH] Tune pool limits\n               \
            Score: 0.55\n";
        assert_eq!(out, want);
    }

    #[test]
    fn graph_search_render_empty_total() {
        let resp = GraphSearchResponse::default();
        assert_eq!(
            render_graph_search(&resp, "x"),
            "No knowledge found matching query.\n"
        );
    }

    // --- foresight ---

    #[test]
    fn foresight_body_matches_go_sorted_map_marshal() {
        assert_eq!(
            foresight_body("technology", "redis", 3, 0.3, true, None),
            r#"{"depth":3,"entity_id":"redis","entity_type":"technology","include_mitigations":true,"min_strength":0.3}"#
        );
        assert_eq!(
            foresight_body(
                "service",
                "checkout-api",
                5,
                0.5,
                false,
                Some("causes,depends_on")
            ),
            r#"{"depth":5,"entity_id":"checkout-api","entity_type":"service","include_mitigations":false,"min_strength":0.5,"relation_types":["causes","depends_on"]}"#
        );
    }

    #[test]
    fn foresight_args_are_validated() {
        assert!(validate_foresight_args(&Some("service".into()), &Some("api".into()), 0.3).is_ok());
        let f =
            validate_foresight_args(&Some("service".into()), &Some("api".into()), 1.5).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: --min-strength expects a number between 0 and 1, got \"1.5\""
        );
        for (et, eid) in [
            (None, Some("api".to_string())),
            (Some("service".to_string()), None),
            (Some("service".to_string()), Some(String::new())),
        ] {
            let f = validate_foresight_args(&et, &eid, 0.3).unwrap_err();
            assert_eq!(f.code, 2);
            assert!(
                f.msg
                    .starts_with("Error: --entity-type and --entity-id are required"),
                "{}",
                f.msg
            );
            assert!(f.msg.contains("knowledge foresight --entity-type=<type>"));
        }
    }

    #[test]
    fn foresight_delay_formatting_truncates_like_go() {
        assert_eq!(format_foresight_delay(45), "45s");
        assert_eq!(format_foresight_delay(59), "59s");
        assert_eq!(format_foresight_delay(90), "1m");
        assert_eq!(format_foresight_delay(3599), "59m");
        assert_eq!(format_foresight_delay(7200), "2h");
    }

    #[test]
    fn foresight_render_chains_mitigations_and_separators() {
        let resp: ForesightResponse = serde_json::from_str(
            r#"{"impact_paths":[
                {"chain":[
                    {"entity_type":"service","entity_id":"api","label":"checkout-api","relation_type":"causes","strength":0.8,"depth":1},
                    {"entity_type":"pattern","entity_id":"p1","label":"Retry storm","relation_type":"amplifies","delay_seconds":90,"strength":0.6,"depth":2}
                ],"total_strength":0.48,"mitigations":[
                    {"control_code":"RC-018","control_name":"Timeouts","entity_type":"control","entity_id":"c1","entity_label":"x","edge_strength":0.9,"for_node_id":"p1"},
                    {"procedure_title":"Backoff runbook","entity_type":"procedure","entity_id":"pr1","entity_label":"y","edge_strength":0.7,"for_node_id":"p1"}
                ]},
                {"chain":[
                    {"entity_type":"technology","entity_id":"redis","label":"redis","relation_type":"depends_on","strength":0.4,"depth":1}
                ],"total_strength":0.4}
            ],"metadata":{"traversal_depth":3,"edges_examined":42,"query_time_ms":128.4}}"#,
        )
        .unwrap();
        let out = render_foresight(&resp, "service", "checkout-api");
        // Indent per node is "  " + "  "*depth, exactly Go's
        // `"  %s-[%s]..."` with strings.Repeat("  ", depth).
        let want = concat!(
            "Foresight: service checkout-api (depth 3, 42 edges examined, 128ms)\n",
            "\n",
            "    -[causes]-> checkout-api [service] (strength: 80%)\n",
            "      -[amplifies]-> Retry storm [pattern] (strength: 60%) (1m)\n",
            "    Mitigations:\n",
            "      [control] RC-018: Timeouts (strength: 90%)\n",
            "      [procedure] Backoff runbook (strength: 70%)\n",
            "\n",
            "    -[depends_on]-> redis [technology] (strength: 40%)\n",
        );
        assert_eq!(out, want);
    }

    #[test]
    fn foresight_render_no_paths() {
        let resp = ForesightResponse::default();
        assert_eq!(
            render_foresight(&resp, "technology", "redis"),
            "No impact paths found from technology redis\n"
        );
    }

    // --- enrich ---

    #[test]
    fn enrich_render_all_sections() {
        let patterns: PatternsResponse = serde_json::from_str(
            r#"{"patterns":[{"id":"pat_1","title":"Retry storm","pattern_type":"failure_mode","occurrence_count":4,"typical_blast_radius":"regional","typical_mttr":"45m","related_controls":["RC-018"],"prevention_strategies":["cap retries","jittered backoff"]}],"total":1}"#,
        )
        .unwrap();
        let procs: ProceduresResponse = serde_json::from_str(
            r#"{"procedures":[
                {"id":"proc_1","title":"Set timeouts","procedure_type":"runbook","description":"How to set them","related_controls":["RC-018"],"effectiveness_score":0.9,"applied_count":3},
                {"id":"proc_2","title":"Other","procedure_type":"runbook","related_controls":["RC-099"]}
            ],"total":2}"#,
        )
        .unwrap();
        let health: Health = serde_json::from_str(
            r#"{"total_facts":10,"total_procedures":5,"total_patterns":3,"validated_percentage":80,"avg_confidence":0.75,"stale_count":2}"#,
        )
        .unwrap();
        let facts: FactsResponse = serde_json::from_str(
            r#"{"facts":[{"id":"fact_1","content":"Redis default timeout is unbounded","vertical":"fault-tolerance","confidence":0.8,"validation_status":"analyst_validated"}],"total":1}"#,
        )
        .unwrap();
        let search: SearchResponse = serde_json::from_str(
            r#"{"results":[{"type":"fact","id":"fact_2","title":"Timeout budget","vertical":"fault-tolerance","similarity":0.88}],"total":1}"#,
        )
        .unwrap();
        let out = render_enrich(
            &patterns,
            procs,
            &health,
            &facts,
            &search,
            Some("RC-018"),
            Some("redis"),
            Some("timeout failure"),
        );
        let want = concat!(
            "=== Patterns (1) ===\n",
            "\n",
            "  pat_1 [failure_mode] Retry storm (seen 4x, blast: regional, MTTR: 45m)\n",
            "    Controls: RC-018\n",
            "    Prevention: cap retries; jittered backoff\n",
            "\n=== Procedures (2) ===\n",
            "\n",
            "  proc_1 [runbook] Set timeouts (effectiveness: 90%, applied: 3)\n",
            "    How to set them\n",
            "    Controls: RC-018\n",
            "\n=== Facts for redis (1) ===\n",
            "\n",
            "  fact_1 [VALIDATED] [fault-tolerance] (confidence: 80%)\n",
            "    Redis default timeout is unbounded\n",
            "\n=== Search Results for \"timeout failure\" (1) ===\n",
            "\n",
            "  fact_2       [FACT] Timeout budget\n",
            "               Similarity: 0.88  Vertical: fault-tolerance\n",
            "\n=== Knowledge Health ===\n",
            "\n",
            "  Total Items:       18\n",
            "    Facts:           10\n",
            "    Procedures:      5\n",
            "    Patterns:        3\n",
            "  Validated:         80%\n",
            "  Avg Confidence:    75%\n",
            "  Stale:             2\n",
        );
        assert_eq!(out, want);
    }

    #[test]
    fn enrich_render_keeps_unfiltered_procedures_when_control_matches_nothing() {
        // rvl-cli quirk: an unmatched --control leaves the full list.
        let procs: ProceduresResponse = serde_json::from_str(
            r#"{"procedures":[{"id":"proc_1","title":"A","procedure_type":"runbook","related_controls":["RC-001"]}],"total":1}"#,
        )
        .unwrap();
        let out = render_enrich(
            &PatternsResponse::default(),
            procs,
            &Health::default(),
            &FactsResponse::default(),
            &SearchResponse::default(),
            Some("RC-999"),
            None,
            None,
        );
        assert!(out.contains("proc_1 [runbook] A"), "{out}");
        // Optional sections stay hidden without --technology/--query.
        assert!(!out.contains("=== Facts for"), "{out}");
        assert!(!out.contains("=== Search Results"), "{out}");
    }

    // --- relationships ---

    #[test]
    fn relationships_render_directions_observations_and_evidence() {
        let resp: RelationshipsResponse = serde_json::from_str(
            r#"{"relationships":[
                {"id":"rel_1","relation_type":"causes","source_type":"fact","source_id":"fact_a1","source_label":"Redis timeout","target_type":"pattern","target_id":"pat_b2","target_label":"Retry storm","strength":0.8,"direction":"outbound","evidence":["INC-1234","INC-9"],"observation_count":3},
                {"id":"rel_2","relation_type":"correlates_with","source_type":"pattern","source_id":"pat_b2","source_label":"Retry storm","target_type":"service","target_id":"svc_c3","target_label":"checkout-api","strength":0.45,"direction":"bidirectional","observation_count":1}
            ],"total":2}"#,
        )
        .unwrap();
        let out = render_relationships(&resp, "fact", "fact_a1");
        // Exact Go format string: `"  %s [%s]%s%s [%s] (strength: %s"` with
        // dirIcon " -> " / " <-> ", then optional ", seen Nx" and ")".
        let want = concat!(
            "Relationships for fact fact_a1 (2 total):\n",
            "\n",
            "  Redis timeout [fact] -> Retry storm [pattern] (strength: 80%, seen 3x)\n",
            "    Relation: causes  ID: rel_1\n",
            "    Evidence: INC-1234\n",
            "  Retry storm [pattern] <-> checkout-api [service] (strength: 45%)\n",
            "    Relation: correlates_with  ID: rel_2\n",
        );
        assert_eq!(out, want);
    }

    #[test]
    fn relationships_render_empty_total() {
        let resp = RelationshipsResponse::default();
        assert_eq!(
            render_relationships(&resp, "fact", "fact_abc12"),
            "No relationships found for fact fact_abc12\n"
        );
    }

    // --- graph ---

    #[test]
    fn graph_render_groups_by_depth_with_go_indentation() {
        let resp: TraversalResponse = serde_json::from_str(
            r#"{"results":[
                {"entity_type":"pattern","entity_id":"pat_b2","entity_label":"Retry storm","relation_type":"causes","strength":0.8,"depth":1},
                {"entity_type":"service","entity_id":"svc_c3","entity_label":"checkout-api","relation_type":"impacts","strength":0.6,"depth":2},
                {"entity_type":"control","entity_id":"ctl_d4","entity_label":"RC-018 Timeouts","relation_type":"mitigates","strength":0.9,"depth":1}
            ],"total":3}"#,
        )
        .unwrap();
        let out = render_graph(&resp, "fact", "fact_a1");
        // Indent per node is "  " + "  "*depth, exactly Go's
        // `"  %s-[%s]-> ..."` with strings.Repeat("  ", depth).
        let want = concat!(
            "Graph traversal from fact fact_a1 (3 nodes):\n",
            "\n",
            "  Depth 1:\n",
            "    -[causes]-> Retry storm [pattern] (strength: 80%)\n",
            "             ID: pat_b2\n",
            "    -[mitigates]-> RC-018 Timeouts [control] (strength: 90%)\n",
            "             ID: ctl_d4\n",
            "  Depth 2:\n",
            "      -[impacts]-> checkout-api [service] (strength: 60%)\n",
            "               ID: svc_c3\n",
        );
        assert_eq!(out, want);
    }

    #[test]
    fn graph_render_empty_total() {
        let resp = TraversalResponse::default();
        assert_eq!(
            render_graph(&resp, "fact", "fact_abc12"),
            "No connected nodes found from fact fact_abc12\n"
        );
    }

    // --- health ---

    #[test]
    fn health_render_matches_go_layout() {
        let health: Health = serde_json::from_str(
            r#"{"total_facts":10,"total_procedures":5,"total_patterns":3,"validated_percentage":80,"avg_confidence":0.75,"stale_count":2,"contradiction_count":1}"#,
        )
        .unwrap();
        let want = concat!(
            "Knowledge Base Health\n",
            "\n",
            "  Total Items:       18\n",
            "    Facts:           10\n",
            "    Procedures:      5\n",
            "    Patterns:        3\n",
            "  Validated:         80%\n",
            "  Avg Confidence:    75%\n",
            "  Stale:             2\n",
            "  Contradictions:    1\n",
        );
        assert_eq!(render_health(&health), want);
    }

    #[test]
    fn health_render_hides_zero_stale_and_contradictions() {
        let health: Health = serde_json::from_str(
            r#"{"total_facts":1,"total_procedures":0,"total_patterns":0,"validated_percentage":100,"avg_confidence":1}"#,
        )
        .unwrap();
        let out = render_health(&health);
        assert!(!out.contains("Stale:"), "{out}");
        assert!(!out.contains("Contradictions:"), "{out}");
        assert!(out.contains("  Total Items:       1\n"), "{out}");
    }
}
