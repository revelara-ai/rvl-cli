//! `rvl stpa submit`, ported from rvl-cli `internal/commands/stpa.go`.
//!
//! This is the SOLE ingestion path for the shipped `stpa-review` skill
//! (po-av01j.183): the skill writes a findings JSON file and runs
//! `rvl stpa submit --file findings.json`. It is NOT substitutable by
//! `scan --cs-file`, which carries only `control_structure` — losses, UCAs
//! and loss scenarios have no other way in.
//!
//! Six endpoints, in this order, with ids from earlier responses feeding
//! later calls:
//!   1. `GET  /api/v1/loss-definitions`            (dedup by title)
//!      `POST /api/v1/loss-definitions`
//!   2. `POST /api/v1/ucas`                        -> uca id per finding index
//!   3. `POST /api/v1/loss-scenarios`              -> scenario id, parents by title
//!   4. `POST /api/v1/loss-scenarios/{id}/ucas`    (uses 2's ids)
//!   5. `POST /api/v1/loss-scenarios/{id}/controls`(uses controls/by-code)
//!   6. `POST /api/v1/control-structure/model`     (needs --service as repo_url)
//!
//! Partial failure is the design: every per-item error is a warning on
//! stderr and the run continues, the summary reports how many failed, and
//! the process still exits 0. Only a missing/unreadable/unparseable file or
//! a config failure aborts.
//!
//! Note: `stpa list-ucas` is deliberately NOT ported — cutover decision 2
//! ratified its retirement. That retirement covered list-ucas ONLY.

use crate::client::{self, Client};
use crate::control;
use crate::gojson::{compact, path_escape, G};
use crate::{Failure, BIN};
use serde::Deserialize;
use std::process::ExitCode;

#[derive(clap::Subcommand)]
pub enum StpaCmd {
    /// Submit findings from an STPA-inspired design review JSON file
    /// (losses, UCAs, loss scenarios, and the control-structure model).
    Submit {
        /// Path to the STPA design review JSON output (required)
        #[arg(long)]
        file: Option<String>,
        /// Service name / repo URL used to scope the control structure
        #[arg(long)]
        service: Option<String>,
    },
}

// ---------------------------------------------------------------- input --

/// The input JSON produced by the `stpa-review` skill.
#[derive(Debug, Default, Deserialize)]
pub struct StpaFindings {
    #[serde(default)]
    pub losses: Vec<StpaLoss>,
    #[serde(default)]
    pub findings: Vec<StpaFinding>,
    #[serde(default)]
    pub loss_scenarios: Vec<StpaLossScenario>,
    #[serde(default)]
    pub control_structure: Option<StpaControlStructure>,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaLoss {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub category: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaFinding {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub uca_type: String,
    /// `Option` on purpose: Go marshals a nil `[]string` as `null`, and an
    /// absent `causal_factors` must stay `null` on the wire, not `[]`.
    #[serde(default)]
    pub causal_factors: Option<Vec<String>>,
    #[serde(default)]
    pub loss_scenario: String,
    #[serde(default)]
    pub canonical_form: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub control_code: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaLossScenario {
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub parent_title: String,
    #[serde(default)]
    pub uca_refs: Vec<i64>,
    #[serde(default)]
    pub control_links: Vec<StpaControlLink>,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaControlLink {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub relationship: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaControlStructure {
    #[serde(default)]
    pub nodes: Vec<StpaCsNode>,
    #[serde(default)]
    pub edges: Vec<StpaCsEdge>,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaCsNode {
    #[serde(default)]
    pub node_key: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hierarchy_level: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub confidence: i64,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct StpaCsEdge {
    #[serde(default)]
    pub from_key: String,
    #[serde(default)]
    pub to_key: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub edge_type: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub confidence: i64,
}

/// Counters mirroring Go's `submitStats`, reported in the closing summary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SubmitStats {
    pub loss_defs_total: usize,
    pub loss_defs_new: usize,
    pub ucas_total: usize,
    pub ucas_new: usize,
    pub scenarios_created: usize,
    pub uca_links: usize,
    pub control_links: usize,
    pub cs_nodes: i64,
    pub cs_edges: i64,
    pub errors: usize,
}

// ------------------------------------------------------------- request --

/// `POST /api/v1/loss-definitions` body. Go marshals a `map[string]string`,
/// so the keys are sorted.
pub fn loss_definition_body(loss: &StpaLoss) -> String {
    compact(&G::Obj(vec![
        ("category".into(), G::Str(loss.category.clone())),
        ("description".into(), G::Str(loss.description.clone())),
        ("title".into(), G::Str(loss.title.clone())),
    ]))
}

/// `POST /api/v1/ucas` body. Go marshals a `map[string]any` (sorted keys);
/// `control_code` is present only when non-empty, and `source` is always
/// `design_review` — that is what puts the finding behind the product's
/// "Design Review" badge.
pub fn uca_body(f: &StpaFinding) -> String {
    let mut fields: Vec<(String, G)> = vec![
        ("canonical_form".into(), G::Str(f.canonical_form.clone())),
        (
            "causal_factors".into(),
            match &f.causal_factors {
                Some(v) => G::Arr(v.iter().map(|s| G::Str(s.clone())).collect()),
                None => G::Null,
            },
        ),
        ("confidence".into(), G::Float(f.confidence)),
        ("content".into(), G::Str(f.content.clone())),
    ];
    if !f.control_code.is_empty() {
        fields.push(("control_code".into(), G::Str(f.control_code.clone())));
    }
    fields.push(("loss_scenario".into(), G::Str(f.loss_scenario.clone())));
    fields.push(("source".into(), G::Str("design_review".into())));
    fields.push(("uca_type".into(), G::Str(f.uca_type.clone())));
    // Sorted-key order: control_code sorts between confidence/content and
    // loss_scenario, which is exactly where it was pushed.
    compact(&G::Obj(fields))
}

/// `POST /api/v1/loss-scenarios` body (sorted keys; `parent_id` only when
/// the parent title resolved to an already-created scenario).
pub fn loss_scenario_body(sc: &StpaLossScenario, parent_id: Option<&str>) -> String {
    let mut fields: Vec<(String, G)> = vec![
        ("description".into(), G::Str(sc.description.clone())),
        ("level".into(), G::Str(sc.level.clone())),
    ];
    if let Some(pid) = parent_id {
        fields.push(("parent_id".into(), G::Str(pid.to_string())));
    }
    fields.push(("title".into(), G::Str(sc.title.clone())));
    compact(&G::Obj(fields))
}

/// `POST /api/v1/control-structure/model` body. The outer object is a Go
/// `map[string]any` (sorted: edges, nodes, repo_url); the node/edge elements
/// are Go structs, so their fields keep declaration order and `description`
/// is `omitempty`.
pub fn control_structure_body(repo_url: &str, cs: &StpaControlStructure) -> String {
    let nodes: Vec<G> = cs
        .nodes
        .iter()
        .map(|n| {
            let mut fields: Vec<(String, G)> = vec![
                ("node_key".into(), G::Str(n.node_key.clone())),
                ("name".into(), G::Str(n.name.clone())),
            ];
            if !n.description.is_empty() {
                fields.push(("description".into(), G::Str(n.description.clone())));
            }
            fields.push(("hierarchy_level".into(), G::Str(n.hierarchy_level.clone())));
            fields.push(("source".into(), G::Str(n.source.clone())));
            fields.push(("confidence".into(), G::Int(n.confidence)));
            G::Obj(fields)
        })
        .collect();
    let edges: Vec<G> = cs
        .edges
        .iter()
        .map(|e| {
            G::Obj(vec![
                ("from_key".into(), G::Str(e.from_key.clone())),
                ("to_key".into(), G::Str(e.to_key.clone())),
                ("label".into(), G::Str(e.label.clone())),
                ("edge_type".into(), G::Str(e.edge_type.clone())),
                ("source".into(), G::Str(e.source.clone())),
                ("confidence".into(), G::Int(e.confidence)),
            ])
        })
        .collect();
    compact(&G::Obj(vec![
        ("edges".into(), G::Arr(edges)),
        ("nodes".into(), G::Arr(nodes)),
        ("repo_url".into(), G::Str(repo_url.to_string())),
    ]))
}

/// Go's `levelOrder` map: an unknown (or missing) level sorts as 0, the way
/// a missing Go map key yields the zero value.
fn level_order(level: &str) -> u8 {
    match level {
        "top_level" => 0,
        "intermediate" => 1,
        "immediate" => 2,
        _ => 0,
    }
}

/// Reproduces Go's hand-rolled selection-style sort verbatim (including its
/// instability) so scenario creation order — and therefore parent
/// resolution — matches rvl-cli exactly.
pub fn sort_scenarios(scenarios: &mut [usize], level_of: impl Fn(usize) -> u8) {
    if scenarios.is_empty() {
        return;
    }
    for i in 0..scenarios.len() - 1 {
        for j in i + 1..scenarios.len() {
            if level_of(scenarios[i]) > level_of(scenarios[j]) {
                scenarios.swap(i, j);
            }
        }
    }
}

/// Go's `content[:47] + "..."` for strings longer than 50 bytes, floored to
/// a char boundary so multi-byte content cannot panic.
fn truncate(s: &str, max: usize, keep: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = keep.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Go's `%q`.
fn goq(s: &str) -> String {
    format!("{s:?}")
}

// ------------------------------------------------------------ dispatch --

pub fn run(cmd: StpaCmd) -> ExitCode {
    match cmd {
        StpaCmd::Submit { file, service } => match submit(file.as_deref(), service.as_deref()) {
            Ok(code) => code,
            Err(f) => {
                eprintln!("{}", f.msg);
                ExitCode::from(f.code)
            }
        },
    }
}

fn submit(file: Option<&str>, service: Option<&str>) -> Result<ExitCode, Failure> {
    let Some(file_path) = file.filter(|p| !p.is_empty()) else {
        return Err(Failure::usage(format!(
            "Error: --file is required\nUsage: {BIN} stpa submit --file=<path>"
        )));
    };
    // `--service` carries the repo URL used to scope the control structure.
    let repo_url = service.unwrap_or("");

    let data = std::fs::read(file_path)
        .map_err(|e| Failure::runtime(format!("Error reading file: {e}")))?;
    let findings: StpaFindings = serde_json::from_slice(&data)
        .map_err(|e| Failure::runtime(format!("Error parsing JSON: {e}")))?;

    let (_cfg, client) = client::load_and_resolve()?;

    let stats = submit_all(&client, &findings, repo_url);

    println!();
    println!(
        "Submitted: {} loss definitions ({} new), {} UCAs ({} new), {} loss scenarios",
        stats.loss_defs_total,
        stats.loss_defs_new,
        stats.ucas_total,
        stats.ucas_new,
        stats.scenarios_created
    );
    if stats.cs_nodes > 0 || stats.cs_edges > 0 {
        println!(
            "Control structure: {} nodes, {} edges upserted",
            stats.cs_nodes, stats.cs_edges
        );
    }
    if stats.uca_links > 0 || stats.control_links > 0 {
        println!(
            "Linked: {} UCA associations, {} control associations",
            stats.uca_links, stats.control_links
        );
    }
    if stats.errors > 0 {
        eprintln!("Warnings: {} items failed (see above)", stats.errors);
    }
    Ok(ExitCode::SUCCESS)
}

/// The four submission phases in Go's order, sharing one stats counter.
/// Split out from [`submit`] so the hermetic HTTP suite can drive the exact
/// call sequence without touching config or the process's exit code.
pub fn submit_all(client: &Client, findings: &StpaFindings, repo_url: &str) -> SubmitStats {
    let mut stats = SubmitStats::default();

    // 1. Loss definitions (dedup by title).
    if !findings.losses.is_empty() {
        submit_loss_definitions(client, &findings.losses, &mut stats);
    }

    // 2. UCAs; the created ids are keyed by findings index so loss scenarios
    //    can reference them by `uca_refs`.
    let mut uca_ids: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    if !findings.findings.is_empty() {
        submit_ucas(client, &findings.findings, &mut uca_ids, &mut stats);
    }

    // 3. Loss scenarios, top-down by level so parents exist before children.
    if !findings.loss_scenarios.is_empty() {
        submit_loss_scenarios(client, &findings.loss_scenarios, &uca_ids, &mut stats);
    }

    // 4. Control structure (nodes + edges).
    if let Some(cs) = &findings.control_structure {
        if !cs.nodes.is_empty() || !cs.edges.is_empty() {
            if repo_url.is_empty() {
                eprintln!("  [skip] control_structure present but --service not set; skipping");
            } else {
                submit_control_structure(client, repo_url, cs, &mut stats);
            }
        }
    }
    stats
}

fn submit_loss_definitions(client: &Client, losses: &[StpaLoss], stats: &mut SubmitStats) {
    println!("Submitting loss definitions...");

    // Best-effort dedup: a failed list is not fatal, it just means nothing
    // is considered pre-existing (same as Go, which ignores the error).
    let mut existing: std::collections::HashSet<String> = std::collections::HashSet::new();
    let url = format!("{}/api/v1/loss-definitions", client.api_url);
    if let Ok(body) = client.request("GET", &url, None) {
        #[derive(Deserialize)]
        struct ListResp {
            #[serde(default)]
            loss_definitions: Vec<TitleOnly>,
        }
        #[derive(Deserialize)]
        struct TitleOnly {
            #[serde(default)]
            title: String,
        }
        if let Ok(list) = serde_json::from_slice::<ListResp>(&body) {
            for ld in list.loss_definitions {
                existing.insert(ld.title.to_lowercase());
            }
        }
    }

    for loss in losses {
        stats.loss_defs_total += 1;
        if existing.contains(&loss.title.to_lowercase()) {
            println!("  [skip] {} (already exists)", loss.title);
            continue;
        }
        let body = loss_definition_body(loss);
        if let Err(e) = client.request("POST", &url, Some(body.as_bytes())) {
            eprintln!("  [error] {}: {e}", loss.title);
            stats.errors += 1;
            continue;
        }
        println!("  [created] {}", loss.title);
        stats.loss_defs_new += 1;
    }
}

fn submit_ucas(
    client: &Client,
    findings: &[StpaFinding],
    uca_ids: &mut std::collections::HashMap<usize, String>,
    stats: &mut SubmitStats,
) {
    println!("Submitting UCAs...");
    let url = format!("{}/api/v1/ucas", client.api_url);

    for (i, f) in findings.iter().enumerate() {
        stats.ucas_total += 1;
        let body = uca_body(f);
        let resp = match client.request("POST", &url, Some(body.as_bytes())) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [error] UCA {i}: {e}");
                stats.errors += 1;
                continue;
            }
        };

        #[derive(Deserialize)]
        struct UcaResp {
            #[serde(default)]
            uca: UcaId,
            #[serde(default)]
            is_new: bool,
        }
        #[derive(Default, Deserialize)]
        struct UcaId {
            #[serde(default)]
            id: String,
        }
        let parsed: UcaResp = match serde_json::from_slice(&resp) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  [error] UCA {i} parse: {e}");
                stats.errors += 1;
                continue;
            }
        };

        uca_ids.insert(i, parsed.uca.id);

        let content = truncate(&f.content, 50, 47);
        if parsed.is_new {
            println!("  [created] {content}");
            stats.ucas_new += 1;
        } else {
            println!("  [exists]  {content} (detection count bumped)");
        }
    }
}

fn submit_loss_scenarios(
    client: &Client,
    scenarios: &[StpaLossScenario],
    uca_ids: &std::collections::HashMap<usize, String>,
    stats: &mut SubmitStats,
) {
    println!("Submitting loss scenarios...");

    let mut order: Vec<usize> = (0..scenarios.len()).collect();
    sort_scenarios(&mut order, |i| level_order(&scenarios[i].level));

    // title -> created id, for resolving `parent_title`.
    let mut title_to_id: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let url = format!("{}/api/v1/loss-scenarios", client.api_url);

    for idx in order {
        let sc = &scenarios[idx];

        let mut parent_id: Option<String> = None;
        if !sc.parent_title.is_empty() {
            match title_to_id.get(&sc.parent_title) {
                Some(pid) => parent_id = Some(pid.clone()),
                None => eprintln!(
                    "  [warn] parent {} not found for {}, creating without parent",
                    goq(&sc.parent_title),
                    goq(&sc.title)
                ),
            }
        }

        let body = loss_scenario_body(sc, parent_id.as_deref());
        let resp = match client.request("POST", &url, Some(body.as_bytes())) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [error] {}: {e}", sc.title);
                stats.errors += 1;
                continue;
            }
        };

        #[derive(Deserialize)]
        struct LsResp {
            #[serde(default)]
            id: String,
        }
        let ls: LsResp = match serde_json::from_slice(&resp) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("  [error] {} parse: {e}", sc.title);
                stats.errors += 1;
                continue;
            }
        };

        title_to_id.insert(sc.title.clone(), ls.id.clone());
        stats.scenarios_created += 1;
        println!("  [created] [{}] {}", sc.level, sc.title);

        // Link UCAs created in step 2.
        for &r in &sc.uca_refs {
            let key = usize::try_from(r).ok().filter(|k| uca_ids.contains_key(k));
            let Some(key) = key else {
                eprintln!("    [warn] UCA ref {r} not found, skipping link");
                continue;
            };
            let link_body = compact(&G::Obj(vec![(
                "uca_id".into(),
                G::Str(uca_ids[&key].clone()),
            )]));
            let link_url = format!(
                "{}/api/v1/loss-scenarios/{}/ucas",
                client.api_url,
                path_escape(&ls.id)
            );
            if let Err(e) = client.request("POST", &link_url, Some(link_body.as_bytes())) {
                eprintln!("    [warn] link UCA {r}: {e}");
                continue;
            }
            stats.uca_links += 1;
        }

        // Link controls by RC-XXX code.
        for cl in &sc.control_links {
            let control_id = match control::find_control_id_by_code(client, &cl.control_code) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("    [warn] resolve {}: {e}", cl.control_code);
                    continue;
                }
            };
            let link_body = compact(&G::Obj(vec![
                ("control_id".into(), G::Str(control_id)),
                ("relationship".into(), G::Str(cl.relationship.clone())),
            ]));
            let link_url = format!(
                "{}/api/v1/loss-scenarios/{}/controls",
                client.api_url,
                path_escape(&ls.id)
            );
            if let Err(e) = client.request("POST", &link_url, Some(link_body.as_bytes())) {
                eprintln!("    [warn] link control {}: {e}", cl.control_code);
                continue;
            }
            stats.control_links += 1;
        }
    }
}

fn submit_control_structure(
    client: &Client,
    repo_url: &str,
    cs: &StpaControlStructure,
    stats: &mut SubmitStats,
) {
    println!("Submitting control structure...");
    let body = control_structure_body(repo_url, cs);
    let url = format!("{}/api/v1/control-structure/model", client.api_url);
    let resp = match client.request("POST", &url, Some(body.as_bytes())) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [error] {e}");
            stats.errors += 1;
            return;
        }
    };
    #[derive(Deserialize)]
    struct CsResp {
        #[serde(default)]
        nodes_upserted: i64,
        #[serde(default)]
        edges_upserted: i64,
    }
    let result: CsResp = match serde_json::from_slice(&resp) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  [error] parse response: {e}");
            stats.errors += 1;
            return;
        }
    };
    stats.cs_nodes = result.nodes_upserted;
    stats.cs_edges = result.edges_upserted;
    println!(
        "  [upserted] {} nodes, {} edges for {repo_url}",
        result.nodes_upserted, result.edges_upserted
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_a_usage_error() {
        let err = submit(None, None).unwrap_err();
        assert_eq!(err.code, 2);
        assert!(err.msg.contains("--file is required"), "{}", err.msg);
        assert!(err.msg.contains("stpa submit --file=<path>"), "{}", err.msg);
    }

    #[test]
    fn unreadable_file_is_a_runtime_error() {
        let err = submit(Some("/nonexistent/stpa-findings.json"), None).unwrap_err();
        assert_eq!(err.code, 1);
        assert!(err.msg.starts_with("Error reading file:"), "{}", err.msg);
    }

    #[test]
    fn bad_json_is_a_runtime_error() {
        let dir = std::env::temp_dir().join(format!("rvl-stpa-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.json");
        std::fs::write(&p, b"{not json").unwrap();
        let err = submit(Some(p.to_str().unwrap()), None).unwrap_err();
        assert_eq!(err.code, 1);
        assert!(err.msg.starts_with("Error parsing JSON:"), "{}", err.msg);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loss_definition_body_has_sorted_keys() {
        let loss = StpaLoss {
            title: "Customer data loss".into(),
            description: "Irrecoverable".into(),
            category: "zero_tolerance".into(),
        };
        assert_eq!(
            loss_definition_body(&loss),
            r#"{"category":"zero_tolerance","description":"Irrecoverable","title":"Customer data loss"}"#
        );
    }

    #[test]
    fn uca_body_matches_go_map_marshal() {
        let f = StpaFinding {
            content: "Retry is not provided on 503".into(),
            uca_type: "not_provided".into(),
            causal_factors: Some(vec!["inadequate_feedback".into()]),
            loss_scenario: "trigger -> condition -> loss".into(),
            canonical_form: "retry not provided".into(),
            confidence: 0.8,
            control_code: "RC-018".into(),
        };
        // `>` arrives HTML-escaped because Go's `json.Marshal` escapes it.
        assert_eq!(
            uca_body(&f),
            r#"{"canonical_form":"retry not provided","causal_factors":["inadequate_feedback"],"confidence":0.8,"content":"Retry is not provided on 503","control_code":"RC-018","loss_scenario":"trigger -\u003e condition -\u003e loss","source":"design_review","uca_type":"not_provided"}"#
        );
    }

    #[test]
    fn uca_body_omits_empty_control_code_and_nulls_absent_factors() {
        let f = StpaFinding {
            content: "c".into(),
            uca_type: "wrong_timing".into(),
            causal_factors: None,
            confidence: 1.0,
            ..Default::default()
        };
        let body = uca_body(&f);
        assert!(!body.contains("control_code"), "{body}");
        assert!(body.contains(r#""causal_factors":null"#), "{body}");
        // Go prints an integral float64 without a fractional part.
        assert!(body.contains(r#""confidence":1"#), "{body}");
    }

    #[test]
    fn loss_scenario_body_includes_parent_only_when_resolved() {
        let sc = StpaLossScenario {
            title: "Checkout fails".into(),
            description: "d".into(),
            level: "immediate".into(),
            parent_title: "Revenue loss".into(),
            ..Default::default()
        };
        assert_eq!(
            loss_scenario_body(&sc, None),
            r#"{"description":"d","level":"immediate","title":"Checkout fails"}"#
        );
        assert_eq!(
            loss_scenario_body(&sc, Some("abc-123")),
            r#"{"description":"d","level":"immediate","parent_id":"abc-123","title":"Checkout fails"}"#
        );
    }

    #[test]
    fn control_structure_body_keeps_struct_field_order_and_omitempty() {
        let cs = StpaControlStructure {
            nodes: vec![
                StpaCsNode {
                    node_key: "api".into(),
                    name: "API".into(),
                    hierarchy_level: "controller".into(),
                    source: "design_review".into(),
                    confidence: 80,
                    description: "edge service".into(),
                },
                StpaCsNode {
                    node_key: "db".into(),
                    name: "DB".into(),
                    hierarchy_level: "controlled_process".into(),
                    source: "design_review".into(),
                    confidence: 90,
                    description: String::new(),
                },
            ],
            edges: vec![StpaCsEdge {
                from_key: "api".into(),
                to_key: "db".into(),
                label: "writes".into(),
                edge_type: "control_action".into(),
                source: "design_review".into(),
                confidence: 70,
            }],
        };
        assert_eq!(
            control_structure_body("github.com/acme/shop", &cs),
            r#"{"edges":[{"from_key":"api","to_key":"db","label":"writes","edge_type":"control_action","source":"design_review","confidence":70}],"nodes":[{"node_key":"api","name":"API","description":"edge service","hierarchy_level":"controller","source":"design_review","confidence":80},{"node_key":"db","name":"DB","hierarchy_level":"controlled_process","source":"design_review","confidence":90}],"repo_url":"github.com/acme/shop"}"#
        );
    }

    #[test]
    fn scenarios_sort_top_down_by_level() {
        let levels = ["immediate", "top_level", "intermediate", "immediate"];
        let mut order: Vec<usize> = (0..levels.len()).collect();
        sort_scenarios(&mut order, |i| level_order(levels[i]));
        let sorted: Vec<&str> = order.iter().map(|&i| levels[i]).collect();
        assert_eq!(
            sorted,
            vec!["top_level", "intermediate", "immediate", "immediate"]
        );
    }

    #[test]
    fn unknown_level_sorts_first_like_gos_zero_value() {
        let levels = ["immediate", "bogus"];
        let mut order: Vec<usize> = (0..levels.len()).collect();
        sort_scenarios(&mut order, |i| level_order(levels[i]));
        assert_eq!(order, vec![1, 0]);
    }

    #[test]
    fn content_truncates_at_50_bytes() {
        let short = "a".repeat(50);
        assert_eq!(truncate(&short, 50, 47), short);
        let long = "a".repeat(51);
        assert_eq!(truncate(&long, 50, 47), format!("{}...", "a".repeat(47)));
        // Multi-byte content must not panic on the boundary.
        let wide = "é".repeat(40); // 80 bytes
        let t = truncate(&wide, 50, 47);
        assert!(t.ends_with("..."));
        assert_eq!(t.chars().count(), 23 + 3);
    }
}
