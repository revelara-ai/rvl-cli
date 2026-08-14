//! `scan` submission mode, ported from rvl-cli `internal/commands/scan.go`
//! (the `--stdin` / `--file` / `--scan-dir` submit surface). rvl-cli is the
//! contract: same flags, same merge semantics, same wire body (byte-identical
//! for identical input, via the gojson Go-marshal emitters), same
//! deterministic idempotency key, same retry/error messages.
//!
//! Out of scope here (deliberately): the interactive `--review` prompt, the
//! `--dry-run` / `--cs-file` flags, and the agent-scan surface — none of
//! which the plugin skill content invokes.

use crate::client::Client;
use crate::gojson::{compact, compact_raw, pretty, G};
use crate::scan_cached_output::{note_cached_scan, print_scan_findings, scan_submit_headline};
use crate::scan_normalize::{
    normalization_summary, normalize_findings, print_normalization_issues, print_stpa_loss_banner,
    FindingNormReport,
};
use crate::scan_team::{apply_team_assignments, slugify_team_preview, warn_unknown_teams};
use crate::{Failure, BIN};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

// --- wire types (request) ---

/// Mirrors rvl-cli's `ScanRequest`. Deserialization accepts the same part
/// shapes; emission goes through [`request_body`] so the bytes match Go's
/// struct marshal (field order, omitempty, HTML escaping).
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ScanRequest {
    pub service: String,
    pub scan_type: String,
    pub scan_mode: String,
    /// `None` mirrors Go's nil `[]interface{}` (marshals as `null`).
    pub findings: Option<Vec<Value>>,
    pub metadata: ScanMetadata,
    pub repo_url: String,
    pub control_structure: Option<ControlStructureData>,
    pub stack: Option<StackInfo>,
    pub components: Vec<Component>,
    pub dependencies: Vec<Dependency>,
    pub catalog_meta: Option<CatalogMeta>,
    pub business_criticality: Option<f64>,
    pub service_tolerance: Option<ServiceToleranceConfig>,
    pub idempotency_key: String,

    /// In-repo team ownership (po-77b6w.1, org-ownership spec Decision 1).
    /// Wire contract shared with the server's `ScanRequest`: `team` is the
    /// repo-level owning team from `.revelara.yaml` `team:` or the `--team`
    /// override; `team_source` is `"override"` when `--team` was used (the
    /// server defaults to `"scan"` when omitted); `component_teams` maps
    /// component name -> team for per-component `team:` declarations. The
    /// server slugifies and creates teams on first sight; bindings are
    /// latest-submission-wins. A `BTreeMap` reproduces Go's sorted map-key
    /// marshal order.
    pub team: String,
    pub team_source: String,
    pub component_teams: BTreeMap<String, String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ScanMetadata {
    pub git_commit: String,
    pub git_branch: String,
    pub scanner_id: String,
    pub skill_name: String,
    pub skill_version: String,
    pub skill_checksum: String,
    pub matcher_version: String,
    pub excluded_matchers: Vec<String>,
    pub applied_waivers: Vec<AppliedWaiver>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct AppliedWaiver {
    pub matcher: String,
    pub paths: Vec<String>,
    pub expires: String,
    pub reason: String,
}

/// The control-structure part. `nodes`/`edges` are kept as raw JSON text
/// (Go `json.RawMessage`): key order and number literals survive to the
/// wire unless normalization had to rewrite them.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ControlStructureData {
    #[serde(deserialize_with = "raw_json", default)]
    pub nodes: Option<String>,
    #[serde(deserialize_with = "raw_json", default)]
    pub edges: Option<String>,
    pub scanned_files: i64,
    pub scanned_lines: i64,
}

fn raw_json<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw: Option<Box<RawValue>> = Option::deserialize(d)?;
    Ok(raw.map(|r| r.get().to_string()))
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct StackInfo {
    pub languages: Vec<String>,
    pub frameworks: Vec<String>,
    pub databases: Vec<String>,
    pub infrastructure: Vec<String>,
    pub cloud_provider: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Component {
    pub name: String,
    pub path: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub description: String,
    pub technologies: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Dependency {
    pub target: String,
    #[serde(rename = "type")]
    pub dependency_type: String,
    pub criticality: String,
    pub description: String,
    pub source: String,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct CatalogMeta {
    pub display_name: String,
    pub description: String,
    pub tier: String,
    pub team_name: String,
    pub team_contact: String,
}

/// Mirrors the server-side ServiceToleranceConfig exactly. Options
/// distinguish "unset" from "zero value" so the resolver can fall through
/// to org defaults.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct ServiceToleranceConfig {
    pub tolerance_target: Option<i64>,
    pub tolerance_headroom_pct: Option<i64>,
    pub strict_enforcement: Option<bool>,
}

// --- wire types (response) ---

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScanResponse {
    pub scan_id: String,
    pub service: String,
    pub summary: ScanSummary,
    pub findings: Option<Vec<ScanResult>>,
    pub control_structure: Option<ControlStructureResult>,
    pub warnings: Vec<String>,
    pub timestamp: String,
    pub effective_tolerance: Option<EffectiveTolerance>,

    /// True when the server replayed a previously-processed response because
    /// this submission's `idempotency_key` matched a recent scan. Nothing in
    /// `findings` was created or updated by this run, so the output must not
    /// re-announce those risks as `[NEW]`. Servers that predate the field omit
    /// it; `false` is the pre-existing behavior (po-72d5d).
    pub cached: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScanSummary {
    pub total: i64,
    pub created: i64,
    pub updated: i64,
    pub unchanged: i64,
    pub resolved_this_scan: i64,
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScanResult {
    pub risk_id: String,
    pub risk_code: String,
    pub title: String,
    pub status: String,
    pub score: i64,
    pub priority: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ControlStructureResult {
    pub snapshot_id: String,
    pub node_count: i64,
    pub edge_count: i64,
    pub scanned_files: i64,
    pub scanned_lines: i64,
    pub uca_coverage: Option<UcaCoverage>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UcaCoverage {
    pub discovered: i64,
    pub analyzed: i64,
    pub cap: i64,
    pub ucas_generated: i64,
    pub ucas_stored: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct EffectiveTolerance {
    pub tolerance_target: i64,
    pub tolerance_headroom_pct: i64,
    pub strict_enforcement: bool,
    pub calibrating: bool,
}

// --- typed finding (dedup round-trip; rvl-cli internal/scanner/wire.go) ---

/// The typed finding the `--scan-dir` dedup pass round-trips through.
/// Carries the STPA and graph-evidence fields so the round-trip cannot
/// strip them from the request (po-gli2z).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanFinding {
    pub title: String,
    pub category: String,
    pub likelihood: String,
    pub impact: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub narrative: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub component: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub linked_services: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub control_codes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ScanEvidence>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ScanProvenance>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub slug: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub confidence: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub risk_score: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub corroborated_by_agents: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub priority: String,
    // STPA fields (po-gli2z): before they existed on the wire type, any
    // dedup round-trip silently stripped them from the whole request.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub uca_type: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub causal_factors: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub loss_scenario: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub loss_category: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub estimated_fix_complexity: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub constraint_type: String,
    // Graph evidence fields: opaque to the CLI, preserved so the dedup
    // round-trip cannot lose them either.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact_chains: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigations: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foresight_depth: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_adjacent_knowledge: Option<Value>,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanEvidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub path: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub line_number: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanProvenance {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub incident_frequency: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub typical_blast_radius: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub typical_mttr: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_pattern_ids: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub org_incident_count: i64,
}

/// Collapse findings that share a (slug|title, path, line) key, keeping
/// the highest risk_score (first-seen wins ties by lexical order) and
/// merging corroboration. Port of rvl-cli scanner.DeduplicateFindings.
pub fn deduplicate_findings(findings: Vec<ScanFinding>) -> Vec<ScanFinding> {
    if findings.is_empty() {
        return findings;
    }

    fn evidence_path(f: &ScanFinding) -> &str {
        f.evidence.first().map(|e| e.path.as_str()).unwrap_or("")
    }
    // Keys slug-less (LLM) findings by title so they do not all collapse
    // into the empty-slug bucket.
    fn slug_or_title(f: &ScanFinding) -> &str {
        if f.slug.is_empty() {
            &f.title
        } else {
            &f.slug
        }
    }
    fn key_for(f: &ScanFinding) -> (String, String, i64) {
        match f.evidence.first() {
            Some(e) if !e.path.is_empty() => {
                (slug_or_title(f).to_string(), e.path.clone(), e.line_number)
            }
            _ => (slug_or_title(f).to_string(), String::new(), 0),
        }
    }
    fn merge_strings(a: &[String], b: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in a.iter().chain(b.iter()) {
            if !s.is_empty() && !out.contains(s) {
                out.push(s.clone());
            }
        }
        out
    }
    fn append_unique(mut v: Vec<String>, s: &str) -> Vec<String> {
        let s = s.trim();
        if !s.is_empty() && !v.iter().any(|x| x == s) {
            v.push(s.to_string());
        }
        v
    }

    let mut winners: std::collections::HashMap<(String, String, i64), usize> =
        std::collections::HashMap::with_capacity(findings.len());
    let mut result: Vec<ScanFinding> = Vec::with_capacity(findings.len());

    for f in findings {
        let k = key_for(&f);
        let Some(&idx) = winners.get(&k) else {
            winners.insert(k, result.len());
            result.push(f);
            continue;
        };

        let winner = &result[idx];
        let mut replace = f.risk_score > winner.risk_score;
        if !replace && f.risk_score == winner.risk_score {
            let win_key = format!("{}{}", slug_or_title(winner), evidence_path(winner));
            let new_key = format!("{}{}", slug_or_title(&f), evidence_path(&f));
            replace = new_key < win_key;
        }

        if replace {
            let loser_component = winner.component.clone();
            let mut corroboration =
                merge_strings(&f.corroborated_by_agents, &winner.corroborated_by_agents);
            if !loser_component.is_empty() && loser_component != f.component {
                corroboration = append_unique(corroboration, &loser_component);
            }
            let mut new_winner = f;
            new_winner.corroborated_by_agents = corroboration;
            result[idx] = new_winner;
        } else {
            let loser_component = f.component.clone();
            let mut corroboration = merge_strings(
                &result[idx].corroborated_by_agents,
                &f.corroborated_by_agents,
            );
            if !loser_component.is_empty() && loser_component != result[idx].component {
                corroboration = append_unique(corroboration, &loser_component);
            }
            result[idx].corroborated_by_agents = corroboration;
        }
    }
    result
}

// --- request emission (Go struct-marshal parity) ---

fn push_str_opt(f: &mut Vec<(String, G)>, key: &str, v: &str) {
    if !v.is_empty() {
        f.push((key.to_string(), G::Str(v.to_string())));
    }
}

fn push_str_arr_opt(f: &mut Vec<(String, G)>, key: &str, v: &[String]) {
    if !v.is_empty() {
        f.push((
            key.to_string(),
            G::Arr(v.iter().map(|s| G::Str(s.clone())).collect()),
        ));
    }
}

fn raw_g(o: &Option<String>) -> G {
    match o {
        None => G::Null,
        Some(s) => G::Raw(compact_raw(s)),
    }
}

fn metadata_g(m: &ScanMetadata) -> G {
    let mut f = Vec::new();
    push_str_opt(&mut f, "git_commit", &m.git_commit);
    push_str_opt(&mut f, "git_branch", &m.git_branch);
    push_str_opt(&mut f, "scanner_id", &m.scanner_id);
    push_str_opt(&mut f, "skill_name", &m.skill_name);
    push_str_opt(&mut f, "skill_version", &m.skill_version);
    push_str_opt(&mut f, "skill_checksum", &m.skill_checksum);
    push_str_opt(&mut f, "matcher_version", &m.matcher_version);
    push_str_arr_opt(&mut f, "excluded_matchers", &m.excluded_matchers);
    if !m.applied_waivers.is_empty() {
        let waivers = m
            .applied_waivers
            .iter()
            .map(|w| {
                let mut wf = vec![("matcher".to_string(), G::Str(w.matcher.clone()))];
                push_str_arr_opt(&mut wf, "paths", &w.paths);
                push_str_opt(&mut wf, "expires", &w.expires);
                wf.push(("reason".to_string(), G::Str(w.reason.clone())));
                G::Obj(wf)
            })
            .collect();
        f.push(("applied_waivers".to_string(), G::Arr(waivers)));
    }
    G::Obj(f)
}

fn request_g(req: &ScanRequest, include_key: bool) -> G {
    let mut f: Vec<(String, G)> = vec![
        ("service".to_string(), G::Str(req.service.clone())),
        ("scan_type".to_string(), G::Str(req.scan_type.clone())),
    ];
    push_str_opt(&mut f, "scan_mode", &req.scan_mode);
    f.push((
        "findings".to_string(),
        match &req.findings {
            None => G::Null,
            Some(v) => G::Dyn(Value::Array(v.clone())),
        },
    ));
    f.push(("metadata".to_string(), metadata_g(&req.metadata)));
    push_str_opt(&mut f, "repo_url", &req.repo_url);
    if let Some(cs) = &req.control_structure {
        f.push((
            "control_structure".to_string(),
            G::Obj(vec![
                ("nodes".to_string(), raw_g(&cs.nodes)),
                ("edges".to_string(), raw_g(&cs.edges)),
                ("scanned_files".to_string(), G::Int(cs.scanned_files)),
                ("scanned_lines".to_string(), G::Int(cs.scanned_lines)),
            ]),
        ));
    }
    if let Some(stack) = &req.stack {
        let mut sf = Vec::new();
        push_str_arr_opt(&mut sf, "languages", &stack.languages);
        push_str_arr_opt(&mut sf, "frameworks", &stack.frameworks);
        push_str_arr_opt(&mut sf, "databases", &stack.databases);
        push_str_arr_opt(&mut sf, "infrastructure", &stack.infrastructure);
        push_str_opt(&mut sf, "cloud_provider", &stack.cloud_provider);
        f.push(("stack".to_string(), G::Obj(sf)));
    }
    if !req.components.is_empty() {
        let comps = req
            .components
            .iter()
            .map(|c| {
                let mut cf = vec![("name".to_string(), G::Str(c.name.clone()))];
                push_str_opt(&mut cf, "path", &c.path);
                push_str_opt(&mut cf, "type", &c.component_type);
                push_str_opt(&mut cf, "description", &c.description);
                push_str_arr_opt(&mut cf, "technologies", &c.technologies);
                G::Obj(cf)
            })
            .collect();
        f.push(("components".to_string(), G::Arr(comps)));
    }
    if !req.dependencies.is_empty() {
        let deps = req
            .dependencies
            .iter()
            .map(|d| {
                let mut df = vec![("target".to_string(), G::Str(d.target.clone()))];
                push_str_opt(&mut df, "type", &d.dependency_type);
                push_str_opt(&mut df, "criticality", &d.criticality);
                push_str_opt(&mut df, "description", &d.description);
                push_str_opt(&mut df, "source", &d.source);
                G::Obj(df)
            })
            .collect();
        f.push(("dependencies".to_string(), G::Arr(deps)));
    }
    if let Some(cm) = &req.catalog_meta {
        let mut mf = Vec::new();
        push_str_opt(&mut mf, "display_name", &cm.display_name);
        push_str_opt(&mut mf, "description", &cm.description);
        push_str_opt(&mut mf, "tier", &cm.tier);
        push_str_opt(&mut mf, "team_name", &cm.team_name);
        push_str_opt(&mut mf, "team_contact", &cm.team_contact);
        f.push(("catalog_meta".to_string(), G::Obj(mf)));
    }
    if let Some(bc) = req.business_criticality {
        f.push(("business_criticality".to_string(), G::Float(bc)));
    }
    if let Some(st) = &req.service_tolerance {
        let mut tf = Vec::new();
        if let Some(v) = st.tolerance_target {
            tf.push(("tolerance_target".to_string(), G::Int(v)));
        }
        if let Some(v) = st.tolerance_headroom_pct {
            tf.push(("tolerance_headroom_pct".to_string(), G::Int(v)));
        }
        if let Some(v) = st.strict_enforcement {
            tf.push(("strict_enforcement".to_string(), G::Bool(v)));
        }
        f.push(("service_tolerance".to_string(), G::Obj(tf)));
    }
    if include_key && !req.idempotency_key.is_empty() {
        f.push((
            "idempotency_key".to_string(),
            G::Str(req.idempotency_key.clone()),
        ));
    }
    // po-77b6w.1 team ownership: struct order puts these last, and all three
    // stay off the wire when empty so older servers see no change.
    push_str_opt(&mut f, "team", &req.team);
    push_str_opt(&mut f, "team_source", &req.team_source);
    if !req.component_teams.is_empty() {
        f.push((
            "component_teams".to_string(),
            G::Obj(
                req.component_teams
                    .iter()
                    .map(|(k, v)| (k.clone(), G::Str(v.clone())))
                    .collect(),
            ),
        ));
    }
    G::Obj(f)
}

/// The POST body, byte-identical to Go's `json.Marshal(scanReq)`.
pub fn request_body(req: &ScanRequest, include_key: bool) -> String {
    compact(&request_g(req, include_key))
}

/// A stable 32-hex-char key derived from the request body with the
/// idempotency key cleared. Two invocations against the same service with
/// the same findings/metadata produce the same key, so the server-side
/// cache recognizes the second submission as a retry.
pub fn derive_idempotency_key(req: &ScanRequest) -> String {
    let canonical = request_body(req, false);
    let sum = Sha256::digest(canonical.as_bytes());
    hex::encode(&sum[..16])
}

// --- scan-dir merge (rvl-cli mergeScanDir) ---

/// Read all `*.json` files from `dir` (alphabetical order; use numeric
/// prefixes like 01-stack.json to control it) and merge them into one
/// request. Array fields (findings, components, dependencies) concatenate;
/// scalar/object fields use the last non-zero value, with a stderr warning
/// when a later file overrides an earlier one.
pub fn merge_scan_dir(dir: &Path, req: &mut ScanRequest) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("glob scan-dir: {e}"))?;
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".json"))
        })
        .collect();
    if files.is_empty() {
        return Err(format!("no JSON files found in {}", dir.display()));
    }
    files.sort();

    for f in &files {
        let base = f
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let data = match std::fs::read(f) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: skipping {base}: {e}");
                continue;
            }
        };
        let partial: ScanRequest = match serde_json::from_slice(&data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Warning: skipping {base}: invalid JSON: {e}");
                continue;
            }
        };

        // Warn on overlapping scalars/objects so the user knows later
        // files in alphabetical order win. Silent last-write-wins makes
        // scan-parts ordering accidentally significant.
        if !partial.repo_url.is_empty() {
            if !req.repo_url.is_empty() && req.repo_url != partial.repo_url {
                eprintln!("Warning: repo_url in {base} overrides earlier value");
            }
            req.repo_url = partial.repo_url;
        }
        if partial.control_structure.is_some() {
            if req.control_structure.is_some() {
                eprintln!("Warning: control_structure in {base} overrides earlier value");
            }
            req.control_structure = partial.control_structure;
        }
        if partial.stack.is_some() {
            if req.stack.is_some() {
                eprintln!("Warning: stack in {base} overrides earlier value");
            }
            req.stack = partial.stack;
        }
        if !partial.components.is_empty() {
            req.components.extend(partial.components);
        }
        if !partial.dependencies.is_empty() {
            req.dependencies.extend(partial.dependencies);
        }
        if let Some(pf) = partial.findings {
            if !pf.is_empty() {
                req.findings.get_or_insert_with(Vec::new).extend(pf);
            }
        }
        if partial.catalog_meta.is_some() {
            req.catalog_meta = partial.catalog_meta;
        }
        if partial.business_criticality.is_some() {
            req.business_criticality = partial.business_criticality;
        }
        if !partial.scan_mode.is_empty() {
            req.scan_mode = partial.scan_mode;
        }

        eprintln!("Merged: {base} ({} bytes)", data.len());
    }

    if req.findings.as_ref().is_none_or(|f| f.is_empty()) {
        eprintln!("Warning: no findings found in scan-dir files");
    }
    Ok(())
}

// --- control-structure normalization (rvl-cli normalizeControlStructure) ---

/// Fix common field-name errors agents produce: node_key -> id,
/// from_key/from_node -> from_id, to_key/to_node -> to_id; remove edge_type
/// (set server-side); node provenance coerced to array, edge provenance
/// coerced to object.
pub fn normalize_control_structure(cs: &mut Option<ControlStructureData>) {
    let Some(cs) = cs.as_mut() else { return };

    if let Some(nodes_raw) = &cs.nodes {
        if let Ok(mut nodes) =
            serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(nodes_raw)
        {
            let mut changed = false;
            for node in &mut nodes {
                if let Some(v) = node.get("node_key").cloned() {
                    if !node.contains_key("id") {
                        node.insert("id".into(), v);
                    }
                    node.remove("node_key");
                    changed = true;
                }
                // Node provenance must be an array.
                if let Some(prov) = node.get("provenance") {
                    if prov.is_object() {
                        let prov = prov.clone();
                        node.insert("provenance".into(), Value::Array(vec![prov]));
                        changed = true;
                    }
                }
            }
            if changed {
                let arr = Value::Array(nodes.into_iter().map(Value::Object).collect());
                cs.nodes = Some(compact(&G::Dyn(arr)));
            }
        }
    }

    if let Some(edges_raw) = &cs.edges {
        if let Ok(mut edges) =
            serde_json::from_str::<Vec<serde_json::Map<String, Value>>>(edges_raw)
        {
            let mut changed = false;
            for edge in &mut edges {
                for (from, to) in [
                    ("from_key", "from_id"),
                    ("from_node", "from_id"),
                    ("to_key", "to_id"),
                    ("to_node", "to_id"),
                ] {
                    if let Some(v) = edge.get(from).cloned() {
                        if !edge.contains_key(to) {
                            edge.insert(to.into(), v);
                        }
                        edge.remove(from);
                        changed = true;
                    }
                }
                if edge.remove("edge_type").is_some() {
                    changed = true;
                }
                // Edge provenance must be an object (not array).
                if let Some(Value::Array(arr)) = edge.get("provenance") {
                    if !arr.is_empty() {
                        let first = arr[0].clone();
                        edge.insert("provenance".into(), first);
                        changed = true;
                    }
                }
            }
            if changed {
                let arr = Value::Array(edges.into_iter().map(Value::Object).collect());
                cs.edges = Some(compact(&G::Dyn(arr)));
            }
        }
    }
}

// --- timeout resolution (rvl-cli resolveScanTimeout) ---

/// The default HTTP submission timeout: 60s, matching rvl-cli.
pub const DEFAULT_SCAN_TIMEOUT: Duration = Duration::from_secs(60);

/// Parse a duration flag value: Go-style unit suffixes (`90s`, `2m`,
/// `1m30s`, `1h`) plus bare seconds (`90`) as a convenience.
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(secs) = s.parse::<u64>() {
        return (secs > 0).then(|| Duration::from_secs(secs));
    }
    let mut total = 0f64;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let value: f64 = num.parse().ok()?;
        num.clear();
        let unit = match c {
            'h' => 3600.0,
            'm' => {
                if chars.peek() == Some(&'s') {
                    chars.next();
                    0.001
                } else {
                    60.0
                }
            }
            's' => 1.0,
            _ => return None,
        };
        total += value * unit;
    }
    if !num.is_empty() {
        return None; // trailing digits without a unit
    }
    (total > 0.0).then(|| Duration::from_secs_f64(total))
}

/// Go `time.Duration` String() for whole-second values ("45s", "1m0s",
/// "2m0s"), used in the retry/warning messages.
fn go_duration_string(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h{}m{}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// Effective HTTP timeout: `--timeout` flag > `RVL_SCAN_TIMEOUT` env >
/// default. Invalid values warn and fall through rather than failing the
/// scan.
pub fn resolve_scan_timeout(flag: Option<&str>) -> Duration {
    if let Some(v) = flag {
        if let Some(d) = parse_duration(v) {
            return d;
        }
        eprintln!(
            "Warning: invalid --timeout {v:?}; using default {}",
            go_duration_string(DEFAULT_SCAN_TIMEOUT)
        );
    }
    if let Ok(env) = std::env::var("RVL_SCAN_TIMEOUT") {
        if !env.is_empty() {
            if let Some(d) = parse_duration(&env) {
                return d;
            }
            eprintln!(
                "Warning: invalid RVL_SCAN_TIMEOUT {env:?}; using default {}",
                go_duration_string(DEFAULT_SCAN_TIMEOUT)
            );
        }
    }
    DEFAULT_SCAN_TIMEOUT
}

// --- submit (rvl-cli submitScan) ---

/// Parse an HTTP Retry-After value as delta-seconds. rvl-cli also accepts
/// an HTTP-date; a date here returns None and the caller falls back to the
/// 60s default (the server sends delta-seconds).
fn parse_retry_after(v: &str) -> Option<Duration> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    v.parse::<u64>().ok().map(Duration::from_secs)
}

/// Extract message + code from a JSON `{code,message}` error body, falling
/// back to `{"error": ...}` and then to the raw body.
fn decode_server_error(body: &[u8]) -> (String, String) {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct Envelope {
        code: String,
        message: String,
        error: String,
    }
    if let Ok(parsed) = serde_json::from_slice::<Envelope>(body) {
        if !parsed.message.is_empty() {
            return (parsed.message, parsed.code);
        }
        if !parsed.error.is_empty() {
            return (parsed.error, parsed.code);
        }
    }
    (String::from_utf8_lossy(body).into_owned(), String::new())
}

/// POST the scan request to `{api_url}/api/v1/risks/scan`.
///
/// Honors Retry-After on a 429 by retrying once after the declared delay
/// (capped at 120s, default 60s). 401/403 get a distinct actionable
/// message including the API URL. Server `{code,message}` error envelopes
/// are surfaced verbatim. A deterministic idempotency key derived from the
/// request body is set when the caller did not supply one, so the same
/// command rerun after a client timeout reuses the server's cached
/// response instead of re-running every side effect.
pub fn submit_scan(
    client: &Client,
    req: &mut ScanRequest,
    timeout: Duration,
) -> Result<ScanResponse, String> {
    const MAX_RETRIES: u32 = 1;
    const MAX_BACKOFF: Duration = Duration::from_secs(120);

    let timeout = if timeout.is_zero() {
        DEFAULT_SCAN_TIMEOUT
    } else {
        timeout
    };

    if req.idempotency_key.is_empty() {
        req.idempotency_key = derive_idempotency_key(req);
    }
    let body = request_body(req, true);
    let url = format!("{}/api/v1/risks/scan", client.api_url);

    let mut attempt = 0u32;
    loop {
        let mut r = ureq::request("POST", &url)
            .timeout(timeout)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", client.api_key));
        if let Some(org) = &client.org_id {
            r = r.set("X-Organization-ID", org);
        }
        match r.send_bytes(body.as_bytes()) {
            Ok(resp) => {
                let mut buf = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("read response body: {e}"))?;
                return serde_json::from_slice(&buf).map_err(|e| format!("parse response: {e}"));
            }
            Err(ureq::Error::Status(code @ (401 | 403), _)) => {
                return Err(format!(
                    "authentication failed against {} - run '{BIN} login' to reconfigure (status {code})",
                    client.api_url
                ));
            }
            Err(ureq::Error::Status(429, resp)) if attempt < MAX_RETRIES => {
                let mut delay = parse_retry_after(resp.header("Retry-After").unwrap_or(""))
                    .unwrap_or(Duration::ZERO);
                if delay.is_zero() || delay > MAX_BACKOFF {
                    delay = Duration::from_secs(60);
                }
                eprintln!(
                    "rate limited by server; retrying in {}",
                    go_duration_string(delay)
                );
                std::thread::sleep(delay);
                attempt += 1;
            }
            Err(ureq::Error::Status(code, resp)) => {
                let mut buf = Vec::new();
                let _ = resp.into_reader().read_to_end(&mut buf);
                let (msg, ecode) = decode_server_error(&buf);
                return Err(format!(
                    "server error ({code} {ecode}) from {}: {msg}",
                    client.api_url
                ));
            }
            Err(ureq::Error::Transport(t)) => return Err(format!("request failed: {t}")),
        }
    }
}

// --- response emission for --format json (Go MarshalIndent parity) ---

fn response_g(r: &ScanResponse) -> G {
    let summary = {
        let mut sf = vec![
            ("total".to_string(), G::Int(r.summary.total)),
            ("created".to_string(), G::Int(r.summary.created)),
            ("updated".to_string(), G::Int(r.summary.updated)),
            ("unchanged".to_string(), G::Int(r.summary.unchanged)),
        ];
        if r.summary.resolved_this_scan != 0 {
            sf.push((
                "resolved_this_scan".to_string(),
                G::Int(r.summary.resolved_this_scan),
            ));
        }
        sf.push(("critical".to_string(), G::Int(r.summary.critical)));
        sf.push(("high".to_string(), G::Int(r.summary.high)));
        sf.push(("medium".to_string(), G::Int(r.summary.medium)));
        sf.push(("low".to_string(), G::Int(r.summary.low)));
        G::Obj(sf)
    };
    let findings = match &r.findings {
        None => G::Null,
        Some(fs) => G::Arr(
            fs.iter()
                .map(|f| {
                    let mut ff = vec![
                        ("risk_id".to_string(), G::Str(f.risk_id.clone())),
                        ("risk_code".to_string(), G::Str(f.risk_code.clone())),
                        ("title".to_string(), G::Str(f.title.clone())),
                        ("status".to_string(), G::Str(f.status.clone())),
                        ("score".to_string(), G::Int(f.score)),
                        ("priority".to_string(), G::Str(f.priority.clone())),
                    ];
                    push_str_arr_opt(&mut ff, "warnings", &f.warnings);
                    G::Obj(ff)
                })
                .collect(),
        ),
    };
    let mut f = vec![
        ("scan_id".to_string(), G::Str(r.scan_id.clone())),
        ("service".to_string(), G::Str(r.service.clone())),
        ("summary".to_string(), summary),
        ("findings".to_string(), findings),
    ];
    if let Some(cs) = &r.control_structure {
        let mut cf = vec![
            ("snapshot_id".to_string(), G::Str(cs.snapshot_id.clone())),
            ("node_count".to_string(), G::Int(cs.node_count)),
            ("edge_count".to_string(), G::Int(cs.edge_count)),
            ("scanned_files".to_string(), G::Int(cs.scanned_files)),
            ("scanned_lines".to_string(), G::Int(cs.scanned_lines)),
        ];
        if let Some(uca) = &cs.uca_coverage {
            cf.push((
                "uca_coverage".to_string(),
                G::Obj(vec![
                    ("discovered".to_string(), G::Int(uca.discovered)),
                    ("analyzed".to_string(), G::Int(uca.analyzed)),
                    ("cap".to_string(), G::Int(uca.cap)),
                    ("ucas_generated".to_string(), G::Int(uca.ucas_generated)),
                    ("ucas_stored".to_string(), G::Int(uca.ucas_stored)),
                ]),
            ));
        }
        f.push(("control_structure".to_string(), G::Obj(cf)));
    }
    push_str_arr_opt(&mut f, "warnings", &r.warnings);
    f.push(("timestamp".to_string(), G::Str(r.timestamp.clone())));
    if let Some(et) = &r.effective_tolerance {
        let mut tf = vec![
            ("tolerance_target".to_string(), G::Int(et.tolerance_target)),
            (
                "tolerance_headroom_pct".to_string(),
                G::Int(et.tolerance_headroom_pct),
            ),
            (
                "strict_enforcement".to_string(),
                G::Bool(et.strict_enforcement),
            ),
        ];
        if et.calibrating {
            tf.push(("calibrating".to_string(), G::Bool(true)));
        }
        f.push(("effective_tolerance".to_string(), G::Obj(tf)));
    }
    // omitempty, so a fresh scan's JSON is byte-identical to before
    // (po-72d5d).
    if r.cached {
        f.push(("cached".to_string(), G::Bool(true)));
    }
    G::Obj(f)
}

// --- helpers ---

/// How many findings lack both a `component` field and `linked_services`:
/// they fall back to the bare service label and split Reliability Budget
/// rows (po-6u5yx).
fn count_findings_without_component(findings: &[Value]) -> usize {
    findings
        .iter()
        .filter(|raw| {
            let Some(m) = raw.as_object() else {
                return false;
            };
            let has_component = m
                .get("component")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.trim().is_empty());
            let has_linked = m
                .get("linked_services")
                .and_then(Value::as_array)
                .is_some_and(|ls| !ls.is_empty());
            !has_component && !has_linked
        })
        .count()
}

fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Populate git_commit/git_branch from the target repo when the merged
/// parts did not carry them (mirrors rvl-cli's `git rev-parse HEAD`
/// detection on the evidence path; a detached HEAD leaves git_branch
/// empty).
fn populate_git_metadata(meta: &mut ScanMetadata, target: &Path) {
    if meta.git_commit.is_empty() {
        if let Some(commit) = git_output(target, &["rev-parse", "HEAD"]) {
            meta.git_commit = commit;
        }
    }
    if meta.git_branch.is_empty() {
        if let Some(branch) = git_output(target, &["rev-parse", "--abbrev-ref", "HEAD"]) {
            if branch != "HEAD" {
                meta.git_branch = branch;
            }
        }
    }
}

// --- CLI entry ---

/// The submission-mode arguments carried over from the `scan` subcommand.
pub struct SubmitArgs {
    pub service: Option<String>,
    /// Owning team for the WHOLE submission, overriding every `.revelara.yaml`
    /// `team:` value (po-77b6w.1).
    pub team: Option<String>,
    pub target: Option<PathBuf>,
    pub stdin: bool,
    pub file: Option<PathBuf>,
    pub scan_dir: Option<PathBuf>,
    pub cleanup_on_success: bool,
    /// Validate, normalize, and print the submit summary without
    /// submitting (po-4g59y contract: JSON on stdout, framing on stderr).
    pub dry_run: bool,
    pub timeout: Option<String>,
    pub format: Option<String>,
}

enum OutputFormat {
    Text,
    Json,
}

fn fail(f: Failure) -> ExitCode {
    eprintln!("{}", f.msg);
    ExitCode::from(f.code)
}

/// Run the scan submission end to end. `version` feeds the
/// `scanner_id: "rvlscan/<version>"` metadata field.
pub fn run(args: SubmitArgs, version: &str) -> ExitCode {
    let format = match args.format.as_deref() {
        None | Some("text") => OutputFormat::Text,
        Some("json") => OutputFormat::Json,
        Some(f) => {
            return fail(Failure::usage(format!(
                "Error: invalid --format \"{f}\" (valid: text, json)"
            )))
        }
    };

    // po-77b6w.1: validate the override early; a value that slugifies to
    // nothing usable would be silently dropped server-side.
    let team_flag = args.team.clone().unwrap_or_default();
    if !team_flag.is_empty() && slugify_team_preview(&team_flag).is_empty() {
        return fail(Failure::usage(format!(
            "Error: --team {team_flag:?} is not a usable team name (slugifies to nothing)"
        )));
    }

    // Target directory: default cwd, must exist and be a directory.
    let target = match &args.target {
        Some(t) => {
            let abs = if t.is_absolute() {
                t.clone()
            } else {
                std::env::current_dir().unwrap_or_default().join(t)
            };
            match std::fs::metadata(&abs) {
                Err(_) => {
                    return fail(Failure::runtime(format!(
                        "Error: target directory does not exist: {}",
                        abs.display()
                    )))
                }
                Ok(md) if !md.is_dir() => {
                    return fail(Failure::runtime(format!(
                        "Error: target is not a directory: {}",
                        abs.display()
                    )))
                }
                Ok(_) => abs,
            }
        }
        None => PathBuf::from("."),
    };

    let Some(service) = args.service.filter(|s| !s.is_empty()) else {
        eprintln!("Error: --service is required");
        eprintln!(
            "Usage: {BIN} scan --service <name> [--stdin|--file <path>|--scan-dir <path>] [--target <path>]"
        );
        return ExitCode::FAILURE;
    };

    let (_cfg, client) = match crate::client::load_and_resolve() {
        Ok(v) => v,
        Err(f) => return fail(f),
    };

    let mut req = ScanRequest::default();
    let scan_dir = args.scan_dir.clone();

    if let Some(dir) = &scan_dir {
        if let Err(e) = merge_scan_dir(dir, &mut req) {
            return fail(Failure::runtime(format!("Error: {e}")));
        }
    } else {
        let data: Vec<u8> = if args.stdin {
            let mut buf = Vec::new();
            if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
                return fail(Failure::runtime(format!("Error reading stdin: {e}")));
            }
            buf
        } else if let Some(file) = &args.file {
            match std::fs::read(file) {
                Ok(d) => d,
                Err(e) => return fail(Failure::runtime(format!("Error reading file: {e}"))),
            }
        } else {
            return fail(Failure::runtime(
                "Error: Must specify --stdin, --file, or --scan-dir".to_string(),
            ));
        };

        match serde_json::from_slice::<ScanRequest>(&data) {
            Ok(parsed) => req = parsed,
            Err(e) => match serde_json::from_slice::<Vec<Value>>(&data) {
                Ok(findings) => req.findings = Some(findings),
                Err(_) => return fail(Failure::runtime(format!("Error parsing input: {e}"))),
            },
        }
    }

    // Validate and coerce finding fields client-side (po-gli2z): runs
    // BEFORE dedup so the typed round-trip never sees uncoercible shapes.
    let norm_report = match req.findings.as_mut() {
        Some(f) => normalize_findings(f),
        None => FindingNormReport::default(),
    };
    print_normalization_issues(&norm_report);

    // Deduplicate cross-agent findings after a scan-dir merge, via the
    // typed round-trip (which is exactly why ScanFinding carries the STPA
    // fields). A round-trip that cannot parse leaves findings untouched.
    if scan_dir.is_some() {
        if let Some(findings) = &req.findings {
            if !findings.is_empty() {
                if let Ok(typed) =
                    serde_json::from_value::<Vec<ScanFinding>>(Value::Array(findings.clone()))
                {
                    let original = typed.len();
                    let deduped = deduplicate_findings(typed);
                    if deduped.len() < original {
                        eprintln!(
                            "scanner: deduplicated {} cross-agent duplicate(s)",
                            original - deduped.len()
                        );
                        if let Ok(Value::Array(vals)) = serde_json::to_value(&deduped) {
                            req.findings = Some(vals);
                        }
                    }
                }
            }
        }
    }

    normalize_control_structure(&mut req.control_structure);

    req.service = service.clone();
    if req.scan_type.is_empty() {
        req.scan_type = "full".to_string();
    }
    req.metadata.scanner_id = format!("{BIN}/{version}");
    populate_git_metadata(&mut req.metadata, &target);

    // Submission is non-interactive here: "ci" carries the JSON contract,
    // "auto" everything else (the interactive review prompt is not ported).
    req.scan_mode = match format {
        OutputFormat::Json => "ci".to_string(),
        OutputFormat::Text => "auto".to_string(),
    };

    // po-77b6w.1: carry team ownership on the submission. --team overrides the
    // whole submission; otherwise `.revelara.yaml` `team:` (repo default) and
    // per-component `team:` entries apply.
    let project_cfg = crate::project_config::load_project_config_from(&target);
    apply_team_assignments(&mut req, project_cfg.as_ref(), &team_flag);

    // Dry run (po-4g59y): machine-readable summary on stdout so the scan
    // skill and CI can parse it, human framing on stderr, no submit.
    // serde_json's default Map is sorted, matching Go's map-key encoding,
    // so the two CLIs emit byte-comparable summaries.
    if args.dry_run {
        eprintln!("Dry run - would submit to {}:", client.api_url);
        let mut summary = serde_json::Map::new();
        summary.insert("dry_run".into(), Value::Bool(true));
        summary.insert("api_url".into(), Value::String(client.api_url.clone()));
        summary.insert("service".into(), Value::String(req.service.clone()));
        summary.insert("mode".into(), Value::String(req.scan_mode.clone()));
        summary.insert("scan_type".into(), Value::String(req.scan_type.clone()));
        summary.insert(
            "findings".into(),
            Value::from(req.findings.as_ref().map(Vec::len).unwrap_or(0)),
        );
        // po-gli2z: normalization counts so CI can assert no STPA loss.
        summary.insert(
            "findings_with_stpa".into(),
            Value::from(norm_report.with_stpa),
        );
        summary.insert(
            "findings_coerced".into(),
            Value::from(norm_report.coerced_findings),
        );
        summary.insert(
            "findings_with_dropped".into(),
            Value::from(norm_report.dropped_findings),
        );
        summary.insert(
            "dropped_fields".into(),
            Value::from(norm_report.dropped_fields),
        );
        if args.target.is_some() {
            summary.insert("target".into(), Value::String(target.display().to_string()));
        }
        if !req.team.is_empty() {
            summary.insert("team".into(), Value::String(req.team.clone()));
        }
        match serde_json::to_string_pretty(&Value::Object(summary)) {
            Ok(s) => println!("{s}"),
            Err(e) => return fail(Failure::runtime(format!("Error encoding summary: {e}"))),
        }
        print_stpa_loss_banner(&norm_report);
        return ExitCode::SUCCESS;
    }

    // Warn (don't block) when findings have no component and no
    // linked_services: they land at the bare project label and split
    // Reliability Budget rows (po-6u5yx).
    let total_findings = req.findings.as_ref().map(Vec::len).unwrap_or(0);
    if let Some(findings) = &req.findings {
        let missing = count_findings_without_component(findings);
        if missing > 0 {
            eprintln!(
                "Warning: {missing}/{total_findings} findings have no `component` or `linked_services` and will be attributed to the bare service label {:?}.",
                req.service
            );
        }
    }

    // po-77b6w.1: pre-submit did-you-mean against the org's known team slugs.
    // Loud, never blocking: a fetch failure skips the check and an unknown
    // team still submits (create-on-first-sight).
    if !req.team.is_empty() || !req.component_teams.is_empty() {
        warn_unknown_teams(
            &mut std::io::stderr(),
            crate::client::fetch_team_slugs(&client).as_deref(),
            &req,
        );
    }

    let timeout = resolve_scan_timeout(args.timeout.as_deref());
    let response = match submit_scan(&client, &mut req, timeout) {
        Ok(r) => r,
        Err(e) => {
            // On submit failure, remind the user the scan-parts directory
            // is intact and can be re-submitted as-is.
            if let Some(dir) = &scan_dir {
                eprintln!(
                    "Scan parts preserved at {dir}; re-run after resolving the error with:\n  {BIN} scan --service {service} --scan-dir {dir}",
                    dir = dir.display()
                );
            }
            if matches!(format, OutputFormat::Json) {
                let out = compact(&G::Obj(vec![
                    ("error".to_string(), G::Str(e)),
                    ("service".to_string(), G::Str(service)),
                ]));
                println!("{out}");
                return ExitCode::from(2);
            }
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    // On success, either clean up (--cleanup-on-success) or surface the
    // cleanup instruction so stale part files do not accumulate.
    if let Some(dir) = &scan_dir {
        if args.cleanup_on_success {
            match std::fs::remove_dir_all(dir) {
                Ok(()) => eprintln!(
                    "Removed scan parts at {} (--cleanup-on-success)",
                    dir.display()
                ),
                Err(e) => eprintln!("Warning: failed to remove {}: {e}", dir.display()),
            }
        } else {
            eprintln!(
                "Scan parts kept at {dir}; remove with: rm -rf {dir}",
                dir = dir.display()
            );
        }
    }

    // Surface server-side partial acceptance instead of swallowing it.
    if response.summary.total > 0 && (response.summary.total as usize) < total_findings {
        eprintln!(
            "Warning: server processed {} of {} submitted finding(s); the rest were rejected or ignored server-side.",
            response.summary.total, total_findings
        );
    }

    if matches!(format, OutputFormat::Json) {
        eprintln!(
            "Findings submitted: {}",
            normalization_summary(&norm_report)
        );
        // stdout stays machine-readable (the `cached` field simply rides
        // along in the marshalled body); the human-facing note goes to stderr.
        note_cached_scan(&mut std::io::stderr(), &response);
        print_stpa_loss_banner(&norm_report);
        println!("{}", pretty(&response_g(&response)));
        if response.summary.critical > 0 || response.summary.high > 0 {
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    render_text(&response, &norm_report, &client.api_url);
    ExitCode::SUCCESS
}

/// The human-readable success block, mirroring rvl-cli's standard output
/// path (plus the effective-tolerance line the response now carries).
fn render_text(response: &ScanResponse, norm_report: &FindingNormReport, api_url: &str) {
    println!("{}", scan_submit_headline(response.cached));
    println!("  Scan ID: {}", response.scan_id);
    println!("  Service: {}", response.service);
    println!(
        "  Submitted findings: {}",
        normalization_summary(norm_report)
    );
    println!(
        "  Total: {} (Created: {}, Updated: {}, Unchanged: {})",
        response.summary.total,
        response.summary.created,
        response.summary.updated,
        response.summary.unchanged
    );
    if response.summary.critical > 0 || response.summary.high > 0 {
        println!(
            "  Priority: Critical={}, High={}, Medium={}, Low={}",
            response.summary.critical,
            response.summary.high,
            response.summary.medium,
            response.summary.low
        );
    }
    if let Some(et) = &response.effective_tolerance {
        println!(
            "  Effective tolerance: target={}, headroom={}%, strict={}{}",
            et.tolerance_target,
            et.tolerance_headroom_pct,
            et.strict_enforcement,
            if et.calibrating { " (calibrating)" } else { "" }
        );
    }
    if let Some(cs) = &response.control_structure {
        println!(
            "  Control Structure: {} nodes, {} edges ({} files scanned)",
            cs.node_count, cs.edge_count, cs.scanned_files
        );
        if let Some(uca) = &cs.uca_coverage {
            print!(
                "  STPA Coverage: {}/{} control actions analyzed",
                uca.analyzed, uca.discovered
            );
            if uca.cap > 0 && uca.discovered > uca.cap {
                print!(" (capped at {})", uca.cap);
            }
            println!(" | {} UCAs identified", uca.ucas_generated);
        }
    }
    println!();

    // Risk rows on stdout, per-finding server warnings on stderr: a
    // server-side partial accept of a finding's fields must be visible.
    print_scan_findings(&mut std::io::stdout(), &mut std::io::stderr(), response);

    if !response.warnings.is_empty() {
        eprintln!("Warnings:");
        for w in &response.warnings {
            eprintln!("  \u{26a0} {w}");
        }
        eprintln!();
    }

    print_stpa_loss_banner(norm_report);

    println!("View results: {api_url}/risks");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_request() -> ScanRequest {
        let mut req = ScanRequest {
            service: "checkout-api".into(),
            scan_type: "full".into(),
            scan_mode: "auto".into(),
            findings: Some(vec![serde_json::json!({
                "title": "Missing timeout",
                "category": "resilience",
                "likelihood": "high",
                "impact": "high",
                "risk_score": 61,
            })]),
            ..Default::default()
        };
        req.metadata.scanner_id = "rvlscan/0.1.0".into();
        req
    }

    // --- idempotency ---

    #[test]
    fn idempotency_key_is_stable_32_hex() {
        let req = base_request();
        let k1 = derive_idempotency_key(&req);
        let k2 = derive_idempotency_key(&req);
        assert_eq!(k1, k2, "same request must produce the same key");
        assert_eq!(k1.len(), 32);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn idempotency_key_changes_with_findings() {
        let a = base_request();
        let mut b = base_request();
        b.findings
            .as_mut()
            .unwrap()
            .push(serde_json::json!({"title": "Another"}));
        assert_ne!(derive_idempotency_key(&a), derive_idempotency_key(&b));
    }

    #[test]
    fn idempotency_key_field_is_excluded_from_the_hash() {
        let a = base_request();
        let mut b = base_request();
        b.idempotency_key = "deadbeefdeadbeefdeadbeefdeadbeef".into();
        assert_eq!(
            derive_idempotency_key(&a),
            derive_idempotency_key(&b),
            "the key field itself must not feed the hash"
        );
        // And the wire body carries the key while the canonical form omits it.
        assert!(request_body(&b, true).contains("idempotency_key"));
        assert!(!request_body(&b, false).contains("idempotency_key"));
    }

    // --- request emission ---

    #[test]
    fn request_body_matches_go_struct_marshal_order() {
        let mut req = base_request();
        req.metadata.git_commit = "abc123".into();
        req.business_criticality = Some(0.9);
        req.service_tolerance = Some(ServiceToleranceConfig {
            tolerance_target: Some(25),
            tolerance_headroom_pct: None,
            strict_enforcement: Some(true),
        });
        req.idempotency_key = "k".into();
        let body = request_body(&req, true);
        assert_eq!(
            body,
            r#"{"service":"checkout-api","scan_type":"full","scan_mode":"auto","findings":[{"category":"resilience","impact":"high","likelihood":"high","risk_score":61,"title":"Missing timeout"}],"metadata":{"git_commit":"abc123","scanner_id":"rvlscan/0.1.0"},"business_criticality":0.9,"service_tolerance":{"tolerance_target":25,"strict_enforcement":true},"idempotency_key":"k"}"#
        );
    }

    /// The team wire contract shared with the server's `ScanRequest`: field
    /// names `team`, `team_source`, `component_teams`, marshalled last (Go
    /// struct order) with sorted component keys, and all three omitted when
    /// empty so older servers see no change (po-77b6w.1).
    #[test]
    fn team_fields_ride_last_and_stay_off_the_wire_when_empty() {
        let mut req = base_request();
        req.idempotency_key = "k".into();
        req.team = "checkout".into();
        req.team_source = "override".into();
        req.component_teams
            .insert("worker".into(), "payments".into());
        req.component_teams.insert("api".into(), "checkout".into());
        let body = request_body(&req, true);
        assert!(
            body.ends_with(
                r#""idempotency_key":"k","team":"checkout","team_source":"override","component_teams":{"api":"checkout","worker":"payments"}}"#
            ),
            "{body}"
        );

        let plain = request_body(&base_request(), false);
        for key in ["team", "team_source", "component_teams"] {
            assert!(
                !plain.contains(&format!("\"{key}\"")),
                "{key} must be omitted when empty: {plain}"
            );
        }
    }

    /// Team ownership is part of the deduplicated payload: re-submitting the
    /// same findings under a different team is a different scan.
    #[test]
    fn idempotency_key_changes_with_team() {
        let a = base_request();
        let mut b = base_request();
        b.team = "checkout".into();
        assert_ne!(derive_idempotency_key(&a), derive_idempotency_key(&b));
    }

    #[test]
    fn nil_findings_marshal_as_null_like_go() {
        let mut req = base_request();
        req.findings = None;
        assert!(request_body(&req, false).contains(r#""findings":null"#));
    }

    #[test]
    fn control_structure_raw_json_preserves_key_order() {
        let mut req = base_request();
        req.control_structure = Some(ControlStructureData {
            nodes: Some("[ {\"z\": 1, \"a\": 2} ]".into()),
            edges: None,
            scanned_files: 3,
            scanned_lines: 400,
        });
        let body = request_body(&req, false);
        assert!(
            body.contains(r#""control_structure":{"nodes":[{"z":1,"a":2}],"edges":null,"scanned_files":3,"scanned_lines":400}"#),
            "{body}"
        );
    }

    // --- scan-dir merge ---

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn merge_scan_dir_concats_arrays_and_last_writer_wins_scalars() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write(
            dir,
            "01-stack.json",
            r#"{"stack":{"languages":["go"]},"repo_url":"https://a","components":[{"name":"api"}]}"#,
        );
        write(
            dir,
            "02-findings.json",
            r#"{"findings":[{"title":"A","category":"c","likelihood":"l","impact":"i"}],"dependencies":[{"target":"redis"}]}"#,
        );
        write(
            dir,
            "03-more.json",
            r#"{"findings":[{"title":"B","category":"c","likelihood":"l","impact":"i"}],"repo_url":"https://b","components":[{"name":"worker"}]}"#,
        );

        let mut req = ScanRequest::default();
        merge_scan_dir(dir, &mut req).unwrap();

        let findings = req.findings.as_ref().unwrap();
        assert_eq!(findings.len(), 2, "findings concatenate");
        assert_eq!(findings[0]["title"], "A");
        assert_eq!(findings[1]["title"], "B");
        assert_eq!(req.components.len(), 2, "components concatenate");
        assert_eq!(req.dependencies.len(), 1);
        assert_eq!(req.repo_url, "https://b", "later file wins the scalar");
        assert_eq!(req.stack.as_ref().unwrap().languages, vec!["go"]);
    }

    #[test]
    fn merge_scan_dir_skips_invalid_json_and_merges_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write(dir, "01-bad.json", "{not json");
        write(
            dir,
            "02-ok.json",
            r#"{"findings":[{"title":"A","category":"c","likelihood":"l","impact":"i"}]}"#,
        );
        let mut req = ScanRequest::default();
        merge_scan_dir(dir, &mut req).unwrap();
        assert_eq!(req.findings.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn merge_scan_dir_zero_findings_still_succeeds() {
        // The zero-findings case warns but does not error (the warning is
        // on stderr; the merge result is what is pinned here).
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write(dir, "01-stack.json", r#"{"stack":{"languages":["go"]}}"#);
        let mut req = ScanRequest::default();
        merge_scan_dir(dir, &mut req).unwrap();
        assert!(req.findings.is_none());
    }

    #[test]
    fn merge_scan_dir_empty_dir_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let mut req = ScanRequest::default();
        let err = merge_scan_dir(tmp.path(), &mut req).unwrap_err();
        assert!(err.starts_with("no JSON files found in"), "{err}");
    }

    // --- control-structure normalization ---

    #[test]
    fn control_structure_field_names_normalized() {
        let mut cs = Some(ControlStructureData {
            nodes: Some(
                r#"[{"node_key":"n1","provenance":{"file":"a.go"}},{"id":"n2"}]"#.into(),
            ),
            edges: Some(
                r#"[{"from_key":"n1","to_node":"n2","edge_type":"x","provenance":[{"file":"b.go"}]}]"#
                    .into(),
            ),
            scanned_files: 1,
            scanned_lines: 2,
        });
        normalize_control_structure(&mut cs);
        let cs = cs.unwrap();

        let nodes: Vec<Value> = serde_json::from_str(cs.nodes.as_ref().unwrap()).unwrap();
        assert_eq!(nodes[0]["id"], "n1");
        assert!(nodes[0].get("node_key").is_none());
        assert!(
            nodes[0]["provenance"].is_array(),
            "node provenance is array"
        );
        assert_eq!(nodes[1]["id"], "n2");

        let edges: Vec<Value> = serde_json::from_str(cs.edges.as_ref().unwrap()).unwrap();
        assert_eq!(edges[0]["from_id"], "n1");
        assert_eq!(edges[0]["to_id"], "n2");
        assert!(edges[0].get("edge_type").is_none(), "edge_type stripped");
        assert!(
            edges[0]["provenance"].is_object(),
            "edge provenance is object"
        );
    }

    #[test]
    fn untouched_control_structure_keeps_raw_bytes() {
        let raw = r#"[{"id":"n1","provenance":[{"file":"a.go"}]}]"#;
        let mut cs = Some(ControlStructureData {
            nodes: Some(raw.into()),
            edges: None,
            scanned_files: 0,
            scanned_lines: 0,
        });
        normalize_control_structure(&mut cs);
        assert_eq!(cs.unwrap().nodes.as_deref(), Some(raw));
    }

    // --- dedup (port of wire_stpa_test.go) ---

    #[test]
    fn dedup_preserves_stpa_fields_through_round_trip() {
        let raw = serde_json::json!([
            {
                "title": "Missing timeout",
                "category": "resilience",
                "likelihood": "high",
                "impact": "high",
                "priority": "high",
                "risk_score": 61,
                "slug": "missing-timeout",
                "evidence": [{"type": "code", "path": "a.go", "line_number": 10}],
                "uca_type": "not_provided",
                "causal_factors": ["no deadline propagation", "no client timeout"],
                "loss_scenario": "request hangs, worker pool exhausts",
                "loss_category": "error_budget_managed",
                "estimated_fix_complexity": "medium",
                "constraint_type": "primary",
                "impact_chains": [{"chain": ["a", "b"]}],
                "mitigations": ["add context deadline"],
                "foresight_depth": 2,
                "graph_adjacent_knowledge": ["k1"]
            },
            {
                "title": "Missing timeout",
                "category": "resilience",
                "likelihood": "high",
                "impact": "high",
                "risk_score": 40,
                "slug": "missing-timeout",
                "evidence": [{"type": "code", "path": "a.go", "line_number": 10}]
            }
        ]);
        let findings: Vec<ScanFinding> = serde_json::from_value(raw).unwrap();
        let deduped = deduplicate_findings(findings);
        assert_eq!(deduped.len(), 1, "expected dedup to 1 finding");
        let f = &deduped[0];

        assert_eq!(f.uca_type, "not_provided");
        assert_eq!(f.causal_factors.len(), 2);
        assert!(!f.loss_scenario.is_empty());
        assert_eq!(f.loss_category, "error_budget_managed");
        assert_eq!(f.estimated_fix_complexity, "medium");
        assert_eq!(f.constraint_type, "primary");
        assert_eq!(f.priority, "high");
        assert_eq!(f.risk_score, 61, "highest score wins");

        // Round-trip back to JSON (what the submit path does) must keep
        // the STPA and graph fields on the wire.
        let out = serde_json::to_value(f).unwrap();
        for field in [
            "uca_type",
            "causal_factors",
            "loss_scenario",
            "loss_category",
            "estimated_fix_complexity",
            "constraint_type",
            "impact_chains",
            "mitigations",
            "foresight_depth",
            "graph_adjacent_knowledge",
            "priority",
        ] {
            assert!(out.get(field).is_some(), "field {field} lost on the wire");
        }
    }

    #[test]
    fn dedup_merges_component_corroboration() {
        let mk = |component: &str, score: i64| ScanFinding {
            title: "T".into(),
            category: "c".into(),
            likelihood: "l".into(),
            impact: "i".into(),
            slug: "s".into(),
            component: component.into(),
            risk_score: score,
            evidence: vec![ScanEvidence {
                evidence_type: "code".into(),
                path: "a.go".into(),
                line_number: 5,
                description: String::new(),
            }],
            ..Default::default()
        };
        let deduped = deduplicate_findings(vec![mk("api", 10), mk("worker", 90)]);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].component, "worker", "higher score wins");
        assert_eq!(
            deduped[0].corroborated_by_agents,
            vec!["api".to_string()],
            "loser component recorded as corroboration"
        );
    }

    // --- misc helpers ---

    #[test]
    fn timeout_parsing_accepts_go_durations_and_bare_seconds() {
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("1m30s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("bogus"), None);
        assert_eq!(parse_duration("0"), None);
        assert_eq!(go_duration_string(Duration::from_secs(60)), "1m0s");
        assert_eq!(go_duration_string(Duration::from_secs(45)), "45s");
        assert_eq!(go_duration_string(Duration::from_secs(120)), "2m0s");
    }

    #[test]
    fn retry_after_parses_delta_seconds_only() {
        assert_eq!(parse_retry_after("30"), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(" 5 "), Some(Duration::from_secs(5)));
        assert_eq!(parse_retry_after(""), None);
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
    }

    #[test]
    fn findings_without_component_are_counted() {
        let findings = vec![
            serde_json::json!({"title": "a"}),
            serde_json::json!({"title": "b", "component": "api"}),
            serde_json::json!({"title": "c", "linked_services": ["svc"]}),
            serde_json::json!({"title": "d", "component": "  "}),
        ];
        assert_eq!(count_findings_without_component(&findings), 2);
    }

    #[test]
    fn server_error_envelope_decoding() {
        assert_eq!(
            decode_server_error(br#"{"code":"validation_failed","message":"bad findings"}"#),
            ("bad findings".to_string(), "validation_failed".to_string())
        );
        assert_eq!(
            decode_server_error(br#"{"error":"boom"}"#),
            ("boom".to_string(), String::new())
        );
        assert_eq!(
            decode_server_error(b"plain text"),
            ("plain text".to_string(), String::new())
        );
    }

    #[test]
    fn file_input_falls_back_to_bare_findings_array() {
        // Mirrors rvl-cli: a full request parses as-is; a bare array
        // becomes the findings list.
        let full: ScanRequest =
            serde_json::from_str(r#"{"service":"x","findings":[{"title":"t"}]}"#).unwrap();
        assert_eq!(full.service, "x");
        assert_eq!(full.findings.unwrap().len(), 1);

        let arr = serde_json::from_str::<ScanRequest>(r#"[{"title":"t"}]"#);
        assert!(arr.is_err(), "bare array must not parse as a request");
        let findings: Vec<Value> = serde_json::from_str(r#"[{"title":"t"}]"#).unwrap();
        assert_eq!(findings.len(), 1);
    }
}
