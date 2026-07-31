//! Destination-gate scoring: gate-set loading, provenance enforcement
//! (fail-closed), and per-language precision as a Wilson 95% lower bound.
//!
//! Contract sources: rvlscan-eval gate-sets/README.md and
//! docs/POPULATION_TEMPLATE.md (po-3t3oj.10), wayfinder po-ipkfg.1 / po-ipkfg.11.

use crate::stats::wilson_lower_bound;
use serde::Deserialize;
use std::path::Path;

/// A pinned source repo inside a gate-set manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct RepoPin {
    pub repo: String,
    pub frozen_sha: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdjudicationMeta {
    pub protocol: String,
    pub panel: String,
    pub adjudicator: String,
    pub date: String,
}

/// manifest.yaml for a minted gate set (POPULATION_TEMPLATE.md schema).
/// Every field is required: a manifest missing any of them fails to parse,
/// and a gate set without a complete population document is not valid gate
/// evidence.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateManifest {
    pub set_id: String,
    pub language: String,
    pub minted: String,
    pub registry_version: u64,
    pub consumed: bool,
    pub repos: Vec<RepoPin>,
    pub sampling_frame: String,
    pub sample_size: usize,
    pub adjudication: AdjudicationMeta,
}

/// Panel verdict domain. Typed so a typo'd adjudication value refuses at
/// load instead of silently counting as decided-but-not-confirmed, which
/// would quietly deflate the precision it is supposed to gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicatedVerdict {
    Violates,
    Satisfies,
    NotApplicable,
    Unsure,
}

/// One adjudicated row of verdicts.jsonl (the gold).
#[derive(Debug, Clone, Deserialize)]
pub struct GoldRow {
    pub file_path: String,
    pub line_number: u64,
    /// Panel-adjudicated verdict.
    pub adjudicated: AdjudicatedVerdict,
}

/// Why a gate run was refused. All refusals are fail-closed: absence of
/// evidence is refusal, never a skipped check.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The set is designated as a seed set (permanently gate-ineligible).
    SeedSet(String),
    /// `consumed: true` — single-use per version, never reset.
    Consumed(String),
    /// sample_size below the n>=50 bar (po-ipkfg.1).
    SampleTooSmall(usize),
    /// Quarantine registry missing or unreadable.
    RegistryUnavailable(String),
    /// Any other required gate input missing, unreadable, or malformed
    /// (manifest, seed-set registry, grounding manifest, verdicts).
    EvidenceUnreadable(String),
    /// A manifest repo is not in the quarantine registry.
    RepoNotQuarantined(String),
    /// A gate-set repo appears in the engine's grounding corpus.
    GroundingOverlap(String),
    /// Fewer decided adjudications than the manifest's sample_size claims.
    GoldTooSmall { decided: usize, required: usize },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::SeedSet(s) => write!(
                f,
                "refused: {s} is a seed set (permanently gate-ineligible)"
            ),
            Refusal::Consumed(s) => write!(f, "refused: {s} is consumed (single-use per version)"),
            Refusal::SampleTooSmall(n) => write!(f, "refused: sample_size {n} < 50"),
            Refusal::RegistryUnavailable(e) => write!(
                f,
                "refused (fail-closed): quarantine registry unavailable: {e}"
            ),
            Refusal::EvidenceUnreadable(e) => {
                write!(f, "refused (fail-closed): gate evidence unreadable: {e}")
            }
            Refusal::RepoNotQuarantined(r) => write!(f, "refused: {r} not in quarantine registry"),
            Refusal::GroundingOverlap(r) => {
                write!(f, "refused: gate-set repo {r} present in grounding corpus")
            }
            Refusal::GoldTooSmall { decided, required } => {
                write!(
                    f,
                    "refused: only {decided} decided adjudications < sample_size {required}"
                )
            }
        }
    }
}

/// Parse a manifest.yaml string.
pub fn parse_manifest(yaml: &str) -> anyhow::Result<GateManifest> {
    Ok(serde_yaml::from_str(yaml)?)
}

#[derive(Debug, Deserialize)]
struct SeedSetEntry {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SeedSetsFile {
    seed_sets: Vec<SeedSetEntry>,
}

/// Names of seed sets from registry/seed_sets.yaml content.
pub fn parse_seed_set_names(yaml: &str) -> anyhow::Result<Vec<String>> {
    let f: SeedSetsFile = serde_yaml::from_str(yaml)?;
    Ok(f.seed_sets.into_iter().map(|s| s.name).collect())
}

/// Quarantine registry: version + quarantined repo names.
#[derive(Debug)]
pub struct Registry {
    pub registry_version: u64,
    pub repos: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QuarantinedRepo {
    repo: String,
}

#[derive(Debug, Deserialize)]
struct QuarantineFile {
    registry_version: u64,
    quarantined_repos: Vec<QuarantinedRepo>,
}

/// Load the quarantine registry fail-closed: a missing or unreadable file is
/// a `Refusal::RegistryUnavailable`, never a skipped check.
pub fn load_registry(path: &Path) -> Result<Registry, Refusal> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Refusal::RegistryUnavailable(format!("{}: {e}", path.display())))?;
    let f: QuarantineFile = serde_yaml::from_str(&raw)
        .map_err(|e| Refusal::RegistryUnavailable(format!("{}: {e}", path.display())))?;
    Ok(Registry {
        registry_version: f.registry_version,
        repos: f.quarantined_repos.into_iter().map(|r| r.repo).collect(),
    })
}

/// A loaded, not-yet-validated gate set plus the registry state it will be
/// judged against. Produced by [`load_gate_inputs`]; every load failure is a
/// typed [`Refusal`] so the CLI's 3-code exit contract (0 pass / 1 metric
/// fail / 2 refusal) holds for missing evidence, not just invalid evidence.
#[derive(Debug)]
pub struct GateInputs {
    pub manifest: GateManifest,
    pub seed_set_names: Vec<String>,
    pub registry: Registry,
    pub grounding_repos: Vec<String>,
    pub rows: Vec<GoldRow>,
}

/// Load everything a gate run needs, fail-closed on every input.
pub fn load_gate_inputs(
    set_dir: &Path,
    seed_sets: &Path,
    registry: &Path,
    grounding_manifest: &Path,
) -> Result<GateInputs, Refusal> {
    let read = |p: &Path| -> Result<String, Refusal> {
        std::fs::read_to_string(p)
            .map_err(|e| Refusal::EvidenceUnreadable(format!("{}: {e}", p.display())))
    };
    let manifest = parse_manifest(&read(&set_dir.join("manifest.yaml"))?).map_err(|e| {
        Refusal::EvidenceUnreadable(format!(
            "{}: {e} (a gate set without a complete population document is not valid gate evidence)",
            set_dir.join("manifest.yaml").display()
        ))
    })?;
    let seed_set_names = parse_seed_set_names(&read(seed_sets)?)
        .map_err(|e| Refusal::EvidenceUnreadable(format!("{}: {e}", seed_sets.display())))?;
    let registry = load_registry(registry)?;
    let grounding_repos: Vec<String> = read(grounding_manifest)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    let verdicts_path = set_dir.join("verdicts.jsonl");
    let rows: Vec<GoldRow> = read(&verdicts_path)?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .map_err(|e| Refusal::EvidenceUnreadable(format!("{}: {e}", verdicts_path.display())))?;
    Ok(GateInputs {
        manifest,
        seed_set_names,
        registry,
        grounding_repos,
        rows,
    })
}

/// Validate a gate set's provenance before any scoring. Returns the registry
/// version to record in the gate report.
pub fn validate_gate_set(
    manifest: &GateManifest,
    seed_set_names: &[String],
    registry: &Registry,
    grounding_repos: &[String],
) -> Result<u64, Refusal> {
    if seed_set_names.iter().any(|n| n == &manifest.set_id) {
        return Err(Refusal::SeedSet(manifest.set_id.clone()));
    }
    if manifest.consumed {
        return Err(Refusal::Consumed(manifest.set_id.clone()));
    }
    if manifest.sample_size < 50 {
        return Err(Refusal::SampleTooSmall(manifest.sample_size));
    }
    for pin in &manifest.repos {
        if !registry.repos.contains(&pin.repo) {
            return Err(Refusal::RepoNotQuarantined(pin.repo.clone()));
        }
        if grounding_repos.contains(&pin.repo) {
            return Err(Refusal::GroundingOverlap(pin.repo.clone()));
        }
    }
    Ok(registry.registry_version)
}

/// Gate score for one language.
#[derive(Debug)]
pub struct GateScore {
    /// Decided adjudications (unsure excluded, but counted below).
    pub n_decided: usize,
    pub n_unsure: usize,
    pub confirmed_violates: usize,
    pub precision: f64,
    pub wilson_lb: f64,
    /// wilson_lb >= target
    pub pass: bool,
}

/// Score adjudicated gold rows: precision = confirmed violates / decided,
/// with the pass verdict taken on the Wilson 95% lower bound vs `target`.
pub fn score_gate(rows: &[GoldRow], sample_size: usize, target: f64) -> Result<GateScore, Refusal> {
    let n_unsure = rows
        .iter()
        .filter(|r| r.adjudicated == AdjudicatedVerdict::Unsure)
        .count();
    let n_decided = rows.len() - n_unsure;
    if n_decided < sample_size {
        return Err(Refusal::GoldTooSmall {
            decided: n_decided,
            required: sample_size,
        });
    }
    let confirmed = rows
        .iter()
        .filter(|r| r.adjudicated == AdjudicatedVerdict::Violates)
        .count();
    let precision = confirmed as f64 / n_decided as f64;
    let wilson_lb = wilson_lower_bound(confirmed as u64, n_decided as u64);
    Ok(GateScore {
        n_decided,
        n_unsure,
        confirmed_violates: confirmed,
        precision,
        wilson_lb,
        pass: wilson_lb >= target,
    })
}
