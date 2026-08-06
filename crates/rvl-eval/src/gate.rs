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
    /// The consumption ledger already records this set, or this exact gold
    /// under another name (po-av01j.89). Distinct from `Consumed`, which is
    /// the manifest's self-declaration; this one is a fact the gate process
    /// wrote itself and therefore the one that can actually be trusted.
    AlreadyConsumed { set_id: String, reason: String },
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
            Refusal::AlreadyConsumed { set_id, reason } => write!(
                f,
                "refused: {set_id} is already consumed ({reason}). Gate sets are single-use per version; mint a fresh set rather than re-running this one."
            ),
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

/// Score adjudicated gold rows straight off the file.
///
/// DO NOT USE THIS AS A GATE (po-av01j.95). It computes the PANEL's
/// confirmation rate on a static verdicts.jsonl: a correct number about
/// whatever engine produced that file, and completely unchanged by any engine
/// change afterwards. Wiring it to a gate meant the engine could regress and a
/// re-run would re-read the same rows and still pass.
///
/// Kept because it is still the right function for describing a gold set on its
/// own terms -- "what did the panel confirm when this was minted" -- which is a
/// real question when reviewing a freshly adjudicated corpus. It is simply not
/// a measurement OF THE SCANNER. For that, see `score_gate_against_engine`,
/// which joins these rows to live findings.
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

/// What the engine currently says about one gold site, for the join.
///
/// Deliberately only the two facts the score needs. Carrying the whole finding
/// would invite scoring on `reason` strings, which are an output contract for
/// humans, not a stable key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineSaid {
    /// The engine flagged this site as a violation.
    Flagged,
    /// The engine reached the site and did NOT flag it.
    NotFlagged,
    /// The engine has no site at this (file, line) at all.
    Absent,
}

/// A gold row joined to what the engine says about it now.
#[derive(Debug, Clone)]
pub struct JoinedRow {
    pub file_path: String,
    pub line_number: u64,
    pub adjudicated: AdjudicatedVerdict,
    pub engine: EngineSaid,
}

/// Engine-measured gate score (po-av01j.95).
#[derive(Debug)]
pub struct EngineGateScore {
    /// Gold rows the engine still flags AND the panel decided. The precision
    /// denominator.
    pub n_scored: usize,
    /// Of those, panel-confirmed violations. The numerator.
    pub confirmed_violates: usize,
    /// Flagged, decided, and the panel said this is NOT a violation. These are
    /// the false positives the number exists to catch.
    pub false_positives: usize,
    /// Gold rows the engine no longer flags. NOT a precision term -- reported
    /// because a large value means the engine got quieter, which precision
    /// alone cannot show and which a reader must see next to the number.
    pub no_longer_flagged: usize,
    /// Gold rows with no corresponding site in this run at all (file moved or
    /// deleted, retriever changed). Also not a precision term; a large value
    /// means the gold and the checkout have drifted apart.
    pub unmatched: usize,
    pub n_unsure: usize,
    pub precision: f64,
    pub wilson_lb: f64,
    pub pass: bool,
}

/// Score the CURRENT ENGINE against adjudicated gold.
///
/// This is the measurement `score_gate` only appeared to make. That function
/// computes confirmed/decided straight off verdicts.jsonl, which is the panel's
/// confirmation rate on a STATIC FILE: correct for whatever engine produced the
/// file, and unchanged by any engine change afterwards. Re-running it after a
/// regression re-reads the same rows and still passes. `GoldRow.file_path` and
/// `line_number` existed for this join and were parsed and never read.
///
/// PRECISION IS OVER WHAT THE ENGINE FLAGS TODAY. A gold row the engine no
/// longer flags is not a false positive and must not sit in the denominator --
/// it is a recall question, reported separately. A row the engine flags that
/// the panel called Satisfies or NotApplicable IS a false positive, and is
/// exactly what a static file could never surface.
///
/// `Unsure` rows are excluded from both terms, as before: the panel declining
/// to decide is not evidence either way.
pub fn score_gate_against_engine(
    joined: &[JoinedRow],
    sample_size: usize,
    target: f64,
) -> Result<EngineGateScore, Refusal> {
    let n_unsure = joined
        .iter()
        .filter(|r| r.adjudicated == AdjudicatedVerdict::Unsure)
        .count();
    let no_longer_flagged = joined
        .iter()
        .filter(|r| r.engine == EngineSaid::NotFlagged)
        .count();
    let unmatched = joined
        .iter()
        .filter(|r| r.engine == EngineSaid::Absent)
        .count();

    let scored: Vec<&JoinedRow> = joined
        .iter()
        .filter(|r| r.engine == EngineSaid::Flagged && r.adjudicated != AdjudicatedVerdict::Unsure)
        .collect();

    // The n bar applies to what was actually SCORED, not to the file's row
    // count. An engine that stops flagging most of the gold cannot borrow the
    // original sample size to make a claim it no longer has the evidence for.
    if scored.len() < sample_size {
        return Err(Refusal::GoldTooSmall {
            decided: scored.len(),
            required: sample_size,
        });
    }

    let confirmed = scored
        .iter()
        .filter(|r| r.adjudicated == AdjudicatedVerdict::Violates)
        .count();
    let false_positives = scored.len() - confirmed;
    let precision = confirmed as f64 / scored.len() as f64;
    let wilson_lb = crate::stats::wilson_lower_bound(confirmed as u64, scored.len() as u64);

    Ok(EngineGateScore {
        n_scored: scored.len(),
        confirmed_violates: confirmed,
        false_positives,
        no_longer_flagged,
        unmatched,
        n_unsure,
        precision,
        wilson_lb,
        pass: wilson_lb >= target,
    })
}

/// Join gold rows to what the engine says now, keyed on (file_path, line_number).
///
/// The key is deliberately NOT the full site_key (`file:line:client_type:method`).
/// A gold row records a LOCATION a panel looked at; if a retriever change alters
/// how the client type at that location resolves, the panel's judgment about
/// that location still stands, and keying on the type would silently drop the
/// row into `unmatched` and shrink the denominator. Location is the stable part
/// of the identity, and shrinking the denominator is the failure mode that
/// makes a gate easier to pass.
///
/// One location can carry several sites (different client types, different
/// verdicts). Flagged wins: if ANY site at that location is a violation, the
/// engine flagged that location, which is what the panel was shown.
pub fn join_gold_to_engine(
    rows: &[GoldRow],
    engine_sites: &[(String, u64, bool)],
) -> Vec<JoinedRow> {
    use std::collections::HashMap;
    let mut by_loc: HashMap<(&str, u64), bool> = HashMap::new();
    for (file, line, flagged) in engine_sites {
        let e = by_loc.entry((file.as_str(), *line)).or_insert(false);
        *e = *e || *flagged;
    }
    rows.iter()
        .map(|r| JoinedRow {
            file_path: r.file_path.clone(),
            line_number: r.line_number,
            adjudicated: r.adjudicated,
            engine: match by_loc.get(&(r.file_path.as_str(), r.line_number)) {
                Some(true) => EngineSaid::Flagged,
                Some(false) => EngineSaid::NotFlagged,
                None => EngineSaid::Absent,
            },
        })
        .collect()
}
