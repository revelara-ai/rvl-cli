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
    /// The artifact under test declares a grounding manifest and the run was
    /// handed a different one (po-av01j.90).
    GroundingManifestMismatch {
        artifact: String,
        declared: String,
        supplied: String,
    },
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
            Refusal::GroundingManifestMismatch {
                artifact,
                declared,
                supplied,
            } => write!(
                f,
                "refused: {artifact} declares grounding manifest {declared} but the run supplied {supplied}. The manifest must belong to the artifact under test."
            ),
            Refusal::GoldTooSmall { decided, required } => {
                write!(
                    f,
                    "refused: only {decided} decided adjudications < sample_size {required}"
                )
            }
        }
    }
}

/// Normalize a repo identity to lowercase `owner_repo`.
///
/// A PORT, not a new convention: `tools/quarantine_check.py::normalize` in
/// rvlscan-eval is the source of truth, and it exists because the collection
/// pipeline's manifest.json labels repos as `getsentry_sentry`, not
/// `getsentry/sentry`. The gate compared raw strings with exact byte equality,
/// so a real pipeline manifest matched NOTHING and the overlap refusal --
/// the fence that stops a gate repo that taught the engine -- silently found
/// zero every time (po-av01j.90).
///
/// Keep this in step with the Python. Two normalizers that drift are worse
/// than one that is wrong, because the drift is invisible until it admits
/// something.
pub fn normalize_repo_id(s: &str) -> String {
    s.trim().to_ascii_lowercase().replace('/', "_")
}

/// Parse a grounding manifest in either shape the ecosystem actually produces.
///
/// `.txt`: one `owner/name` per line, `#` comments allowed. This is the
/// hand-written form po-av01j.80 shipped.
///
/// `.json`: the collection pipeline's own manifest, an array of objects each
/// carrying a `label`. This is the form an operator would honestly reach for,
/// and the old line-based reader parsed it as junk lines (`[`, `{"label": ...},`)
/// with no error and zero matches -- a fail-open that looked like a clean run.
///
/// Returns NORMALIZED identities.
pub fn parse_grounding_manifest(text: &str) -> Vec<String> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') || trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            let mut out = Vec::new();
            collect_labels(&v, &mut out);
            return out;
        }
        // Looks like JSON and did NOT parse: return nothing so the caller
        // refuses. Falling through to the line reader here would turn
        // `{ this is not json` into a junk "identity", which is non-empty,
        // which means the empty-manifest refusal never fires and the run
        // passes on a manifest nobody could read. That is fail-open path (b)
        // from po-av01j.90 wearing a different hat.
        return Vec::new();
    }
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalize_repo_id)
        .collect()
}

/// Pull every `label` (and `repo`) string out of a pipeline manifest, whatever
/// nesting it uses. Tolerant on purpose: the manifest is someone else's format
/// and this side should not break when it gains a wrapper object.
fn collect_labels(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_labels(x, out)),
        serde_json::Value::Object(m) => {
            for key in ["label", "repo"] {
                if let Some(serde_json::Value::String(s)) = m.get(key) {
                    out.push(normalize_repo_id(s));
                }
            }
            m.values().for_each(|x| collect_labels(x, out));
        }
        _ => {}
    }
}

/// Parse a manifest.yaml string.
pub fn parse_manifest(yaml: &str) -> anyhow::Result<GateManifest> {
    Ok(serde_yaml::from_str(yaml)?)
}

#[derive(Debug, Deserialize)]
struct SeedSetEntry {
    name: String,
    /// Per-artifact grounding manifest (registry/seed_sets.yaml). Parsed away
    /// and never read before po-av01j.90, so NOTHING bound the manifest an
    /// operator passed on the command line to the artifact actually under
    /// test: you could hand the gate any manifest and it would be believed.
    #[serde(default)]
    grounding_manifest: Option<String>,
}

/// One seed-set designation: its name and, when declared, the grounding
/// manifest that belongs to it.
#[derive(Debug, Clone)]
pub struct SeedSet {
    pub name: String,
    pub grounding_manifest: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SeedSetsFile {
    seed_sets: Vec<SeedSetEntry>,
}

/// Names of seed sets from registry/seed_sets.yaml content.
pub fn parse_seed_set_names(yaml: &str) -> anyhow::Result<Vec<String>> {
    Ok(parse_seed_sets(yaml)?.into_iter().map(|s| s.name).collect())
}

/// Seed-set designations WITH their declared grounding manifests.
pub fn parse_seed_sets(yaml: &str) -> anyhow::Result<Vec<SeedSet>> {
    let f: SeedSetsFile = serde_yaml::from_str(yaml)?;
    Ok(f.seed_sets
        .into_iter()
        .map(|s| SeedSet {
            name: s.name,
            grounding_manifest: s.grounding_manifest,
        })
        .collect())
}

/// Refuse when a designated artifact declares a grounding manifest and the run
/// was handed a different one (po-av01j.90).
///
/// Without this the CLI-supplied manifest is unbound: the registry can say
/// "artifact X was grounded by manifest Y" and the gate will happily check
/// against manifest Z, which is the same shape of hole as a guard trusting a
/// label the guarded party supplies.
///
/// Only artifacts that DECLARE a manifest are checked. A seed set with no
/// declaration makes no claim, and inventing one for it would refuse honest
/// runs.
pub fn check_manifest_matches_artifact(
    seed_sets: &[SeedSet],
    artifact_name: &str,
    supplied_manifest: &Path,
) -> Result<(), Refusal> {
    let Some(entry) = seed_sets.iter().find(|s| s.name == artifact_name) else {
        return Ok(());
    };
    let Some(declared) = entry.grounding_manifest.as_deref() else {
        return Ok(());
    };
    // Compare on file name: the registry stores a repo-relative path and the
    // operator passes a path on their own disk, so the directories legitimately
    // differ while the artifact identity does not.
    let declared_file = Path::new(declared).file_name();
    let supplied_file = supplied_manifest.file_name();
    if declared_file != supplied_file {
        return Err(Refusal::GroundingManifestMismatch {
            artifact: artifact_name.to_string(),
            declared: declared.to_string(),
            supplied: supplied_manifest.display().to_string(),
        });
    }
    Ok(())
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
    let grounding_repos: Vec<String> = parse_grounding_manifest(&read(grounding_manifest)?);
    // A manifest that yields NO identities is not "no overlap", it is no
    // evidence. Empty files, comment-only files, and JSON the reader could not
    // understand all landed here as a silent pass before po-av01j.90; the
    // overlap check is the fence that stops a gate repo which taught the
    // engine, so an unusable manifest must refuse.
    if grounding_repos.is_empty() {
        return Err(Refusal::EvidenceUnreadable(format!(
            "grounding manifest {} yielded zero repo identities (empty, comment-only, or an \
             unrecognised format). The overlap check cannot pass on no evidence.",
            grounding_manifest.display()
        )));
    }
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
        // Normalize BOTH sides, HERE, rather than trusting the caller to have
        // done it. parse_grounding_manifest already normalizes, but this
        // function is public and takes a plain Vec<String>; an unnormalized
        // caller would silently get zero matches, which is the same fail-open
        // this bead exists to close. A guard that depends on its caller having
        // been careful is not a guard.
        if grounding_repos
            .iter()
            .any(|g| normalize_repo_id(g) == normalize_repo_id(&pin.repo))
        {
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
