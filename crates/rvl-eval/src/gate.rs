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
    /// Dependency provenance, required for languages whose retrieval depends on
    /// installed packages (see `language_requires_deps`). Defaulted so the
    /// already-minted Go set, and any future bare-checkout language, keeps
    /// parsing without ceremony.
    #[serde(default)]
    pub deps: Vec<DepsPin>,
}

/// One installed dependency tree a TypeScript gate set depends on.
///
/// A frozen SHA does not determine the TypeScript packet stream. tsindex
/// resolves client types through the TS compiler, which needs `node_modules`,
/// and on a bare clone that resolution fails SILENTLY rather than erroring:
/// measured on infisical at one fixed SHA, installing dependencies took the
/// stream from 1,911 sites to 83,927. Same commit, 44x the data.
///
/// So a TS manifest that pins only a SHA claims a reproducibility it cannot
/// deliver. Pinning the lockfile content hash closes that: the resolved tree is
/// part of the evidence, not an ambient property of the machine that minted it.
///
/// Monorepos install per workspace, hence a list: infisical needs root,
/// `backend/` and `frontend/`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DepsPin {
    /// The `packageManager` field's value, e.g. `pnpm@10.33.2`. The five TS
    /// candidates surveyed used three different managers, each version-pinned,
    /// so the mint step has to honour this rather than assume npm.
    pub package_manager: String,
    /// Repo-relative path to the lockfile, e.g. `backend/package-lock.json`.
    pub lockfile: String,
    /// sha256 of the lockfile's bytes.
    pub lockfile_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdjudicationMeta {
    pub protocol: String,
    pub panel: String,
    pub adjudicator: String,
    pub date: String,
}

/// A gate set retracted after minting (po-av01j.119).
///
/// A set can be mechanically well-formed and still not be evidence. eval-go-v1
/// parsed, pinned four quarantined repos at frozen SHAs, and carried a properly
/// adjudicated 75-row sample -- and was measured against a spec cache whose own
/// provenance stamp says "NEVER valid as gate evidence". Every check the gate
/// ran passed, because none of them looked at the cache.
///
/// WHY WITHDRAWAL IS RECORDED IN THE SET RATHER THAN BY DELETING IT: the
/// withdrawal record is the useful artifact. Deleting the set removes the
/// counter-record while leaving the number fully citable from git history, from
/// the merged PR, and from anyone's notes. A withdrawn set that refuses loudly
/// is worth more than an absent one that refuses nothing.
///
/// ON SELF-DECLARATION: `tools/provenance_check.py` refuses to let an artifact
/// declare its own eligibility, and this block is exactly such a declaration --
/// in the opposite direction. It can only ever refuse a set, never admit one,
/// so forging it achieves nothing and forgetting it changes nothing that was
/// previously true. That asymmetry is the whole reason it is safe here and the
/// reason `gate_eligible` must NOT be added alongside it (po-av01j.120).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Withdrawal {
    pub date: String,
    /// Who made the call. A withdrawal is a judgment, and judgments are owned.
    pub by: String,
    /// Why, in full. This text is carried into the refusal, so the operator who
    /// hits it does not have to go and read the file that just refused them.
    pub reason: String,
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
    /// Present only on a retracted set. Absent means not withdrawn, which is
    /// the only default that lets an already-minted set keep parsing -- and is
    /// safe precisely because the block can only subtract eligibility.
    #[serde(default)]
    pub withdrawn: Option<Withdrawal>,
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
    /// The set carries a `withdrawn:` block: retracted after minting by a
    /// human decision (po-av01j.119). Checked before everything else, because
    /// a withdrawn set is usually also wrong mechanically and the mechanical
    /// complaint invites fixing the symptom and re-running.
    Withdrawn { set_id: String, reason: String },
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
    /// A gate set in a language whose retrieval depends on installed packages
    /// pinned a commit but no dependency tree (po-av01j.117). The SHA alone
    /// does not determine the packet stream, so the set is not reproducible.
    MissingDepsProvenance { repo: String, language: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Withdrawn { set_id, reason } => write!(
                f,
                "refused: {set_id} is withdrawn and is not evidence. {reason} \
                 A withdrawn set is never rescinded in place; mint a fresh version."
            ),
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
            Refusal::MissingDepsProvenance { repo, language } => write!(
                f,
                "refused: {repo} pins a commit but no dependency tree, and {language} retrieval reads installed packages. \
                 The SHA alone does not determine the packet stream (measured: 1,911 -> 83,927 sites at one fixed commit, \
                 depending only on whether dependencies were installed). Pin each workspace's lockfile path, sha256 and \
                 packageManager under `deps:`."
            ),
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
    let manifest: GateManifest = serde_yaml::from_str(yaml)?;
    if let Some(w) = &manifest.withdrawn {
        // A withdrawal that records no reason still refuses the set, and tells
        // the next reader nothing about why -- which is how a bad number gets
        // quietly re-minted from the same bad inputs.
        for (field, value) in [("reason", &w.reason), ("date", &w.date), ("by", &w.by)] {
            if value.trim().is_empty() {
                anyhow::bail!(
                    "withdrawn.{field} is empty: a withdrawal that records nothing is not a record"
                );
            }
        }
    }
    Ok(manifest)
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
/// Languages whose retrieval reads an INSTALLED dependency tree, so a commit
/// alone is not sufficient provenance for a gate set.
///
/// Go and Python retrievers read a bare checkout, so demanding a lockfile there
/// would be ceremony with no reproducibility gain. TypeScript genuinely needs
/// it. Kept as an explicit list rather than a default-on rule so adding a
/// language is a deliberate decision with this comment in front of it.
pub fn language_requires_deps(language: &str) -> bool {
    matches!(
        language.to_ascii_lowercase().as_str(),
        "typescript" | "javascript" | "ts" | "js"
    )
}

/// Compare a pinned lockfile hash against what is actually on disk at mint or
/// run time. Split out as a pure function so it is testable without a checkout.
pub fn check_lockfile_matches(pin: &DepsPin, actual_sha256: &str) -> Result<(), Refusal> {
    if pin.lockfile_sha256.eq_ignore_ascii_case(actual_sha256) {
        return Ok(());
    }
    Err(Refusal::EvidenceUnreadable(format!(
        "lockfile {} does not match the manifest: pinned {}, found {}",
        pin.lockfile, pin.lockfile_sha256, actual_sha256
    )))
}

pub fn validate_gate_set(
    manifest: &GateManifest,
    seed_set_names: &[String],
    registry: &Registry,
    grounding_repos: &[String],
) -> Result<u64, Refusal> {
    // FIRST, ahead of every mechanical check. A withdrawn set typically also
    // trips one of the checks below, and answering "repo not quarantined"
    // invites an operator to fix the registry entry and re-run something a
    // human already ruled out.
    if let Some(w) = &manifest.withdrawn {
        return Err(Refusal::Withdrawn {
            set_id: manifest.set_id.clone(),
            reason: w.reason.clone(),
        });
    }
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
        // A SHA alone does not determine the packet stream in these languages;
        // see DepsPin. A deps block whose hash is blank pins nothing while
        // LOOKING like provenance in review, which is worse than omitting it,
        // so require every entry to carry a non-empty lockfile hash.
        if language_requires_deps(&manifest.language)
            && (pin.deps.is_empty()
                || pin
                    .deps
                    .iter()
                    .any(|d| d.lockfile_sha256.trim().is_empty() || d.lockfile.trim().is_empty()))
        {
            return Err(Refusal::MissingDepsProvenance {
                repo: pin.repo.clone(),
                language: manifest.language.clone(),
            });
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
