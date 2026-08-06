//! Single-use enforcement for gate sets (po-av01j.89).
//!
//! The gate manifest carries `consumed: bool`, documented "single-use per
//! version, never reset", and the loader refuses on it. Nothing ever wrote it.
//! Gate mode performed zero file writes, so the guard was a self-declared field
//! in a file the guarded process never mutates -- structurally the same defect
//! as the `repo: seed/minikube-test` self-declaration that the provenance
//! checker's own docstring says a guard must never believe.
//!
//! What that bought an attacker who was not even trying: run the gate, get
//! Wilson LB 0.86, FAIL. Tune specs for two weeks. Run the same command in the
//! same directory. `consumed: false` is still on disk. 0.91, PASS. Ship
//! "precision >= 0.90 (n=50, single-use gate set)". Every check green, every
//! gate honored, and the number is train-on-test.
//!
//! This replaces the self-declaration with an append-only ledger the gate
//! process itself writes.
//!
//! TWO DESIGN POINTS THAT ARE LOAD-BEARING:
//!
//! 1. The record is appended BEFORE scoring, never after. Writing after would
//!    mean a failing run does not consume the set, which is exactly the
//!    retry-until-it-passes loop above. Consumption is the act of LOOKING at
//!    the gold, not the act of liking what you saw.
//!
//! 2. Refusal keys on the verdicts HASH as well as the set_id. A set_id match
//!    catches an honest re-run; the hash catches the copy-and-rename path,
//!    where the same gold is presented under a new name. Neither alone is
//!    enough, and the second is the one someone reaches for under deadline
//!    pressure without feeling like they are cheating.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::gate::Refusal;

/// One consumption event: a gate run that read a gold set.
// PartialEq without Eq: `target` is an f64 and Eq would be a lie about it.
// Nothing compares records for total equality anyway; lookups key on set_id and
// the verdicts hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsumptionRecord {
    pub set_id: String,
    /// sha256 of verdicts.jsonl. Catches the same gold under a new set_id.
    pub verdicts_sha256: String,
    /// sha256 of manifest.yaml, so an edited manifest is visible in the ledger
    /// even when the gold itself is unchanged.
    pub manifest_sha256: String,
    pub target: f64,
    /// RFC3339-ish UTC stamp. Free-form on purpose: this is a human audit
    /// trail, and a parse failure here must never be able to block a gate.
    pub run_at: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Where the ledger lives for a given gate set: a single `consumed.jsonl`
/// beside the set directories, so one file covers every set in `gate-sets/`
/// and is committed once.
pub fn default_ledger_path(set_dir: &Path) -> PathBuf {
    set_dir.parent().unwrap_or(set_dir).join("consumed.jsonl")
}

/// Read the ledger. A MISSING file is an empty ledger (nothing consumed yet),
/// which is correct and not a refusal -- `gate-sets/` legitimately starts with
/// no ledger. An UNREADABLE or malformed file IS a refusal: a ledger we cannot
/// read cannot prove a set is unconsumed, and fail-closed is the house rule.
pub fn read_ledger(path: &Path) -> Result<Vec<ConsumptionRecord>, Refusal> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(Refusal::EvidenceUnreadable(format!(
                "consumption ledger {}: {e}",
                path.display()
            )))
        }
    };
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<ConsumptionRecord>(line) {
            Ok(r) => out.push(r),
            Err(e) => {
                return Err(Refusal::EvidenceUnreadable(format!(
                    "consumption ledger {} line {}: {e}",
                    path.display(),
                    i + 1
                )))
            }
        }
    }
    Ok(out)
}

/// Refuse if this set, or this exact gold under any name, has been run before.
pub fn check_unconsumed(
    ledger: &[ConsumptionRecord],
    set_id: &str,
    verdicts_sha256: &str,
) -> Result<(), Refusal> {
    if let Some(prev) = ledger.iter().find(|r| r.set_id == set_id) {
        return Err(Refusal::AlreadyConsumed {
            set_id: set_id.to_string(),
            reason: format!("set_id already run at {}", prev.run_at),
        });
    }
    if let Some(prev) = ledger.iter().find(|r| r.verdicts_sha256 == verdicts_sha256) {
        // The rename/copy path. Naming it explicitly matters: the operator
        // needs to know the gold is the same, not that they mistyped an id.
        return Err(Refusal::AlreadyConsumed {
            set_id: set_id.to_string(),
            reason: format!(
                "identical gold (sha256 {}) already run at {} as {}",
                &verdicts_sha256[..16.min(verdicts_sha256.len())],
                prev.run_at,
                prev.set_id
            ),
        });
    }
    Ok(())
}

/// Append a consumption record. Called BEFORE scoring; see the module docs.
///
/// A write failure is a REFUSAL, not a warning: if the run cannot be recorded,
/// the set cannot be proven single-use, and proceeding would produce exactly
/// the unenforced guarantee this module exists to remove.
pub fn append_consumption(path: &Path, rec: &ConsumptionRecord) -> Result<(), Refusal> {
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return Err(Refusal::EvidenceUnreadable(format!(
                "cannot create ledger directory {}: {e}",
                dir.display()
            )));
        }
    }
    let line = match serde_json::to_string(rec) {
        Ok(l) => l,
        Err(e) => {
            return Err(Refusal::EvidenceUnreadable(format!(
                "cannot serialize consumption record: {e}"
            )))
        }
    };
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| {
            Refusal::EvidenceUnreadable(format!("cannot open ledger {}: {e}", path.display()))
        })?;
    writeln!(f, "{line}").map_err(|e| {
        Refusal::EvidenceUnreadable(format!("cannot append to ledger {}: {e}", path.display()))
    })?;
    Ok(())
}
