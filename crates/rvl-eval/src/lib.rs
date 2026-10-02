//! rvl-eval library: destination-gate metrics and provenance enforcement.
//!
//! The binary in `main.rs` is the CLI; this library holds the gate logic so
//! it is testable without shelling out.

use anyhow::Context;
use serde::de::DeserializeOwned;
use std::path::Path;

pub mod compare;
pub mod consumption;
pub mod gate;
pub mod latency;
pub mod stats;

/// Load a JSONL file (blank lines skipped) into typed rows.
pub fn load_jsonl<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Vec<T>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<T>>>()
        .with_context(|| format!("{path:?} has malformed rows"))
}

/// Which array of an `rvl scan --out` document a subcommand scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Lane {
    /// Per-call-site rows (`.sites`), joined to gold on `site_id`.
    Sites,
    /// Repo-structure control rows (`.structure`), joined to gold on `class`.
    Structure,
}

impl Lane {
    /// The document key holding this lane's rows.
    pub fn key(self) -> &'static str {
        match self {
            Lane::Sites => "sites",
            Lane::Structure => "structure",
        }
    }
}

/// Load a findings JSON array. The one loader for the one findings format.
pub fn load_findings(path: &Path) -> anyhow::Result<Vec<compare::Finding>> {
    load_findings_lane(path, Lane::Sites)
}

/// Load one lane's findings. Accepts the bare array (`rvl-eval run --out`, or
/// a lane cut out of a scan document by hand) and the whole `rvl scan --out`
/// document, from which it takes the lane's own array.
pub fn load_findings_lane(path: &Path, lane: Lane) -> anyhow::Result<Vec<compare::Finding>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    let rows = match serde_json::from_str(&text)? {
        serde_json::Value::Object(mut doc) => doc.remove(lane.key()).with_context(|| {
            format!(
                "{path:?} is a scan document with no `{}` array; a missing lane is not an \
                 empty one (was it written by an older rvl?)",
                lane.key()
            )
        })?,
        rows => rows,
    };
    serde_json::from_value(rows).with_context(|| format!("{path:?} has malformed findings"))
}
