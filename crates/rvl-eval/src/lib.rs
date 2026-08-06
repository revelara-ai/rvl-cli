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

/// Load a findings JSON array. The one loader for the one findings format.
pub fn load_findings(path: &Path) -> anyhow::Result<Vec<compare::Finding>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {path:?}"))?;
    Ok(serde_json::from_str(&text)?)
}
