//! A model bundle: one directory holding a classifier and what it needs.
//!
//! ```text
//! <bundle>/
//!   model.onnx      the classifier, exported to ONNX
//!   tokenizer.json  its tokenizer, in the Hugging Face `tokenizers` format
//!   bundle.json     {model_id, labels, temperature, max_length, pad_id}
//!   cells.json      {verdict_outputs, cells}, for a model with a cell head
//! ```
//!
//! A published bundle has no `bundle.json`: its signed manifest says the same
//! things, and [`Bundle::from_parts`] takes them from it.
//!
//! The model's logits are its output named `logits` (else its first output),
//! `[batch, labels.len()]`. A model with a cell head also has `cell_logits`,
//! `[batch, cells.len()]`, one per cell id of `cells.json`. Its inputs are
//! named the way Hugging Face exports name them: `input_ids` and
//! `attention_mask`, and `token_type_ids` when the encoder has segments.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub const MODEL_FILE: &str = "model.onnx";
pub const TOKENIZER_FILE: &str = "tokenizer.json";
pub const MANIFEST_FILE: &str = "bundle.json";
pub const CELLS_FILE: &str = "cells.json";

/// `bundle.json`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Names the model in every record, e.g. `revelara/boundary-encoder-v3`.
    pub model_id: String,
    /// The class of each logit, in output order.
    pub labels: Vec<String>,
    /// Calibration temperature: confidence is `softmax(logits / temperature)`.
    pub temperature: f64,
    /// Every input is truncated and padded to this many tokens, so a record
    /// never depends on which other inputs shared its batch.
    pub max_length: usize,
    /// The token id padding is filled with; absent, the tokenizer's `[PAD]`
    /// token, else 0.
    #[serde(default)]
    pub pad_id: Option<u32>,
}

/// `cells.json`: the cell id of each `cell_logits` output, in output order.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Cells {
    /// The width of the verdict logits, which must be the label count.
    pub verdict_outputs: usize,
    pub cells: Vec<String>,
}

/// A bundle read from disk and checked, not yet loaded into a runtime.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The bytes of `model.onnx`.
    pub model: Vec<u8>,
    /// `sha256:<hex>` of the model file.
    pub weights_digest: String,
    /// The cell ids of the model's cell head, when it has one.
    pub cells: Option<Vec<String>>,
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("read {}", path.display()))
}

impl Bundle {
    pub fn load(dir: &Path) -> Result<Bundle> {
        let path = dir.join(MANIFEST_FILE);
        let manifest: Manifest = serde_json::from_slice(&read(&path)?)
            .with_context(|| format!("parse {}", path.display()))?;
        Bundle::from_parts(dir, manifest, MODEL_FILE)
    }

    /// A bundle whose manifest came from elsewhere (a published bundle's
    /// signed manifest), with the model in `dir/model_file`.
    pub fn from_parts(dir: &Path, manifest: Manifest, model_file: &str) -> Result<Bundle> {
        manifest
            .check()
            .with_context(|| format!("the manifest of {}", dir.display()))?;
        let model = read(&dir.join(model_file))?;
        let weights_digest = format!("sha256:{}", hex::encode(Sha256::digest(&model)));
        let cells_path = dir.join(CELLS_FILE);
        let cells = match std::fs::read(&cells_path) {
            Ok(bytes) => {
                let c: Cells = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse {}", cells_path.display()))?;
                if c.verdict_outputs != manifest.labels.len() || c.cells.is_empty() {
                    bail!(
                        "{}: {} verdict outputs and {} cells, for {} labels",
                        cells_path.display(),
                        c.verdict_outputs,
                        c.cells.len(),
                        manifest.labels.len()
                    );
                }
                Some(c.cells)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e).with_context(|| format!("read {}", cells_path.display())),
        };
        Ok(Bundle {
            dir: dir.to_path_buf(),
            manifest,
            model,
            weights_digest,
            cells,
        })
    }

    pub fn tokenizer_path(&self) -> PathBuf {
        self.dir.join(TOKENIZER_FILE)
    }
}

impl Manifest {
    fn check(&self) -> Result<()> {
        if self.model_id.trim().is_empty() {
            bail!("model_id is empty");
        }
        if self.labels.len() < 2 {
            bail!(
                "a classifier needs at least two labels, got {:?}",
                self.labels
            );
        }
        if !(self.temperature.is_finite() && self.temperature > 0.0) {
            bail!(
                "temperature must be a positive number, got {}",
                self.temperature
            );
        }
        if self.max_length == 0 {
            bail!("max_length must be at least 1");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_bundle(manifest: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(MANIFEST_FILE), manifest).unwrap();
        std::fs::write(tmp.path().join(MODEL_FILE), b"not really onnx").unwrap();
        tmp
    }

    const GOOD: &str = r#"{"model_id":"m","labels":["a","b"],"temperature":2.0,"max_length":8}"#;

    #[test]
    fn the_weights_digest_is_the_sha256_of_the_model_file() {
        let tmp = write_bundle(GOOD);
        let b = Bundle::load(tmp.path()).unwrap();
        assert_eq!(
            b.weights_digest,
            format!("sha256:{}", hex::encode(Sha256::digest(b"not really onnx")))
        );
        assert_eq!(b.manifest.pad_id, None, "pad_id is optional");
        assert_eq!(b.cells, None, "no cells.json, no cell head");
    }

    #[test]
    fn a_manifest_that_cannot_calibrate_is_refused() {
        for bad in [
            r#"{"model_id":"m","labels":["a","b"],"temperature":0,"max_length":8}"#,
            r#"{"model_id":"m","labels":["a","b"],"temperature":-1,"max_length":8}"#,
            r#"{"model_id":"m","labels":["a"],"temperature":1,"max_length":8}"#,
            r#"{"model_id":" ","labels":["a","b"],"temperature":1,"max_length":8}"#,
            r#"{"model_id":"m","labels":["a","b"],"temperature":1,"max_length":0}"#,
            r#"{"model_id":"m","labels":["a","b"],"temperature":1,"max_length":8,"extra":1}"#,
        ] {
            let tmp = write_bundle(bad);
            assert!(Bundle::load(tmp.path()).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn cells_json_must_match_the_labels() {
        let tmp = write_bundle(GOOD);
        let cells = tmp.path().join(CELLS_FILE);
        std::fs::write(&cells, r#"{"verdict_outputs":2,"cells":["M1","S1"]}"#).unwrap();
        let b = Bundle::load(tmp.path()).unwrap();
        assert_eq!(b.cells, Some(vec!["M1".to_string(), "S1".to_string()]));
        std::fs::write(&cells, r#"{"verdict_outputs":4,"cells":["M1"]}"#).unwrap();
        assert!(Bundle::load(tmp.path()).is_err());
    }

    #[test]
    fn a_missing_model_file_names_the_path() {
        let tmp = write_bundle(GOOD);
        std::fs::remove_file(tmp.path().join(MODEL_FILE)).unwrap();
        let err = format!("{:#}", Bundle::load(tmp.path()).unwrap_err());
        assert!(err.contains(MODEL_FILE), "{err}");
    }
}
