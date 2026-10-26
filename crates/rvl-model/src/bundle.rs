//! A model bundle: one directory holding a classifier and what it needs.
//!
//! ```text
//! <bundle>/
//!   model.onnx      the classifier, exported to ONNX
//!   tokenizer.json  its tokenizer, in the Hugging Face `tokenizers` format
//!   bundle.json     {model_id, labels, temperature, max_length, pad_id}
//! ```
//!
//! The model's first output is its logits, `[batch, labels.len()]`. Its inputs
//! are named the way Hugging Face exports name them: `input_ids` and
//! `attention_mask`, and `token_type_ids` when the encoder has segments.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

pub const MODEL_FILE: &str = "model.onnx";
pub const TOKENIZER_FILE: &str = "tokenizer.json";
pub const MANIFEST_FILE: &str = "bundle.json";

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
    /// The token id padding is filled with.
    #[serde(default)]
    pub pad_id: u32,
}

/// A bundle read from disk and checked, not yet loaded into a runtime.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
    /// The bytes of `model.onnx`.
    pub model: Vec<u8>,
    /// `sha256:<hex>` of `model.onnx`.
    pub weights_digest: String,
}

impl Bundle {
    pub fn load(dir: &Path) -> Result<Bundle> {
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read(&path).with_context(|| format!("read {}", path.display()))
        };
        let manifest: Manifest = serde_json::from_slice(&read(MANIFEST_FILE)?)
            .with_context(|| format!("parse {}", dir.join(MANIFEST_FILE).display()))?;
        manifest
            .check()
            .with_context(|| format!("{}", dir.join(MANIFEST_FILE).display()))?;
        let model = read(MODEL_FILE)?;
        let weights_digest = format!("sha256:{}", hex::encode(Sha256::digest(&model)));
        Ok(Bundle {
            dir: dir.to_path_buf(),
            manifest,
            model,
            weights_digest,
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
        assert_eq!(b.manifest.pad_id, 0, "pad_id defaults to 0");
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
    fn a_missing_model_file_names_the_path() {
        let tmp = write_bundle(GOOD);
        std::fs::remove_file(tmp.path().join(MODEL_FILE)).unwrap();
        let err = format!("{:#}", Bundle::load(tmp.path()).unwrap_err());
        assert!(err.contains(MODEL_FILE), "{err}");
    }
}
