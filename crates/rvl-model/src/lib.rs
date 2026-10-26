//! Local classifier inference on CPU, through ONNX Runtime.
//!
//! A scan lane hands a batch of texts to a [`Classifier`] built from a model
//! bundle directory ([`Bundle`]) and gets one [`Record`] back per text: the
//! argmax label, its temperature-calibrated confidence, the raw logits, the
//! model id and the digest of the weights. Inference runs on a fixed number
//! of CPU threads (`scanner.model_threads`, default [`DEFAULT_THREADS`]) and
//! inside a per-scan time budget; the inputs the budget does not reach are
//! abstains, counted in a [`Coverage`] line.
//!
//! ONNX Runtime is a native library loaded at run time, never linked: a
//! release vendors a pinned build beside `rvl` ([`runtime`]).

pub mod bundle;
pub mod classify;
pub mod runtime;

use serde::Deserialize;

pub use bundle::{Bundle, Manifest};
pub use classify::{AbstainReason, Classification, Classifier, Coverage, Options, Record, Verdict};
pub use runtime::{Runtime, Source};

/// Intra-op threads when `scanner.model_threads` is absent.
pub const DEFAULT_THREADS: usize = 4;

/// The model keys of `.revelara.yaml`. Only these are read here; unknown keys
/// are tolerated so the shared file never breaks a consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelConfig {
    /// `scanner.model_threads`.
    pub threads: usize,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            threads: DEFAULT_THREADS,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RepoFile {
    scanner: ScannerModelSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ScannerModelSection {
    model_threads: Option<usize>,
}

impl ModelConfig {
    /// Parse the model keys out of a `.revelara.yaml` document. A malformed
    /// file is an error: a thread count nobody asked for would change what
    /// the scan reports as configured.
    pub fn from_yaml_str(text: &str) -> anyhow::Result<ModelConfig> {
        let f: RepoFile = serde_yaml::from_str(text)?;
        let threads = f.scanner.model_threads.unwrap_or(DEFAULT_THREADS);
        if threads == 0 {
            anyhow::bail!("scanner.model_threads must be at least 1");
        }
        Ok(ModelConfig { threads })
    }

    /// Load from `<repo_root>/.revelara.yaml`. A missing file is the default.
    pub fn load(repo_root: &std::path::Path) -> anyhow::Result<ModelConfig> {
        match std::fs::read_to_string(repo_root.join(".revelara.yaml")) {
            Ok(text) => Self::from_yaml_str(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_threads_defaults_to_four() {
        assert_eq!(
            ModelConfig::from_yaml_str("project: x\n").unwrap().threads,
            4
        );
        assert_eq!(ModelConfig::from_yaml_str("").unwrap().threads, 4);
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(ModelConfig::load(tmp.path()).unwrap().threads, 4);
    }

    #[test]
    fn model_threads_is_read_from_the_scanner_section() {
        let cfg = ModelConfig::from_yaml_str("scanner:\n  model_threads: 1\n  waivers: []\n");
        assert_eq!(cfg.unwrap().threads, 1);
    }

    #[test]
    fn a_zero_or_malformed_thread_count_is_an_error() {
        assert!(ModelConfig::from_yaml_str("scanner:\n  model_threads: 0\n").is_err());
        assert!(ModelConfig::from_yaml_str("scanner:\n  model_threads: many\n").is_err());
    }
}
