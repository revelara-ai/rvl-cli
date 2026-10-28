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
//!
//! The model's input text is written by [`render`], byte for byte as the
//! model's training renderer writes it.

pub mod bundle;
pub mod classify;
pub mod render;
pub mod runtime;

use std::time::Duration;

use serde::Deserialize;

pub use bundle::{Bundle, Manifest};
pub use classify::{AbstainReason, Classification, Classifier, Coverage, Options, Record, Verdict};
pub use render::{render_input, Layout, Question};
pub use runtime::{Runtime, Source};

/// The verdict outputs of a published decision model, in logit order.
pub const VERDICTS: [&str; 4] = ["violates", "satisfies", "not_applicable", "abstain"];

/// Intra-op threads when `scanner.model_threads` is absent.
pub const DEFAULT_THREADS: usize = 4;

/// The decision model's time budget per scan when
/// `scanner.decision_model_budget` is absent, and its ceiling under a hook
/// and `--changed-only`.
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(60);

/// The model keys of `.revelara.yaml`. Only these are read here; unknown keys
/// are tolerated so the shared file never breaks a consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelConfig {
    /// `scanner.model_threads`.
    pub threads: usize,
    /// `scanner.decision_model: on`: the scan decides served frame questions
    /// with the decision model. Off by default.
    pub decision_model: bool,
    /// `scanner.decision_model_budget`: the longest the decision model may
    /// run in one scan, inside the scan budget.
    pub budget: Duration,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            threads: DEFAULT_THREADS,
            decision_model: false,
            budget: DEFAULT_BUDGET,
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
    decision_model: Option<serde_yaml::Value>,
    decision_model_budget: Option<serde_yaml::Value>,
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
        let decision_model = match f.scanner.decision_model {
            None => false,
            Some(serde_yaml::Value::Bool(b)) => b,
            Some(serde_yaml::Value::String(s)) if s == "on" || s == "off" => s == "on",
            Some(other) => anyhow::bail!(
                "scanner.decision_model must be `on` or `off`, not {}",
                serde_yaml::to_string(&other).unwrap_or_default().trim()
            ),
        };
        let budget = match f.scanner.decision_model_budget {
            None => DEFAULT_BUDGET,
            Some(v) => parse_budget(&v).ok_or_else(|| {
                anyhow::anyhow!(
                    "scanner.decision_model_budget must be a positive duration \
                     (90, 90s, 15m, 1h), not {}",
                    serde_yaml::to_string(&v).unwrap_or_default().trim()
                )
            })?,
        };
        Ok(ModelConfig {
            threads,
            decision_model,
            budget,
        })
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

/// Bare seconds (`90`) or one unit suffix (`90s`, `15m`, `1h`); `None` for
/// anything else, and for zero.
fn parse_budget(v: &serde_yaml::Value) -> Option<Duration> {
    let text = match v {
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s.trim().to_string(),
        _ => return None,
    };
    let (num, scale) = match text.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        None => (text.as_str(), 1),
        Some((i, _)) => match text.split_at(i) {
            (n, "s") => (n, 1),
            (n, "m") => (n, 60),
            (n, "h") => (n, 3600),
            _ => return None,
        },
    };
    let n: u64 = num.parse().ok().filter(|&n| n > 0)?;
    Some(Duration::from_secs(n.checked_mul(scale)?))
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
    fn the_decision_model_is_off_unless_turned_on() {
        let on = |yaml: &str| ModelConfig::from_yaml_str(yaml).map(|c| c.decision_model);
        assert!(!on("").unwrap());
        assert!(on("scanner:\n  decision_model: on\n").unwrap());
        assert!(!on("scanner:\n  decision_model: off\n").unwrap());
        assert!(on("scanner:\n  decision_model: true\n").unwrap());
        assert!(on("scanner:\n  decision_model: maybe\n").is_err());
    }

    #[test]
    fn a_zero_or_malformed_thread_count_is_an_error() {
        assert!(ModelConfig::from_yaml_str("scanner:\n  model_threads: 0\n").is_err());
        assert!(ModelConfig::from_yaml_str("scanner:\n  model_threads: many\n").is_err());
    }

    #[test]
    fn the_decision_model_budget_defaults_to_sixty_seconds() {
        let budget = |yaml: &str| ModelConfig::from_yaml_str(yaml).map(|c| c.budget);
        assert_eq!(budget("").unwrap(), Duration::from_secs(60));
        let set = |v: &str| budget(&format!("scanner:\n  decision_model_budget: {v}\n"));
        assert_eq!(set("150").unwrap(), Duration::from_secs(150));
        assert_eq!(set("150s").unwrap(), Duration::from_secs(150));
        assert_eq!(set("\"5m\"").unwrap(), Duration::from_secs(300));
        assert_eq!(set("1h").unwrap(), Duration::from_secs(3600));
        for bad in ["0", "0s", "-5", "1.5", "5d", "soon", "[]"] {
            assert!(set(bad).is_err(), "{bad}");
        }
    }
}
