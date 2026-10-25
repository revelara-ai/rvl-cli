//! Batch inference: a record per input, inside a time budget.
//!
//! Determinism (the same input gives the same bytes): the session runs on a
//! fixed intra-op thread count with ONNX Runtime's deterministic kernels, one
//! inter-op thread and sequential execution; every input is padded to the
//! bundle's `max_length` and runs alone, as a `[1, max_length]` tensor, so a
//! record does not depend on which inputs shared its batch; and argmax and
//! softmax are computed here, in f64, with ties going to the lower label
//! index.
//!
//! Running an input alone is what makes the record independent of its batch
//! on every platform: ONNX Runtime picks kernels and summation orders by
//! tensor shape, per CPU architecture, so the same row in a `[4, n]` and a
//! `[1, n]` tensor can differ in the last bit of a logit. A transformer
//! encoder at a fixed `max_length` already gives its matrix products
//! `max_length` rows per input, so batching inputs together buys little on
//! CPU.
//!
//! The budget is checked before each batch. A batch that has started runs to
//! its end, and every input after the first batch the budget did not allow
//! is recorded as [`Verdict::Abstain`], counted in [`Coverage`].

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _, Result};
use ort::session::Session;
use ort::value::{Tensor, TensorElementType, ValueType};
use serde::Serialize;
use tokenizers::{PaddingParams, PaddingStrategy, Tokenizer, TruncationParams};

use crate::bundle::Bundle;
use crate::runtime::Runtime;

/// How a classifier runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Intra-op threads (`scanner.model_threads`).
    pub threads: usize,
    /// Inputs per batch. The budget is checked between batches; each input
    /// in a batch is its own session run.
    pub batch_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            threads: crate::DEFAULT_THREADS,
            batch_size: 8,
        }
    }
}

/// What the model decided for one input.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The argmax label.
    Label(String),
    /// No inference ran for this input.
    Abstain(AbstainReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstainReason {
    /// The scan's model time budget ran out before this input's batch.
    TimeBudget,
}

/// One input's result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Record {
    pub verdict: Verdict,
    /// `softmax(logits / temperature)` at the verdict's label; absent on an
    /// abstain.
    pub confidence: Option<f64>,
    /// The raw model output; empty on an abstain.
    pub logits: Vec<f32>,
    pub model_id: String,
    /// `sha256:<hex>` of the bundle's `model.onnx`.
    pub weights_digest: String,
}

/// How much of the input the model reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub total: usize,
    pub inferred: usize,
    pub abstained: usize,
    /// The budget that stopped inference, when one was given.
    pub budget_ms: Option<u128>,
}

impl Coverage {
    /// The coverage line for a scan's `COVERAGE` section, or `None` when every
    /// input was inferred.
    pub fn line(&self) -> Option<String> {
        if self.abstained == 0 {
            return None;
        }
        let budget = match self.budget_ms {
            Some(ms) => format!("the {ms} ms model time budget"),
            None => "the model time budget".to_string(),
        };
        Some(format!(
            "{} of {} model input(s) abstain — {budget} ran out before inference reached them",
            self.abstained, self.total
        ))
    }
}

/// The records, in input order, and their coverage.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Classification {
    pub records: Vec<Record>,
    pub coverage: Coverage,
}

/// The model inputs this classifier knows how to fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Input {
    Ids,
    Mask,
    TypeIds,
}

/// A loaded bundle, ready to classify.
pub struct Classifier {
    session: Session,
    tokenizer: Tokenizer,
    inputs: Vec<(String, Input)>,
    labels: Vec<String>,
    temperature: f64,
    max_length: usize,
    batch_size: usize,
    model_id: String,
    weights_digest: String,
}

impl Classifier {
    pub fn new(runtime: &Runtime, bundle: Bundle, opts: Options) -> Result<Classifier> {
        if opts.threads == 0 {
            bail!("the model thread count must be at least 1");
        }
        if opts.batch_size == 0 {
            bail!("the model batch size must be at least 1");
        }
        let m = &bundle.manifest;
        let mut tokenizer = Tokenizer::from_file(bundle.tokenizer_path())
            .map_err(|e| anyhow!("{e}"))
            .with_context(|| format!("load {}", bundle.tokenizer_path().display()))?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: m.max_length,
                ..Default::default()
            }))
            .map_err(|e| anyhow!("{e}"))
            .context("set the tokenizer's truncation")?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::Fixed(m.max_length),
            pad_id: m.pad_id,
            ..Default::default()
        }));

        let session = open_session(runtime, &bundle.model, opts.threads)
            .with_context(|| format!("load {} into ONNX Runtime", bundle.dir.display()))?;

        let mut inputs = Vec::new();
        for outlet in session.inputs() {
            let which = match outlet.name() {
                "input_ids" => Input::Ids,
                "attention_mask" => Input::Mask,
                "token_type_ids" => Input::TypeIds,
                other => bail!(
                    "{}: the model takes an input `{other}`; a classifier bundle takes \
                     input_ids, attention_mask and token_type_ids only",
                    bundle.dir.display()
                ),
            };
            if !matches!(
                outlet.dtype(),
                ValueType::Tensor {
                    ty: TensorElementType::Int64,
                    ..
                }
            ) {
                bail!(
                    "{}: model input `{}` must be an int64 tensor, is {}",
                    bundle.dir.display(),
                    outlet.name(),
                    outlet.dtype()
                );
            }
            inputs.push((outlet.name().to_string(), which));
        }
        if !inputs.iter().any(|(_, i)| *i == Input::Ids) {
            bail!("{}: the model takes no `input_ids`", bundle.dir.display());
        }
        if session.outputs().is_empty() {
            bail!("{}: the model has no output", bundle.dir.display());
        }

        Ok(Classifier {
            session,
            tokenizer,
            inputs,
            labels: m.labels.clone(),
            temperature: m.temperature,
            max_length: m.max_length,
            batch_size: opts.batch_size,
            model_id: m.model_id.clone(),
            weights_digest: bundle.weights_digest.clone(),
        })
    }

    /// Classify `texts` within `budget`, measured from this call.
    pub fn classify(&mut self, texts: &[&str], budget: Duration) -> Result<Classification> {
        let start = Instant::now();
        let mut c = self.classify_until(texts, || start.elapsed() >= budget)?;
        c.coverage.budget_ms = Some(budget.as_millis());
        Ok(c)
    }

    /// Classify `texts`, asking `expired` before each batch whether the
    /// budget is spent. Once it says yes, every remaining input abstains.
    pub fn classify_until(
        &mut self,
        texts: &[&str],
        mut expired: impl FnMut() -> bool,
    ) -> Result<Classification> {
        let mut records = Vec::with_capacity(texts.len());
        for batch in texts.chunks(self.batch_size) {
            if expired() {
                break;
            }
            for text in batch {
                records.push(self.run_one(text)?);
            }
        }
        let inferred = records.len();
        while records.len() < texts.len() {
            records.push(Record {
                verdict: Verdict::Abstain(AbstainReason::TimeBudget),
                confidence: None,
                logits: Vec::new(),
                model_id: self.model_id.clone(),
                weights_digest: self.weights_digest.clone(),
            });
        }
        Ok(Classification {
            coverage: Coverage {
                total: texts.len(),
                inferred,
                abstained: texts.len() - inferred,
                budget_ms: None,
            },
            records,
        })
    }

    /// Run one input as a `[1, max_length]` batch and make its record.
    fn run_one(&mut self, text: &str) -> Result<Record> {
        let len = self.max_length;
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;
        if enc.get_ids().len() != len {
            bail!(
                "the tokenizer gave {} tokens, not the fixed {len}",
                enc.get_ids().len()
            );
        }
        let widen = |v: &[u32]| v.iter().map(|&x| i64::from(x)).collect::<Vec<_>>();
        let shape = vec![1, len as i64];
        let mut feed = Vec::with_capacity(self.inputs.len());
        for (name, which) in &self.inputs {
            let data = match which {
                Input::Ids => widen(enc.get_ids()),
                Input::Mask => widen(enc.get_attention_mask()),
                Input::TypeIds => widen(enc.get_type_ids()),
            };
            let t = Tensor::from_array((shape.clone(), data)).map_err(|e| anyhow!("{e}"))?;
            feed.push((name.clone(), t));
        }
        let outputs = self
            .session
            .run(feed)
            .map_err(|e| anyhow!("model inference: {e}"))?;
        let (out_shape, logits) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("model output: {e}"))?;
        let width = self.labels.len();
        if out_shape.len() != 2 || out_shape[0] != 1 || out_shape[1] != width as i64 {
            bail!(
                "the model's logits are {:?}, expected [1, {width}] (one per label)",
                &out_shape[..]
            );
        }
        let (best, p) = calibrate(logits, self.temperature);
        Ok(Record {
            verdict: Verdict::Label(self.labels[best].clone()),
            confidence: Some(p),
            logits: logits.to_vec(),
            model_id: self.model_id.clone(),
            weights_digest: self.weights_digest.clone(),
        })
    }
}

/// A CPU session on `threads` intra-op threads, deterministic kernels and
/// sequential execution of the graph.
fn open_session(runtime: &Runtime, model: &[u8], threads: usize) -> Result<Session> {
    let e = |e: ort::Error<_>| anyhow!("{e}");
    let mut b = Session::builder(&runtime.env)
        .map_err(|e| anyhow!("{e}"))?
        .with_intra_threads(threads)
        .map_err(e)?
        .with_inter_threads(1)
        .map_err(e)?
        .with_parallel_execution(false)
        .map_err(e)?
        .with_deterministic_compute(true)
        .map_err(e)?;
    b.commit_from_memory(model).map_err(|e| anyhow!("{e}"))
}

/// The argmax index (ties to the lower index) and its probability under
/// `softmax(logits / temperature)`.
pub fn calibrate(logits: &[f32], temperature: f64) -> (usize, f64) {
    let mut best = 0;
    for (i, &v) in logits.iter().enumerate() {
        if v > logits[best] {
            best = i;
        }
    }
    let top = f64::from(logits[best]);
    let sum: f64 = logits
        .iter()
        .map(|&v| ((f64::from(v) - top) / temperature).exp())
        .sum();
    (best, 1.0 / sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argmax_ties_go_to_the_lower_label() {
        assert_eq!(calibrate(&[1.0, 1.0], 1.0), (0, 0.5));
        assert_eq!(calibrate(&[0.0, 2.0, 2.0], 1.0).0, 1);
    }

    #[test]
    fn temperature_softens_confidence_without_changing_the_verdict() {
        let (a, p1) = calibrate(&[0.0, 2.0], 1.0);
        let (b, p2) = calibrate(&[0.0, 2.0], 2.0);
        assert_eq!((a, b), (1, 1));
        assert!((p1 - 1.0 / (1.0 + (-2.0f64).exp())).abs() < 1e-12, "{p1}");
        assert!((p2 - 1.0 / (1.0 + (-1.0f64).exp())).abs() < 1e-12, "{p2}");
        assert!(p2 < p1);
    }

    #[test]
    fn large_logits_do_not_overflow() {
        let (i, p) = calibrate(&[1000.0, -1000.0], 1.0);
        assert_eq!(i, 0);
        assert_eq!(p, 1.0);
    }

    #[test]
    fn coverage_is_silent_when_everything_was_inferred() {
        let c = Coverage {
            total: 3,
            inferred: 3,
            abstained: 0,
            budget_ms: Some(10),
        };
        assert_eq!(c.line(), None);
    }

    #[test]
    fn coverage_names_the_abstains_and_the_budget() {
        let c = Coverage {
            total: 10,
            inferred: 4,
            abstained: 6,
            budget_ms: Some(2000),
        };
        assert_eq!(
            c.line().unwrap(),
            "6 of 10 model input(s) abstain — the 2000 ms model time budget ran out before \
             inference reached them"
        );
    }
}
