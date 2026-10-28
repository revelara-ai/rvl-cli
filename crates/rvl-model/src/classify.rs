//! Batch inference: a record per input, inside a time budget.
//!
//! Determinism is per input (the same input gives the same bytes): the
//! session runs on a fixed intra-op thread count with ONNX Runtime's
//! deterministic kernels, one inter-op thread and sequential execution;
//! every input is truncated to the bundle's `max_length` and runs alone, as
//! a `[1, n]` tensor of its own `n` tokens, with no padding, so the tensor's
//! shape depends on the input and nothing else, and a record does not depend
//! on which inputs shared its batch; and argmax and softmax are computed
//! here, in f64, with ties going to the lower label index.
//!
//! Running an input alone is what makes the record independent of its batch
//! on every platform: ONNX Runtime picks kernels and summation orders by
//! tensor shape, per CPU architecture, so the same row in a `[4, n]` and a
//! `[1, n]` tensor can differ in the last bit of a logit. A record of an
//! input run at its own length can differ from one padded to `max_length`
//! ([`Options::fixed_padding`]) by more than that: a dynamically quantized
//! model scales each activation tensor by its range, and the padding rows
//! are in that range. `examples/padding.rs` measures the difference on a
//! model's answer key. Not padding is what makes inference fast: an
//! encoder's cost grows with the tokens it reads, and most inputs are a
//! fraction of `max_length`. Batching inputs together, which would need
//! padding again, measured slower than single runs on CPU.
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
    /// Pad every input to the bundle's `max_length`, as rvl did before it
    /// ran each input at its own length. Slower, and its logits differ in
    /// the last bits; kept to compare the two on a model's answer key.
    pub fixed_padding: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            threads: crate::DEFAULT_THREADS,
            batch_size: 8,
            fixed_padding: false,
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
    /// The raw cell-head output, one per [`Classifier::cells`] id; empty on
    /// an abstain and for a model without a cell head.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cell_logits: Vec<f32>,
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
    /// The output index of the verdict logits.
    logits_at: usize,
    /// The cell ids and the output index of the cell head, when it has one.
    cells: Option<(Vec<String>, usize)>,
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
        let pad_id = m
            .pad_id
            .or_else(|| tokenizer.token_to_id("[PAD]"))
            .unwrap_or(0);
        tokenizer.with_padding(opts.fixed_padding.then(|| PaddingParams {
            strategy: PaddingStrategy::Fixed(m.max_length),
            pad_id,
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
        let output = |name: &str| session.outputs().iter().position(|o| o.name() == name);
        let logits_at = output("logits").unwrap_or(0);
        let cells = match bundle.cells.clone() {
            None => None,
            Some(ids) => match output("cell_logits") {
                Some(at) => Some((ids, at)),
                None => bail!(
                    "{}: the bundle lists cells, and the model has no `cell_logits` output",
                    bundle.dir.display()
                ),
            },
        };

        Ok(Classifier {
            session,
            tokenizer,
            inputs,
            labels: m.labels.clone(),
            logits_at,
            cells,
            temperature: m.temperature,
            max_length: m.max_length,
            batch_size: opts.batch_size,
            model_id: m.model_id.clone(),
            weights_digest: bundle.weights_digest.clone(),
        })
    }

    /// The cell ids of the model's cell head; `None` without one.
    pub fn cells(&self) -> Option<&[String]> {
        self.cells.as_ref().map(|(ids, _)| ids.as_slice())
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
                cell_logits: Vec::new(),
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

    /// Run one input as a `[1, n]` batch of its `n` tokens and make its
    /// record.
    fn run_one(&mut self, text: &str) -> Result<Record> {
        let enc = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;
        let len = enc.get_ids().len();
        if len > self.max_length {
            bail!(
                "the tokenizer gave {len} tokens, more than the bundle's {}",
                self.max_length
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
        let (out_shape, logits) = outputs[self.logits_at]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow!("model output: {e}"))?;
        let width = self.labels.len();
        if out_shape.len() != 2 || out_shape[0] != 1 || out_shape[1] != width as i64 {
            bail!(
                "the model's logits are {:?}, expected [1, {width}] (one per label)",
                &out_shape[..]
            );
        }
        let cell_logits = match &self.cells {
            None => Vec::new(),
            Some((ids, at)) => {
                let (shape, v) = outputs[*at]
                    .try_extract_tensor::<f32>()
                    .map_err(|e| anyhow!("model cell output: {e}"))?;
                if shape.len() != 2 || shape[0] != 1 || shape[1] != ids.len() as i64 {
                    bail!(
                        "the model's cell_logits are {:?}, expected [1, {}] (one per cell)",
                        &shape[..],
                        ids.len()
                    );
                }
                v.to_vec()
            }
        };
        let (best, p) = calibrate(logits, self.temperature);
        Ok(Record {
            verdict: Verdict::Label(self.labels[best].clone()),
            confidence: Some(p),
            logits: logits.to_vec(),
            cell_logits,
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

/// The top cell among `allowed`: the index into `ids` of the highest
/// `cell_logits` entry whose id is in `allowed`, ties to the lower index.
/// `None` when no id is allowed or the logits do not match the ids.
pub fn top_cell(ids: &[String], cell_logits: &[f32], allowed: &[&str]) -> Option<usize> {
    if ids.len() != cell_logits.len() {
        return None;
    }
    let mut best: Option<usize> = None;
    for (i, id) in ids.iter().enumerate() {
        if allowed.contains(&id.as_str()) && best.is_none_or(|b| cell_logits[i] > cell_logits[b]) {
            best = Some(i);
        }
    }
    best
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
    fn the_top_cell_is_masked_to_the_frame() {
        let ids: Vec<String> = ["M1", "M2", "S1", "C1"].map(String::from).to_vec();
        let logits = [0.5, 3.0, 2.0, 2.0];
        assert_eq!(top_cell(&ids, &logits, &["M1", "M2", "S1"]), Some(1));
        assert_eq!(top_cell(&ids, &logits, &["M1", "S1", "C1"]), Some(2));
        assert_eq!(top_cell(&ids, &logits, &["X9"]), None);
        assert_eq!(top_cell(&ids, &logits[..2], &["M1"]), None);
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
