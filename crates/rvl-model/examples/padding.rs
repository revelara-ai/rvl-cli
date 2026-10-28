//! Compare own-length inputs with inputs padded to `max_length`, on a
//! model's answer key: how far the logits move, which verdicts change, the
//! precision and calibration of each control under both, and inferences per
//! second.
//!
//!     RVL_ONNXRUNTIME=<libonnxruntime> cargo run --release -p rvl-model \
//!         --example padding -- <bundle-dir> <rows.jsonl> [threads]
//!
//! `<bundle-dir>` holds `bundle.json`, `model.onnx`, `tokenizer.json` and,
//! for a model with a cell head, `cells.json` (`src/bundle.rs`). Each line of
//! `<rows.jsonl>` is `{"text": <rendered input>, "control": "RC-019",
//! "label": "violates"}`; `control` and `label` are optional and only feed
//! the per-control table.
//!
//! Per control, precision is the share of `violates` verdicts whose label is
//! `violates`, and ECE the expected calibration error of the verdict's
//! confidence over ten equal-width bins.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use rvl_model::{runtime, Bundle, Classifier, Options, Record, Verdict};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    text: String,
    #[serde(default)]
    control: String,
    #[serde(default)]
    label: Option<String>,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (dir, rows) = match &args[..] {
        [d, r] | [d, r, _] => (d, r),
        _ => bail!("usage: padding <bundle-dir> <rows.jsonl> [threads]"),
    };
    let threads = args
        .get(2)
        .map_or(Ok(rvl_model::DEFAULT_THREADS), |t| t.parse())?;
    let rows: Vec<Row> = std::fs::read_to_string(rows)
        .with_context(|| format!("read {rows}"))?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let texts: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
    let rt = runtime::load(&runtime::resolve_from_env()?)?;

    let mut runs = Vec::new();
    for fixed_padding in [true, false] {
        let opts = Options {
            threads,
            fixed_padding,
            ..Options::default()
        };
        let mut c = Classifier::new(rt, Bundle::load(dir.as_ref())?, opts)?;
        c.classify(&texts[..texts.len().min(4)], Duration::MAX)?; // warm up
        let start = Instant::now();
        let got = c.classify(&texts, Duration::MAX)?;
        let rate = texts.len() as f64 / start.elapsed().as_secs_f64();
        let name = if fixed_padding {
            "max_length"
        } else {
            "own length"
        };
        println!(
            "{name:>10}: {rate:.1} inferences/s over {} inputs, {threads} threads",
            texts.len()
        );
        runs.push(got.records);
    }
    let (fixed, own) = (&runs[0], &runs[1]);

    let (mut max_delta, mut max_logit) = (0f32, 0f32);
    let mut changed = Vec::new();
    for (i, (a, b)) in fixed.iter().zip(own).enumerate() {
        let pairs = a.logits.iter().zip(&b.logits);
        for (x, y) in pairs.chain(a.cell_logits.iter().zip(&b.cell_logits)) {
            max_delta = max_delta.max((x - y).abs());
            max_logit = max_logit.max(x.abs());
        }
        if a.verdict != b.verdict {
            changed.push(format!(
                "  row {i} {}: {} -> {}",
                rows[i].control,
                label(a),
                label(b)
            ));
        }
    }
    println!("max |logit delta|: {max_delta:e} (largest |logit|: {max_logit})");
    println!("argmax changes: {}", changed.len());
    for line in &changed {
        println!("{line}");
    }

    println!("control      n  precision(max_length)  ece(max_length)  precision(own)  ece(own)");
    let mut by_control: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, r) in rows.iter().enumerate() {
        if r.label.is_some() {
            by_control.entry(r.control.as_str()).or_default().push(i);
        }
    }
    for (control, at) in by_control {
        let gold: Vec<&str> = at
            .iter()
            .map(|&i| rows[i].label.as_deref().unwrap())
            .collect();
        let pick = |rs: &[Record]| at.iter().map(|&i| rs[i].clone()).collect::<Vec<_>>();
        let (pf, ef) = scores(&pick(fixed), &gold);
        let (po, eo) = scores(&pick(own), &gold);
        println!(
            "{control:<9} {:>4}  {pf:>21.3}  {ef:>15.3}  {po:>14.3}  {eo:>8.3}",
            at.len()
        );
    }
    Ok(())
}

fn label(r: &Record) -> &str {
    match &r.verdict {
        Verdict::Label(l) => l,
        Verdict::Abstain(_) => "abstain",
    }
}

/// Precision of `violates` (NaN with no `violates` verdict) and the ten-bin
/// expected calibration error.
fn scores(records: &[Record], gold: &[&str]) -> (f64, f64) {
    let flagged: Vec<bool> = records
        .iter()
        .zip(gold)
        .filter(|(r, _)| label(r) == "violates")
        .map(|(_, g)| *g == "violates")
        .collect();
    let precision = flagged.iter().filter(|&&t| t).count() as f64 / flagged.len() as f64;
    // Per bin, the summed confidence and the summed hits.
    let mut bins = [(0f64, 0f64); 10];
    for (r, g) in records.iter().zip(gold) {
        let p = r.confidence.unwrap_or(0.0);
        let b = &mut bins[((p * 10.0) as usize).min(9)];
        b.0 += p;
        b.1 += f64::from(u8::from(label(r) == *g));
    }
    let n = records.len() as f64;
    let ece = bins.iter().map(|&(conf, hit)| (hit - conf).abs() / n).sum();
    (precision, ece)
}
