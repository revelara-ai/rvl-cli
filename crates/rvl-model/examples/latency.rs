//! Milliseconds a site for one model file of a bundle, at each thread count:
//! how `scanner.model_threads` and the served file (`model.onnx` or
//! `model.int8.onnx`) bear on a scan's time in the decision-model lane.
//!
//!     RVL_ONNXRUNTIME=<libonnxruntime> cargo run --release -p rvl-model \
//!         --example latency -- <bundle-dir> <model-file> <rows.jsonl> [threads...]
//!
//! `<bundle-dir>` holds `tokenizer.json`, `<model-file>`, `cells.json` for a
//! model with a cell head, and `bundle.json` (`src/bundle.rs`) or, as in the
//! cached bundle `rvl model sync` writes, the published `manifest.json`. Each
//! line of
//! `<rows.jsonl>` has a `text`, the rendered input: the lines
//! `RVL_DECISION_MODEL_INPUTS` writes from a scan will do. Threads default
//! to 1 and 4. Each input runs at its own length, as a scan runs it; the
//! inputs run once to warm up, then three times timed, and the fastest run
//! is printed.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _, Result};
use rvl_model::{bundle, runtime, Bundle, Classifier, Manifest, Options};
use serde::Deserialize;

#[derive(Deserialize)]
struct Row {
    text: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir, model_file, rows, threads @ ..] = &args[..] else {
        bail!("usage: latency <bundle-dir> <model-file> <rows.jsonl> [threads...]");
    };
    let threads: Vec<usize> = if threads.is_empty() {
        vec![1, 4]
    } else {
        threads
            .iter()
            .map(|t| t.parse())
            .collect::<Result<_, _>>()?
    };
    let rows: Vec<Row> = std::fs::read_to_string(rows)
        .with_context(|| format!("read {rows}"))?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    let texts: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
    let dir = Path::new(dir);
    let manifest = manifest(dir)?;
    let rt = runtime::load(&runtime::resolve_from_env()?)?;
    for threads in threads {
        let b = Bundle::from_parts(dir, manifest.clone(), model_file)?;
        let opts = Options {
            threads,
            ..Options::default()
        };
        let mut c = Classifier::new(rt, b, opts)?;
        c.classify(&texts, Duration::MAX)?; // warm up
        let mut best = Duration::MAX;
        for _ in 0..3 {
            let start = Instant::now();
            c.classify(&texts, Duration::MAX)?;
            best = best.min(start.elapsed());
        }
        let ms = best.as_secs_f64() * 1000.0 / texts.len() as f64;
        println!(
            "{model_file}: {ms:.1} ms a site, {threads} thread(s), {} inputs, {}",
            texts.len(),
            std::env::consts::ARCH
        );
    }
    Ok(())
}

/// `bundle.json`, else the fields of a published `manifest.json`.
fn manifest(dir: &Path) -> Result<Manifest> {
    if let Ok(bytes) = std::fs::read(dir.join(bundle::MANIFEST_FILE)) {
        return Ok(serde_json::from_slice(&bytes)?);
    }
    #[derive(Deserialize)]
    struct Published {
        model_id: String,
        temperature: f64,
        max_len: usize,
    }
    let path = dir.join("manifest.json");
    let p: Published = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )?;
    Ok(Manifest {
        model_id: p.model_id,
        labels: rvl_model::VERDICTS.map(String::from).to_vec(),
        temperature: p.temperature,
        max_length: p.max_len,
        pad_id: None,
    })
}
