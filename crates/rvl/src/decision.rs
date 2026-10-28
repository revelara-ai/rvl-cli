//! The decision-model lane: the sites the deterministic lanes left undecided,
//! asked a served frame's question by the local decision model.
//!
//! It runs after the deterministic lanes and before the agent lane, only when
//! the repository turns it on (`scanner.decision_model: on` in
//! `.revelara.yaml`), and only on the bundle `rvl model sync` cached and
//! verified. Inference runs on this machine: no code leaves it.
//!
//! For each undecided call site and each `call_site` frame of the spec cache
//! whose class markers cover the site's class:
//!
//! * a control the bundle's manifest SERVES is rendered, inferred and
//!   decided: `violates` becomes an advisory finding, `satisfies` and
//!   `not_applicable` a decided site, each with the model's record (model
//!   id, weights digest, confidence) in `--out`;
//! * a served control whose manifest entry lists `served_classes` is asked
//!   only for a site whose class family is listed; any other site abstains,
//!   counted as out of distribution on the coverage line;
//! * any other control abstains, and the coverage line names it.
//!
//! Each decision's reason is the frame cell the model's cell head ranks top,
//! masked to the frame's cells, with that cell's definition: "RC-022
//! violates, M2: <definition>". A `violates` whose top cell is not a
//! manifestation cell of the frame abstains, counted on the coverage line:
//! the model's two heads disagree, and its measured precision is of flags
//! with a manifestation cell. Under the other verdicts, a top cell of
//! another kind is not shown: the reason is unknown. A model without a cell
//! head says the reason is not in this model.
//!
//! Model findings are advisory: their severity is not graded.

use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

use indicatif::ProgressBar;

use rvl_cache::model::{ModelManifest, ModelStore, MODEL_DIR};
use rvl_model::render::{self, Layout, Question};
use rvl_spec::frames::{Frame, CALL_SITE};

use crate::render as ladder;

/// The lane's part of the `--out` document.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// Empty when the lane did not run.
    pub model_id: String,
    /// `sha256:<hex>` of the model file.
    pub weights_digest: String,
    /// Why the lane did not run; null when it ran.
    pub not_run: Option<String>,
    pub served_controls: Vec<String>,
    pub withheld_controls: Vec<String>,
    /// One row per (site, served frame) the model was asked.
    pub sites: Vec<Decision>,
    /// The site questions of controls the model does not serve, per control.
    pub unserved: Vec<Unserved>,
    /// The site questions of served controls whose class family the manifest
    /// does not serve for that control, per control.
    pub out_of_distribution: Vec<Unserved>,
    /// The lines the COVERAGE block prints.
    pub coverage: Vec<String>,
}

/// The model's answer for one site and one frame, with its record.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decision {
    pub site_id: String,
    pub class: String,
    pub control: String,
    pub frame_version: String,
    /// `violates` | `satisfies` | `not_applicable` | `abstain`.
    pub verdict: String,
    pub confidence: Option<f64>,
    /// The frame cell given as the reason, when there is one.
    pub cell: Option<String>,
    pub reason: String,
    pub model_id: String,
    pub weights_digest: String,
    /// The model said `violates` and this abstain replaced it, because its
    /// top cell is not a manifestation cell of the frame.
    #[serde(skip)]
    pub off_cell: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unserved {
    pub control: String,
    pub sites: usize,
}

/// What the lane hands the scan.
#[derive(Debug, Default)]
pub struct LaneOutput {
    /// Advisory ladder rows, one per `violates` decision.
    pub findings: Vec<ladder::Finding>,
    pub summary: Summary,
}

/// One question for the model: a site and a served frame.
struct Ask<'a> {
    site: &'a rvl_core::Site,
    class: String,
    frame: &'a Frame,
}

/// Whether the repository turned the lane on. A `.revelara.yaml` that does
/// not parse leaves it off, said on stderr.
pub fn enabled(repo_root: &Path) -> Option<rvl_model::ModelConfig> {
    match rvl_model::ModelConfig::load(repo_root) {
        Ok(c) if c.decision_model => Some(c),
        Ok(_) => None,
        Err(e) => {
            eprintln!("warning: the decision model lane is off: .revelara.yaml: {e:#}");
            None
        }
    }
}

/// Run the lane over the deterministic lanes' verdicts.
#[allow(clippy::too_many_arguments)]
pub fn run(
    cfg: &rvl_model::ModelConfig,
    repo_root: &Path,
    cache_root: &Path,
    keyset: &rvl_cache::Keyset,
    findings: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    specs: &rvl_spec::SpecCache,
    budget: Duration,
    progress: &ProgressBar,
) -> LaneOutput {
    crate::progress::step(progress, "Loading the decision model");
    let loaded = ModelStore::open(&cache_root.join(MODEL_DIR)).and_then(|s| s.load(keyset));
    let cached = match loaded {
        Ok(c) => c,
        Err(e) => return not_run(format!("{e:#}; run `{} model sync`", rvl_core::BIN)),
    };
    let m = &cached.manifest;
    let Selected {
        asks,
        unserved,
        out_of_distribution,
    } = select(findings, sites, specs.frames(), m);
    let mut summary = Summary {
        model_id: m.model_id.clone(),
        served_controls: m
            .served_controls
            .iter()
            .map(|c| c.control.clone())
            .collect(),
        withheld_controls: m
            .withheld_controls
            .iter()
            .map(|c| c.control.clone())
            .collect(),
        unserved,
        out_of_distribution,
        ..Summary::default()
    };
    let mut budget_lines = Vec::new();
    if !asks.is_empty() {
        let imports = imports_of(repo_root, &asks);
        match infer(cfg, &cached.dir, m, &asks, &imports, budget, progress) {
            Ok((digest, decisions, lines)) => {
                summary.weights_digest = digest;
                summary.sites = decisions;
                budget_lines = lines;
            }
            Err(e) => summary.not_run = Some(format!("{e:#}")),
        }
    }
    summary.coverage = coverage_lines(&summary, budget_lines, specs.frames_rejected());
    LaneOutput {
        findings: summary.sites.iter().filter_map(finding_of).collect(),
        summary,
    }
}

fn not_run(why: String) -> LaneOutput {
    let mut summary = Summary {
        not_run: Some(why),
        ..Summary::default()
    };
    summary.coverage = coverage_lines(&summary, Vec::new(), 0);
    LaneOutput {
        findings: Vec::new(),
        summary,
    }
}

/// What [`select`] found.
struct Selected<'a> {
    /// The site questions to ask, in site order then frame order.
    asks: Vec<Ask<'a>>,
    /// The unserved controls with how many site questions each left
    /// unanswered.
    unserved: Vec<Unserved>,
    /// The served controls with how many site questions each left
    /// unanswered because the site's class family is not served.
    out_of_distribution: Vec<Unserved>,
}

fn select<'a>(
    findings: &[rvl_propagate::Finding],
    sites: &'a [rvl_core::Site],
    frames: &'a [Frame],
    manifest: &ModelManifest,
) -> Selected<'a> {
    let mut asks = Vec::new();
    let mut unserved: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut ood: std::collections::BTreeMap<&str, usize> = Default::default();
    for (f, site) in findings.iter().zip(sites) {
        if f.verdict.is_resolved() {
            continue;
        }
        let class = rvl_triage::class_key_string(site);
        for frame in frames
            .iter()
            .filter(|fr| fr.habitat == CALL_SITE && fr.covers_class(&class))
        {
            if !manifest.serves(&frame.control) {
                *unserved.entry(frame.control.as_str()).or_default() += 1;
            } else if !manifest.serves_class(&frame.control, &class) {
                *ood.entry(frame.control.as_str()).or_default() += 1;
            } else {
                asks.push(Ask {
                    site,
                    class: class.clone(),
                    frame,
                });
            }
        }
    }
    let rows = |counts: std::collections::BTreeMap<&str, usize>| {
        counts
            .into_iter()
            .map(|(control, sites)| Unserved {
                control: control.to_string(),
                sites,
            })
            .collect()
    };
    Selected {
        asks,
        unserved: rows(unserved),
        out_of_distribution: rows(ood),
    }
}

/// Load the runtime and the bundle, and ask every question, the status line
/// counting them. Returns the weights digest, the decisions and, when the
/// budget cut inference short, the coverage lines that say so.
fn infer(
    cfg: &rvl_model::ModelConfig,
    dir: &Path,
    m: &ModelManifest,
    asks: &[Ask],
    imports: &Imports,
    budget: Duration,
    progress: &ProgressBar,
) -> anyhow::Result<(String, Vec<Decision>, Vec<String>)> {
    let layout = match m.layout.as_str() {
        "compact" => Layout::Compact,
        "full" => Layout::Full,
        other => anyhow::bail!("the model's layout {other:?} is not one rvl renders"),
    };
    let runtime = rvl_model::runtime::load(&rvl_model::runtime::resolve_from_env()?)?;
    let bundle = rvl_model::Bundle::from_parts(
        dir,
        rvl_model::Manifest {
            model_id: m.model_id.clone(),
            labels: rvl_model::VERDICTS.map(String::from).to_vec(),
            temperature: m.temperature,
            max_length: m.max_len,
            pad_id: None,
        },
        &m.model_file().name,
    )?;
    let digest = bundle.weights_digest.clone();
    let opts = rvl_model::Options {
        threads: cfg.threads,
        ..Default::default()
    };
    let mut classifier = rvl_model::Classifier::new(runtime, bundle, opts)?;
    let texts: Vec<String> = asks.iter().map(|a| input_of(a, imports, layout)).collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    progress.set_message("Running the decision model");
    progress.set_position(0);
    progress.set_length(refs.len() as u64);
    // `classify`'s budget, measured from this call, with the count moved on
    // between batches.
    let start = Instant::now();
    let mut c = classifier.classify_until(
        &refs,
        batch_hook(progress, opts.batch_size, || start.elapsed() >= budget),
    )?;
    c.coverage.budget_ms = Some(budget.as_millis());
    let cells = classifier.cells();
    let decisions = asks
        .iter()
        .zip(&c.records)
        .map(|(a, r)| decide(a, r, cells))
        .collect();
    let mut lines: Vec<String> = c.coverage.line().into_iter().collect();
    lines.extend(cut_line(&asks[c.coverage.inferred..]));
    Ok((digest, decisions, lines))
}

/// What a budget cut dropped: the questions are asked site by site in scan
/// order, each site's frames in turn, so the cut is the tail of that order.
/// `None` when nothing was cut.
fn cut_line(cut: &[Ask]) -> Option<String> {
    let first = cut.first()?;
    let files: std::collections::BTreeSet<&str> =
        cut.iter().map(|a| a.site.file_path.as_str()).collect();
    Some(format!(
        "decision model: questions are asked site by site in scan order, so the budget cut \
         the last {} question(s), in {} file(s) from {} on; \
         `scanner.decision_model_budget` raises the budget (a hook and --changed-only hold \
         it to {}s)",
        cut.len(),
        files.len(),
        first.site.file_path,
        rvl_model::DEFAULT_BUDGET.as_secs()
    ))
}

/// The hook `classify_until` asks before each batch of `batch` questions:
/// when the budget is not spent, the count moves on by the batch about to be
/// asked. A spent budget leaves the count where it is: the rest abstain.
fn batch_hook<'a>(
    progress: &'a ProgressBar,
    batch: usize,
    mut expired: impl FnMut() -> bool + 'a,
) -> impl FnMut() -> bool + 'a {
    move || {
        if expired() {
            return true;
        }
        let next = progress.position() + batch as u64;
        progress.set_position(progress.length().map_or(next, |len| next.min(len)));
        false
    }
}

/// The import block of each file asked about, by its path in the site.
type Imports = std::collections::HashMap<String, String>;

/// Each file is read once, however many questions its sites are asked. A
/// file that cannot be read has no import block.
fn imports_of(repo_root: &Path, asks: &[Ask]) -> Imports {
    let mut out = Imports::new();
    for a in asks {
        let file = &a.site.file_path;
        if !out.contains_key(file) {
            let source = std::fs::read_to_string(repo_root.join(file)).unwrap_or_default();
            out.insert(file.clone(), render::imports_block(file, &source));
        }
    }
    out
}

/// The model's input for one question.
fn input_of(a: &Ask, imports: &Imports, layout: Layout) -> String {
    render::render_input(&site_of(a, imports), &question_of(a.frame), layout)
}

/// The model's input site, from what rvl retrieved: the file's import
/// block, and the retriever's first callee as the definition called at the
/// site.
fn site_of(a: &Ask, imports: &Imports) -> render::Site {
    let s = a.site;
    let callee = s.callees.first();
    render::Site {
        class: a.class.clone(),
        scope: s.scope().as_str().to_string(),
        language: s.lang.clone(),
        file: s.file_path.clone(),
        site: format!("{}:{}", s.file_path, s.line_number),
        snippet: s.snippet.clone(),
        imports: imports.get(&s.file_path).cloned().unwrap_or_default(),
        callee_name: callee.map(|c| c.symbol.clone()).unwrap_or_default(),
        callee_definition: callee.map(|c| c.source.clone()).unwrap_or_default(),
        packet: render::SitePacket::from(s),
        ..render::Site::default()
    }
}

/// A frame's question, with its cells in the training text's form,
/// `M1  [violates] <definition>`. A frame from a cache written before
/// control names were published renders `Control: RC-022` alone.
fn question_of(f: &Frame) -> Question {
    Question::Frame(render::Frame {
        control: f.control.clone(),
        control_name: f.control_name.clone(),
        question: f.question.clone(),
        cells: f
            .cells
            .iter()
            .map(|c| format!("{}  [{}] {}", c.id, c.verdict, c.definition))
            .collect(),
    })
}

/// The cell kind a verdict's reason must be.
fn kind_of(verdict: &str) -> Option<&'static str> {
    match verdict {
        "violates" => Some("manifestation"),
        "satisfies" => Some("satisfying"),
        "not_applicable" => Some("context"),
        _ => None,
    }
}

/// One record as a decision with its reason.
fn decide(a: &Ask, r: &rvl_model::Record, cells: Option<&[String]>) -> Decision {
    let control = &a.frame.control;
    let mut verdict = match &r.verdict {
        rvl_model::Verdict::Label(l) => l.clone(),
        rvl_model::Verdict::Abstain(_) => "abstain".to_string(),
    };
    let mut off_cell = false;
    let (cell, reason) = match (kind_of(&verdict), cells) {
        (None, _) if r.confidence.is_none() => (
            None,
            format!("{control} abstains: the model time budget ran out"),
        ),
        (None, _) => (None, format!("{control} abstains: the model abstained")),
        (Some(_), None) => (
            None,
            format!("{control} {verdict}, reason: not in this model"),
        ),
        (Some(kind), Some(ids)) => {
            let allowed: Vec<&str> = a.frame.cells.iter().map(|c| c.id.as_str()).collect();
            let top = rvl_model::classify::top_cell(ids, &r.cell_logits, &allowed)
                .and_then(|i| a.frame.cell(&ids[i]));
            match top {
                Some(c) if c.kind == kind => (
                    Some(c.id.clone()),
                    format!("{control} {verdict}, {}: {}", c.id, c.definition),
                ),
                _ if verdict == "violates" => {
                    off_cell = true;
                    let top = top.map_or("no cell of the frame ranked".to_string(), |c| {
                        format!("its top cell {} is not a manifestation cell", c.id)
                    });
                    (
                        None,
                        format!("{control} abstains: the model says violates, but {top}"),
                    )
                }
                Some(c) => (
                    None,
                    format!(
                        "{control} {verdict}, reason unknown: the model's top cell {} is not \
                         a {kind} cell",
                        c.id
                    ),
                ),
                None => (
                    None,
                    format!("{control} {verdict}, reason unknown: no cell of the frame ranked"),
                ),
            }
        }
    };
    if off_cell {
        verdict = "abstain".to_string();
    }
    Decision {
        site_id: format!("{}:{}", a.site.file_path, a.site.line_number),
        class: a.class.clone(),
        control: control.clone(),
        frame_version: a.frame.version.clone(),
        verdict,
        // An abstain has no confidence.
        confidence: r.confidence.filter(|_| !off_cell),
        cell,
        reason,
        model_id: r.model_id.clone(),
        weights_digest: r.weights_digest.clone(),
        off_cell,
    }
}

/// An advisory ladder row for a `violates` decision. The waiver key is
/// `model.<control>`.
fn finding_of(d: &Decision) -> Option<ladder::Finding> {
    if d.verdict != "violates" {
        return None;
    }
    let class_rule = format!("model.{}", d.control);
    Some(ladder::Finding {
        id: ladder::finding_id(&format!("{class_rule}@{}", d.site_id)),
        site: d.site_id.clone(),
        description: format!(
            "{} (decision model {}, confidence {:.2})",
            d.reason,
            d.model_id,
            d.confidence.unwrap_or_default()
        ),
        disposition: "surface".into(),
        // Not graded: advisory until a severity is set for the control.
        severity: String::new(),
        incident_count: 0,
        critical_count: 0,
        control: d.control.clone(),
        fix: String::new(),
        site_count: 1,
        example_sites: vec![d.site_id.clone()],
        class_rule,
        suppressed: false,
        gate_exempt: false,
        factors: Vec::new(),
    })
}

fn coverage_lines(s: &Summary, budget_lines: Vec<String>, frames_rejected: usize) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(why) = &s.not_run {
        out.push(format!("decision model: not run \u{2014} {why}"));
    } else if s.sites.is_empty() {
        out.push(format!(
            "decision model {}: no undecided site has a frame of a served control",
            s.model_id
        ));
    } else {
        let count = |v: &str| s.sites.iter().filter(|d| d.verdict == v).count();
        let parts: Vec<String> = [
            ("violates", "violates"),
            ("satisfies", "satisfies"),
            ("not_applicable", "not applicable"),
            ("abstain", "abstain"),
        ]
        .iter()
        .map(|(v, label)| (count(v), label))
        .filter(|(n, _)| *n > 0)
        .map(|(n, label)| format!("{n} {label}"))
        .collect();
        out.push(format!(
            "decision model {}: {} site question(s) asked \u{2014} {} (advisory)",
            s.model_id,
            s.sites.len(),
            parts.join(" \u{00b7} ")
        ));
    }
    out.extend(budget_lines);
    let named = |rows: &[Unserved]| {
        rows.iter()
            .map(|u| format!("{} ({})", u.control, u.sites))
            .collect::<Vec<_>>()
            .join(" \u{00b7} ")
    };
    let mut off_cell: std::collections::BTreeMap<&str, usize> = Default::default();
    for d in s.sites.iter().filter(|d| d.off_cell) {
        *off_cell.entry(d.control.as_str()).or_default() += 1;
    }
    if !off_cell.is_empty() {
        let rows: Vec<String> = off_cell
            .iter()
            .map(|(control, n)| format!("{control} ({n})"))
            .collect();
        out.push(format!(
            "decision model abstains where it says violates but its top cell is not a \
             manifestation cell: {}",
            rows.join(" \u{00b7} ")
        ));
    }
    if !s.out_of_distribution.is_empty() {
        out.push(format!(
            "decision model abstains out of distribution, on class families it does not \
             serve: {}",
            named(&s.out_of_distribution)
        ));
    }
    if !s.unserved.is_empty() {
        out.push(format!(
            "decision model abstains on controls it does not serve: {}",
            named(&s.unserved)
        ));
    }
    if !s.withheld_controls.is_empty() {
        out.push(format!(
            "decision model withholds {} (below its publication gate)",
            s.withheld_controls.join(", ")
        ));
    }
    if frames_rejected > 0 {
        out.push(format!(
            "{frames_rejected} frame(s) in the spec cache did not parse and were skipped"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(cells: &[(&str, &str)]) -> Frame {
        serde_json::from_value(serde_json::json!({
            "control": "RC-022", "version": "v2", "habitat": "call_site", "question": "q",
            "cells": cells.iter().map(|(id, kind)| serde_json::json!({
                "id": id, "kind": kind, "verdict": "violates", "definition": format!("def {id}")
            })).collect::<Vec<_>>(),
        }))
        .unwrap()
    }

    fn record(verdict: &str, cell_logits: Vec<f32>) -> rvl_model::Record {
        rvl_model::Record {
            verdict: rvl_model::Verdict::Label(verdict.into()),
            confidence: Some(0.9),
            logits: vec![0.0; 4],
            cell_logits,
            model_id: "m".into(),
            weights_digest: "sha256:x".into(),
        }
    }

    fn ask<'a>(site: &'a rvl_core::Site, frame: &'a Frame) -> Ask<'a> {
        Ask {
            site,
            class: "a.B.C".into(),
            frame,
        }
    }

    #[test]
    fn the_reason_is_the_top_cell_of_the_frame_masked_and_of_the_verdicts_kind() {
        let site = rvl_core::Site::default();
        let ids: Vec<String> = ["M1", "M2", "S1", "C1"].map(String::from).to_vec();
        let f = frame(&[
            ("M1", "manifestation"),
            ("M2", "manifestation"),
            ("S1", "satisfying"),
        ]);
        // C1 ranks top over all cells, but it is not one of the frame's.
        let r = record("violates", vec![1.0, 2.0, 0.0, 9.0]);
        let d = decide(&ask(&site, &f), &r, Some(&ids));
        assert_eq!(d.cell.as_deref(), Some("M2"));
        assert_eq!(d.reason, "RC-022 violates, M2: def M2");

        let r = record("satisfies", vec![9.0, 0.0, 5.0, 0.0]);
        let d = decide(&ask(&site, &f), &r, Some(&ids));
        assert_eq!(d.cell, None, "an M cell is not a reason to satisfy");
        assert!(d.reason.contains("reason unknown"), "{}", d.reason);

        let d = decide(&ask(&site, &f), &record("violates", vec![]), None);
        assert_eq!(d.reason, "RC-022 violates, reason: not in this model");
    }

    #[test]
    fn a_budget_cut_names_what_it_dropped() {
        let site = |file: &str| rvl_core::Site {
            file_path: file.into(),
            ..rvl_core::Site::default()
        };
        let (a, b, c) = (site("a.go"), site("b.go"), site("c.go"));
        let f = frame(&[]);
        let asks = [ask(&a, &f), ask(&b, &f), ask(&b, &f), ask(&c, &f)];
        assert_eq!(cut_line(&asks[4..]), None, "nothing cut");
        assert_eq!(
            cut_line(&asks[1..]).unwrap(),
            "decision model: questions are asked site by site in scan order, so the budget \
             cut the last 3 question(s), in 2 file(s) from b.go on; \
             `scanner.decision_model_budget` raises the budget (a hook and --changed-only \
             hold it to 60s)"
        );
    }

    #[test]
    fn a_violation_whose_top_cell_is_not_a_manifestation_cell_abstains() {
        let site = rvl_core::Site::default();
        let ids: Vec<String> = ["M1", "S1", "C3"].map(String::from).to_vec();
        let f = frame(&[
            ("M1", "manifestation"),
            ("S1", "satisfying"),
            ("C3", "context"),
        ]);
        let off = decide(
            &ask(&site, &f),
            &record("violates", vec![1.0, 0.0, 5.0]),
            Some(&ids),
        );
        assert_eq!(off.verdict, "abstain");
        assert_eq!((off.cell.as_ref(), off.confidence), (None, None));
        assert_eq!(
            off.reason,
            "RC-022 abstains: the model says violates, but its top cell C3 is not a \
             manifestation cell"
        );
        assert!(finding_of(&off).is_none(), "an abstain is not a finding");
        let none = decide(
            &ask(&site, &frame(&[])),
            &record("violates", vec![]),
            Some(&[]),
        );
        assert_eq!(none.verdict, "abstain", "{}", none.reason);

        let on = decide(
            &ask(&site, &f),
            &record("violates", vec![5.0, 0.0, 1.0]),
            Some(&ids),
        );
        assert_eq!(on.verdict, "violates");
        let s = Summary {
            model_id: "m".into(),
            sites: vec![off, none, on],
            ..Summary::default()
        };
        let lines = coverage_lines(&s, Vec::new(), 0);
        assert!(
            lines[0].contains("3 site question(s) asked")
                && lines[0].contains("1 violates")
                && lines[0].contains("2 abstain"),
            "{lines:?}"
        );
        assert!(
            lines[1].contains("top cell is not a manifestation cell: RC-022 (2)"),
            "{lines:?}"
        );
    }

    #[test]
    fn a_frame_with_its_control_name_renders_the_golden_byte_for_byte() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rvl-model/testdata/render-goldens/render-goldens.jsonl"
        );
        let goldens = std::fs::read_to_string(path).unwrap();
        let mut checked = 0;
        for line in goldens.lines().filter(|l| !l.trim().is_empty()) {
            let g: serde_json::Value = serde_json::from_str(line).unwrap();
            let row = &g["input"]["row"];
            if row["id"] != "g24" {
                continue;
            }
            // The frame as the spec cache serves it, its name included.
            let f: Frame = serde_json::from_value(serde_json::json!({
                "control": "RC-022", "control_name": "Retry, Backoff and Request Coalescing",
                "version": "v1", "habitat": "call_site",
                "question": "Is the call at this site retried on a transient failure?",
                "cells": [
                    {"id": "M1", "kind": "manifestation", "verdict": "violates", "definition": "No retry at any layer"},
                    {"id": "S1", "kind": "satisfying", "verdict": "satisfies", "definition": "A library-configured retry"},
                    {"id": "C1", "kind": "context", "verdict": "not_applicable", "definition": "Test, fixture or mock code"},
                ],
            }))
            .unwrap();
            let mut site: rvl_core::Site =
                serde_json::from_value(g["input"]["site_packet"].clone()).unwrap();
            site.snippet = row["packet"]["snippet"].as_str().unwrap().into();
            site.lang = row["language"].as_str().unwrap().into();
            let a = Ask {
                site: &site,
                class: row["class"].as_str().unwrap().into(),
                frame: &f,
            };
            let layout = match g["layout"].as_str().unwrap() {
                "full" => Layout::Full,
                _ => Layout::Compact,
            };
            let text = input_of(&a, &Imports::new(), layout);
            assert_eq!(text, g["text"].as_str().unwrap(), "{layout:?}");
            assert!(text.contains("\nControl: RC-022 Retry, Backoff and Request Coalescing\n"));
            checked += 1;
        }
        assert_eq!(checked, 2, "the golden under both layouts");
    }

    /// The served frame a golden's question text describes, read as the
    /// training renderer reads it.
    fn frame_of_text(control: &str, text: &str) -> Frame {
        let after = |prefix: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(prefix))
                .unwrap_or("")
                .to_string()
        };
        let (version, question) = after(&format!("Question ({control}, "))
            .split_once("): ")
            .map(|(v, q)| (v.to_string(), q.to_string()))
            .unwrap();
        let cells: Vec<serde_json::Value> = text
            .lines()
            .skip_while(|l| !l.starts_with("Cells of the "))
            .skip(1)
            .take_while(|l| l.starts_with("  "))
            .map(|l| {
                let (id, rest) = l.trim().split_once("  [").unwrap();
                let (verdict, definition) = rest.split_once("] ").unwrap();
                serde_json::json!({"id": id, "kind": "manifestation", "verdict": verdict, "definition": definition})
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "control": control, "version": version, "habitat": "call_site", "question": question,
            "control_name": after(&format!("Control meaning: {control} - ")), "cells": cells,
        }))
        .unwrap()
    }

    /// A file whose import lines are the block's, each on its line, the
    /// other lines code that imports nothing.
    fn file_of_imports(block: &str) -> String {
        let mut lines: Vec<String> = Vec::new();
        for l in block.lines() {
            let (n, text) = l.split_once(" | ").unwrap();
            let n: usize = n.trim().parse().unwrap();
            lines.resize(n - 1, "x = 1".into());
            lines.push(text.into());
        }
        lines.push("x = 1".into());
        lines.join("\n")
    }

    #[test]
    fn imports_and_the_callee_render_the_training_goldens_byte_for_byte() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rvl-model/testdata/render-goldens/render-goldens.jsonl"
        );
        let goldens = std::fs::read_to_string(path).unwrap();
        let mut checked = [0usize; 3];
        for line in goldens.lines().filter(|l| !l.trim().is_empty()) {
            let g: serde_json::Value = serde_json::from_str(line).unwrap();
            let (row, sp) = (&g["input"]["row"], &g["input"]["site_packet"]);
            let packet = &row["packet"];
            let str_of = |v: &serde_json::Value| v.as_str().unwrap_or("").to_string();
            // A frame row of a runtime site whose retriever packet is rvl's:
            // what the lane asks.
            if row["kind"] != "frame_question"
                || row["scope"] != "runtime"
                || sp["file_path"] != row["file"]
                || !row["question"]["text"]
                    .as_str()
                    .unwrap()
                    .contains("Cells of the ")
            {
                continue;
            }
            let root = tempfile::tempdir().unwrap();
            let file = str_of(&row["file"]);
            std::fs::create_dir_all(root.path().join(&file).parent().unwrap()).unwrap();
            std::fs::write(
                root.path().join(&file),
                file_of_imports(&str_of(&packet["imports"])),
            )
            .unwrap();
            let mut site: rvl_core::Site = serde_json::from_value(sp.clone()).unwrap();
            site.snippet = str_of(&packet["snippet"]);
            site.lang = str_of(&row["language"]);
            if !str_of(&packet["callee_definition"]).is_empty() {
                site.callees = vec![rvl_core::Snippet {
                    file: file.clone(),
                    line: 1,
                    symbol: str_of(&packet["callee_name"]),
                    source: str_of(&packet["callee_definition"]),
                }];
            }
            let f = frame_of_text(&str_of(&row["control"]), &str_of(&row["question"]["text"]));
            let a = Ask {
                site: &site,
                class: str_of(&row["class"]),
                frame: &f,
            };
            let layout = match g["layout"].as_str().unwrap() {
                "full" => Layout::Full,
                _ => Layout::Compact,
            };
            let imports = imports_of(root.path(), std::slice::from_ref(&a));
            let text = input_of(&a, &imports, layout);
            assert_eq!(text, str_of(&g["text"]), "{} {layout:?}", row["id"]);
            checked[0] += 1;
            checked[1] += !str_of(&packet["imports"]).is_empty() as usize;
            checked[2] += !site.callees.is_empty() as usize;
        }
        assert_eq!(
            checked,
            [54, 30, 26],
            "goldens checked: all, with an import block, with a callee definition"
        );
    }

    #[test]
    fn only_a_violation_is_a_ladder_row_and_it_is_advisory() {
        let site = rvl_core::Site::default();
        let f = frame(&[]);
        let d = decide(&ask(&site, &f), &record("satisfies", vec![]), None);
        assert!(finding_of(&d).is_none());
        let d = decide(&ask(&site, &f), &record("violates", vec![]), None);
        let row = finding_of(&d).unwrap();
        assert_eq!(row.class_rule, "model.RC-022");
        assert_eq!(ladder::classify(&row), ladder::Section::Advisory);
    }

    fn manifest(served_classes: &str) -> ModelManifest {
        let sha = "0".repeat(64);
        ModelManifest::parse(
            format!(
                r#"{{"schema_version":1,"model_id":"m","layout":"compact","max_len":8,
                "temperature":1.0,"bundle_url":"/b/",
                "served_controls":[{{"control":"RC-022"{served_classes}}}],
                "files":[{{"name":"m.onnx","sha256":"{sha}"}},
                         {{"name":"tokenizer.json","sha256":"{sha}"}}]}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    }

    fn undecided(client_type: &str, method: &str) -> (rvl_propagate::Finding, rvl_core::Site) {
        let site = rvl_core::Site {
            client_type: client_type.into(),
            method: method.into(),
            ..rvl_core::Site::default()
        };
        let f = rvl_propagate::Finding {
            site_id: String::new(),
            verdict: rvl_core::Verdict::Abstain,
            reason: String::new(),
        };
        (f, site)
    }

    #[test]
    fn a_site_whose_class_family_is_not_served_abstains_out_of_distribution() {
        let (f1, redis) = undecided("github.com/redis/go-redis/v9.Client", "Get");
        let (f2, http) = undecided("net/http.Client", "Do");
        let (findings, sites) = (vec![f1, f2], vec![redis, http]);
        let frames = vec![frame(&[])];

        let listed = manifest(r#","served_classes":["net/http"]"#);
        let sel = select(&findings, &sites, &frames, &listed);
        let asked: Vec<&str> = sel.asks.iter().map(|a| a.class.as_str()).collect();
        assert_eq!(asked, ["net/http.Client.Do"], "the listed class is asked");
        assert_eq!(
            sel.out_of_distribution,
            [Unserved {
                control: "RC-022".into(),
                sites: 1,
            }],
            "the go-redis Client.Get site abstains"
        );
        assert!(sel.unserved.is_empty());

        let unlisted = manifest("");
        let sel = select(&findings, &sites, &frames, &unlisted);
        assert_eq!(sel.asks.len(), 2, "no served_classes asks every class");
        assert!(sel.out_of_distribution.is_empty());
    }

    /// `classify_until`'s loop over 20 questions in batches of 8, the hook
    /// asked before each batch; the budget is spent after `budget_batches`.
    fn ask_twenty(budget_batches: usize) -> (u64, usize) {
        let progress = indicatif::ProgressBar::hidden();
        progress.set_length(20);
        let mut checks = 0;
        let mut hook = batch_hook(&progress, 8, || {
            checks += 1;
            checks > budget_batches
        });
        let mut inferred = 0;
        for batch in [(); 20].chunks(8) {
            if hook() {
                break;
            }
            inferred += batch.len();
        }
        (progress.position(), 20 - inferred)
    }

    #[test]
    fn the_question_count_moves_one_batch_at_a_time_and_the_budget_still_stops_it() {
        assert_eq!(ask_twenty(usize::MAX), (20, 0), "every question asked");
        assert_eq!(
            ask_twenty(1),
            (8, 12),
            "the budget stop abstains the rest, and the count does not pass it"
        );
    }

    #[test]
    fn unserved_and_withheld_controls_are_named_on_the_coverage_line() {
        let s = Summary {
            model_id: "m".into(),
            withheld_controls: vec!["RC-022".into()],
            unserved: vec![Unserved {
                control: "RC-022".into(),
                sites: 2,
            }],
            out_of_distribution: vec![Unserved {
                control: "RC-019".into(),
                sites: 3,
            }],
            ..Summary::default()
        };
        let lines = coverage_lines(&s, Vec::new(), 1);
        assert!(
            lines[1].contains("out of distribution") && lines[1].contains("RC-019 (3)"),
            "{lines:?}"
        );
        assert!(lines[2].contains("RC-022 (2)"), "{lines:?}");
        assert!(lines[3].contains("withholds RC-022"), "{lines:?}");
        assert!(lines[4].contains("1 frame(s)"), "{lines:?}");
    }
}
