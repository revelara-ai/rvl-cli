//! Two-condition retriever comparison (skilleval contract, wayfinder
//! po-ipkfg.15): baseline vs treatment retriever with the downstream engine
//! frozen. Emits a per-repo x per-class table, an explicit regression list,
//! and a seeded disagreement sample. Never a lone scalar verdict.

use crate::stats::BootDelta;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The canonical findings row: emitted by `rvl-eval run`, consumed by every
/// scoring subcommand. Input-tolerant (`reason`/`class`/`snapshot_id` may be
/// absent in older files) so one loader serves all readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub site_id: String,
    #[serde(default)]
    pub snapshot_id: String,
    pub verdict: String,
    #[serde(default)]
    pub reason: String,
    /// Spec class (api key) the verdict came from; "unclassified" when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

/// Wire-string mirror of `rvl_core::Verdict::is_decided`, for findings files
/// whose verdicts are read without re-parsing into the enum.
pub fn decided(verdict: &str) -> bool {
    matches!(verdict, "violates" | "satisfies")
}

/// One cell of the per-repo x per-class table.
#[derive(Debug, Default)]
pub struct Cell {
    pub n: usize,
    pub a_decided: usize,
    pub b_decided: usize,
    pub a_violates: usize,
    pub b_violates: usize,
}

/// A site the treatment made worse.
#[derive(Debug)]
pub struct Regression {
    pub site_id: String,
    pub repo: String,
    pub a_verdict: String,
    pub b_verdict: String,
    /// "lost_decision" | "flipped_decided" | "wrong_vs_gold"
    pub kind: String,
}

#[derive(Debug)]
pub struct Disagreement {
    pub site_id: String,
    pub a_verdict: String,
    pub b_verdict: String,
    pub a_reason: String,
    pub b_reason: String,
}

#[derive(Debug)]
pub struct CompareReport {
    /// Keyed by (repo, class).
    pub table: BTreeMap<(String, String), Cell>,
    pub shared: usize,
    pub only_a: usize,
    pub only_b: usize,
    pub regressions: Vec<Regression>,
    pub disagreement_sample: Vec<Disagreement>,
    pub decided_delta: BootDelta,
    /// Present only when gold was supplied.
    pub accuracy_delta: Option<BootDelta>,
    /// Gold rows that joined a shared site / total gold rows supplied.
    /// Reported so an accuracy CI over a partial join cannot masquerade as
    /// one over the full gold set.
    pub gold_matched: usize,
    pub gold_total: usize,
}

/// Compare baseline `a` vs treatment `b` on their shared sites.
/// `gold` maps site_id -> expected verdict; when present, regressions include
/// sites correct in A but wrong in B. `sample_k`/`seed` bound the printed
/// disagreement sample deterministically.
pub fn compare_conditions(
    a: &[Finding],
    b: &[Finding],
    gold: Option<&BTreeMap<String, String>>,
    boot: usize,
    sample_k: usize,
    seed: u64,
) -> anyhow::Result<CompareReport> {
    let by_id_b: BTreeMap<&str, &Finding> = b.iter().map(|f| (f.site_id.as_str(), f)).collect();
    let mut shared: Vec<(&Finding, &Finding)> = Vec::new();
    let mut only_a = 0usize;
    for fa in a {
        match by_id_b.get(fa.site_id.as_str()) {
            Some(fb) => shared.push((fa, *fb)),
            None => only_a += 1,
        }
    }
    // by_id_b collapses duplicate ids, so its size minus the joined count is
    // exactly the number of B-only sites.
    let only_b = by_id_b.len() - shared.len();
    if shared.is_empty() {
        anyhow::bail!(
            "no shared sites between the two conditions ({only_a} only in A, {only_b} only in B); \
             an empty join is a bug, not a result"
        );
    }

    let mut table: BTreeMap<(String, String), Cell> = BTreeMap::new();
    for (fa, fb) in &shared {
        let class = fa
            .class
            .as_deref()
            .or(fb.class.as_deref())
            .unwrap_or("unclassified");
        let cell = table.entry((fa.snapshot_id.clone(), class.to_string())).or_default();
        cell.n += 1;
        cell.a_decided += decided(&fa.verdict) as usize;
        cell.b_decided += decided(&fb.verdict) as usize;
        cell.a_violates += (fa.verdict == "violates") as usize;
        cell.b_violates += (fb.verdict == "violates") as usize;
    }

    let mk = |fa: &Finding, fb: &Finding, kind: &str| Regression {
        site_id: fa.site_id.clone(),
        repo: fa.snapshot_id.clone(),
        a_verdict: fa.verdict.clone(),
        b_verdict: fb.verdict.clone(),
        kind: kind.into(),
    };
    let mut regressions = Vec::new();
    // Single pass: verdict-change regressions, gold regressions, and the
    // gold-scored accuracy vectors all come from the same walk.
    let mut gold_matched = 0usize;
    let mut ca: Vec<bool> = Vec::new();
    let mut cb: Vec<bool> = Vec::new();
    for (fa, fb) in &shared {
        if fa.verdict != fb.verdict && decided(&fa.verdict) {
            let kind = if decided(&fb.verdict) { "flipped_decided" } else { "lost_decision" };
            regressions.push(mk(fa, fb, kind));
        }
        if let Some(expect) = gold.and_then(|g| g.get(&fa.site_id)) {
            gold_matched += 1;
            ca.push(&fa.verdict == expect);
            cb.push(&fb.verdict == expect);
            if &fa.verdict == expect && &fb.verdict != expect {
                regressions.push(mk(fa, fb, "wrong_vs_gold"));
            }
        }
    }

    // Deterministic disagreement sample for human review.
    let mut disagreeing: Vec<(&Finding, &Finding)> = shared
        .iter()
        .filter(|(fa, fb)| fa.verdict != fb.verdict)
        .copied()
        .collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    disagreeing.shuffle(&mut rng);
    let disagreement_sample: Vec<Disagreement> = disagreeing
        .into_iter()
        .take(sample_k)
        .map(|(fa, fb)| Disagreement {
            site_id: fa.site_id.clone(),
            a_verdict: fa.verdict.clone(),
            b_verdict: fb.verdict.clone(),
            a_reason: fa.reason.clone(),
            b_reason: fb.reason.clone(),
        })
        .collect();

    let da: Vec<bool> = shared.iter().map(|(fa, _)| decided(&fa.verdict)).collect();
    let db: Vec<bool> = shared.iter().map(|(_, fb)| decided(&fb.verdict)).collect();
    let decided_delta = crate::stats::paired_bootstrap(&da, &db, boot, seed);

    let accuracy_delta = match gold {
        Some(_) if !ca.is_empty() => Some(crate::stats::paired_bootstrap(&ca, &cb, boot, seed)),
        _ => None,
    };

    Ok(CompareReport {
        table,
        shared: shared.len(),
        only_a,
        only_b,
        regressions,
        disagreement_sample,
        decided_delta,
        accuracy_delta,
        gold_matched,
        gold_total: gold.map(|g| g.len()).unwrap_or(0),
    })
}
