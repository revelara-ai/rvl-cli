//! Latency replay + triage-count metrics for the destination gate:
//! warm staged-diff p95 < 2s, hook delta-scoped triage counts median 0 / p95 <= 3.

use serde::Deserialize;

/// One replayed hook invocation.
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayRow {
    pub diff_id: String,
    /// Warm-path wall time for the staged-diff scan, milliseconds.
    pub warm_ms: f64,
    /// Findings surfaced to the developer for this diff (triage burden).
    pub findings: u64,
}

use crate::stats::percentile;

#[derive(Debug)]
pub struct LatencyReport {
    pub n: usize,
    pub warm_p95_ms: f64,
    pub triage_median: f64,
    pub triage_p95: f64,
    pub latency_pass: bool,
    pub triage_pass: bool,
}

pub fn score_replay(
    rows: &[ReplayRow],
    p95_target_ms: f64,
    triage_median_target: f64,
    triage_p95_target: f64,
) -> anyhow::Result<LatencyReport> {
    if rows.is_empty() {
        anyhow::bail!("empty replay: no diffs to score");
    }
    let warm: Vec<f64> = rows.iter().map(|r| r.warm_ms).collect();
    let findings: Vec<f64> = rows.iter().map(|r| r.findings as f64).collect();
    let warm_p95_ms = percentile(&warm, 95.0);
    let triage_median = percentile(&findings, 50.0);
    let triage_p95 = percentile(&findings, 95.0);
    Ok(LatencyReport {
        n: rows.len(),
        warm_p95_ms,
        triage_median,
        triage_p95,
        latency_pass: warm_p95_ms < p95_target_ms,
        triage_pass: triage_median <= triage_median_target && triage_p95 <= triage_p95_target,
    })
}
