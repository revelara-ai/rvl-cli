//! Latency replay + triage-count gate metrics (po-3t3oj.1).
//! Warm staged-diff p95 < 2s; hook delta-scoped triage counts median 0 / p95 <= 3.

use rvl_eval::latency::*;

fn rows(spec: &[(f64, u64)]) -> Vec<ReplayRow> {
    spec.iter()
        .enumerate()
        .map(|(i, (ms, findings))| ReplayRow {
            diff_id: format!("d{i}"),
            warm_ms: *ms,
            findings: *findings,
        })
        .collect()
}

#[test]
fn replay_passes_within_targets() {
    // 20 diffs: nearest-rank p95 = 19th sorted value, so two 1800ms rows put
    // 1800 at p95. Warm p95 1800 < 2000; findings median 0, p95 3 <= 3.
    let mut spec: Vec<(f64, u64)> = (0..18).map(|_| (300.0, 0)).collect();
    spec.push((1800.0, 3));
    spec.push((1800.0, 3));
    let r = score_replay(&rows(&spec), 2000.0, 0.0, 3.0).unwrap();
    assert_eq!(r.n, 20);
    assert_eq!(r.warm_p95_ms, 1800.0);
    assert_eq!(r.triage_median, 0.0);
    assert_eq!(r.triage_p95, 3.0);
    assert!(r.latency_pass);
    assert!(r.triage_pass);
}

#[test]
fn replay_fails_slow_p95_and_noisy_triage() {
    let spec: Vec<(f64, u64)> = (0..20).map(|_| (2500.0, 5)).collect();
    let r = score_replay(&rows(&spec), 2000.0, 0.0, 3.0).unwrap();
    assert!(!r.latency_pass);
    assert!(!r.triage_pass);
}

#[test]
fn empty_replay_is_error() {
    assert!(score_replay(&[], 2000.0, 0.0, 3.0).is_err());
}
