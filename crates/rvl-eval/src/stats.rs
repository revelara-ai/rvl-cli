//! Shared statistics: the Wilson interval, percentiles, and the paired
//! bootstrap. Every statistical primitive lives here so no two modules can
//! drift apart on constants or algebra.

use rand::distributions::{Distribution, Uniform};
use rand::SeedableRng;

/// The one 95% critical value. Two modules independently hard-coding "1.96"
/// is how a gate and a report end up computed against different intervals.
pub const Z95: f64 = 1.959963984540054;

/// 95% Wilson score interval (lo, hi) for `successes` out of `n`.
/// Stays finite and sensible at p = 0 and p = 1, where Wald does not.
pub fn wilson_interval(successes: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    let n = n as f64;
    let p = successes as f64 / n;
    let z2 = Z95 * Z95;
    let denom = 1.0 + z2 / n;
    let center = p + z2 / (2.0 * n);
    let margin = Z95 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    (((center - margin) / denom).max(0.0), ((center + margin) / denom).min(1.0))
}

/// The gate metric: Wilson 95% lower bound.
pub fn wilson_lower_bound(successes: u64, n: u64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    wilson_interval(successes, n).0
}

/// Percentile by the nearest-rank method on a sorted copy of `values`.
pub fn percentile(values: &[f64], pct: f64) -> f64 {
    assert!(!values.is_empty(), "percentile of empty slice");
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("NaN in percentile input"));
    let rank = ((pct / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// Result of a paired bootstrap on the delta (B - A).
#[derive(Debug, Clone, Copy)]
pub struct BootDelta {
    pub mean: f64,
    pub lo: f64,
    pub hi: f64,
    pub p_better: f64,
}

/// Paired bootstrap over the SHARED evaluation set. Paired because both arms
/// are scored on the same resampled indices in each replicate, which cancels
/// the "which sites happened to be easy" variance and isolates the arm
/// difference. Panics on empty input: callers guard the join first.
pub fn paired_bootstrap(a: &[bool], b: &[bool], reps: usize, seed: u64) -> BootDelta {
    let n = a.len();
    // One pass over the pair, then each replicate sums a single i8 vector
    // instead of indexing two bool vectors; the sampler is built once.
    let d: Vec<i8> = a.iter().zip(b).map(|(x, y)| *y as i8 - *x as i8).collect();
    let dist = Uniform::from(0..n);
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut deltas = Vec::with_capacity(reps);
    for _ in 0..reps {
        let mut s = 0i64;
        for _ in 0..n {
            s += d[dist.sample(&mut rng)] as i64;
        }
        deltas.push(s as f64 / n as f64);
    }
    deltas.sort_by(|x, y| x.partial_cmp(y).unwrap());
    let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
    let lo = deltas[(0.025 * deltas.len() as f64) as usize];
    let hi = deltas[((0.975 * deltas.len() as f64) as usize).min(deltas.len() - 1)];
    let p_better = deltas.iter().filter(|d| **d > 0.0).count() as f64 / deltas.len() as f64;
    BootDelta { mean, lo, hi, p_better }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_arms_produce_a_ci_containing_zero() {
        let a = vec![true, false, true, true, false, true, false, true];
        let r = paired_bootstrap(&a, &a, 500, 1);
        assert!(r.mean.abs() < 1e-9);
        assert!(r.lo <= 0.0 && r.hi >= 0.0, "identical arms must not appear separated");
    }

    #[test]
    fn a_real_gap_separates() {
        let a = vec![false; 40];
        let b = vec![true; 40];
        let r = paired_bootstrap(&a, &b, 500, 1);
        assert!((r.mean - 1.0).abs() < 1e-9);
        assert!(r.lo > 0.0);
        assert!(r.p_better > 0.99);
    }

    #[test]
    fn wilson_interval_brackets_the_point_estimate() {
        let (lo, hi) = wilson_interval(45, 50);
        assert!(lo < 0.9 && 0.9 < hi);
        assert!((lo - 0.7864).abs() < 1e-3);
        // degenerate ends stay in [0, 1]
        assert_eq!(wilson_interval(0, 0), (0.0, 1.0));
        assert!(wilson_interval(50, 50).1 <= 1.0);
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(percentile(&v, 95.0), 95.0);
        assert_eq!(percentile(&v, 50.0), 50.0);
        assert_eq!(percentile(&[7.0], 95.0), 7.0);
    }
}
