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
    wilson_interval_at(successes as f64 / n as f64, n as f64)
}

/// The Wilson interval at proportion `p` and a sample size that need not be
/// whole. An effective sample size (`DesignEffect::n_eff`) is fractional, and
/// rounding it would move the bound in a direction nobody chose.
fn wilson_interval_at(p: f64, n: f64) -> (f64, f64) {
    if n <= 0.0 {
        return (0.0, 1.0);
    }
    let z2 = Z95 * Z95;
    let denom = 1.0 + z2 / n;
    let center = p + z2 / (2.0 * n);
    let margin = Z95 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    (
        ((center - margin) / denom).max(0.0),
        ((center + margin) / denom).min(1.0),
    )
}

/// The gate metric: Wilson 95% lower bound.
pub fn wilson_lower_bound(successes: u64, n: u64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    wilson_interval(successes, n).0
}

/// The gate metric on clustered rows: Wilson 95% lower bound at the observed
/// proportion `p` and the effective sample size `n_eff`.
pub fn wilson_lower_bound_at(p: f64, n_eff: f64) -> f64 {
    if n_eff <= 0.0 {
        return 0.0;
    }
    wilson_interval_at(p, n_eff).0
}

/// The intra-cluster correlation the gate assumes: 1.0, the upper bound.
///
/// WHY A CONSTANT AND NOT AN ESTIMATE (po-io8sk.1). The usual estimate of rho
/// comes from the within- and between-cluster variance of the outcome. A gate
/// set sits at precision near 1, where both are zero and rho is undefined: a
/// perfect 50/50 drawn from 4 specs would estimate to "no correlation" and get
/// deff = 1, which is exactly the run the adjustment exists to refuse. Worse,
/// one false positive would make rho estimable and the verdict would flip on a
/// row that says nothing about clustering.
///
/// 1.0 is the one value that needs no tuning. It is also what the mechanism
/// says: one spec decides every site of its class, so the sites of a cluster
/// are one decision observed many times.
pub const GATE_ICC: f64 = 1.0;

/// A clustered sample's size, raw and effective. Reported together, always:
/// `n_eff` alone hides how much evidence was discounted, and `n` alone is the
/// number this type exists to stop a gate from trusting.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DesignEffect {
    pub n: usize,
    pub n_clusters: usize,
    pub deff: f64,
    pub n_eff: f64,
}

/// Kish design effect for a clustered sample:
///
///   deff = 1 + (m' - 1) * rho,   m' = sum(m_k^2) / n,   n_eff = n / deff
///
/// `m_k` are the cluster sizes and `m'` is the size-weighted mean cluster
/// size, which is Kish's form for unequal clusters (it reduces to the plain
/// mean when the clusters are equal). The plain mean understates the effect
/// when one cluster dominates, and gate sets are dominated: one repo supplied
/// 182 of the 232 violates in eval-go-v1.
///
/// At rho = 1 this is n_eff = n^2 / sum(m_k^2), the effective number of
/// clusters. At rho = 0, or when every cluster is a singleton, n_eff = n.
pub fn kish_design_effect(cluster_sizes: &[usize], rho: f64) -> DesignEffect {
    let n: usize = cluster_sizes.iter().sum();
    let n_clusters = cluster_sizes.iter().filter(|m| **m > 0).count();
    if n == 0 {
        return DesignEffect {
            n,
            n_clusters,
            deff: 1.0,
            n_eff: 0.0,
        };
    }
    let sum_sq: f64 = cluster_sizes
        .iter()
        .map(|m| (*m as f64) * (*m as f64))
        .sum();
    let weighted_mean_size = sum_sq / n as f64;
    let deff = 1.0 + (weighted_mean_size - 1.0) * rho;
    DesignEffect {
        n,
        n_clusters,
        deff,
        n_eff: n as f64 / deff,
    }
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
    BootDelta {
        mean,
        lo,
        hi,
        p_better,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_arms_produce_a_ci_containing_zero() {
        let a = vec![true, false, true, true, false, true, false, true];
        let r = paired_bootstrap(&a, &a, 500, 1);
        assert!(r.mean.abs() < 1e-9);
        assert!(
            r.lo <= 0.0 && r.hi >= 0.0,
            "identical arms must not appear separated"
        );
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
    fn kish_design_effect_matches_a_hand_computed_example() {
        // Clusters of 20, 15, 10 and 5: n = 50, sum(m^2) = 400 + 225 + 100 +
        // 25 = 750, so the size-weighted mean cluster size is 750 / 50 = 15.
        let sizes = [20, 15, 10, 5];
        // rho = 0.5: deff = 1 + (15 - 1) * 0.5 = 8, n_eff = 50 / 8 = 6.25.
        let d = kish_design_effect(&sizes, 0.5);
        assert_eq!((d.n, d.n_clusters), (50, 4));
        assert!((d.deff - 8.0).abs() < 1e-12);
        assert!((d.n_eff - 6.25).abs() < 1e-12);
        // rho = 1, the gate's value: deff = 15, n_eff = 50 / 15 = 3.33.
        let d = kish_design_effect(&sizes, GATE_ICC);
        assert!((d.deff - 15.0).abs() < 1e-12);
        assert!((d.n_eff - 50.0 / 15.0).abs() < 1e-12);
        // rho = 0, or every cluster a singleton: no adjustment.
        assert!((kish_design_effect(&sizes, 0.0).n_eff - 50.0).abs() < 1e-12);
        assert!((kish_design_effect(&[1; 50], GATE_ICC).n_eff - 50.0).abs() < 1e-12);
        // No rows: no evidence, and no division by zero.
        let d = kish_design_effect(&[], GATE_ICC);
        assert_eq!((d.n, d.n_clusters), (0, 0));
        assert_eq!(d.n_eff, 0.0);
    }

    #[test]
    fn wilson_lower_bound_at_a_fractional_n() {
        // Agrees with the integer form when n is whole.
        assert!((wilson_lower_bound_at(0.9, 50.0) - wilson_lower_bound(45, 50)).abs() < 1e-12);
        // p = 1 reduces to n / (n + z^2): 3.3333 / (3.3333 + 3.8415) = 0.4646.
        assert!((wilson_lower_bound_at(1.0, 50.0 / 15.0) - 0.4646).abs() < 1e-4);
        assert_eq!(wilson_lower_bound_at(1.0, 0.0), 0.0);
    }

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        assert_eq!(percentile(&v, 95.0), 95.0);
        assert_eq!(percentile(&v, 50.0), 50.0);
        assert_eq!(percentile(&[7.0], 95.0), 7.0);
    }
}
