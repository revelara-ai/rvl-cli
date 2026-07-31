//! rvl-eval: the measurement harness, built before the scanner it measures.
//!
//! Every result in this project that survived came from a check that was cheap
//! to run and hard to fool. Every retracted claim came from reporting a number
//! before checking the population that produced it: a 0.768 that was an
//! `is_test_file` shortcut, a 0.850 that was a labeller read back through its
//! own features, a +0.167 at n=72 that collapsed to +0.029 at n=117.
//!
//! So the requirements below are enforced by the tool rather than left to
//! discipline:
//!
//!   * splits are grouped by repository, never random
//!   * deltas carry paired bootstrap confidence intervals
//!   * the population is printed with the number
//!   * abstain and not_applicable are reported, never folded into a binary

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rvl_core::parse_stream;
use rvl_eval::compare::{self, Finding};
use rvl_eval::stats::{paired_bootstrap, wilson_interval};
use rvl_eval::{gate, latency, load_findings, load_jsonl};
use rvl_propagate::propagate_all;
use rvl_spec::SpecCache;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rvl-eval", about = "Run and measure the reliability scanner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Propagate specs over a retrieved site stream and emit findings.
    Run {
        #[arg(long)] retrieved: PathBuf,
        #[arg(long)] specs: PathBuf,
        #[arg(long)] out: Option<PathBuf>,
    },
    /// Score findings against adjudicated ground truth.
    Score {
        #[arg(long)] findings: PathBuf,
        #[arg(long)] gold: PathBuf,
    },
    /// Sweep a retrieval-policy axis and report what each setting buys.
    ///
    /// Retrieval budgets were hand-set constants until it turned out the
    /// binding constraint was somewhere else entirely: raising max-callers from
    /// 4 to 16 would have covered 12% more sites while 54.9% of searches were
    /// truncated for an unrelated reason. Sweeping is how that gets found
    /// rather than guessed.
    Sweep {
        /// Command template; {flag} is replaced with the axis setting.
        #[arg(long)] retriever: String,
        #[arg(long)] axis: String,
        #[arg(long)] values: String,
        #[arg(long)] specs: PathBuf,
    },
    /// Prediction-Powered Inference: a debiased estimate with valid CIs from
    /// many machine labels plus a few human ones.
    Ppi {
        #[arg(long)] findings: PathBuf,
        #[arg(long)] adjudicated: PathBuf,
        /// Which verdict the rate is being estimated for.
        #[arg(long, default_value = "violates")] target: String,
    },
    /// Score against mined bounded/unbounded twins (paired protocol).
    Twins {
        #[arg(long)] paired: PathBuf,
        #[arg(long)] specs: PathBuf,
    },
    /// Compare two runs on the sites they share, with a paired bootstrap CI.
    Compare {
        #[arg(long)] a: PathBuf,
        #[arg(long)] b: PathBuf,
        #[arg(long)] gold: PathBuf,
        #[arg(long, default_value_t = 2000)] boot: usize,
    },
    /// GATE MODE: score a minted gate set (per-language precision as Wilson
    /// 95% lower bound) with fail-closed provenance enforcement.
    Gate {
        /// Gate-set directory containing manifest.yaml + verdicts.jsonl.
        #[arg(long)] set: PathBuf,
        /// registry/seed_sets.yaml from rvlscan-eval (seed-set refusal).
        #[arg(long)] seed_sets: PathBuf,
        /// registry/quarantine.yaml from rvlscan-eval (fail-closed if absent).
        #[arg(long)] registry: PathBuf,
        /// Engine grounding-corpus manifest: one repo (owner/name) per line.
        #[arg(long)] grounding_manifest: PathBuf,
        /// Wilson-LB precision target.
        #[arg(long, default_value_t = 0.90)] target: f64,
    },
    /// Latency replay: warm staged-diff p95 and hook triage-count targets.
    Latency {
        /// JSONL of {diff_id, warm_ms, findings} rows.
        #[arg(long)] replay: PathBuf,
        #[arg(long, default_value_t = 2000.0)] p95_target_ms: f64,
        #[arg(long, default_value_t = 0.0)] triage_median: f64,
        #[arg(long, default_value_t = 3.0)] triage_p95: f64,
    },
    /// Two-condition retriever comparison (baseline vs treatment, downstream
    /// frozen): per-repo x per-class table, regression list, disagreement
    /// sample, paired bootstrap CIs. Never a lone scalar.
    Compare2 {
        #[arg(long)] a: PathBuf,
        #[arg(long)] b: PathBuf,
        /// Optional gold file ({"cases":[{path|site_id, expect|verdict}]}).
        #[arg(long)] gold: Option<PathBuf>,
        #[arg(long, default_value_t = 2000)] boot: usize,
        /// Disagreement sites to print for human review.
        #[arg(long, default_value_t = 10)] sample: usize,
        #[arg(long, default_value_t = 42)] seed: u64,
    },
}

#[derive(Deserialize)]
struct GoldCase {
    #[serde(alias = "path", alias = "site_id")]
    id: String,
    #[serde(alias = "expect", alias = "verdict")]
    expect: String,
}

#[derive(Deserialize)]
struct GoldFile {
    cases: Vec<GoldCase>,
}

/// Gold ids may be file paths (fixture cases) while findings are file:line.
/// Match on the id, falling back to path-prefix, and report how many matched so
/// a silent partial join cannot masquerade as a result.
fn join<'a>(findings: &'a [Finding], gold: &'a [GoldCase]) -> Vec<(&'a GoldCase, &'a Finding)> {
    let mut out = Vec::new();
    for g in gold {
        let prefix = format!("{}:", g.id);
        if let Some(f) = findings
            .iter()
            .find(|f| f.site_id == g.id || f.site_id.starts_with(&prefix))
        {
            out.push((g, f));
        }
    }
    out
}

fn counts(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.verdict.clone()).or_insert(0) += 1;
    }
    m
}

fn score(findings: &[Finding], gold: &[GoldCase]) -> (usize, usize, Vec<String>) {
    let pairs = join(findings, gold);
    let mut correct = 0;
    let mut misses = Vec::new();
    for (g, f) in &pairs {
        if f.verdict == g.expect {
            correct += 1;
        } else {
            misses.push(format!("{}: want {} got {} ({})", g.id, g.expect, f.verdict, f.reason));
        }
    }
    (correct, pairs.len(), misses)
}

#[derive(Deserialize)]
struct Adjudication {
    file_path: String,
    line_number: u32,
    verdict: String,
}

/// Prediction-Powered Inference for a proportion (Angelopoulos et al., Science
/// 2023). The scanner's own verdicts act as a control variate: the point
/// estimate is the machine rate over ALL sites, corrected by the mean
/// machine-minus-human error measured on the adjudicated subset.
///
/// Why bother instead of just reporting the labelled subset's rate: the
/// classical estimate throws away 1500 machine labels and its CI is wide enough
/// to be useless at the sample sizes a human will actually adjudicate. PPI keeps
/// validity while borrowing strength from the unlabelled bulk. It is only valid
/// under i.i.d. sampling of the labelled subset, so the sample must be RANDOM;
/// adjudicating the conflicts (which is the right way to choose what to fix)
/// produces a biased subset and must not be fed here.
fn ppi_proportion(machine_all: &[bool], machine_lab: &[bool], human_lab: &[bool]) -> (f64, f64, f64, f64, f64) {
    let big_n = machine_all.len() as f64;
    let n = human_lab.len() as f64;
    let f_bar = machine_all.iter().filter(|b| **b).count() as f64 / big_n;
    let deltas: Vec<f64> = human_lab
        .iter()
        .zip(machine_lab.iter())
        .map(|(y, f)| (*y as i32 as f64) - (*f as i32 as f64))
        .collect();
    let delta_bar = deltas.iter().sum::<f64>() / n;
    let theta = f_bar + delta_bar;

    let var_f = f_bar * (1.0 - f_bar) / big_n;
    let mean_d = delta_bar;
    let var_d = deltas.iter().map(|d| (d - mean_d).powi(2)).sum::<f64>() / (n - 1.0).max(1.0) / n;
    let se = (var_f + var_d).sqrt();

    // Classical estimate from the labelled subset alone, for comparison, using
    // a WILSON interval rather than Wald. Wald collapses to +/-0 when every
    // labelled item shares a verdict, which happened immediately on the first
    // real input (5 conflict-set items, all violates) and reported a degenerate
    // zero-width interval as though it were a precise one.
    let y_bar = human_lab.iter().filter(|b| **b).count() as f64 / n;
    let half_classical = wilson_half_width(y_bar, n);
    (theta, 1.96 * se, y_bar, half_classical, f_bar)
}

/// Half-width of a 95% Wilson score interval (projection of
/// `stats::wilson_interval`, one shared implementation and z constant).
fn wilson_half_width(p: f64, n: f64) -> f64 {
    if n <= 0.0 {
        return f64::INFINITY;
    }
    let successes = (p * n).round() as u64;
    let (lo, hi) = wilson_interval(successes, n as u64);
    // Report the larger side so the comparison against PPI is never flattering.
    (hi - p).abs().max((p - lo).abs())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Run { retrieved, specs, out } => {
            let text = std::fs::read_to_string(&retrieved)?;
            let (sites, cfg, skipped) = parse_stream(&text);
            let cache = SpecCache::load(&std::fs::read_to_string(&specs)?)?;
            let served = cache.served_bound(&cfg);

            println!("sites {} | specs {} | unparseable lines {skipped}", sites.len(), cache.len());
            println!("repo-level bound on served requests: {served:?}");

            let findings = propagate_all(&sites, &cache, &served);
            let out_rows: Vec<Finding> = findings
                .iter()
                .zip(sites.iter())
                .map(|(f, s)| Finding {
                    site_id: f.site_id.clone(),
                    snapshot_id: s.snapshot_id.clone(),
                    verdict: f.verdict.as_str().to_string(),
                    reason: f.reason.clone(),
                    class: {
                        let (t, m) = s.api_key();
                        Some(format!("{t}.{m}"))
                    },
                })
                .collect();

            let c = counts(&out_rows);
            let n = out_rows.len().max(1);
            println!("\n{:<16} {:>6} {:>8}", "verdict", "n", "share");
            for (k, v) in &c {
                println!("{k:<16} {v:>6} {:>7.1}%", 100.0 * *v as f64 / n as f64);
            }
            let decided = findings.iter().filter(|f| f.verdict.is_decided()).count();
            println!("\ndecided {decided}/{} ({:.1}%), zero model calls",
                     out_rows.len(), 100.0 * decided as f64 / n as f64);

            if let Some(p) = out {
                std::fs::write(&p, serde_json::to_string_pretty(&out_rows)?)?;
                println!("wrote {p:?}");
            }
        }
        Cmd::Score { findings, gold } => {
            let f = load_findings(&findings)?;
            let g: GoldFile = serde_json::from_str(&std::fs::read_to_string(&gold)?)?;
            let (correct, total, misses) = score(&f, &g.cases);
            println!("gold cases {} | joined {total} | UNJOINED {}",
                     g.cases.len(), g.cases.len() - total);
            if total == 0 {
                anyhow::bail!("nothing to score: the join is empty, which is a bug, not a result");
            }
            println!("accuracy {correct}/{total} = {:.1}%", 100.0 * correct as f64 / total as f64);
            for m in &misses {
                println!("  MISS {m}");
            }
        }
        Cmd::Sweep { retriever, axis, values, specs } => {
            let cache = SpecCache::load(&std::fs::read_to_string(&specs)?)?;
            println!("{:<10} {:>7} {:>9} {:>9} {:>9} {:>10}",
                     axis, "sites", "decided", "violates", "abstain", "bytes");
            println!("{}", "-".repeat(58));
            for v in values.split(',') {
                let cmd = retriever.replace("{flag}", v.trim());
                let out = std::process::Command::new("sh").arg("-c").arg(&cmd).output()
                    .with_context(|| format!("running {cmd}"))?;
                let text = String::from_utf8_lossy(&out.stdout);
                let (sites, cfg, skipped) = parse_stream(&text);
                if skipped > 0 {
                    println!("  warning: {skipped} unparseable lines at {axis}={v}");
                }
                let served = cache.served_bound(&cfg);
                let f = propagate_all(&sites, &cache, &served);
                let decided = f.iter().filter(|x| x.verdict.is_decided()).count();
                let viol = f.iter().filter(|x| x.verdict == rvl_core::Verdict::Violates).count();
                let abst = f.iter().filter(|x| x.verdict == rvl_core::Verdict::Abstain).count();
                println!("{:<10} {:>7} {:>8.1}% {:>9} {:>9} {:>10}",
                         v.trim(), sites.len(),
                         100.0 * decided as f64 / sites.len().max(1) as f64,
                         viol, abst, text.len());
            }
            println!("\nA setting that raises `decided` without raising accuracy is buying");
            println!("confidence, not correctness; score each against gold before adopting one.");
        }
        Cmd::Ppi { findings, adjudicated, target } => {
            let f = load_findings(&findings)?;
            let adj: Vec<Adjudication> =
                serde_json::from_str(&std::fs::read_to_string(&adjudicated)?)?;
            let by_id: std::collections::HashMap<String, &Finding> =
                f.iter().map(|x| (x.site_id.clone(), x)).collect();

            let mut machine_lab = Vec::new();
            let mut human_lab = Vec::new();
            let mut unmatched = 0usize;
            let mut unsure = 0usize;
            for a in &adj {
                if a.verdict == "unsure" {
                    unsure += 1;
                    continue;
                }
                match by_id.get(&format!("{}:{}", a.file_path, a.line_number)) {
                    Some(m) => {
                        machine_lab.push(m.verdict == target);
                        human_lab.push(a.verdict == target);
                    }
                    None => unmatched += 1,
                }
            }
            let machine_all: Vec<bool> = f.iter().map(|x| x.verdict == target).collect();

            println!("target '{target}' | machine-labelled {} | adjudicated {} \
(unsure {unsure} excluded, {unmatched} unmatched)",
                     machine_all.len(), human_lab.len());
            if human_lab.len() < 2 {
                println!("too few adjudications for an interval; adjudicate a random sample first");
                return Ok(());
            }
            let (theta, half, classical, half_c, f_bar) =
                ppi_proportion(&machine_all, &machine_lab, &human_lab);
            println!("\n  scanner rate (all sites)     {:.1}%", 100.0 * f_bar);
            println!("  classical (labelled only)    {:.1}%  +/- {:.1}  (Wilson, n={})",
                     100.0 * classical, 100.0 * half_c, human_lab.len());
            println!("  PPI (debiased, all evidence) {:.1}%  +/- {:.1}", 100.0 * theta, 100.0 * half);
            if half < half_c {
                println!("\n  PPI interval is {:.1}x tighter than labelled-only.", half_c / half.max(1e-9));
            } else {
                println!("\n  PPI is NOT tighter here: the machine labels disagree with the humans");
                println!("  enough that they carry little information. That is a finding.");
            }
            println!("  Valid only if the adjudicated subset was sampled at RANDOM.");
        }
        Cmd::Twins { paired, specs } => {
            #[derive(Deserialize)]
            struct TwinMeta { pair_id: String, side: String, label: String }

            let text = std::fs::read_to_string(&paired)?;
            let (sites, _, skipped) = parse_stream(&text);
            // Lenient line parse on purpose: the same file is dual-parsed as
            // sites (above) and twin metadata; rows that are only one of the
            // two must not fail the other pass.
            let metas: Vec<TwinMeta> = text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|l| serde_json::from_str(l).ok())
                .collect();
            // One read serves both the cache load and the raw by-method view.
            let specs_text = std::fs::read_to_string(&specs)?;
            let cache = SpecCache::load(&specs_text)?;

            // Mined twins carry no resolved client_type, so the exact
            // (type, method) key cannot match. Fall back to the most-used spec
            // for that METHOD name. This is approximate and is reported as
            // such: a twin scored through a borrowed spec tests the bound
            // logic, not the spec lookup.
            let mut by_method: BTreeMap<String, (String, String)> = BTreeMap::new();
            let raw: rvl_spec::SpecFile = serde_json::from_str(&specs_text)?;
            let mut best: BTreeMap<String, u32> = BTreeMap::new();
            for a in &raw.apis {
                let e = best.entry(a.method.clone()).or_insert(0);
                if a.site_count >= *e {
                    *e = a.site_count;
                    by_method.insert(a.method.clone(), (a.type_name.clone(), a.method.clone()));
                }
            }

            let served = rvl_spec::ServedBound::None;
            // (verdict, wanted-label) per side of a twin.
            type TwinSide = Option<(String, String)>;
            let mut pairs: BTreeMap<String, (TwinSide, TwinSide)> = BTreeMap::new();
            let mut borrowed = 0usize;
            for (site, meta) in sites.iter().zip(metas.iter()) {
                let mut s = site.clone();
                if cache.api(&s.api_key()).is_none() {
                    if let Some((t, _)) = by_method.get(&s.method) {
                        s.client_type = t.clone();
                        borrowed += 1;
                    }
                }
                let f = rvl_propagate::propagate(&s, &cache, &served);
                let entry = pairs.entry(meta.pair_id.clone()).or_insert((None, None));
                let slot = (f.verdict.as_str().to_string(), meta.label.clone());
                if meta.side == "before" { entry.0 = Some(slot) } else { entry.1 = Some(slot) }
            }

            println!("twins {} rows / {} pairs | unparseable {skipped} | \
specs borrowed by method for {borrowed} rows", sites.len(), pairs.len());

            let (mut both_right, mut discriminated, mut uninformative, mut wrong) = (0, 0, 0, 0);
            let mut detail: Vec<String> = Vec::new();
            for (pid, (b, a)) in &pairs {
                let (Some((bv, bl)), Some((av, al))) = (b, a) else { continue };
                let exact = bv == bl && av == al;
                let disc = bv != av;
                let uninf = bv == "abstain" && av == "abstain";
                if exact { both_right += 1 }
                if disc { discriminated += 1 }
                if uninf { uninformative += 1 }
                if !exact && !uninf {
                    wrong += 1;
                    detail.push(format!("  {pid}: before {bv} (want {bl}), after {av} (want {al})"));
                }
            }
            let n = pairs.len().max(1);
            println!("\n  exactly right (before violates AND after satisfies) {both_right}/{n}");
            println!("  discriminated (verdict CHANGED across the twin)      {discriminated}/{n}");
            println!("  uninformative (abstained on both sides)              {uninformative}/{n}");
            println!("  wrong                                                {wrong}/{n}");
            for d in detail.iter().take(8) { println!("{d}") }
            println!("\nDiscrimination is the weaker but more robust signal: it asks only");
            println!("whether the engine SEES the change a developer made, independent of");
            println!("whether it names both sides correctly.");
        }
        Cmd::Compare { a, b, gold, boot } => {
            let (fa, fb) = (load_findings(&a)?, load_findings(&b)?);
            let g: GoldFile = serde_json::from_str(&std::fs::read_to_string(&gold)?)?;
            let (pa, pb) = (join(&fa, &g.cases), join(&fb, &g.cases));
            let shared: Vec<_> = pa.iter()
                .filter_map(|(gc, f)| pb.iter().find(|(g2, _)| g2.id == gc.id).map(|(_, f2)| (gc, *f, *f2)))
                .collect();
            if shared.is_empty() {
                anyhow::bail!("no shared scored sites; an empty join is a bug, not a result");
            }
            let ha: Vec<bool> = shared.iter().map(|(g, f, _)| f.verdict == g.expect).collect();
            let hb: Vec<bool> = shared.iter().map(|(g, _, f)| f.verdict == g.expect).collect();
            let acc = |v: &[bool]| v.iter().filter(|x| **x).count() as f64 / v.len() as f64;
            let d = paired_bootstrap(&ha, &hb, boot, 42);
            let (mean, lo, hi, p) = (d.mean, d.lo, d.hi, d.p_better);
            println!("shared scored sites: {}", shared.len());
            println!("  A accuracy {:.1}%\n  B accuracy {:.1}%", 100.0 * acc(&ha), 100.0 * acc(&hb));
            println!("  paired delta (B-A) {mean:+.3}  95% CI [{lo:+.3}, {hi:+.3}]  P(B>A) {:.1}%", 100.0 * p);
            if lo > 0.0 {
                println!("  separated: the gap survives resampling");
            } else {
                println!("  NOT separated: the CI crosses zero, do not claim a difference");
            }
        }
        Cmd::Gate { set, seed_sets, registry, grounding_manifest, target } => {
            // Exit contract: 0 pass, 1 metric fail, 2 refusal. EVERY input
            // problem is a refusal (fail-closed) so a CI wrapper can tell
            // "engine not good enough" from "evidence invalid".
            let refuse = |r: &gate::Refusal| -> ! {
                eprintln!("{r}");
                std::process::exit(2);
            };
            let inputs = match gate::load_gate_inputs(&set, &seed_sets, &registry, &grounding_manifest) {
                Ok(i) => i,
                Err(r) => refuse(&r),
            };
            let gate::GateInputs { manifest, seed_set_names, registry: reg, grounding_repos, rows } = inputs;
            let registry_version =
                match gate::validate_gate_set(&manifest, &seed_set_names, &reg, &grounding_repos) {
                    Ok(v) => v,
                    Err(r) => refuse(&r),
                };

            // The population, printed WITH the number, always.
            println!("GATE RUN  set {} | language {} | minted {} | registry v{registry_version}",
                     manifest.set_id, manifest.language, manifest.minted);
            for pin in &manifest.repos {
                println!("  repo {} @ {}", pin.repo, pin.frozen_sha);
            }
            println!("  sampling frame: {}", manifest.sampling_frame.trim());
            println!("  adjudication: {} by {} ({})",
                     manifest.adjudication.protocol,
                     manifest.adjudication.adjudicator,
                     manifest.adjudication.date);

            let s = match gate::score_gate(&rows, manifest.sample_size, target) {
                Ok(s) => s,
                Err(r) => refuse(&r),
            };
            println!("\n  decided {} (unsure {} excluded) | confirmed violates {}",
                     s.n_decided, s.n_unsure, s.confirmed_violates);
            println!("  precision {:.3} | Wilson 95% LB {:.3} | target {target:.2}",
                     s.precision, s.wilson_lb);
            println!("\n  {}", if s.pass { "PASS: the lower bound clears the target" }
                                else { "FAIL: the LOWER BOUND is the gate, not the point estimate" });
            if !s.pass {
                std::process::exit(1);
            }
        }
        Cmd::Latency { replay, p95_target_ms, triage_median, triage_p95 } => {
            let rows: Vec<latency::ReplayRow> = load_jsonl(&replay)?;
            let r = latency::score_replay(&rows, p95_target_ms, triage_median, triage_p95)?;
            println!("replayed diffs {}", r.n);
            println!("  warm p95 {:.0}ms (target < {p95_target_ms:.0}ms)  {}",
                     r.warm_p95_ms, if r.latency_pass { "PASS" } else { "FAIL" });
            println!("  triage counts median {:.0} (target <= {triage_median:.0}), p95 {:.0} (target <= {triage_p95:.0})  {}",
                     r.triage_median, r.triage_p95, if r.triage_pass { "PASS" } else { "FAIL" });
            if !(r.latency_pass && r.triage_pass) {
                std::process::exit(1);
            }
        }
        Cmd::Compare2 { a, b, gold, boot, sample, seed } => {
            let (fa, fb) = (load_findings(&a)?, load_findings(&b)?);
            let gold_map: Option<BTreeMap<String, String>> = match &gold {
                Some(p) => {
                    let g: GoldFile = serde_json::from_str(&std::fs::read_to_string(p)?)?;
                    Some(g.cases.into_iter().map(|c| (c.id, c.expect)).collect())
                }
                None => None,
            };
            let r = compare::compare_conditions(&fa, &fb, gold_map.as_ref(), boot, sample, seed)?;

            println!("shared sites {} | only in A {} | only in B {}", r.shared, r.only_a, r.only_b);
            println!("\n{:<24} {:<40} {:>4} {:>6} {:>6} {:>6} {:>6}",
                     "repo", "class", "n", "A dec", "B dec", "A vio", "B vio");
            println!("{}", "-".repeat(98));
            for ((repo, class), c) in &r.table {
                println!("{:<24} {:<40} {:>4} {:>6} {:>6} {:>6} {:>6}",
                         repo, class, c.n, c.a_decided, c.b_decided, c.a_violates, c.b_violates);
            }

            println!("\nregressions ({}):", r.regressions.len());
            for x in &r.regressions {
                println!("  [{:<15}] {} | A {} -> B {}", x.kind, x.site_id, x.a_verdict, x.b_verdict);
            }
            println!("\ndisagreement sample ({} of the disagreeing sites, seed {seed}):",
                     r.disagreement_sample.len());
            for d in &r.disagreement_sample {
                println!("  {} | A {} ({}) | B {} ({})",
                         d.site_id, d.a_verdict, d.a_reason, d.b_verdict, d.b_reason);
            }

            let d = r.decided_delta;
            println!("\ndecided-rate delta (B-A) {:+.3}  95% CI [{:+.3}, {:+.3}]  P(B>A) {:.1}%",
                     d.mean, d.lo, d.hi, 100.0 * d.p_better);
            if let Some(d) = r.accuracy_delta {
                println!("accuracy delta (B-A)     {:+.3}  95% CI [{:+.3}, {:+.3}]  P(B>A) {:.1}%  \
(gold joined {}/{}; the CI covers only the joined subpopulation)",
                         d.mean, d.lo, d.hi, 100.0 * d.p_better, r.gold_matched, r.gold_total);
            } else if r.gold_total > 0 {
                println!("gold supplied ({} cases) but joined 0 shared sites; no accuracy claim", r.gold_total);
            }
            println!("\nRead the table and the regression list; a favourable delta with a");
            println!("non-empty regression list is a trade-off, not a win.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(id: &str, v: &str) -> Finding {
        Finding { site_id: id.into(), snapshot_id: "r".into(), verdict: v.into(), reason: String::new(), class: None }
    }
    fn g(id: &str, v: &str) -> GoldCase {
        GoldCase { id: id.into(), expect: v.into() }
    }

    #[test]
    fn gold_paths_join_to_file_line_site_ids() {
        let findings = vec![f("app/orders.py:7", "violates")];
        let gold = vec![g("app/orders.py", "violates")];
        let (correct, total, _) = score(&findings, &gold);
        assert_eq!((correct, total), (1, 1));
    }

    #[test]
    fn unjoined_gold_is_reported_not_silently_dropped() {
        let (_, total, _) = score(&[f("a.py:1", "violates")], &[g("a.py", "violates"), g("missing.py", "satisfies")]);
        assert_eq!(total, 1, "the caller must be able to see the join was partial");
    }

    #[test]
    fn wilson_stays_finite_at_the_boundaries() {
        // Wald gives +/-0 here and misreports a degenerate interval as precise.
        let h = wilson_half_width(1.0, 5.0);
        assert!(h > 0.2, "5/5 successes is not a precise estimate, got {h}");
        assert!(wilson_half_width(0.0, 5.0) > 0.2);
        // and it still narrows with n
        assert!(wilson_half_width(1.0, 500.0) < wilson_half_width(1.0, 5.0));
    }

    #[test]
    fn ppi_recovers_the_machine_rate_when_the_machine_is_right() {
        let all = vec![true, true, false, false, true, false, true, false];
        let lab_m = vec![true, false, true, false];
        let lab_y = lab_m.clone();
        let (theta, _, _, _, f_bar) = ppi_proportion(&all, &lab_m, &lab_y);
        assert!((theta - f_bar).abs() < 1e-9, "no disagreement means no correction");
    }

    #[test]
    fn ppi_corrects_a_machine_that_over_reports() {
        // Machine says violates everywhere; humans agree only half the time.
        let all = vec![true; 100];
        let lab_m = vec![true; 10];
        let mut lab_y = vec![true; 5];
        lab_y.extend(vec![false; 5]);
        let (theta, _, _, _, f_bar) = ppi_proportion(&all, &lab_m, &lab_y);
        assert!((f_bar - 1.0).abs() < 1e-9);
        assert!((theta - 0.5).abs() < 1e-9, "PPI must pull the estimate down to the human rate");
    }

}
