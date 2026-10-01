//! The gate must measure the ENGINE, not a static file (po-av01j.95).
//!
//! `score_gate` computes confirmed/decided straight off verdicts.jsonl. That is
//! the panel's confirmation rate on a file: correct for whatever engine
//! produced it, and unchanged by any engine change afterwards. These tests pin
//! the property it never had -- that a regressed engine FAILS a re-run.

use rvl_eval::gate::{
    join_gold_to_engine, score_gate_against_engine, AdjudicatedVerdict, EngineSaid, EngineSite,
    GoldRow, Refusal,
};
use rvl_eval::stats::wilson_lower_bound;

fn gold(file: &str, line: u64, v: AdjudicatedVerdict) -> GoldRow {
    GoldRow {
        file_path: file.into(),
        line_number: line,
        adjudicated: v,
    }
}

/// An engine site in its OWN cluster: one spec class per line. The tests that
/// are not about clustering use it so that n_eff equals n and the design
/// effect stays out of what they measure.
fn site(file: &str, line: u64, flagged: bool) -> EngineSite {
    clustered(file, line, flagged, "o/r", &format!("spec{line}"))
}

/// An engine site decided by `class` in `repo`.
fn clustered(file: &str, line: u64, flagged: bool, repo: &str, class: &str) -> EngineSite {
    EngineSite {
        file_path: file.into(),
        line_number: line,
        flagged,
        repo: repo.into(),
        class: class.into(),
    }
}

/// n gold rows the panel confirmed, all still flagged by the engine.
fn clean_corpus(n: usize) -> (Vec<GoldRow>, Vec<EngineSite>) {
    let rows: Vec<GoldRow> = (0..n)
        .map(|i| gold("a.go", i as u64, AdjudicatedVerdict::Violates))
        .collect();
    let engine = (0..n).map(|i| site("a.go", i as u64, true)).collect();
    (rows, engine)
}

#[test]
fn a_perfect_engine_passes() {
    let (rows, engine) = clean_corpus(60);
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_scored, 60);
    assert_eq!(s.false_positives, 0);
    assert!(
        s.pass,
        "60/60 confirmed must clear 0.90, got {}",
        s.wilson_lb
    );
}

#[test]
fn an_engine_that_starts_flagging_non_violations_fails() {
    // THE TEST THE OLD IMPLEMENTATION COULD NOT EXPRESS. The gold file is
    // unchanged. Only the engine changed: it now also flags 30 sites the panel
    // called Satisfies. score_gate would still read the same file and pass.
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    for i in 0..60 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(site("a.go", i, true));
    }
    for i in 60..90 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Satisfies));
        engine.push(site("a.go", i, true)); // regression: flags these now
    }
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_scored, 90);
    assert_eq!(s.false_positives, 30);
    assert!(
        !s.pass,
        "60/90 = 0.67 must FAIL a 0.90 target, got LB {}",
        s.wilson_lb
    );
}

#[test]
fn rows_the_engine_no_longer_flags_leave_the_denominator() {
    // Not false positives: the engine is not claiming anything about them. But
    // they must be REPORTED, because precision alone cannot show that the
    // engine got quieter.
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    for i in 0..55 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(site("a.go", i, true));
    }
    for i in 55..80 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(site("a.go", i, false)); // reached, not flagged
    }
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_scored, 55, "only flagged rows are scored");
    assert_eq!(s.no_longer_flagged, 25);
    assert!(s.pass);
}

#[test]
fn an_engine_that_goes_quiet_cannot_borrow_the_original_sample_size() {
    // The n>=50 bar applies to what was SCORED. An engine that stops flagging
    // most of the gold has lost the evidence for the claim, and must not be
    // able to pass on 10 rows because the manifest says 50.
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    for i in 0..80 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(site("a.go", i, i < 10));
    }
    let err = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90)
        .expect_err("10 scored rows against a sample_size of 50 must refuse");
    assert!(matches!(
        err,
        Refusal::GoldTooSmall {
            decided: 10,
            required: 50
        }
    ));
}

#[test]
fn unsure_rows_count_toward_neither_term() {
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    for i in 0..55 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(site("a.go", i, true));
    }
    for i in 55..70 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Unsure));
        engine.push(site("a.go", i, true));
    }
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_scored, 55);
    assert_eq!(s.n_unsure, 15);
}

#[test]
fn a_gold_row_with_no_site_at_all_is_unmatched_not_a_pass() {
    // Gold and checkout have drifted (file moved, retriever changed). Silently
    // treating these as satisfied would let drift inflate the number.
    let rows = vec![gold("gone.go", 5, AdjudicatedVerdict::Violates)];
    let joined = join_gold_to_engine(&rows, &[site("other.go", 5, true)]);
    assert_eq!(joined[0].engine, EngineSaid::Absent);
}

#[test]
fn one_location_with_several_sites_counts_as_flagged_if_any_flags() {
    // A file:line can carry several sites with different client types and
    // different verdicts. The panel was shown the LOCATION.
    let rows = vec![gold("a.go", 7, AdjudicatedVerdict::Violates)];
    let joined = join_gold_to_engine(&rows, &[site("a.go", 7, false), site("a.go", 7, true)]);
    assert_eq!(joined[0].engine, EngineSaid::Flagged);
}

// --- Cluster-adjusted bound (po-io8sk.1) ---

#[test]
fn fifty_violates_from_four_specs_in_two_repos_pass_raw_n_and_are_refused() {
    // THE FIXTURE THE RAW-n GATE ADMITTED. 50/50 confirmed clears 0.90 on raw
    // n (LB 0.9287), but the 50 rows are decided by 4 specs in 2 repos, in
    // clusters of 20, 15, 10 and 5. sum(m^2) = 750, so deff = 750/50 = 15 and
    // n_eff = 50/15 = 3.33: far below the n >= 50 bar.
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    let clusters = [
        ("o/a", "http.Client.Do", 20),
        ("o/a", "sql.DB.Query", 15),
        ("o/b", "http.Client.Do", 10),
        ("o/b", "redis.Client.Get", 5),
    ];
    let mut line = 0;
    for (repo, class, m) in clusters {
        for _ in 0..m {
            rows.push(gold("a.go", line, AdjudicatedVerdict::Violates));
            engine.push(clustered("a.go", line, true, repo, class));
            line += 1;
        }
    }
    assert!(
        wilson_lower_bound(50, 50) >= 0.90,
        "the fixture must pass on raw n, or it proves nothing"
    );
    let err = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90)
        .expect_err("4 clusters are not 50 independent observations");
    match err {
        Refusal::EffectiveSampleTooSmall {
            n,
            n_clusters,
            deff,
            n_eff,
        } => {
            assert_eq!(n, 50);
            assert_eq!(n_clusters, 4);
            assert!((deff - 15.0).abs() < 1e-9, "deff {deff}");
            assert!((n_eff - 50.0 / 15.0).abs() < 1e-9, "n_eff {n_eff}");
        }
        other => panic!("expected EffectiveSampleTooSmall, got {other:?}"),
    }
}

#[test]
fn the_refusal_prints_all_four_numbers() {
    let r = Refusal::EffectiveSampleTooSmall {
        n: 50,
        n_clusters: 4,
        deff: 15.0,
        n_eff: 50.0 / 15.0,
    };
    let text = r.to_string();
    for part in ["n 50", "n_clusters 4", "deff 15.00", "n_eff 3.3"] {
        assert!(text.contains(part), "missing {part:?} in {text:?}");
    }
}

#[test]
fn a_bound_that_clears_the_target_on_raw_n_fails_on_n_eff() {
    // 117/120 confirmed, every spec class deciding exactly 2 sites: 60
    // clusters, deff = 2, n_eff = 60. That clears the n_eff >= 50 bar, so the
    // run is scored, but the bound is taken at n_eff: 0.8986 < 0.90, where raw
    // n gave 0.9291.
    let mut rows = Vec::new();
    let mut engine = Vec::new();
    for i in 0..120u64 {
        let adj = if i < 3 {
            AdjudicatedVerdict::Satisfies
        } else {
            AdjudicatedVerdict::Violates
        };
        rows.push(gold("a.go", i, adj));
        engine.push(clustered("a.go", i, true, "o/r", &format!("spec{}", i / 2)));
    }
    assert!(wilson_lower_bound(117, 120) >= 0.90);
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_scored, 120);
    assert_eq!(s.n_clusters, 60);
    assert!((s.deff - 2.0).abs() < 1e-9);
    assert!((s.n_eff - 60.0).abs() < 1e-9);
    assert!((s.wilson_lb - 0.8986).abs() < 1e-3, "LB {}", s.wilson_lb);
    assert!(!s.pass);
}

#[test]
fn the_same_spec_class_in_two_repos_is_two_clusters() {
    let rows: Vec<GoldRow> = (0..60)
        .map(|i| gold("a.go", i, AdjudicatedVerdict::Violates))
        .collect();
    let engine: Vec<EngineSite> = (0..60)
        .map(|i| clustered("a.go", i, true, &format!("o/r{i}"), "http.Client.Do"))
        .collect();
    let s = score_gate_against_engine(&join_gold_to_engine(&rows, &engine), 50, 0.90).unwrap();
    assert_eq!(s.n_clusters, 60);
    assert!((s.n_eff - 60.0).abs() < 1e-9);
    assert!(s.pass);
}

#[test]
fn a_location_takes_its_cluster_from_the_site_that_flagged_it() {
    let rows = vec![gold("a.go", 7, AdjudicatedVerdict::Violates)];
    let joined = join_gold_to_engine(
        &rows,
        &[
            clustered("a.go", 7, false, "o/r", "quiet.Spec"),
            clustered("a.go", 7, true, "o/r", "loud.Spec"),
        ],
    );
    assert_eq!(
        joined[0].cluster,
        Some(("o/r".to_string(), "loud.Spec".to_string()))
    );
}
