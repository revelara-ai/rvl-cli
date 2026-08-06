//! The gate must measure the ENGINE, not a static file (po-av01j.95).
//!
//! `score_gate` computes confirmed/decided straight off verdicts.jsonl. That is
//! the panel's confirmation rate on a file: correct for whatever engine
//! produced it, and unchanged by any engine change afterwards. These tests pin
//! the property it never had -- that a regressed engine FAILS a re-run.

use rvl_eval::gate::{
    join_gold_to_engine, score_gate_against_engine, AdjudicatedVerdict, EngineSaid, GoldRow,
    Refusal,
};

fn gold(file: &str, line: u64, v: AdjudicatedVerdict) -> GoldRow {
    GoldRow {
        file_path: file.into(),
        line_number: line,
        adjudicated: v,
    }
}

/// n gold rows the panel confirmed, all still flagged by the engine.
fn clean_corpus(n: usize) -> (Vec<GoldRow>, Vec<(String, u64, bool)>) {
    let rows: Vec<GoldRow> = (0..n)
        .map(|i| gold("a.go", i as u64, AdjudicatedVerdict::Violates))
        .collect();
    let engine = (0..n)
        .map(|i| ("a.go".to_string(), i as u64, true))
        .collect();
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
        engine.push(("a.go".to_string(), i, true));
    }
    for i in 60..90 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Satisfies));
        engine.push(("a.go".to_string(), i, true)); // regression: flags these now
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
        engine.push(("a.go".to_string(), i, true));
    }
    for i in 55..80 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Violates));
        engine.push(("a.go".to_string(), i, false)); // reached, not flagged
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
        engine.push(("a.go".to_string(), i, i < 10));
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
        engine.push(("a.go".to_string(), i, true));
    }
    for i in 55..70 {
        rows.push(gold("a.go", i, AdjudicatedVerdict::Unsure));
        engine.push(("a.go".to_string(), i, true));
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
    let joined = join_gold_to_engine(&rows, &[("other.go".to_string(), 5, true)]);
    assert_eq!(joined[0].engine, EngineSaid::Absent);
}

#[test]
fn one_location_with_several_sites_counts_as_flagged_if_any_flags() {
    // A file:line can carry several sites with different client types and
    // different verdicts. The panel was shown the LOCATION.
    let rows = vec![gold("a.go", 7, AdjudicatedVerdict::Violates)];
    let joined = join_gold_to_engine(
        &rows,
        &[
            ("a.go".to_string(), 7, false),
            ("a.go".to_string(), 7, true),
        ],
    );
    assert_eq!(joined[0].engine, EngineSaid::Flagged);
}
