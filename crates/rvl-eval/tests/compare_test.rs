//! Two-condition comparison mode acceptance tests (po-3t3oj.1, skilleval
//! contract from wayfinder po-ipkfg.15): per-repo x per-class table, explicit
//! regression list, disagreement-site sampling, no lone scalar.

use rvl_eval::compare::*;
use std::collections::BTreeMap;

fn f(id: &str, repo: &str, class: &str, verdict: &str) -> Finding {
    Finding {
        site_id: id.into(),
        snapshot_id: repo.into(),
        verdict: verdict.into(),
        reason: format!("because {id}"),
        class: Some(class.into()),
    }
}

/// Baseline: 4 sites across 2 repos / 2 classes.
fn arm_a() -> Vec<Finding> {
    vec![
        f("r1/a.go:1", "r1", "db.Query", "violates"),
        f("r1/b.go:2", "r1", "db.Query", "satisfies"),
        f("r1/c.go:3", "r1", "http.Do", "violates"),
        f("r2/d.go:4", "r2", "http.Do", "abstain"),
    ]
}

/// Treatment: same sites; one lost decision, one flip, one new decision.
fn arm_b() -> Vec<Finding> {
    vec![
        f("r1/a.go:1", "r1", "db.Query", "abstain"), // lost_decision (regression)
        f("r1/b.go:2", "r1", "db.Query", "violates"), // flipped_decided (regression)
        f("r1/c.go:3", "r1", "http.Do", "violates"), // unchanged
        f("r2/d.go:4", "r2", "http.Do", "violates"), // improvement (not a regression)
    ]
}

#[test]
fn table_is_per_repo_per_class() {
    let r = compare_conditions(&arm_a(), &arm_b(), None, 200, 5, 42).unwrap();
    assert_eq!(r.shared, 4);
    assert_eq!(r.only_a, 0);
    assert_eq!(r.only_b, 0);

    let c = &r.table[&("r1".to_string(), "db.Query".to_string())];
    assert_eq!(c.n, 2);
    assert_eq!(c.a_decided, 2);
    assert_eq!(c.b_decided, 1);
    assert_eq!(c.a_violates, 1);
    assert_eq!(c.b_violates, 1);

    let c2 = &r.table[&("r2".to_string(), "http.Do".to_string())];
    assert_eq!(c2.n, 1);
    assert_eq!(c2.a_decided, 0);
    assert_eq!(c2.b_decided, 1);
}

#[test]
fn regressions_are_explicit_and_typed() {
    let r = compare_conditions(&arm_a(), &arm_b(), None, 200, 5, 42).unwrap();
    let kinds: BTreeMap<String, String> = r
        .regressions
        .iter()
        .map(|x| (x.site_id.clone(), x.kind.clone()))
        .collect();
    assert_eq!(
        kinds.get("r1/a.go:1").map(String::as_str),
        Some("lost_decision")
    );
    assert_eq!(
        kinds.get("r1/b.go:2").map(String::as_str),
        Some("flipped_decided")
    );
    // the improvement on r2/d.go:4 must NOT appear as a regression
    assert!(!kinds.contains_key("r2/d.go:4"));
}

#[test]
fn disagreements_are_sampled_deterministically() {
    let r1 = compare_conditions(&arm_a(), &arm_b(), None, 200, 2, 42).unwrap();
    let r2 = compare_conditions(&arm_a(), &arm_b(), None, 200, 2, 42).unwrap();
    // 3 sites disagree; sample capped at 2, same seed -> same sample
    assert_eq!(r1.disagreement_sample.len(), 2);
    let ids1: Vec<_> = r1
        .disagreement_sample
        .iter()
        .map(|d| d.site_id.clone())
        .collect();
    let ids2: Vec<_> = r2
        .disagreement_sample
        .iter()
        .map(|d| d.site_id.clone())
        .collect();
    assert_eq!(ids1, ids2);
    // each carries both reasons for human review
    assert!(r1.disagreement_sample[0].a_reason.starts_with("because"));
}

#[test]
fn decided_delta_has_a_ci_not_a_lone_scalar() {
    let r = compare_conditions(&arm_a(), &arm_b(), None, 500, 5, 42).unwrap();
    let d = r.decided_delta;
    // A decided 3/4, B decided 3/4 -> mean delta 0 with a CI around it
    assert!(d.mean.abs() < 0.2);
    assert!(d.lo <= d.mean && d.mean <= d.hi);
    assert!(
        r.accuracy_delta.is_none(),
        "no gold supplied, no accuracy claim"
    );
}

#[test]
fn gold_adds_accuracy_regressions_and_delta() {
    let mut gold = BTreeMap::new();
    gold.insert("r1/b.go:2".to_string(), "satisfies".to_string()); // A right, B wrong
    gold.insert("r1/c.go:3".to_string(), "violates".to_string()); // both right
    let r = compare_conditions(&arm_a(), &arm_b(), Some(&gold), 200, 5, 42).unwrap();
    assert!(r.accuracy_delta.is_some());
    assert!(r
        .regressions
        .iter()
        .any(|x| x.site_id == "r1/b.go:2" && x.kind == "wrong_vs_gold"));
    // the join coverage is part of the report, not a hidden subpopulation
    assert_eq!((r.gold_matched, r.gold_total), (2, 2));
}

#[test]
fn disjoint_arms_are_an_error_not_a_result() {
    let a = vec![f("x:1", "r", "c", "violates")];
    let b = vec![f("y:2", "r", "c", "violates")];
    assert!(compare_conditions(&a, &b, None, 100, 5, 42).is_err());
}

#[test]
fn duplicate_site_ids_do_not_underflow_only_b() {
    // Real corpora repeat a site_id (the same file:line retrieved twice).
    // Counting shared PAIRS against distinct B rows underflows; this is the
    // regression guard for that panic.
    let a = vec![
        f("r1/a.go:1", "r1", "db.Query", "violates"),
        f("r1/a.go:1", "r1", "db.Query", "violates"),
        f("r1/b.go:2", "r1", "db.Query", "satisfies"),
    ];
    let b = vec![
        f("r1/a.go:1", "r1", "db.Query", "violates"),
        f("r1/b.go:2", "r1", "db.Query", "satisfies"),
    ];
    let r = compare_conditions(&a, &b, None, 100, 5, 42).unwrap();
    assert_eq!(r.shared, 3, "every A row that joins is a shared pair");
    assert_eq!(r.only_a, 0);
    assert_eq!(r.only_b, 0, "both B rows matched, so none are B-only");
}

#[test]
fn repeated_site_ids_are_reported_not_silently_joined() {
    let a = vec![
        f("dup.go:1", "r1", "c.M", "violates"),
        f("dup.go:1", "r1", "other.M", "not_applicable"),
    ];
    let b = a.clone();
    let r = compare_conditions(&a, &b, None, 100, 5, 42).unwrap();
    assert!(
        r.ambiguous_join_keys > 0,
        "a repeated join key must be surfaced"
    );
}

/// Pins the seeded streams. The sample and the bootstrap interval come from
/// `rand`'s StdRng, whose output for a seed is stable within one `rand`
/// version only. A `rand` upgrade that moves either value fails here, so the
/// move is seen and re-pinned on purpose, never by accident. Re-pinned once,
/// for rand 0.8 -> 0.10 (po-av01j.233): the sample was f10, f04, f08, f01 and
/// the bootstrap mean was -0.6694166666666747.
#[test]
fn seeded_outputs_are_pinned() {
    let a: Vec<Finding> = (0..12)
        .map(|i| f(&format!("r1/f{i:02}.go:1"), "r1", "db.Query", "violates"))
        .collect();
    let b: Vec<Finding> = (0..12)
        .map(|i| {
            let verdict = if i % 3 == 0 { "violates" } else { "abstain" };
            f(&format!("r1/f{i:02}.go:1"), "r1", "db.Query", verdict)
        })
        .collect();
    let r = compare_conditions(&a, &b, None, 1000, 4, 42).unwrap();
    let ids: Vec<&str> = r
        .disagreement_sample
        .iter()
        .map(|d| d.site_id.as_str())
        .collect();
    assert_eq!(
        ids,
        ["r1/f07.go:1", "r1/f10.go:1", "r1/f05.go:1", "r1/f04.go:1"]
    );
    let d = r.decided_delta;
    assert_eq!(
        (d.mean, d.lo, d.hi, d.p_better),
        (
            -0.6672500000000069,
            -0.9166666666666666,
            -0.4166666666666667,
            0.0
        ),
        "bootstrap stream moved"
    );
}
