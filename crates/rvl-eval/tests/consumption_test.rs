//! Single-use enforcement (po-av01j.89).
//!
//! The property under test is the one the old `consumed: bool` claimed and
//! never had: a gate set cannot be scored twice, and the second attempt is
//! refused by a fact the gate process wrote itself rather than by a field the
//! guarded file declares about itself.

use rvl_eval::consumption::{
    append_consumption, check_unconsumed, default_ledger_path, read_ledger, sha256_hex,
    ConsumptionRecord,
};
use std::path::Path;

fn rec(set_id: &str, sha: &str) -> ConsumptionRecord {
    ConsumptionRecord {
        set_id: set_id.into(),
        verdicts_sha256: sha.into(),
        manifest_sha256: "m".into(),
        target: 0.90,
        run_at: "2026-08-06T00:00:00Z".into(),
    }
}

#[test]
fn a_missing_ledger_is_empty_not_a_refusal() {
    // gate-sets/ legitimately starts with no ledger. Treating absence as a
    // refusal would make the first honest gate run impossible.
    let dir = tempdir();
    let got = read_ledger(&dir.join("consumed.jsonl")).expect("missing ledger must be empty");
    assert!(got.is_empty());
}

#[test]
fn an_unreadable_ledger_is_a_refusal() {
    // Fail-closed: a ledger we cannot parse cannot prove a set is unconsumed.
    let dir = tempdir();
    let p = dir.join("consumed.jsonl");
    std::fs::write(&p, "{not json}\n").unwrap();
    assert!(read_ledger(&p).is_err(), "a malformed ledger must refuse");
}

#[test]
fn the_same_set_id_is_refused_on_the_second_run() {
    let ledger = vec![rec("eval-go-v1", "aaaa")];
    assert!(check_unconsumed(&ledger, "eval-go-v1", "bbbb").is_err());
}

#[test]
fn the_same_gold_under_a_new_name_is_also_refused() {
    // THE POINT OF HASHING. set_id alone catches an honest re-run; this catches
    // copying the directory to `eval-go-v1-retry` after a FAIL, which is what
    // someone reaches for under deadline pressure without feeling like they are
    // cheating.
    let ledger = vec![rec("eval-go-v1", "deadbeef")];
    let err = check_unconsumed(&ledger, "eval-go-v1-retry", "deadbeef")
        .expect_err("identical gold under a new id must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("identical gold"),
        "the refusal must say the gold is the same, not that the id is: {msg}"
    );
}

#[test]
fn a_genuinely_fresh_set_is_admitted() {
    // The guard has to let real work through, or it just gets disabled.
    let ledger = vec![rec("eval-go-v1", "aaaa")];
    assert!(check_unconsumed(&ledger, "eval-go-v2", "bbbb").is_ok());
}

#[test]
fn appending_makes_the_next_run_refuse() {
    // End to end: the write is what closes the door, so this is the test that
    // would have failed for the entire life of the old implementation.
    let dir = tempdir();
    let p = dir.join("consumed.jsonl");
    let sha = sha256_hex(b"gold rows here");
    assert!(check_unconsumed(&read_ledger(&p).unwrap(), "eval-go-v1", &sha).is_ok());
    append_consumption(&p, &rec("eval-go-v1", &sha)).unwrap();
    assert!(
        check_unconsumed(&read_ledger(&p).unwrap(), "eval-go-v1", &sha).is_err(),
        "after one run the set must be consumed"
    );
}

#[test]
fn the_ledger_sits_beside_the_set_directories() {
    // One committed file covering every set, not one per set: a per-set ledger
    // inside the set directory would be deleted by the same `rm -rf` that
    // recreates the set.
    let p = default_ledger_path(Path::new("gate-sets/eval-go-v1"));
    assert_eq!(p, Path::new("gate-sets/consumed.jsonl"));
}

fn tempdir() -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "rvl-eval-consumption-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&base).unwrap();
    base
}
