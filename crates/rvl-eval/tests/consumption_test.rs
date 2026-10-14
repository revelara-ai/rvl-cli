//! Single-use enforcement (po-av01j.89).
//!
//! The property under test is the one the old `consumed: bool` claimed and
//! never had: a gate set cannot be scored twice, and the second attempt is
//! refused by a fact the gate process wrote itself rather than by a field the
//! guarded file declares about itself.

use rvl_eval::consumption::{
    append_consumption, check_unconsumed, consume, default_ledger_path, read_ledger, sha256_hex,
    ConsumptionRecord,
};
use rvl_eval::gate::{score_gate, AdjudicatedVerdict, GoldRow, Refusal};
use std::path::Path;

fn rec(set_id: &str, sha: &str) -> ConsumptionRecord {
    ConsumptionRecord {
        set_id: set_id.into(),
        verdicts_sha256: sha.into(),
        manifest_sha256: "m".into(),
        target: 0.90,
        run_at: "2026-08-06T00:00:00Z".into(),
        operator: Some("jo".into()),
        report_sha256: Some("r".into()),
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

#[test]
fn sha256_hex_is_lowercase_hex_of_the_published_digest() {
    // The ledger compares these strings across runs, so a record written by
    // an older build must still match one computed today (po-av01j.235).
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        sha256_hex(b"gold rows here"),
        "c231b8bc6c632f4fec744ebef86bd4051ce25d89530050edab7d63a9647627e6"
    );
}

/// A minted set on disk: manifest, gold and the adjudication report the
/// operator reads before the go.
fn minted_set(report: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let set = root.path().join("eval-java-v1");
    std::fs::create_dir_all(&set).unwrap();
    std::fs::write(set.join("manifest.yaml"), "set_id: eval-java-v1\n").unwrap();
    std::fs::write(set.join("verdicts.jsonl"), "{}\n").unwrap();
    std::fs::write(set.join("adjudication-report.md"), report).unwrap();
    (root, set)
}

fn violates(n: usize) -> Vec<GoldRow> {
    (0..n)
        .map(|i| GoldRow {
            file_path: format!("f{i}.java"),
            line_number: 1,
            adjudicated: AdjudicatedVerdict::Violates,
        })
        .collect()
}

#[test]
fn a_go_for_the_report_on_disk_records_the_operator_and_hash_then_scores() {
    let (_root, set) = minted_set("# Adjudication report\nconfirmed 50 of 50\n");
    let ledger = default_ledger_path(&set);
    let hash = sha256_hex(b"# Adjudication report\nconfirmed 50 of 50\n");
    let rec = consume(
        &set,
        &ledger,
        "eval-java-v1",
        0.90,
        "jo",
        &hash,
        "now".into(),
    )
    .expect("a go for the committed report must consume the set");
    let written = read_ledger(&ledger).unwrap();
    assert_eq!(written, vec![rec]);
    assert_eq!(written[0].operator.as_deref(), Some("jo"));
    assert_eq!(written[0].report_sha256.as_deref(), Some(hash.as_str()));
    assert!(score_gate(&violates(50), 50, 0.90).unwrap().pass);
}

#[test]
fn the_go_hash_ignores_case_and_surrounding_space() {
    // A hash pasted from `sha256sum` output, or typed upper-case, is the same go.
    let (_root, set) = minted_set("report");
    let hash = format!("  {}\n", sha256_hex(b"report").to_uppercase());
    let rec = consume(
        &set,
        &default_ledger_path(&set),
        "eval-java-v1",
        0.90,
        "jo",
        &hash,
        "now".into(),
    )
    .unwrap();
    assert_eq!(rec.report_sha256, Some(sha256_hex(b"report")));
}

#[test]
fn a_go_for_another_report_refuses_before_the_set_is_consumed() {
    // The operator read one report and the set now holds another: the go does
    // not cover it. Nothing is written, so the set stays unconsumed for a new go.
    let (_root, set) = minted_set("adjudicated again");
    let ledger = default_ledger_path(&set);
    let err = consume(
        &set,
        &ledger,
        "eval-java-v1",
        0.90,
        "jo",
        &sha256_hex(b"what jo read"),
        "now".into(),
    )
    .expect_err("a mismatched report hash must refuse");
    assert!(matches!(err, Refusal::ReportHashMismatch { .. }), "{err:?}");
    assert!(format!("{err}").contains(&sha256_hex(b"adjudicated again")));
    assert!(!ledger.exists(), "a refused go must not touch the ledger");
}

#[test]
fn a_set_with_no_report_cannot_be_given_a_go() {
    // NOT MINTED and NOT QUALIFIED leave no report, so there is nothing to hash.
    let (_root, set) = minted_set("x");
    std::fs::remove_file(set.join("adjudication-report.md")).unwrap();
    let ledger = default_ledger_path(&set);
    let err = consume(
        &set,
        &ledger,
        "eval-java-v1",
        0.90,
        "jo",
        &sha256_hex(b"x"),
        "now".into(),
    )
    .expect_err("no report, no go");
    assert!(matches!(err, Refusal::EvidenceUnreadable(_)), "{err:?}");
    assert!(!ledger.exists());
}

#[test]
fn a_blank_operator_name_is_refused() {
    let (_root, set) = minted_set("r");
    let ledger = default_ledger_path(&set);
    let err = consume(
        &set,
        &ledger,
        "eval-java-v1",
        0.90,
        "  ",
        &sha256_hex(b"r"),
        "now".into(),
    )
    .expect_err("a go needs a person");
    assert!(matches!(err, Refusal::NoOperator), "{err:?}");
    assert!(!ledger.exists());
}

#[test]
fn a_ledger_line_from_before_the_go_still_parses() {
    // Sets consumed before the go existed have no operator or report hash.
    // They must still block a re-run, so the old lines must still read.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("consumed.jsonl");
    std::fs::write(
        &p,
        r#"{"set_id":"eval-go-v1","verdicts_sha256":"aa","manifest_sha256":"m","target":0.9,"run_at":"t"}"#,
    )
    .unwrap();
    let got = read_ledger(&p).unwrap();
    assert_eq!(got[0].operator, None);
    assert!(check_unconsumed(&got, "eval-go-v1", "bb").is_err());
}
