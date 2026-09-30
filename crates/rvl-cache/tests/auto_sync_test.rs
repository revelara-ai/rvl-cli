//! Auto-sync primitives (po-av01j.171): the rate limit on the background
//! check, what suppresses it, the CI pin, and the per-repo record that lets a
//! scan attribute a changed result to a changed corpus.

use rvl_cache::auto::*;

const H: u64 = 3600;

fn root() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

// --- rate limit ---

#[test]
fn first_claim_wins_and_a_second_inside_the_interval_does_not() {
    let dir = root();
    assert!(claim(dir.path(), 1_000_000, 6 * H), "no stamp yet: due");
    assert!(
        !claim(dir.path(), 1_000_000 + 10, 6 * H),
        "a second scan seconds later must not start another check"
    );
    assert!(!claim(dir.path(), 1_000_000 + 6 * H - 1, 6 * H));
    assert!(
        claim(dir.path(), 1_000_000 + 6 * H, 6 * H),
        "one interval later the check is due again"
    );
}

#[test]
fn an_explicit_sync_resets_the_clock() {
    let dir = root();
    record_check(dir.path(), 5_000_000);
    assert!(
        !claim(dir.path(), 5_000_000 + H, 6 * H),
        "init or 'rvl sync' just fetched, so a scan an hour later has nothing to check"
    );
}

#[test]
fn a_held_claim_lock_blocks_a_concurrent_claimer() {
    let dir = root();
    std::fs::write(dir.path().join(CLAIM_LOCK), b"").unwrap();
    assert!(
        !claim(dir.path(), 1_000_000, 6 * H),
        "another scan is mid-claim: this one must not also spawn"
    );
}

#[test]
fn a_garbage_stamp_counts_as_due_not_as_an_error() {
    let dir = root();
    std::fs::write(dir.path().join(STAMP), b"not a number").unwrap();
    assert!(claim(dir.path(), 1_000_000, 6 * H));
}

#[test]
fn a_clock_that_went_backwards_does_not_suppress_checks_forever() {
    let dir = root();
    record_check(dir.path(), 9_000_000);
    assert!(
        claim(dir.path(), 1_000_000, 6 * H),
        "a stamp in the future is not trusted"
    );
}

// --- suppression ---

#[test]
fn offline_pin_and_ci_each_suppress_the_background_check() {
    assert_eq!(suppressed(false, None, None), None);
    assert_eq!(suppressed(true, None, None), Some(Suppressed::Offline));
    assert_eq!(
        suppressed(false, Some("2026-09-01.a"), None),
        Some(Suppressed::Pinned)
    );
    assert_eq!(suppressed(false, None, Some("true")), Some(Suppressed::Ci));
    assert_eq!(suppressed(false, None, Some("1")), Some(Suppressed::Ci));
    // Exported-but-false CI does not count, and neither does an empty pin.
    assert_eq!(suppressed(false, None, Some("false")), None);
    assert_eq!(suppressed(false, None, Some("0")), None);
    assert_eq!(suppressed(false, None, Some("")), None);
    assert_eq!(suppressed(false, Some(" "), None), None);
}

// --- CI pin ---

#[test]
fn pin_accepts_every_loaded_tier_named_in_the_list() {
    assert!(check_pin("2026-09-01.a", &["2026-09-01.a"]).is_ok());
    assert!(check_pin(
        "2026-09-01.a, 2026-09-02.b",
        &["2026-09-02.b", "2026-09-01.a"]
    )
    .is_ok());
}

#[test]
fn pin_rejects_a_tier_not_named_and_says_which() {
    let err = check_pin("2026-09-01.a", &["2026-09-01.a", "2026-09-05.z"]).unwrap_err();
    assert!(err.contains("2026-09-05.z"), "{err}");
    assert!(err.contains("2026-09-01.a"), "{err}");
}

#[test]
fn pin_with_nothing_loaded_is_a_mismatch() {
    assert!(check_pin("2026-09-01.a", &[]).is_err());
}

// --- attribution ---

#[test]
fn tiers_label_names_what_loaded() {
    assert_eq!(tiers_label(None, None), None);
    assert_eq!(tiers_label(Some("o1"), None).as_deref(), Some("oss o1"));
    assert_eq!(
        tiers_label(Some("o1"), Some("c1")).as_deref(),
        Some("commercial c1, oss o1")
    );
}

#[test]
fn applied_record_reports_a_change_once_and_only_per_repo() {
    let dir = root();
    assert_eq!(
        note_applied(dir.path(), "/repo/a", "oss o1"),
        None,
        "a repo's first scan has nothing to compare against"
    );
    assert_eq!(note_applied(dir.path(), "/repo/a", "oss o1"), None);
    assert_eq!(
        note_applied(dir.path(), "/repo/a", "oss o2").as_deref(),
        Some("oss o1"),
        "the corpus moved under this repo: say from what"
    );
    assert_eq!(
        note_applied(dir.path(), "/repo/a", "oss o2"),
        None,
        "said once, then quiet"
    );
    assert_eq!(
        note_applied(dir.path(), "/repo/b", "oss o2"),
        None,
        "another repo's record is its own"
    );
}

#[test]
fn a_corrupt_applied_record_is_rebuilt_not_fatal() {
    let dir = root();
    std::fs::write(dir.path().join(APPLIED), b"{nope").unwrap();
    assert_eq!(note_applied(dir.path(), "/repo/a", "oss o1"), None);
    assert_eq!(
        note_applied(dir.path(), "/repo/a", "oss o2").as_deref(),
        Some("oss o1")
    );
}
