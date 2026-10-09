//! Incremental-scan acceptance tests (po-3t3oj.14): content-hash gate,
//! collision-safe site keys, reuse/retrieve split, budget fail-open vs strict.

use rvl_core::Site;
use rvl_index::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

fn site(path: &str, line: u32, ct: &str, method: &str) -> Site {
    Site {
        file_path: path.into(),
        line_number: line,
        client_type: ct.into(),
        method: method.into(),
        ..Default::default()
    }
}

fn write(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p
}

struct FakeRetriever {
    calls: RefCell<Vec<Vec<PathBuf>>>,
    per_file: usize,
}
impl FakeRetriever {
    fn new(per_file: usize) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            per_file,
        }
    }
}
impl Retriever for FakeRetriever {
    fn retrieve(&self, paths: &[PathBuf]) -> anyhow::Result<Vec<Site>> {
        self.calls.borrow_mut().push(paths.to_vec());
        let mut out = Vec::new();
        for p in paths {
            for i in 0..self.per_file {
                out.push(site(p.to_str().unwrap(), i as u32 + 1, "pkg.Client", "Do"));
            }
        }
        Ok(out)
    }
}

// --- hashing ---

#[test]
fn content_hash_tracks_content_not_path() {
    let dir = tempfile::tempdir().unwrap();
    let a = write(dir.path(), "a.go", "package a\n");
    let b = write(dir.path(), "b.go", "package a\n");
    let c = write(dir.path(), "c.go", "package c\n");
    assert_eq!(hash_file(&a).unwrap(), hash_file(&b).unwrap());
    assert_ne!(hash_file(&a).unwrap(), hash_file(&c).unwrap());
    assert_eq!(hash_bytes(b"package a\n"), hash_file(&a).unwrap());
}

// --- site identity ---

#[test]
fn site_key_disambiguates_a_shared_location() {
    // The finding from po-3t3oj.15: one file:line can resolve to two sites.
    let one = site("svc/x.go", 306, "drive.Service", "Do");
    let two = site("svc/x.go", 306, "http.Client", "Do");
    assert_ne!(
        site_key(&one),
        site_key(&two),
        "file:line alone collides; the key must carry the client type"
    );
    assert_eq!(site_key(&one), site_key(&one.clone()));
}

// --- index round trip + hash gate ---

#[test]
fn index_returns_packets_only_for_a_matching_hash() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let f = write(dir.path(), "a.go", "package a\n");
    let h = hash_file(&f).unwrap();
    let sites = vec![site("a.go", 1, "pkg.C", "Do")];

    assert!(
        idx.get(&f, &h).unwrap().is_none(),
        "empty index has nothing"
    );
    idx.put(&f, &h, &sites).unwrap();
    assert_eq!(idx.len().unwrap(), 1);

    let got = idx
        .get(&f, &h)
        .unwrap()
        .expect("hash matches, packets reused");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].client_type, "pkg.C");
    assert!(
        idx.get(&f, "0000").unwrap().is_none(),
        "a stale hash must not return packets"
    );
}

#[test]
fn plan_reload_splits_on_content_hash() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let stable = write(dir.path(), "stable.go", "package a\n");
    let edited = write(dir.path(), "edited.go", "package b\n");
    let fresh = write(dir.path(), "fresh.go", "package c\n");
    idx.put(
        &stable,
        &hash_file(&stable).unwrap(),
        &[site("stable.go", 1, "p.C", "Do")],
    )
    .unwrap();
    idx.put(&edited, "hash-from-before-the-edit", &[]).unwrap();

    let plan = idx.plan_reload(&[stable.clone(), edited.clone(), fresh.clone()]);
    assert_eq!(plan.unchanged, vec![stable]);
    assert_eq!(plan.changed, vec![edited, fresh]);
}

#[test]
fn unreadable_files_are_treated_as_changed() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let gone = dir.path().join("deleted.go");
    let plan = idx.plan_reload(std::slice::from_ref(&gone));
    assert_eq!(plan.changed, vec![gone], "fail toward doing the work");
}

// --- warm scan ---

#[test]
fn warm_scan_reuses_index_and_retrieves_only_changed() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let warm = write(dir.path(), "warm.go", "package warm\n");
    let cold = write(dir.path(), "cold.go", "package cold\n");
    idx.put(
        &warm,
        &hash_file(&warm).unwrap(),
        &[site("warm.go", 9, "p.C", "Warm")],
    )
    .unwrap();

    let r = FakeRetriever::new(2);
    let scan = idx
        .warm_scan(&[warm.clone(), cold.clone()], &r, &Budget::hook())
        .unwrap();

    assert_eq!(scan.reused_files, 1);
    assert_eq!(scan.retrieved_files, 1);
    assert!(!scan.degraded);
    assert_eq!(scan.sites.len(), 3, "1 reused + 2 retrieved");
    assert_eq!(
        r.calls.borrow().len(),
        1,
        "one retrieval call, only for changed files"
    );
    assert_eq!(r.calls.borrow()[0], vec![cold.clone()]);

    // The freshly retrieved file is now indexed: a second pass reuses both.
    let scan2 = idx
        .warm_scan(&[warm, cold], &FakeRetriever::new(2), &Budget::hook())
        .unwrap();
    assert_eq!(scan2.reused_files, 2);
    assert_eq!(scan2.retrieved_files, 0);
}

// --- budget ---

struct SlowRetriever;
impl Retriever for SlowRetriever {
    fn retrieve(&self, _: &[PathBuf]) -> anyhow::Result<Vec<Site>> {
        std::thread::sleep(Duration::from_millis(50));
        Ok(vec![site("slow.go", 1, "p.C", "Do")])
    }
}

#[test]
fn expired_budget_degrades_instead_of_blocking_the_commit() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let f = write(dir.path(), "slow.go", "package slow\n");
    // Zero budget: already expired before retrieval starts.
    let scan = idx
        .warm_scan(
            std::slice::from_ref(&f),
            &SlowRetriever,
            &Budget::new(Duration::ZERO, false),
        )
        .unwrap();
    assert!(scan.degraded, "an exhausted budget degrades the scan");
    assert!(!scan.note.is_empty(), "degradation must be explained");
    assert_eq!(
        scan.retrieved_files, 0,
        "no retrieval attempted past the cap"
    );
}

#[test]
fn strict_budget_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let f = write(dir.path(), "slow.go", "package slow\n");
    let err = idx
        .warm_scan(&[f], &SlowRetriever, &Budget::new(Duration::ZERO, true))
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("budget"),
        "strict mode must name the budget: {err}"
    );
}

// --- concurrent access (po-l3jo5) ---
//
// redb allows exactly one process to hold the database. Opening therefore has
// to distinguish "someone else is using it right now" from "it is broken",
// and has to wait, because the caller that loses this race is usually the
// background warm and giving up throws away its entire reindex.

/// A locked index surfaces as `IndexBusy`, and only after the open actually
/// waited rather than failing on the first attempt.
#[test]
fn open_reports_busy_when_another_holder_keeps_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("packets.redb");
    let _held = PacketIndex::open(&path).unwrap();

    let started = std::time::Instant::now();
    let Err(err) = PacketIndex::open_with_timeout(&path, Duration::from_millis(300)) else {
        panic!("a second open must not succeed while the first holder is alive");
    };

    assert!(
        err.downcast_ref::<IndexBusy>().is_some(),
        "a locked index must surface as IndexBusy, not a generic open failure: {err}"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "open must retry before giving up, gave up after {:?}",
        started.elapsed()
    );
}

/// The whole point of waiting: a holder that releases mid-wait must not cost
/// the caller its work. This is the background warm's path.
#[test]
fn open_succeeds_when_the_holder_releases_during_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("packets.redb");
    let held = PacketIndex::open(&path).unwrap();

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(held);
    });

    PacketIndex::open_with_timeout(&path, Duration::from_secs(10))
        .expect("open must wait out a transient holder rather than fail");
}

/// A test file the helper declined to read is recorded as SKIPPED, not as
/// scanned-with-zero-packets: the two look the same to `get`, and
/// a warm scan has to tell them apart to report the repository-wide count
/// from reused entries rather than from the files it happened to re-parse.
#[test]
fn a_skipped_test_file_is_flagged_and_reused_like_any_entry() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let t = write(dir.path(), "test_a.py", "def test(): pass\n");
    let p = write(dir.path(), "a.py", "x = 1\n");
    let h_t = hash_file(&t).unwrap();
    let h_p = hash_file(&p).unwrap();
    idx.put_test_skipped(&t, &h_t).unwrap();
    idx.put(&p, &h_p, &[]).unwrap();
    // Reusable on the next pass like any other entry, carrying no packets.
    assert_eq!(idx.get(&t, &h_t).unwrap().map(|v| v.len()), Some(0));
    let plan = idx.plan_reload(&[t.clone(), p.clone()]);
    assert_eq!(plan.unchanged, vec![t.clone(), p.clone()]);
    assert!(idx.lookup(&t, &h_t).unwrap().unwrap().test_skipped);
    assert!(!idx.lookup(&p, &h_p).unwrap().unwrap().test_skipped);
    // A stale hash reads as absent, flag or no flag.
    assert!(idx.lookup(&t, "stale").unwrap().is_none());
    // Re-recording the file as scanned clears the flag: the entry describes
    // the LAST retrieval, not the union of every retrieval.
    idx.put(&t, &h_t, &[]).unwrap();
    assert!(!idx.lookup(&t, &h_t).unwrap().unwrap().test_skipped);
}

/// A translation unit that parsed with errors is recorded AS incomplete
/// (po-av01j.224). Its packets are a floor, and without the flag a warm scan
/// reuses the entry as a clean parse on every later pass.
#[test]
fn an_incompletely_parsed_file_is_flagged_and_reused_like_any_entry() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("index.redb")).unwrap();
    let broken = write(dir.path(), "broken.c", "#include <gone.h>\n");
    let clean = write(dir.path(), "clean.c", "int x;\n");
    let h_b = hash_file(&broken).unwrap();
    let h_c = hash_file(&clean).unwrap();
    // An incomplete parse still carries the sites that did resolve.
    idx.put_incomplete_with_deps(
        &broken,
        &h_b,
        &[site("broken.c", 2, "posix.socket", "send")],
        &[],
    )
    .unwrap();
    idx.put_with_deps(&clean, &h_c, &[], &[]).unwrap();

    let files = [broken.clone(), clean.clone()];
    let plan = idx.plan_reload_with(&files, |_| true);
    assert_eq!(plan.unchanged, files.to_vec(), "both are reusable");
    let got = idx.lookup(&broken, &h_b).unwrap().unwrap();
    assert!(got.parse_incomplete);
    assert_eq!(got.sites.len(), 1);
    assert!(!idx.lookup(&clean, &h_c).unwrap().unwrap().parse_incomplete);
    assert!(
        idx.planned(&broken, &h_b)
            .unwrap()
            .unwrap()
            .parse_incomplete
    );

    // Re-recording the file as cleanly parsed clears the flag.
    idx.put_with_deps(&broken, &h_b, &[], &[]).unwrap();
    assert!(!idx.lookup(&broken, &h_b).unwrap().unwrap().parse_incomplete);
}

/// An entry written before the flag existed does not say whether its parse
/// was complete. Where the caller needs that record (a C/C++ source), the
/// entry is retrieved again, once, instead of being reused as a clean parse.
#[test]
fn an_entry_written_before_the_incomplete_flag_is_retrieved_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.redb");
    let tu = write(dir.path(), "old.c", "int x;\n");
    let h = hash_file(&tu).unwrap();
    // The value shape of the release before the flag: dependencies
    // recorded, no `parse_incomplete`.
    put_raw_entry(
        &path,
        &tu,
        &serde_json::json!({
            "hash": h,
            "packet_schema": rvl_core::PACKET_SCHEMA,
            "test_skipped": false,
            "sites": [],
            "deps": [],
        }),
    );
    let idx = PacketIndex::open(&path).unwrap();
    let files = [tu.clone()];
    assert_eq!(
        idx.plan_reload_with(&files, |_| true).changed,
        files.to_vec(),
        "an entry with no record of its parse is not trusted"
    );
    // A language that never reports an incomplete parse reuses it as before.
    assert_eq!(idx.plan_reload(&files).unchanged, files.to_vec());
    assert!(!idx.lookup(&tu, &h).unwrap().unwrap().parse_incomplete);
}

// --- dependency (header -> TU) invalidation, po-av01j.53 ---

#[test]
fn an_entry_goes_stale_when_a_recorded_dependency_changes() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("i.redb")).unwrap();
    let tu = write(dir.path(), "main.c", "#include \"api.h\"\n");
    let header = write(dir.path(), "api.h", "int f(void);\n");
    let h = hash_file(&tu).unwrap();
    idx.put_with_deps(
        &tu,
        &h,
        &[site("main.c", 3, "libcurl.CURL", "f")],
        std::slice::from_ref(&header),
    )
    .unwrap();

    // Fresh: the TU and its header are as indexed.
    assert!(idx.lookup(&tu, &h).unwrap().is_some());
    assert_eq!(
        idx.plan_reload(std::slice::from_ref(&tu)).unchanged,
        vec![tu.clone()]
    );

    // The header changes; the TU's own bytes do not. The shard is stale.
    std::fs::write(&header, "long f(void);\n").unwrap();
    assert!(idx.lookup(&tu, &h).unwrap().is_none());
    assert_eq!(
        idx.plan_reload(std::slice::from_ref(&tu)).changed,
        vec![tu.clone()]
    );

    // A deleted header is stale too: fail toward doing the work.
    idx.put_with_deps(&tu, &h, &[], std::slice::from_ref(&header))
        .unwrap();
    std::fs::remove_file(&header).unwrap();
    assert!(idx.lookup(&tu, &h).unwrap().is_none());
}

#[test]
fn dependents_maps_a_header_to_the_files_that_recorded_it() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("i.redb")).unwrap();
    let a = write(dir.path(), "a.c", "a\n");
    let b = write(dir.path(), "b.c", "b\n");
    let c = write(dir.path(), "c.c", "c\n");
    let shared = write(dir.path(), "shared.h", "s\n");
    let only_b = write(dir.path(), "only_b.h", "o\n");
    idx.put_with_deps(
        &a,
        &hash_file(&a).unwrap(),
        &[],
        std::slice::from_ref(&shared),
    )
    .unwrap();
    idx.put_with_deps(
        &b,
        &hash_file(&b).unwrap(),
        &[],
        &[shared.clone(), only_b.clone()],
    )
    .unwrap();
    idx.put(&c, &hash_file(&c).unwrap(), &[]).unwrap();

    let canon = |p: &PathBuf| p.canonicalize().unwrap();
    assert_eq!(idx.dependents(&shared).unwrap(), vec![canon(&a), canon(&b)]);
    assert_eq!(idx.dependents(&only_b).unwrap(), vec![canon(&b)]);
    assert!(idx.dependents(&c).unwrap().is_empty());
}

// --- on-disk format across the redb 2 -> 4 bump (po-av01j.210) ---
//
// Every user has a live index written by redb 2, and redb 4 refuses to open
// that file format. The index is a content-hash cache, so the story is
// detect-and-rebuild: opening must succeed with an empty index and SAY that
// it rebuilt, never surface the storage engine's upgrade error.

/// A real index written through `PacketIndex` by redb 2.6.3 (one entry),
/// unpacked into `dir`.
fn redb2_index(dir: &std::path::Path) -> PathBuf {
    use std::io::Read;
    let gz = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/packets-redb2.redb.gz");
    let mut bytes = Vec::new();
    flate2::read::GzDecoder::new(std::fs::File::open(gz).unwrap())
        .read_to_end(&mut bytes)
        .unwrap();
    let path = dir.join("packets.redb");
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn an_index_written_by_redb_2_is_detected_and_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let path = redb2_index(dir.path());

    let idx = PacketIndex::open(&path).expect("an old-format index must open, not error");
    assert!(
        idx.rebuilt_from_old_format(),
        "the rebuild must be reported, not silent"
    );
    assert!(idx.is_empty().unwrap(), "a rebuilt index starts empty");

    // The rebuilt index is a working one, and the rebuild happens once.
    let f = write(dir.path(), "a.go", "package a");
    let h = hash_file(&f).unwrap();
    idx.put(&f, &h, &[site("a.go", 1, "http.Client", "Do")])
        .unwrap();
    drop(idx);
    let idx = PacketIndex::open(&path).unwrap();
    assert!(!idx.rebuilt_from_old_format());
    assert_eq!(idx.get(&f, &h).unwrap().unwrap().len(), 1);
}

#[test]
fn a_fresh_index_is_not_reported_as_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let idx = PacketIndex::open(&dir.path().join("packets.redb")).unwrap();
    assert!(!idx.rebuilt_from_old_format());
}

// --- packet contract stamp (po-av01j.67) ---
//
// The content hash says the FILE has not changed; it says nothing about the
// packet contract the entry was retrieved under. An entry written before a
// packet field existed would otherwise serve sites without that field for as
// long as the file stays untouched.

/// Write `value` as the raw stored entry for `file`, the way an older binary
/// would have left it. The index must be closed: redb is single-opener.
fn put_raw_entry(index: &std::path::Path, file: &std::path::Path, value: &serde_json::Value) {
    const ENTRIES: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("entries");
    let db = redb::Database::create(index).unwrap();
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(ENTRIES).unwrap();
        let key = std::fs::canonicalize(file).unwrap();
        table
            .insert(key.to_str().unwrap(), value.to_string().as_str())
            .unwrap();
    }
    tx.commit().unwrap();
}

/// One stored entry for `a.go` whose content hash still matches, carrying
/// `stamp` as its packet contract version (`None` = written before the stamp).
fn index_with_entry_stamped(dir: &std::path::Path, stamp: Option<u32>) -> (PathBuf, PathBuf) {
    let index = dir.join("packets.redb");
    let f = write(dir, "a.go", "package a\n");
    let mut entry = serde_json::json!({
        "hash": hash_file(&f).unwrap(),
        "sites": [site("a.go", 1, "pkg.C", "Do")],
    });
    if let Some(stamp) = stamp {
        entry["packet_schema"] = stamp.into();
    }
    put_raw_entry(&index, &f, &entry);
    (index, f)
}

#[test]
fn an_entry_written_under_an_older_packet_schema_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let (index, f) = index_with_entry_stamped(dir.path(), Some(rvl_core::PACKET_SCHEMA - 1));
    let idx = PacketIndex::open(&index).unwrap();
    let h = hash_file(&f).unwrap();

    assert!(
        idx.get(&f, &h).unwrap().is_none(),
        "the hash matches but the entry predates the packet contract: a miss"
    );
    assert!(idx.lookup(&f, &h).unwrap().is_none());
    assert!(
        idx.planned(&f, &h).unwrap().is_none(),
        "the plan's fast read applies the same contract check"
    );
    let plan = idx.plan_reload(std::slice::from_ref(&f));
    assert_eq!(plan.changed, vec![f.clone()], "the file is re-retrieved");
    assert!(plan.unchanged.is_empty());
}

#[test]
fn an_entry_with_no_packet_schema_stamp_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let (index, f) = index_with_entry_stamped(dir.path(), None);
    let idx = PacketIndex::open(&index).unwrap();

    assert!(idx.get(&f, &hash_file(&f).unwrap()).unwrap().is_none());
}

#[test]
fn an_entry_written_under_a_newer_packet_schema_is_not_reused() {
    let dir = tempfile::tempdir().unwrap();
    let (index, f) = index_with_entry_stamped(dir.path(), Some(rvl_core::PACKET_SCHEMA + 1));
    let idx = PacketIndex::open(&index).unwrap();

    assert!(
        idx.get(&f, &hash_file(&f).unwrap()).unwrap().is_none(),
        "a downgraded binary must not read a shape it does not know"
    );
}

#[test]
fn a_warm_scan_re_retrieves_a_stale_stamped_entry_and_heals_it() {
    let dir = tempfile::tempdir().unwrap();
    let (index, f) = index_with_entry_stamped(dir.path(), None);
    let idx = PacketIndex::open(&index).unwrap();
    let r = FakeRetriever::new(1);

    let first = idx
        .warm_scan(std::slice::from_ref(&f), &r, &Budget::hook())
        .unwrap();
    assert_eq!((first.reused_files, first.retrieved_files), (0, 1));

    // The re-retrieved entry carries the current stamp: the next pass is warm.
    let second = idx
        .warm_scan(std::slice::from_ref(&f), &r, &Budget::hook())
        .unwrap();
    assert_eq!((second.reused_files, second.retrieved_files), (1, 0));
    assert_eq!(idx.len().unwrap(), 1, "healed in place, not duplicated");
}
