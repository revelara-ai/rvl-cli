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
