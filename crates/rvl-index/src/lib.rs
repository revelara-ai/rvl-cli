//! Incremental scan: a persistent per-repo packet index keyed by content
//! hash, so a warm pre-commit scan re-retrieves only what actually changed
//! (wayfinder po-ipkfg.14).
//!
//! Two invariants shape this crate:
//!
//! * **A site key is not a file:line.** One location can resolve to several
//!   sites (different client types) carrying different verdicts, so the index
//!   keys sites by (path, line, client_type, method). Keying on file:line
//!   silently drops one of a colliding pair.
//! * **A scan never blocks a commit.** The wall budget fails OPEN by default:
//!   when time runs out the scan degrades to what it has and says so.
//!   `--strict` inverts that for CI, where a partial answer is worse than a
//!   failed job.

use anyhow::Context;
use redb::{ReadableDatabase, ReadableTableMetadata};
use rvl_core::Site;
use rvl_core::BIN;
use rvl_core::PACKET_SCHEMA;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// blake3 of a file's contents, hex-encoded.
pub fn hash_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
    Ok(hash_bytes(&bytes))
}

/// blake3 of bytes, hex-encoded.
pub fn hash_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Stable identity for one retrieved site. A location alone is ambiguous:
/// the same file:line can yield several sites with different client types.
pub fn site_key(site: &Site) -> String {
    format!(
        "{}:{}:{}:{}",
        site.file_path, site.line_number, site.client_type, site.method
    )
}

/// What a warm pre-commit pass decided to do.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReloadPlan {
    /// Files whose content hash matches an index entry written under the
    /// current packet contract: packets are reused.
    pub unchanged: Vec<PathBuf>,
    /// Files that must be re-retrieved (changed, new, never indexed, or
    /// indexed under another packet contract version).
    pub changed: Vec<PathBuf>,
}

/// Retrieval of packets for changed files. Implemented by the per-language
/// helper binaries (po-3t3oj.16/.6/.17); the in-memory fake in tests keeps
/// this crate honest until they exist.
pub trait Retriever {
    fn retrieve(&self, paths: &[PathBuf]) -> anyhow::Result<Vec<Site>>;
}

/// The persistent index: path -> (content hash, packets retrieved from it).
pub struct PacketIndex {
    db: redb::Database,
    rebuilt_from_old_format: bool,
}

/// path -> JSON {hash, packet_schema, sites}. One table keeps the store
/// trivially forward-compatible: a schema change is a new value shape, not a
/// migration. The value shape decoding is not the same as the packets being
/// current, which is what `Entry::packet_schema` is for.
const ENTRIES: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("entries");

#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    hash: String,
    /// The packet contract version ([`PACKET_SCHEMA`]) the sites were
    /// retrieved under. The content hash only says the file has not changed;
    /// an entry written before a packet field existed would otherwise serve
    /// sites without it until the file is next edited. Any other version,
    /// older or newer, is a miss (po-av01j.67). Defaults to 0, older than
    /// every real version, so an entry written before the stamp is a miss
    /// too.
    ///
    /// The stamp is only as good as the constant: a field added to the
    /// contract WITHOUT a version bump is not noticed here.
    #[serde(default)]
    packet_schema: u32,
    /// The helper declined to read this file as test material.
    /// Indistinguishable from scanned-with-zero-packets without the flag,
    /// and a warm scan needs the distinction to report the repository-wide
    /// skip count from reused entries. Defaults to false so an entry written
    /// before the flag existed still decodes.
    #[serde(default)]
    test_skipped: bool,
    sites: Vec<Site>,
    /// The files this entry's packets also depend on, as (index key, content
    /// hash at indexing time): for a C/C++ translation unit, the headers it
    /// includes. The entry is reusable only while every one still hashes the
    /// same. `None` on an entry written before dependencies were recorded,
    /// which is "unknown", not "none".
    #[serde(default)]
    deps: Option<Vec<(String, String)>>,
}

/// Content hashes of dependency files, memoized for one pass. Many
/// translation units share the same headers; each is hashed once. `None` is
/// an unreadable file, which never matches a recorded hash.
type DepHashes = std::collections::HashMap<String, Option<String>>;

impl Entry {
    /// Is this the entry for the file's content at `hash`, written under the
    /// packet contract version this build reads?
    fn current_at(&self, hash: &str) -> bool {
        self.hash == hash && self.packet_schema == PACKET_SCHEMA
    }

    /// Does every recorded dependency still hash as it did at indexing time?
    /// A missing or unreadable dependency is stale: fail toward doing the work.
    fn deps_fresh(&self, memo: &mut DepHashes) -> bool {
        self.deps.iter().flatten().all(|(path, recorded)| {
            memo.entry(path.clone())
                .or_insert_with(|| hash_file(Path::new(path)).ok())
                .as_deref()
                == Some(recorded.as_str())
        })
    }
}

/// How long [`PacketIndex::open`] waits for a busy index before giving up.
/// Deliberately short: an interactive command should report a busy index
/// promptly rather than look like it hung.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(2);

/// The index could not be acquired because another rvl process holds
/// redb's exclusive lock.
///
/// redb permits exactly one process to have the database open, so this is a
/// normal, transient condition (a scan, a status check, a background warm),
/// not a corrupt index. It is its own error type so callers can
/// `downcast_ref` and say "busy" instead of reporting a broken database.
#[derive(Debug)]
pub struct IndexBusy {
    pub path: PathBuf,
    pub waited: Duration,
}

impl std::fmt::Display for IndexBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "index busy: another {BIN} process holds {} (waited {:.1}s)",
            self.path.display(),
            self.waited.as_secs_f32()
        )
    }
}

impl std::error::Error for IndexBusy {}

impl PacketIndex {
    /// Open (creating if needed) the index at `path`, waiting briefly for a
    /// concurrent holder to finish. See [`PacketIndex::open_with_timeout`].
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        Self::open_with_timeout(path, DEFAULT_OPEN_TIMEOUT)
    }

    /// Open (creating if needed) the index at `path`, waiting up to
    /// `timeout` for another process to release redb's exclusive lock.
    ///
    /// Waiting matters most for the background warm: it is a batch job with
    /// nobody watching, and failing instantly because a status check held
    /// the lock for a few milliseconds throws away the whole reindex
    /// (po-l3jo5).
    ///
    /// Only `DatabaseAlreadyOpen` is retried. A storage error will not
    /// resolve itself, and retrying one for a minute only delays the report.
    ///
    /// An index in an older on-disk format (one written by redb 2, which
    /// redb 4 refuses to open) is deleted and created afresh. The index is a
    /// content-hash cache, so nothing is lost but warmth, and the next scan
    /// refills it. The rebuild is recorded, never silent: see
    /// [`PacketIndex::rebuilt_from_old_format`] (po-av01j.210).
    pub fn open_with_timeout(path: &Path, timeout: Duration) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let started = Instant::now();
        let mut backoff = Duration::from_millis(25);
        let mut rebuilt_from_old_format = false;
        let db = loop {
            match redb::Database::create(path) {
                Ok(db) => break db,
                Err(redb::DatabaseError::DatabaseAlreadyOpen) => {
                    if started.elapsed() + backoff >= timeout {
                        return Err(anyhow::Error::new(IndexBusy {
                            path: path.to_path_buf(),
                            waited: started.elapsed(),
                        }));
                    }
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(250));
                }
                // Once only: a second refusal after the delete is a real
                // fault, and looping on it would never end.
                Err(redb::DatabaseError::UpgradeRequired(_)) if !rebuilt_from_old_format => {
                    std::fs::remove_file(path).with_context(|| {
                        format!("removing old-format packet index at {}", path.display())
                    })?;
                    rebuilt_from_old_format = true;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e))
                        .with_context(|| format!("opening packet index at {}", path.display()))
                }
            }
        };
        // Materialize the table so reads on a fresh index do not error.
        let tx = db.begin_write()?;
        {
            let _ = tx.open_table(ENTRIES)?;
        }
        tx.commit()?;
        Ok(Self {
            db,
            rebuilt_from_old_format,
        })
    }

    /// Record the packets retrieved from `file` at content hash `hash`.
    pub fn put(&self, file: &Path, hash: &str, sites: &[Site]) -> anyhow::Result<()> {
        self.put_with_deps(file, hash, sites, &[])
    }

    /// Record the packets retrieved from `file` at content hash `hash`,
    /// together with the files those packets also depend on (`deps`, hashed
    /// here as they are now). A later change to any of them makes the entry
    /// stale. A dependency that cannot be read is recorded with a hash
    /// nothing matches, so the entry is re-retrieved on the next pass.
    pub fn put_with_deps(
        &self,
        file: &Path,
        hash: &str,
        sites: &[Site],
        deps: &[PathBuf],
    ) -> anyhow::Result<()> {
        let deps = deps
            .iter()
            .map(|d| (key_of(d), hash_file(d).unwrap_or_default()))
            .collect();
        self.put_entry(
            file,
            Entry {
                hash: hash.to_string(),
                packet_schema: PACKET_SCHEMA,
                test_skipped: false,
                sites: sites.to_vec(),
                deps: Some(deps),
            },
        )
    }

    /// Record that the helper declined to read `file` (test material) at
    /// content hash `hash`. Reused on the next pass like any entry, carrying
    /// no packets, but counted as a skip rather than as a scan.
    pub fn put_test_skipped(&self, file: &Path, hash: &str) -> anyhow::Result<()> {
        self.put_entry(
            file,
            Entry {
                hash: hash.to_string(),
                packet_schema: PACKET_SCHEMA,
                test_skipped: true,
                sites: Vec::new(),
                deps: Some(Vec::new()),
            },
        )
    }

    fn put_entry(&self, file: &Path, entry: Entry) -> anyhow::Result<()> {
        let encoded = serde_json::to_string(&entry)?;
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(ENTRIES)?;
            table.insert(key_of(file).as_str(), encoded.as_str())?;
        }
        tx.commit()?;
        Ok(())
    }

    fn entry(&self, file: &Path) -> anyhow::Result<Option<Entry>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ENTRIES)?;
        let Some(raw) = table.get(key_of(file).as_str())? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(raw.value())?))
    }

    /// Packets stored for `file`, if the stored hash matches `hash` and the
    /// entry was written under the current packet contract.
    pub fn get(&self, file: &Path, hash: &str) -> anyhow::Result<Option<Vec<Site>>> {
        Ok(self.lookup(file, hash)?.map(|e| e.sites))
    }

    /// What the index holds for `file` at `hash`: its packets and whether it
    /// was skipped as test material rather than scanned. `None` when the
    /// stored hash differs, a recorded dependency has changed since, or the
    /// entry was written under another packet contract version, so the
    /// caller re-retrieves the file and overwrites the entry.
    pub fn lookup(&self, file: &Path, hash: &str) -> anyhow::Result<Option<Indexed>> {
        Ok(self
            .entry(file)?
            .filter(|e| e.current_at(hash) && e.deps_fresh(&mut DepHashes::new()))
            .map(Indexed::from))
    }

    /// What the index holds for a file [`PacketIndex::plan_reload`] has just
    /// declared unchanged at `hash`. Unlike [`PacketIndex::lookup`] it does
    /// not hash the dependencies again: the plan did, a moment ago, and on a
    /// header-heavy repo that second pass is the cost of the whole scan.
    pub fn planned(&self, file: &Path, hash: &str) -> anyhow::Result<Option<Indexed>> {
        Ok(self
            .entry(file)?
            .filter(|e| e.current_at(hash))
            .map(Indexed::from))
    }

    /// The indexed files that recorded `dep` as a dependency, sorted: for a
    /// header, the translation units that include it.
    pub fn dependents(&self, dep: &Path) -> anyhow::Result<Vec<PathBuf>> {
        use redb::ReadableTable;
        let want = key_of(dep);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ENTRIES)?;
        let mut out = Vec::new();
        for row in table.iter()? {
            let (key, raw) = row?;
            // An entry this build cannot decode has no dependencies to name.
            let Ok(entry) = serde_json::from_str::<Entry>(raw.value()) else {
                continue;
            };
            if entry.deps.iter().flatten().any(|(path, _)| *path == want) {
                out.push(PathBuf::from(key.value()));
            }
        }
        out.sort();
        Ok(out)
    }

    /// True when opening found an index in an older on-disk format and
    /// replaced it with an empty one. Callers report it, so that a cold
    /// scan after an upgrade has a stated cause.
    pub fn rebuilt_from_old_format(&self) -> bool {
        self.rebuilt_from_old_format
    }

    /// Number of indexed files.
    pub fn len(&self) -> anyhow::Result<usize> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ENTRIES)?;
        Ok(table.len()? as usize)
    }

    pub fn is_empty(&self) -> anyhow::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Hash-gate the candidate files: split into reusable and must-retrieve.
    /// Unreadable files count as changed (fail toward doing the work).
    pub fn plan_reload(&self, files: &[PathBuf]) -> ReloadPlan {
        self.plan_reload_with(files, |_| false)
    }

    /// [`PacketIndex::plan_reload`], for callers with files whose packets
    /// depend on other files. Where `needs_deps` says so (a C/C++ source,
    /// whose packets change with its headers), an entry written before
    /// dependencies were recorded counts as changed: nothing says which
    /// headers it saw, so it is retrieved again, once.
    pub fn plan_reload_with(
        &self,
        files: &[PathBuf],
        needs_deps: impl Fn(&Path) -> bool,
    ) -> ReloadPlan {
        let mut plan = ReloadPlan::default();
        let mut memo = DepHashes::new();
        for f in files {
            let reusable = match hash_file(f) {
                Ok(h) => self
                    .entry(f)
                    .ok()
                    .flatten()
                    .filter(|e| e.current_at(&h) && e.deps_fresh(&mut memo))
                    .is_some_and(|e| e.deps.is_some() || !needs_deps(f)),
                Err(_) => false,
            };
            if reusable {
                plan.unchanged.push(f.clone());
            } else {
                plan.changed.push(f.clone());
            }
        }
        plan
    }

    /// The warm path: reuse indexed packets, retrieve the rest, merge, and
    /// update the index with what was freshly retrieved.
    pub fn warm_scan(
        &self,
        files: &[PathBuf],
        retriever: &dyn Retriever,
        budget: &Budget,
    ) -> anyhow::Result<WarmScan> {
        let plan = self.plan_reload(files);
        let mut sites = Vec::new();
        for f in &plan.unchanged {
            if let Ok(h) = hash_file(f) {
                if let Some(cached) = self.get(f, &h)? {
                    sites.extend(cached);
                }
            }
        }
        let reused_files = plan.unchanged.len();

        if plan.changed.is_empty() {
            return Ok(WarmScan {
                sites,
                reused_files,
                retrieved_files: 0,
                degraded: false,
                note: String::new(),
            });
        }
        if budget.expired() {
            // Out of time before doing the expensive part.
            if budget.is_strict() {
                anyhow::bail!(
                    "wall budget exhausted before retrieving {} changed file(s); \
                     --strict refuses a partial answer",
                    plan.changed.len()
                );
            }
            return Ok(WarmScan {
                sites,
                reused_files,
                retrieved_files: 0,
                degraded: true,
                note: format!(
                    "wall budget exhausted: {} changed file(s) not re-scanned; \
                     results cover the indexed portion only",
                    plan.changed.len()
                ),
            });
        }

        let fresh = retriever.retrieve(&plan.changed)?;
        // Index what came back, per originating file, so the next pass is warm.
        let mut by_file: std::collections::BTreeMap<&str, Vec<Site>> =
            std::collections::BTreeMap::new();
        for s in &fresh {
            by_file
                .entry(s.file_path.as_str())
                .or_default()
                .push(s.clone());
        }
        for f in &plan.changed {
            let key = f.to_string_lossy().to_string();
            let for_file = by_file.remove(key.as_str()).unwrap_or_default();
            if let Ok(h) = hash_file(f) {
                self.put(f, &h, &for_file)?;
            }
        }
        let retrieved_files = plan.changed.len();
        sites.extend(fresh);
        Ok(WarmScan {
            sites,
            reused_files,
            retrieved_files,
            degraded: false,
            note: String::new(),
        })
    }
}

/// One indexed file, as [`PacketIndex::lookup`] returns it.
#[derive(Debug, Clone)]
pub struct Indexed {
    pub sites: Vec<Site>,
    /// The helper declined to read the file as test material; `sites` is
    /// empty because nothing was retrieved, not because nothing was found.
    pub test_skipped: bool,
}

impl From<Entry> for Indexed {
    fn from(e: Entry) -> Self {
        Indexed {
            sites: e.sites,
            test_skipped: e.test_skipped,
        }
    }
}

/// Index key for a path. Absolute where possible so the same file is not
/// indexed twice under different relative spellings.
fn key_of(file: &Path) -> String {
    std::fs::canonicalize(file)
        .unwrap_or_else(|_| file.to_path_buf())
        .to_string_lossy()
        .to_string()
}

#[derive(Debug)]
pub struct WarmScan {
    pub sites: Vec<Site>,
    pub reused_files: usize,
    pub retrieved_files: usize,
    /// True when the budget expired before retrieval finished.
    pub degraded: bool,
    /// Human-readable note when degraded (empty otherwise).
    pub note: String,
}

/// Wall-clock budget for a hook-path scan.
pub struct Budget {
    cap: Duration,
    strict: bool,
    start: Instant,
}

impl Budget {
    /// Default hook budget: 10s, fail-open.
    pub fn hook() -> Self {
        Self::new(Duration::from_secs(10), false)
    }

    pub fn new(cap: Duration, strict: bool) -> Self {
        Self {
            cap,
            strict,
            start: Instant::now(),
        }
    }

    pub fn strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    pub fn expired(&self) -> bool {
        self.start.elapsed() >= self.cap
    }

    pub fn is_strict(&self) -> bool {
        self.strict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry from before dependencies were recorded decodes and is
    /// reusable at its hash, except for a file whose packets depend on
    /// other files: nothing says which, so it is planned as changed. `put`
    /// records "none", which is a known answer.
    #[test]
    fn a_pre_dependency_entry_is_replanned_only_where_dependencies_matter() {
        let dir = tempfile::tempdir().unwrap();
        let idx = PacketIndex::open(&dir.path().join("i.redb")).unwrap();
        let tu = dir.path().join("main.c");
        std::fs::write(&tu, "x\n").unwrap();
        let h = hash_file(&tu).unwrap();
        let files = std::slice::from_ref(&tu);

        let legacy: Entry =
            serde_json::from_str(&format!(r#"{{"hash":"{h}","sites":[]}}"#)).unwrap();
        idx.put_entry(&tu, legacy).unwrap();
        assert!(idx.lookup(&tu, &h).unwrap().is_some());
        assert_eq!(idx.plan_reload(files).unchanged, vec![tu.clone()]);
        assert_eq!(
            idx.plan_reload_with(files, |_| true).changed,
            vec![tu.clone()]
        );

        idx.put(&tu, &h, &[]).unwrap();
        assert_eq!(
            idx.plan_reload_with(files, |_| true).unchanged,
            vec![tu.clone()]
        );
    }
}
