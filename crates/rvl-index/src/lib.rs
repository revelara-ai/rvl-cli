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
use redb::ReadableTableMetadata;
use rvl_core::Site;
use rvl_core::BIN;
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
    /// Files whose content hash matches the index: packets are reused.
    pub unchanged: Vec<PathBuf>,
    /// Files that must be re-retrieved (changed, new, or never indexed).
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
}

/// path -> JSON {hash, sites}. One table keeps the store trivially
/// forward-compatible: a schema change is a new value shape, not a migration.
const ENTRIES: redb::TableDefinition<&str, &str> = redb::TableDefinition::new("entries");

#[derive(serde::Serialize, serde::Deserialize)]
struct Entry {
    hash: String,
    sites: Vec<Site>,
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
    /// Only `DatabaseAlreadyOpen` is retried. A storage error or a required
    /// format upgrade will not resolve itself, and retrying one for a minute
    /// only delays the report.
    pub fn open_with_timeout(path: &Path, timeout: Duration) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let started = Instant::now();
        let mut backoff = Duration::from_millis(25);
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
        Ok(Self { db })
    }

    /// Record the packets retrieved from `file` at content hash `hash`.
    pub fn put(&self, file: &Path, hash: &str, sites: &[Site]) -> anyhow::Result<()> {
        let entry = Entry {
            hash: hash.to_string(),
            sites: sites.to_vec(),
        };
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

    /// Packets stored for `file`, if the stored hash matches `hash`.
    pub fn get(&self, file: &Path, hash: &str) -> anyhow::Result<Option<Vec<Site>>> {
        Ok(self
            .entry(file)?
            .filter(|e| e.hash == hash)
            .map(|e| e.sites))
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
        let mut plan = ReloadPlan::default();
        for f in files {
            let reusable = match hash_file(f) {
                Ok(h) => self.get(f, &h).ok().flatten().is_some(),
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
