//! Keeping the cache current without the user thinking about it (po-av01j.171).
//!
//! Three constraints shape everything here, in order of weight:
//!
//! 1. A SCAN NEVER WAITS ON THE NETWORK. The pre-commit hook is the flagship
//!    path and a warm scan is well under a second; a synchronous round trip
//!    on every commit is what gets hooks uninstalled. So the scan only
//!    decides whether a check is due ([`claim`]) and hands the fetch to a
//!    detached process. Everything in this module is local file I/O, and
//!    every failure degrades to "no check this time", never to an error.
//! 2. A FETCHED ARTIFACT APPLIES ON THE NEXT RUN. The check starts after the
//!    scan has loaded its cache, so no scan sees two corpora. Otherwise the
//!    same commit could pass at 10:00 and block at 10:05 with no code change.
//! 3. A CHANGE IN RESULT IS ATTRIBUTED. When a scan runs on a different
//!    corpus than the repo's previous scan did, it says so ([`note_applied`]),
//!    so a newly blocked commit reads as "the corpus updated", not "your code
//!    broke".
//!
//! CI does not auto-update: a gate must be reproducible across time, so a pin
//! ([`check_pin`]) or the conventional `CI` variable turns the check off.

use rvl_core::BIN;
use std::collections::BTreeMap;
use std::path::Path;

/// How often a scan may start a background check. A published corpus moves
/// on the order of days; six hours keeps a developer current within a
/// working day while costing at most four conditional GETs a day.
pub const AUTO_SYNC_INTERVAL_SECS: u64 = 6 * 3600;

/// Unix seconds of the last check (background, init, or explicit sync).
pub const STAMP: &str = "auto-sync.stamp";
/// Held only while a scan decides and records a claim (milliseconds), so
/// two scans that start together cannot both spawn a check.
pub const CLAIM_LOCK: &str = "auto-sync.lock";
/// Per-repo record of the corpus each repo last scanned on.
pub const APPLIED: &str = "applied.json";

/// A lock older than this was left by a claimer that died mid-claim.
const STALE_LOCK_SECS: u64 = 60;

/// Why the background check is off for this run.
#[derive(Debug, PartialEq, Eq)]
pub enum Suppressed {
    /// `RVL_OFFLINE=1`: no fetch of any kind.
    Offline,
    /// A content_version pin: the run must use exactly what is installed.
    Pinned,
    /// A CI runner: auto-update is a developer convenience, not a CI default.
    Ci,
}

/// Whether the background check is suppressed. `pin` is the requested
/// content_version pin, `ci` the value of the `CI` variable. An empty pin and
/// an exported-but-false `CI` do not count.
pub fn suppressed(offline: bool, pin: Option<&str>, ci: Option<&str>) -> Option<Suppressed> {
    if offline {
        return Some(Suppressed::Offline);
    }
    if pin.is_some_and(|p| !p.trim().is_empty()) {
        return Some(Suppressed::Pinned);
    }
    match ci.map(str::trim) {
        None | Some("") | Some("0") | Some("false") => None,
        Some(_) => Some(Suppressed::Ci),
    }
}

/// Unix seconds now (0 if the clock is before the epoch, which makes every
/// check due rather than none).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_stamp(root: &Path) -> Option<u64> {
    std::fs::read_to_string(root.join(STAMP))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Record that a check happened at `now`. Best-effort: a stamp that cannot be
/// written only means the next scan checks again.
pub fn record_check(root: &Path, now: u64) {
    let tmp = root.join(format!("{STAMP}.{}", std::process::id()));
    if std::fs::write(&tmp, now.to_string()).is_ok() {
        let _ = std::fs::rename(&tmp, root.join(STAMP));
    }
    let _ = std::fs::remove_file(&tmp);
}

fn due(root: &Path, now: u64, interval: u64) -> bool {
    match read_stamp(root) {
        // A stamp in the future means the clock moved backwards; trusting it
        // would suppress every check until the clock caught up.
        Some(last) if last <= now => now - last >= interval,
        _ => true,
    }
}

/// Decide whether this run starts the background check, and if so record
/// the claim so no other run in the same interval does. Returns true exactly
/// when the caller should spawn the check.
///
/// Double-checked under a create-exclusive lock: two scans that both read an
/// old stamp cannot both claim, because only one holds the lock while it
/// re-reads and rewrites the stamp.
pub fn claim(root: &Path, now: u64, interval: u64) -> bool {
    if !due(root, now, interval) {
        return false;
    }
    let lock = root.join(CLAIM_LOCK);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
    {
        Ok(_) => {}
        Err(_) => {
            // Held, or left behind by a claimer that died. Clear a stale one
            // for the next run; either way this run does not check.
            let stale = std::fs::metadata(&lock)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age.as_secs() > STALE_LOCK_SECS);
            if stale {
                let _ = std::fs::remove_file(&lock);
            }
            return false;
        }
    }
    let won = due(root, now, interval);
    if won {
        record_check(root, now);
    }
    let _ = std::fs::remove_file(&lock);
    won
}

/// Check a CI pin: `pin` is one content_version or a comma-separated list
/// (one per tier), and every loaded tier must be named in it. The error says
/// what is installed, so a CI log shows why the gate refused.
pub fn check_pin(pin: &str, loaded: &[&str]) -> Result<(), String> {
    let wanted: Vec<&str> = pin
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let hint = format!("import the pinned artifact with '{BIN} cache import', or change the pin");
    if loaded.is_empty() {
        return Err(format!(
            "spec cache pinned to {} but no spec cache is installed; {hint}",
            wanted.join(", ")
        ));
    }
    match loaded.iter().find(|v| !wanted.contains(v)) {
        None => Ok(()),
        Some(v) => Err(format!(
            "spec cache pinned to {} but {v} is installed; {hint}",
            wanted.join(", ")
        )),
    }
}

/// One label for the corpus a scan ran on, from the loaded tiers' versions.
pub fn tiers_label(oss: Option<&str>, commercial: Option<&str>) -> Option<String> {
    match (commercial, oss) {
        (None, None) => None,
        (Some(c), None) => Some(format!("commercial {c}")),
        (None, Some(o)) => Some(format!("oss {o}")),
        (Some(c), Some(o)) => Some(format!("commercial {c}, oss {o}")),
    }
}

/// Record that `repo` was scanned on `label`, and return the label of its
/// previous scan when that differs. A repo's first scan returns None: there
/// is no earlier result for a change to explain.
///
/// Best-effort: a missing or corrupt record is rebuilt, and an unwritable
/// one only means the attribution may print again. Two scans in different
/// repos that write at the same moment can lose one repo's update, which at
/// worst repeats one attribution line; a lock is not worth that.
pub fn note_applied(root: &Path, repo: &str, label: &str) -> Option<String> {
    let path = root.join(APPLIED);
    let mut record: BTreeMap<String, String> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let previous = record.insert(repo.to_string(), label.to_string());
    if previous.as_deref() != Some(label) {
        if let Ok(bytes) = serde_json::to_vec_pretty(&record) {
            let tmp = root.join(format!("{APPLIED}.{}", std::process::id()));
            if std::fs::write(&tmp, bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
            let _ = std::fs::remove_file(&tmp);
        }
    }
    previous.filter(|p| p != label)
}
