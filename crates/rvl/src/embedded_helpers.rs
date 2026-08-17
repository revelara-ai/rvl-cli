//! The scripted retrievers, carried INSIDE the rvl binary (po-aml3h).
//!
//! `pyindex.py`, `tsindex.js` and `javaindex.java` are platform-independent
//! TEXT — one build of rvl can carry them for every target it ships to —
//! so they are `include_str!`d and materialized on first use instead of being
//! hand-installed. Before this, `brew install rvl` delivered the binary
//! and none of the seven helpers, and a fresh user's first scan hard-failed
//! with "no retriever for N of the N language(s) in this repo".
//!
//! The native helpers stay out of here on purpose: `cindex` and `rustindex`
//! are workspace binaries that ride the release archive, `goindex` is built
//! per target by release CI, and `csindex` drags ~9 MB of Roslyn and is
//! deliberately not carried (see `missing_helper_hint` in `main.rs`).
//!
//! ## Where the extracted copy lives, and when it is rewritten
//!
//! `$HOME/.revelara/helpers/<rvl version>/`, VERSIONED so two rvl
//! builds on one machine cannot hand each other a helper from the wrong
//! generation — a scripted helper and the binary that drives it share a packet
//! contract, and a stale script is a silently wrong scan rather than a loud
//! one. Within a version dir the file is rewritten whenever its sha256 differs
//! from the embedded text, so a truncated write, a half-finished disk, or a
//! hand-edit heals on the next run instead of persisting forever.
//!
//! Extraction is best-effort by design: a read-only or absent HOME must not
//! fail a scan, it must fall through to the next resolution step (PATH).

use anyhow::Context as _;
use sha2::Digest as _;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A retriever carried as source text, plus the name it is written out under.
pub struct Embedded {
    /// The on-disk name. It carries the extension resolution classifies on
    /// (`.py` -> python3, `.js` -> node, `.java` -> JEP 330 source mode), so
    /// it must match what `resolve_helper` looks for.
    pub file_name: &'static str,
    pub contents: &'static str,
}

pub static PYINDEX: Embedded = Embedded {
    file_name: "pyindex.py",
    contents: include_str!("../../../helpers/pyindex/pyindex.py"),
};

pub static TSINDEX: Embedded = Embedded {
    file_name: "tsindex.js",
    contents: include_str!("../../../helpers/tsindex/tsindex.js"),
};

pub static JAVAINDEX: Embedded = Embedded {
    file_name: "javaindex.java",
    contents: include_str!("../../../helpers/javaindex/javaindex.java"),
};

/// Overrides where the embedded helpers are materialized. Exists for tests and
/// for a machine whose HOME is not writable; ordinary use never sets it.
pub const HELPER_DIR_ENV: &str = "RVL_HELPER_DIR";

/// The versioned directory the embedded helpers are written to, or `None` when
/// there is nowhere to write them (no HOME and no override).
pub fn cache_root() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os(HELPER_DIR_ENV) {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(
        Path::new(&home)
            .join(".revelara")
            .join("helpers")
            .join(env!("CARGO_PKG_VERSION")),
    )
}

/// Where a user's OWN build of a helper this binary does not carry is looked
/// for, in order (po-aml3h follow-up).
///
/// Naming a canonical location and then still demanding an env var pointing at
/// it is two steps where one will do: if we tell someone to build csindex into
/// `~/.revelara/helpers/csindex`, the binary has to look there. Three shapes
/// are accepted because the build tools disagree about what an output path is:
/// `dotnet build -o DIR` produces a directory of assemblies, while
/// `go build -o FILE` produces one file.
///
///   1. the extraction root (`RVL_HELPER_DIR`, else the versioned dir), so
///      a relocated helper dir holds hand-built helpers too;
///   2. `~/.revelara/helpers/<base>/`, the per-helper subdirectory a
///      directory-producing build writes into;
///   3. `~/.revelara/helpers/`, flat, for a single-file build output.
pub fn install_dirs(base: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(root) = cache_root() {
        dirs.push(root);
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            let helpers = Path::new(&home).join(".revelara").join("helpers");
            dirs.push(helpers.join(base));
            dirs.push(helpers);
        }
    }
    dirs.dedup();
    dirs
}

/// Serializes EVERY test in this binary that mutates process-global env
/// (`HOME`, `RVL_HELPER_DIR`, the per-language overrides).
///
/// One lock for the whole crate on purpose. This module and `main.rs` both
/// move `HOME` and `RVL_HELPER_DIR`, and two separate mutexes guarding the
/// same process-wide state guard nothing: `ensure_writes_then_repairs_a_
/// corrupted_copy` failed four runs in five with "HOME is unset" because a
/// `main.rs` test held the OTHER lock and had just cleared both variables.
/// The lock lives here rather than in `main.rs` because this is the module
/// whose contract the env actually is.
///
/// Poison is absorbed (`into_inner`): a panicking test must fail on its own
/// assertion, not cascade into every later test as a poisoned-lock unwrap.
#[cfg(test)]
pub fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn sha256(bytes: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Per-process memo of "this destination is already known good", keyed by the
/// full destination path so a test that moves HOME is not served a stale
/// answer. `resolve_helper` runs twice per language (the preflight probe, then
/// the retrieval loop) and a polyglot scan multiplies that, so without the memo
/// the same three files are re-hashed on every call.
fn memo() -> &'static Mutex<HashMap<PathBuf, ()>> {
    static MEMO: std::sync::OnceLock<Mutex<HashMap<PathBuf, ()>>> = std::sync::OnceLock::new();
    MEMO.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Materialize `helper` under [`cache_root`] and return the path to run.
///
/// Idempotent: an existing file whose contents hash to the embedded text is
/// left alone. Anything else — missing, truncated, edited, or written by a
/// different build that happened to share the version dir — is rewritten.
///
/// The write goes to a temporary sibling and is renamed into place, so a
/// concurrent rvl reading the helper never observes a partial file.
pub fn ensure(helper: &Embedded) -> anyhow::Result<PathBuf> {
    let root = cache_root().ok_or_else(|| {
        anyhow::anyhow!(
            "no writable location for the embedded helpers (HOME is unset; \
             set {HELPER_DIR_ENV} to choose one)"
        )
    })?;
    let dest = root.join(helper.file_name);
    if memo().lock().is_ok_and(|m| m.contains_key(&dest)) {
        return Ok(dest);
    }
    let want = sha256(helper.contents.as_bytes());
    let current = std::fs::read(&dest).ok().map(|b| sha256(&b));
    if current.as_deref() != Some(want.as_str()) {
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating helper cache {}", root.display()))?;
        // Unique per process: two rvl runs extracting at once must not
        // write the same temporary path and truncate each other's bytes.
        let tmp = root.join(format!("{}.{}.tmp", helper.file_name, std::process::id()));
        std::fs::write(&tmp, helper.contents)
            .with_context(|| format!("writing helper {}", tmp.display()))?;
        std::fs::rename(&tmp, &dest).with_context(|| {
            format!("installing helper {} -> {}", tmp.display(), dest.display())
        })?;
    }
    if let Ok(mut m) = memo().lock() {
        m.insert(dest.clone(), ());
    }
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_root_is_versioned_under_home() {
        let _g = env_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::remove_var(HELPER_DIR_ENV);
        std::env::set_var("HOME", dir.path());
        let root = cache_root().expect("HOME is set");
        assert_eq!(
            root,
            dir.path()
                .join(".revelara")
                .join("helpers")
                .join(env!("CARGO_PKG_VERSION")),
            "the extraction dir must be versioned, so two builds cannot share scripts"
        );
    }

    #[test]
    fn ensure_writes_then_repairs_a_corrupted_copy() {
        let _g = env_lock();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(HELPER_DIR_ENV, dir.path());
        let path = ensure(&PYINDEX).expect("extraction must succeed into a writable dir");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            PYINDEX.contents,
            "the extracted script must be byte-identical to the embedded one"
        );

        // A hand-edited / truncated helper heals rather than persisting: a
        // stale script is a silently wrong scan.
        std::fs::write(&path, "# clobbered\n").unwrap();
        memo().lock().unwrap().remove(&path);
        let again = ensure(&PYINDEX).unwrap();
        assert_eq!(again, path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), PYINDEX.contents);
        std::env::remove_var(HELPER_DIR_ENV);
    }

    #[test]
    fn every_embedded_helper_carries_real_source() {
        for h in [&PYINDEX, &TSINDEX, &JAVAINDEX] {
            assert!(
                h.contents.len() > 10_000,
                "{} looks empty ({} bytes) — the include_str! path is wrong",
                h.file_name,
                h.contents.len()
            );
        }
    }
}
