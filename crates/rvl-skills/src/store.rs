//! Local skills cache, mirroring the spec cache's stance (rvl-cache): the
//! cached artifact is re-verified at load, a corrupt slot is never served,
//! and network failure degrades to the cached copy. Layout under a root dir
//! (default `~/.revelara/cache/skills`):
//!
//! ```text
//! <root>/<editor>/plugin.tar.gz   # the verified tarball as fetched
//! <root>/<editor>/meta.json       # version pin + sha256 + signing key
//! <root>/installed.json           # harness -> installed version/location
//! ```

use rvl_core::BIN;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const TARBALL: &str = "plugin.tar.gz";
const META: &str = "meta.json";
const INSTALLED: &str = "installed.json";

/// Version pin + integrity data for one cached editor tarball.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Meta {
    /// Content semver of the cached tarball (from X-Plugin-SemVer).
    pub version: String,
    /// sha256 hex of the tarball bytes; re-checked at every load.
    pub sha256: String,
    /// The server's Ed25519 signing key (hex) at fetch time, kept so an
    /// offline install can re-verify the integrity manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_hex: Option<String>,
    /// "YYYY-MM-DD" fetch date, for staleness display.
    pub fetched_at: String,
}

/// One installed harness, tracked for drift reporting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstalledInfo {
    pub version: String,
    pub location: String,
    pub installed_at: String,
}

/// The on-disk cache. All methods are best-effort-atomic: writes stage to a
/// temp name in the same directory and rename into place.
pub struct SkillsStore {
    root: PathBuf,
}

/// Editor names become directory components; keep them boring.
fn check_editor(editor: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !editor.is_empty()
            && editor
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
        "invalid editor name: {editor:?}"
    );
    Ok(())
}

impl SkillsStore {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn slot(&self, editor: &str) -> PathBuf {
        self.root.join(editor)
    }

    /// Cache a verified tarball + its pin. Overwrites any previous slot.
    pub fn save(&self, editor: &str, tarball: &[u8], meta: &Meta) -> anyhow::Result<()> {
        check_editor(editor)?;
        let slot = self.slot(editor);
        std::fs::create_dir_all(&slot)?;
        write_atomic(&slot.join(TARBALL), tarball)?;
        write_atomic(&slot.join(META), &serde_json::to_vec_pretty(meta)?)?;
        Ok(())
    }

    /// Load the cached tarball for an editor, re-verifying its sha256
    /// against the pin. `Ok(None)` when nothing is cached; `Err` when the
    /// slot exists but is corrupt (never serve unverified bytes).
    pub fn load(&self, editor: &str) -> anyhow::Result<Option<(Vec<u8>, Meta)>> {
        check_editor(editor)?;
        let slot = self.slot(editor);
        let tarball = match std::fs::read(slot.join(TARBALL)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta: Meta = serde_json::from_slice(&std::fs::read(slot.join(META)).map_err(|e| {
            anyhow::anyhow!("cached tarball for {editor} has no readable meta.json: {e}")
        })?)?;
        let actual = rvl_cache::sha256_hex(&tarball);
        anyhow::ensure!(
            actual == meta.sha256,
            "cached skills tarball for {editor} is corrupt (sha256 mismatch); \
             re-run '{BIN} skills install {editor}' online to refetch"
        );
        Ok(Some((tarball, meta)))
    }

    /// The pinned version of the cached tarball, if any.
    pub fn cached_version(&self, editor: &str) -> Option<String> {
        self.load(editor).ok().flatten().map(|(_, m)| m.version)
    }

    /// Read the installed-harness registry (empty when absent/corrupt —
    /// status display data, not a trust surface).
    pub fn read_installed(&self) -> BTreeMap<String, InstalledInfo> {
        std::fs::read(self.root.join(INSTALLED))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Record one harness install (read-modify-write).
    pub fn record_installed(&self, harness: &str, info: InstalledInfo) -> anyhow::Result<()> {
        let mut map = self.read_installed();
        map.insert(harness.to_string(), info);
        write_atomic(
            &self.root.join(INSTALLED),
            &serde_json::to_vec_pretty(&map)?,
        )?;
        Ok(())
    }

    /// Forget one harness's install record (read-modify-write; a harness
    /// that was never recorded is a no-op, keeping removal idempotent).
    pub fn remove_installed(&self, harness: &str) -> anyhow::Result<()> {
        let mut map = self.read_installed();
        if map.remove(harness).is_none() {
            return Ok(());
        }
        write_atomic(
            &self.root.join(INSTALLED),
            &serde_json::to_vec_pretty(&map)?,
        )?;
        Ok(())
    }
}

/// Write via same-directory temp file + rename, so a crash never leaves a
/// half-written artifact behind the pin.
fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(version: &str, sha256: String) -> Meta {
        Meta {
            version: version.to_string(),
            sha256,
            signing_key_hex: Some("ab".repeat(32)),
            fetched_at: "2026-08-04".to_string(),
        }
    }

    #[test]
    fn save_load_roundtrip_pins_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillsStore::open(dir.path()).unwrap();
        let tarball = b"tarball bytes".to_vec();
        let m = meta("0.2.0", rvl_cache::sha256_hex(&tarball));
        store.save("claude", &tarball, &m).unwrap();

        let (loaded, loaded_meta) = store.load("claude").unwrap().expect("cached");
        assert_eq!(loaded, tarball);
        assert_eq!(loaded_meta, m);
        assert_eq!(store.cached_version("claude").as_deref(), Some("0.2.0"));
    }

    #[test]
    fn empty_store_loads_none() {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillsStore::open(dir.path()).unwrap();
        assert!(store.load("claude").unwrap().is_none());
        assert_eq!(store.cached_version("claude"), None);
    }

    #[test]
    fn corrupt_tarball_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillsStore::open(dir.path()).unwrap();
        let tarball = b"tarball bytes".to_vec();
        let m = meta("0.2.0", rvl_cache::sha256_hex(&tarball));
        store.save("claude", &tarball, &m).unwrap();
        // Flip bytes on disk behind the pin.
        std::fs::write(dir.path().join("claude").join("plugin.tar.gz"), b"tampered").unwrap();

        let err = store.load("claude").unwrap_err();
        assert!(err.to_string().contains("corrupt"), "got: {err}");
        assert_eq!(store.cached_version("claude"), None);
    }

    #[test]
    fn rejects_path_like_editor_names() {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillsStore::open(dir.path()).unwrap();
        assert!(store.load("../evil").is_err());
        assert!(store
            .save("a/b", b"x", &meta("0.1.0", "deadbeef".into()))
            .is_err());
    }

    #[test]
    fn installed_registry_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = SkillsStore::open(dir.path()).unwrap();
        assert!(store.read_installed().is_empty());
        let info = InstalledInfo {
            version: "0.2.0".into(),
            location: "/home/x/.claude".into(),
            installed_at: "2026-08-04".into(),
        };
        store.record_installed("claude", info.clone()).unwrap();
        let map = store.read_installed();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("claude"), Some(&info));

        // remove_installed forgets the record; removing again is a no-op.
        store.remove_installed("claude").unwrap();
        assert!(store.read_installed().is_empty());
        store.remove_installed("claude").unwrap();
    }
}
