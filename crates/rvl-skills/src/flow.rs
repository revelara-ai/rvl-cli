//! Install / update / status orchestration. Pure over the [`Fetcher`] and
//! filesystem roots so the whole flow is testable with an in-memory backend
//! and temp dirs.
//!
//! Failure stance (Mozilla armagadd-on lesson: a verification failure must
//! never brick what is already installed): any fetch or verification
//! failure leaves BOTH the cache and the harness's installed files exactly
//! as they were. Network failure degrades to the verified cached copy with
//! a warning; verification failure aborts with an actionable error.

use rvl_core::BIN;
use std::path::Path;

use crate::fetch::Fetcher;
use crate::harness::{Harness, InstallReceipt};
use crate::semver::semver_newer;
use crate::store::{InstalledInfo, Meta, SkillsStore};
use crate::verify::verify_tarball;

/// Everything an install/status pass needs, resolved once by the CLI layer.
pub struct Env<'a> {
    pub store: &'a SkillsStore,
    pub fetcher: &'a dyn Fetcher,
    pub home: &'a Path,
    /// RVL_OFFLINE=1: no fetch attempted, cache-only.
    pub offline: bool,
    /// RVL_ALLOW_UNSIGNED=1: accept content without a verifiable
    /// integrity manifest (self-hosted servers without signing).
    pub allow_unsigned: bool,
    /// RVL_ALLOW_MISSING_CHECKSUM=1: accept a download without the
    /// X-Checksum transport header.
    pub allow_missing_checksum: bool,
}

/// A completed install for one harness.
#[derive(Debug)]
pub struct InstallReport {
    pub harness: String,
    pub version: String,
    pub receipt: InstallReceipt,
    /// True when no download happened (offline, fetch fallback, or the
    /// cached version already matched the served version).
    pub from_cache: bool,
    pub warnings: Vec<String>,
}

/// One verified tarball ready to install: bytes already checked, version
/// pinned.
struct Acquired {
    bytes: Vec<u8>,
    version: String,
    from_cache: bool,
    warnings: Vec<String>,
}

/// Verify a cached slot's signature policy (sha256 was already re-checked
/// by [`SkillsStore::load`]).
fn check_cached_signature(
    env: &Env,
    editor: &str,
    bytes: &[u8],
    meta: &Meta,
    warnings: &mut Vec<String>,
) -> anyhow::Result<()> {
    match &meta.signing_key_hex {
        Some(key_hex) => {
            let raw: [u8; 32] = hex::decode(key_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("cached signing key is not 32 bytes"))?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
            verify_tarball(bytes, &key).map_err(|e| {
                anyhow::anyhow!(
                    "cached skills for {editor} fail integrity verification ({e}); \
                     re-run '{BIN} skills install' online to refetch"
                )
            })?;
            Ok(())
        }
        None if env.allow_unsigned => {
            warnings.push(format!(
                "cached skills for {editor} were fetched without signing verification"
            ));
            Ok(())
        }
        None => anyhow::bail!(
            "cached skills for {editor} carry no signing key; set RVL_ALLOW_UNSIGNED=1 \
             to install them anyway, or re-run online against a signing-enabled server"
        ),
    }
}

/// Load-and-verify the cached slot; Ok(None) when nothing cached.
fn acquire_from_cache(env: &Env, editor: &str) -> anyhow::Result<Option<Acquired>> {
    let Some((bytes, meta)) = env.store.load(editor)? else {
        return Ok(None);
    };
    let mut warnings = Vec::new();
    check_cached_signature(env, editor, &bytes, &meta, &mut warnings)?;
    Ok(Some(Acquired {
        bytes,
        version: meta.version,
        from_cache: true,
        warnings,
    }))
}

/// Download, verify (transport checksum + integrity manifest), and cache a
/// fresh tarball. Nothing is written on any failure.
fn acquire_fresh(env: &Env, editor: &str) -> anyhow::Result<Acquired> {
    let mut warnings = Vec::new();
    let download = env.fetcher.fetch_tarball(editor)?;

    // Transport checksum (X-Checksum), mandatory by default.
    let mut key_hex = None;
    match &download.checksum {
        Some(expected) => {
            let actual = format!("sha256:{}", rvl_cache::sha256_hex(&download.bytes));
            anyhow::ensure!(
                &actual == expected,
                "checksum mismatch: expected {expected}, got {actual}"
            );
        }
        None if env.allow_missing_checksum => {
            warnings.push("server did not send X-Checksum (allowed by env)".to_string());
        }
        None => anyhow::bail!(
            "server did not send X-Checksum header; set RVL_ALLOW_MISSING_CHECKSUM=1 \
             to install anyway"
        ),
    }

    // Integrity manifest signature, fail-closed.
    match env.fetcher.fetch_signing_key() {
        Ok(raw) => {
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw)?;
            verify_tarball(&download.bytes, &key)
                .map_err(|e| anyhow::anyhow!("integrity verification failed: {e}"))?;
            key_hex = Some(hex::encode(raw));
        }
        Err(e) if env.allow_unsigned => {
            warnings.push(format!(
                "installing without signature verification (RVL_ALLOW_UNSIGNED=1): {e}"
            ));
        }
        Err(e) => anyhow::bail!(
            "could not fetch signing key for integrity verification: {e}; \
             set RVL_ALLOW_UNSIGNED=1 to install unsigned content"
        ),
    }

    env.store.save(
        editor,
        &download.bytes,
        &Meta {
            version: download.version.clone(),
            sha256: rvl_cache::sha256_hex(&download.bytes),
            signing_key_hex: key_hex,
            fetched_at: rvl_cache::today_utc(),
        },
    )?;

    Ok(Acquired {
        bytes: download.bytes,
        version: download.version,
        from_cache: false,
        warnings,
    })
}

/// Resolve a verified tarball for `editor`: served version first, cache
/// when it already matches or when the network is down/off.
fn acquire(env: &Env, editor: &str) -> anyhow::Result<Acquired> {
    if env.offline {
        return acquire_from_cache(env, editor)?.ok_or_else(|| {
            anyhow::anyhow!(
                "offline (RVL_OFFLINE=1) and no cached skills for {editor}; \
                 unset RVL_OFFLINE and re-run once online to seed the cache"
            )
        });
    }
    match env.fetcher.fetch_version() {
        Ok(served) => {
            if env.store.cached_version(editor).as_deref() == Some(served.as_str()) {
                if let Some(acquired) = acquire_from_cache(env, editor)? {
                    return Ok(acquired);
                }
            }
            acquire_fresh(env, editor)
        }
        Err(e) => match acquire_from_cache(env, editor)? {
            Some(mut acquired) => {
                acquired.warnings.push(format!(
                    "Revelara API unreachable ({e}); installed cached version {}",
                    acquired.version
                ));
                Ok(acquired)
            }
            None => anyhow::bail!(
                "cannot reach the Revelara API ({e}) and no cached skills for {editor}; \
                 check network and RVL_API_KEY, then re-run. \
                 Any previously installed skills are untouched."
            ),
        },
    }
}

/// Install (or update — same operation, mirroring `rvl plugin update`) the
/// skills for one harness.
pub fn install_one(env: &Env, harness: &dyn Harness) -> anyhow::Result<InstallReport> {
    let editor = harness.editor_param();
    let acquired = acquire(env, editor)?;
    let files = crate::verify::extract_tarball(&acquired.bytes)?;
    let receipt = harness.install(env.home, &files, &acquired.version)?;
    env.store.record_installed(
        harness.name(),
        InstalledInfo {
            version: acquired.version.clone(),
            location: receipt.location.display().to_string(),
            installed_at: rvl_cache::today_utc(),
        },
    )?;
    Ok(InstallReport {
        harness: harness.name().to_string(),
        version: acquired.version,
        receipt,
        from_cache: acquired.from_cache,
        warnings: acquired.warnings,
    })
}

/// A completed removal for one harness.
#[derive(Debug)]
pub struct RemoveReport {
    pub harness: String,
    pub receipt: crate::harness::RemoveReceipt,
}

/// Remove one harness's installed skills, mirroring `rvl plugin remove`.
/// The installed-file inventory comes from the cached tarball (the cache
/// records exactly what was installed); the harness decides how to apply
/// it. The install record is forgotten afterwards.
pub fn remove_one(env: &Env, harness: &dyn Harness) -> anyhow::Result<RemoveReport> {
    // A corrupt cache slot must not block removal: treat it as absent and
    // let the harness decide whether it can proceed without an inventory.
    let files = env
        .store
        .load(harness.editor_param())
        .ok()
        .flatten()
        .map(|(bytes, _)| crate::verify::extract_tarball(&bytes))
        .transpose()?;
    let receipt = harness.remove(env.home, files.as_ref())?;
    env.store.remove_installed(harness.name())?;
    Ok(RemoveReport {
        harness: harness.name().to_string(),
        receipt,
    })
}

/// The editor targets served by `GET /api/v1/plugin/editors`. Network-only
/// by nature (the server owns the list), so the offline kill switch gates it.
pub fn editors(env: &Env) -> anyhow::Result<Vec<crate::fetch::EditorInfo>> {
    anyhow::ensure!(
        !env.offline,
        "offline (RVL_OFFLINE=1): the editors listing is served by the Revelara API"
    );
    env.fetcher.fetch_editors()
}

/// Drift status for one installed harness.
pub struct HarnessStatus {
    pub harness: String,
    pub installed_version: String,
    pub location: String,
    /// The served version when it is newer than the installed one.
    pub update_available: Option<String>,
}

/// One cached (but not necessarily installed) editor slot.
pub struct CachedStatus {
    pub editor: String,
    pub version: String,
    pub fetched_at: String,
}

/// One install recorded only by rvl-cli's v1 metadata (not yet adopted
/// into rvl's own store).
pub struct V1InstallStatus {
    pub harness: String,
    pub version: String,
    pub location: String,
}

/// Installed-vs-served report, mirroring `rvl plugin list`'s UX.
pub struct StatusReport {
    /// The version the server currently serves; None when unreachable or
    /// offline (see `server_note`).
    pub served_version: Option<String>,
    pub server_note: Option<String>,
    pub harnesses: Vec<HarnessStatus>,
    /// Installs known only from rvl-cli's v1 records (read-only fallback);
    /// harnesses rvl's own store already tracks are excluded.
    pub v1_installs: Vec<V1InstallStatus>,
    pub cached: Vec<CachedStatus>,
}

/// Build the drift report. Never fails: network trouble degrades to
/// installed/cached information plus a note.
pub fn status(env: &Env) -> StatusReport {
    let (served_version, server_note) = if env.offline {
        (None, Some("offline (RVL_OFFLINE=1)".to_string()))
    } else {
        match env.fetcher.fetch_version() {
            Ok(v) => (Some(v), None),
            Err(e) => (None, Some(format!("server unreachable: {e}"))),
        }
    };

    let installed = env.store.read_installed();
    // v1 rvl-cli records are the day-one continuity view: show them until
    // an adoption (any v2 install/update) shadows them.
    let v1_installs = crate::v1::read_v1_installs(env.home)
        .into_iter()
        .filter(|p| !installed.contains_key(&p.editor))
        .map(|p| V1InstallStatus {
            harness: p.editor,
            version: p.version,
            location: p.location,
        })
        .collect();

    let harnesses = installed
        .into_iter()
        .map(|(name, info)| {
            let update_available = served_version
                .as_ref()
                .filter(|served| semver_newer(&info.version, served))
                .cloned();
            HarnessStatus {
                harness: name,
                installed_version: info.version,
                location: info.location,
                update_available,
            }
        })
        .collect();

    let mut cached = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for h in crate::harness::registry() {
        let editor = h.editor_param();
        if !seen.insert(editor) {
            continue;
        }
        if let Ok(Some((_, meta))) = env.store.load(editor) {
            cached.push(CachedStatus {
                editor: editor.to_string(),
                version: meta.version,
                fetched_at: meta.fetched_at,
            });
        }
    }

    StatusReport {
        served_version,
        server_note,
        harnesses,
        v1_installs,
        cached,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::TarballDownload;
    use crate::harness::by_name;
    use crate::verify::testutil::build_signed_tarball;
    use std::cell::Cell;

    const SKILL: &[u8] = b"---\nname: rvl-scan\n---\nScan.\n";

    /// In-memory mock of the backend plugin HTTP surface.
    struct MockFetcher {
        version: Result<String, String>,
        key: Result<[u8; 32], String>,
        tarball: Option<(Vec<u8>, String, Option<String>)>,
        tarball_calls: Cell<usize>,
    }

    impl MockFetcher {
        fn serving(version: &str, tarball: Vec<u8>, key: ed25519_dalek::VerifyingKey) -> Self {
            let checksum = format!("sha256:{}", rvl_cache::sha256_hex(&tarball));
            Self {
                version: Ok(version.to_string()),
                key: Ok(key.to_bytes()),
                tarball: Some((tarball, version.to_string(), Some(checksum))),
                tarball_calls: Cell::new(0),
            }
        }
        fn down(reason: &str) -> Self {
            Self {
                version: Err(reason.to_string()),
                key: Err(reason.to_string()),
                tarball: None,
                tarball_calls: Cell::new(0),
            }
        }
    }

    impl Fetcher for MockFetcher {
        fn fetch_version(&self) -> anyhow::Result<String> {
            self.version.clone().map_err(|e| anyhow::anyhow!(e))
        }
        fn fetch_signing_key(&self) -> anyhow::Result<[u8; 32]> {
            self.key.clone().map_err(|e| anyhow::anyhow!(e))
        }
        fn fetch_tarball(&self, _editor: &str) -> anyhow::Result<TarballDownload> {
            self.tarball_calls.set(self.tarball_calls.get() + 1);
            let (bytes, version, checksum) = self
                .tarball
                .clone()
                .ok_or_else(|| anyhow::anyhow!("server down"))?;
            Ok(TarballDownload {
                bytes,
                version,
                checksum,
            })
        }
        fn fetch_editors(&self) -> anyhow::Result<Vec<crate::fetch::EditorInfo>> {
            // Up when the version endpoint is up, mirroring the server.
            self.version.clone().map_err(|e| anyhow::anyhow!(e))?;
            Ok(vec![crate::fetch::EditorInfo {
                name: "claude".to_string(),
                display_name: "Claude Code".to_string(),
                tier: 1,
            }])
        }
    }

    struct Fixture {
        home: tempfile::TempDir,
        cache: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                home: tempfile::tempdir().unwrap(),
                cache: tempfile::tempdir().unwrap(),
            }
        }
        fn env<'a>(&'a self, store: &'a SkillsStore, fetcher: &'a dyn Fetcher) -> Env<'a> {
            Env {
                store,
                fetcher,
                home: self.home.path(),
                offline: false,
                allow_unsigned: false,
                allow_missing_checksum: false,
            }
        }
    }

    fn signed_fixture(version: &str) -> (Vec<u8>, ed25519_dalek::VerifyingKey) {
        build_signed_tarball(version, &[("rvl-scan/SKILL.md", SKILL)])
    }

    #[test]
    fn install_downloads_verifies_installs_and_caches() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        let env = fx.env(&store, &fetcher);

        let report = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap();
        assert_eq!(report.version, "0.2.0");
        assert!(!report.from_cache);
        assert!(report.warnings.is_empty());
        // Files landed in the harness dir.
        assert_eq!(
            std::fs::read(fx.home.path().join(".agents/skills/rvl-scan/SKILL.md")).unwrap(),
            SKILL
        );
        // Cache pinned, install recorded.
        assert_eq!(store.cached_version("codex").as_deref(), Some("0.2.0"));
        assert_eq!(store.read_installed()["codex"].version, "0.2.0");
    }

    #[test]
    fn second_install_reuses_pinned_cache_without_downloading() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        let env = fx.env(&store, &fetcher);
        let h = by_name("codex").unwrap();

        let first = install_one(&env, h.as_ref()).unwrap();
        let second = install_one(&env, h.as_ref()).unwrap();
        assert!(!first.from_cache);
        assert!(second.from_cache, "same served version must reuse the pin");
        assert_eq!(fetcher.tarball_calls.get(), 1);
    }

    #[test]
    fn offline_with_cache_installs_from_cache() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        // Seed the cache online first.
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        install_one(
            &fx.env(&store, &fetcher),
            by_name("codex").unwrap().as_ref(),
        )
        .unwrap();

        // Then go fully offline against a dead fetcher.
        let dead = MockFetcher::down("no network");
        let mut env = fx.env(&store, &dead);
        env.offline = true;
        let report = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap();
        assert!(report.from_cache);
        assert_eq!(report.version, "0.2.0");
    }

    #[test]
    fn offline_without_cache_fails_with_actionable_message() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let dead = MockFetcher::down("no network");
        let mut env = fx.env(&store, &dead);
        env.offline = true;

        let err = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("offline"), "got: {msg}");
        assert!(msg.contains("no cached skills"), "got: {msg}");
        assert!(
            !fx.home.path().join(".agents").exists(),
            "nothing installed"
        );
    }

    #[test]
    fn fetch_failure_falls_back_to_cache_with_warning() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        install_one(
            &fx.env(&store, &fetcher),
            by_name("codex").unwrap().as_ref(),
        )
        .unwrap();

        let dead = MockFetcher::down("connection refused");
        let env = fx.env(&store, &dead);
        let report = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap();
        assert!(report.from_cache);
        assert!(
            report.warnings.iter().any(|w| w.contains("unreachable")),
            "warnings: {:?}",
            report.warnings
        );
    }

    #[test]
    fn fetch_failure_without_cache_degrades_gracefully() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let dead = MockFetcher::down("connection refused");
        let env = fx.env(&store, &dead);

        let err = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot reach the Revelara API"), "got: {msg}");
        assert!(msg.contains("untouched"), "got: {msg}");
        assert!(!fx.home.path().join(".agents").exists());
    }

    #[test]
    fn tampered_download_is_rejected_and_nothing_lands() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, _key) = signed_fixture("0.2.0");
        // Server serves a tarball signed by SOMEONE ELSE'S key.
        let other = crate::verify::testutil::fresh_key().verifying_key();
        let fetcher = MockFetcher::serving("0.2.0", tarball, other);
        let env = fx.env(&store, &fetcher);

        let err = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("integrity verification failed"),
            "got: {err}"
        );
        assert!(store.load("codex").unwrap().is_none(), "not cached");
        assert!(!fx.home.path().join(".agents").exists(), "not installed");
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let mut fetcher = MockFetcher::serving("0.2.0", tarball, key);
        fetcher.tarball.as_mut().unwrap().2 = Some("sha256:0000".to_string());
        let env = fx.env(&store, &fetcher);

        let err = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "got: {err}");
        assert!(store.load("codex").unwrap().is_none());
    }

    #[test]
    fn missing_signing_key_is_fail_closed_unless_allowed() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let mut fetcher = MockFetcher::serving("0.2.0", tarball, key);
        fetcher.key = Err("404 signing not configured".to_string());

        let env = fx.env(&store, &fetcher);
        let err = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        assert!(err.to_string().contains("RVL_ALLOW_UNSIGNED"), "got: {err}");

        let mut env = fx.env(&store, &fetcher);
        env.allow_unsigned = true;
        let report = install_one(&env, by_name("codex").unwrap().as_ref()).unwrap();
        assert!(report
            .warnings
            .iter()
            .any(|w| w.contains("without signature verification")));
    }

    #[test]
    fn remove_deletes_installed_files_and_forgets_the_record() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        let env = fx.env(&store, &fetcher);
        let h = by_name("codex").unwrap();
        install_one(&env, h.as_ref()).unwrap();
        assert!(fx
            .home
            .path()
            .join(".agents/skills/rvl-scan/SKILL.md")
            .exists());

        let report = remove_one(&env, h.as_ref()).unwrap();
        assert_eq!(report.harness, "codex");
        // The signed fixture ships the skill file plus the integrity
        // manifest; both were installed, both get removed.
        assert_eq!(report.receipt.files_removed, Some(2));
        assert!(!fx
            .home
            .path()
            .join(".agents/skills/rvl-scan/SKILL.md")
            .exists());
        assert!(!fx.home.path().join(".agents/skills/rvl-scan").exists());
        assert!(store.read_installed().is_empty(), "record forgotten");
        // The cache slot survives: removal must not brick a later install.
        assert_eq!(store.cached_version("codex").as_deref(), Some("0.2.0"));
    }

    #[test]
    fn remove_without_cache_fails_actionably_for_dir_harness() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let dead = MockFetcher::down("no network");
        let env = fx.env(&store, &dead);
        let err = remove_one(&env, by_name("codex").unwrap().as_ref()).unwrap_err();
        assert!(
            err.to_string().contains("cached plugin tarball"),
            "got: {err}"
        );
    }

    #[test]
    fn remove_claude_works_without_cache_and_returns_unregistration() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        let env = fx.env(&store, &fetcher);
        let h = by_name("claude").unwrap();
        install_one(&env, h.as_ref()).unwrap();

        let report = remove_one(&env, h.as_ref()).unwrap();
        assert!(!fx.home.path().join(".revelara/marketplace").exists());
        assert!(report.receipt.register.is_some());
        assert!(store.read_installed().is_empty());
    }

    #[test]
    fn editors_is_offline_gated_and_passes_the_served_list_through() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);

        let list = editors(&fx.env(&store, &fetcher)).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "claude");

        let mut env = fx.env(&store, &fetcher);
        env.offline = true;
        let err = editors(&env).unwrap_err();
        assert!(err.to_string().contains("offline"), "got: {err}");
    }

    #[test]
    fn status_surfaces_v1_records_until_adoption_shadows_them() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        std::fs::create_dir_all(fx.home.path().join(".revelara")).unwrap();
        std::fs::write(
            fx.home.path().join(".revelara/plugins.json"),
            r#"[{"editor":"claude","version":"0.9.0",
                 "installed":"2026-08-01T10:00:00Z","location":"/v1/loc"},
                {"editor":"codex","version":"0.9.0",
                 "installed":"2026-08-01T10:00:00Z","location":"/v1/codex"}]"#,
        )
        .unwrap();

        let dead = MockFetcher::down("timeout");
        let report = status(&fx.env(&store, &dead));
        assert_eq!(report.v1_installs.len(), 2, "both v1 records surface");
        assert_eq!(report.v1_installs[0].harness, "claude");
        assert_eq!(report.v1_installs[0].version, "0.9.0");

        // Adopting claude (a v2 install) shadows its v1 record; codex stays.
        let (tarball, key) = signed_fixture("0.2.0");
        let fetcher = MockFetcher::serving("0.2.0", tarball, key);
        let env = fx.env(&store, &fetcher);
        install_one(&env, by_name("claude").unwrap().as_ref()).unwrap();
        let report = status(&env);
        assert_eq!(report.v1_installs.len(), 1);
        assert_eq!(report.v1_installs[0].harness, "codex");
        assert_eq!(report.harnesses.len(), 1);
        assert_eq!(report.harnesses[0].harness, "claude");
    }

    #[test]
    fn status_reports_drift_up_to_date_and_unreachable() {
        let fx = Fixture::new();
        let store = SkillsStore::open(fx.cache.path()).unwrap();
        let (tarball, key) = signed_fixture("0.1.0");
        let fetcher = MockFetcher::serving("0.1.0", tarball, key);
        install_one(
            &fx.env(&store, &fetcher),
            by_name("codex").unwrap().as_ref(),
        )
        .unwrap();

        // Server now serves a newer version: drift.
        let (t2, k2) = signed_fixture("0.2.0");
        let newer = MockFetcher::serving("0.2.0", t2, k2);
        let report = status(&fx.env(&store, &newer));
        assert_eq!(report.served_version.as_deref(), Some("0.2.0"));
        assert_eq!(report.harnesses.len(), 1);
        assert_eq!(
            report.harnesses[0].update_available.as_deref(),
            Some("0.2.0")
        );
        assert_eq!(report.cached.len(), 1);
        assert_eq!(report.cached[0].version, "0.1.0");

        // Same version: up to date.
        let (t1, k1) = signed_fixture("0.1.0");
        let same = MockFetcher::serving("0.1.0", t1, k1);
        let report = status(&fx.env(&store, &same));
        assert!(report.harnesses[0].update_available.is_none());

        // Server down: no served version, note set, installed data intact.
        let dead = MockFetcher::down("timeout");
        let report = status(&fx.env(&store, &dead));
        assert!(report.served_version.is_none());
        assert!(report.server_note.unwrap().contains("unreachable"));
        assert_eq!(report.harnesses[0].installed_version, "0.1.0");
    }
}
