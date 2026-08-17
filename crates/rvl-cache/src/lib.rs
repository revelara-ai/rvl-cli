//! Spec-cache distribution: versioning, signing, sync (wayfinder po-ipkfg.13).
//!
//! The cache artifact is a signed envelope. Verification happens at fetch AND
//! at load; a missing signature is a failed signature; there is no bypass
//! flag. A verification failure quarantines the artifact under `rejected/`
//! and the scanner continues on the last-good copy. An artifact whose schema
//! is newer than this binary supports never fails the scan: the last-good
//! cache stays active and a single upgrade hint line is emitted. Too-new
//! artifacts are deliberately NOT quarantined — `rejected/` holds trust
//! failures only, and a signed artifact that merely needs a newer binary is
//! not a trust failure.

use base64::Engine;
use ed25519_dalek::Verifier;
use rvl_core::BIN;
use serde::Deserialize;
use sha2::Digest;
use std::path::{Path, PathBuf};

/// Highest envelope schema this binary can consume. Anything at or below is
/// accepted (single bound: one check at install and load, no asymmetric
/// range logic); anything above triggers the upgrade-hint path.
pub const SUPPORTED_SCHEMA: u32 = 1;

/// Quarantined artifact pairs kept in `rejected/` (oldest pruned first) so a
/// broken or hostile server cannot grow the directory without bound.
pub const REJECTED_KEEP: usize = 8;

/// Days after which the staleness note appears in coverage output.
pub const STALENESS_DAYS: i64 = 14;

const ARTIFACT: &str = "specs.json";
const SIG: &str = "specs.json.sig";

/// The signed cache artifact: schema integer + factory-assigned date-serial
/// content version + the spec payload (opaque to this crate).
///
/// Only obtain one via [`CacheStore::load`]/[`CacheStore::install`] — reading
/// the cache files directly would sidestep signature verification.
///
/// UNKNOWN FIELDS ARE IGNORED, deliberately, and there is no
/// `deny_unknown_fields` here. That is the forward-compatibility contract: the
/// factory may add a purely additive envelope section without bumping
/// [`SUPPORTED_SCHEMA`], and a binary too old to know the section keeps
/// working on the same artifact instead of pinning itself to its last-good
/// cache. `judgments` below is the first section to use it.
#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub schema: u32,
    /// Date-serial, e.g. "2026-07-30.2" (factory-assigned, hash-addressed).
    pub content_version: String,
    /// The spec payload the scan engine consumes (engine port wires this up;
    /// opaque JSON here so this crate never depends on spec internals).
    pub specs: serde_json::Value,
    /// The ratified judgments corpus: what a resolved, violating finding MEANS
    /// — its severity, its control, its fix (po-av01j.106).
    ///
    /// A spec answers only "is this call bounded". Grading is a separate layer,
    /// and until the factory published it here the scanner could read it only
    /// from an optional `--judgments` file, so an out-of-the-box scan had
    /// nothing to grade findings with and every class surfaced as advisory —
    /// the gate could not fire no matter what the scan found.
    ///
    /// Opaque JSON for the same reason `specs` is: this crate distributes and
    /// verifies artifacts, it does not know what a judgment is. Triage owns
    /// that type.
    ///
    /// `#[serde(default)]`, so an artifact published before this section
    /// existed — every cache in the field today — loads unchanged and grades
    /// nothing, exactly as it does now. Absence is a valid state, never an
    /// error: no judgments means advisory, and advisory is the floor.
    #[serde(default)]
    pub judgments: Option<serde_json::Value>,
}

/// Pinned verifying keys (additive rotation: new keys append, old keys stay
/// until every signed artifact in the field has rolled).
pub struct Keyset {
    keys: Vec<ed25519_dalek::VerifyingKey>,
}

/// The dev keyset: the public half of the ed25519 keypair the spec factory
/// signs dev caches with (minted 2026-08-02; private half held out of band in
/// the minikube secret spec-signing-dev). The factory must mint a separate
/// PRODUCTION keypair and add its public key here (additive rotation) before
/// any customer release; this dev key stays for local/dev caches.
pub const DEV_KEYSET_HEX: &[&str] =
    &["aebac9ca1b7bf75b4848320858eceb1ce421ff152870f01fcdcb8e6be8514e9a"];

impl Keyset {
    pub fn from_hex(keys_hex: &[&str]) -> anyhow::Result<Self> {
        let mut keys = Vec::with_capacity(keys_hex.len());
        for k in keys_hex {
            let raw: [u8; 32] = hex::decode(k)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("pinned key is not 32 bytes"))?;
            keys.push(ed25519_dalek::VerifyingKey::from_bytes(&raw)?);
        }
        anyhow::ensure!(!keys.is_empty(), "empty keyset");
        Ok(Self { keys })
    }

    /// Verify `bytes` against a base64 detached signature with any pinned key.
    /// `None` (missing signature) is a failed signature by definition.
    pub fn verify_detached(&self, bytes: &[u8], sig_b64: Option<&str>) -> anyhow::Result<()> {
        let sig_b64 = sig_b64.ok_or_else(|| anyhow::anyhow!("missing signature"))?;
        let raw: [u8; 64] = base64::engine::general_purpose::STANDARD
            .decode(sig_b64.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&raw);
        for key in &self.keys {
            if key.verify(bytes, &sig).is_ok() {
                return Ok(());
            }
        }
        anyhow::bail!("signature does not verify against any pinned key")
    }
}

/// Where a loaded cache came from.
#[derive(Debug, PartialEq, Eq)]
pub enum LoadSource {
    Current,
    LastGood,
}

#[derive(Debug)]
pub struct Loaded {
    pub envelope: Envelope,
    pub source: LoadSource,
    /// sha256 of the loaded artifact bytes (computed from the bytes already
    /// in hand — status display needs it without a second disk read).
    pub artifact_sha256: String,
    /// One upgrade hint line when current is newer-schema than supported.
    pub upgrade_hint: Option<String>,
    /// Staleness note for coverage output, when the content is old.
    pub staleness_note: Option<String>,
}

/// On-disk layout under a root dir:
/// `current/specs.json` + `current/specs.json.sig`, mirrored in `last-good/`,
/// quarantined artifacts in `rejected/`.
pub struct CacheStore {
    root: PathBuf,
}

/// Outcome of a sync attempt. Sync never fails a scan.
#[derive(Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    /// RVL_OFFLINE=1: no fetch attempted.
    Offline,
    /// Hash-conditional GET returned not-modified.
    UpToDate,
    /// New artifact verified and installed.
    Installed { content_version: String },
    /// Fetched artifact needs a newer binary; current cache kept.
    SchemaTooNew { hint: String },
    /// Fetched artifact failed verification; quarantined, last state kept.
    Rejected { reason: String },
    /// Network or server error; last state kept.
    FetchFailed { reason: String },
    /// Verified artifact could not be written into place. The store may be
    /// mid-rotation: a verifiable copy survives in current or last-good and
    /// load() re-verifies whichever it finds.
    InstallFailed { reason: String },
}

/// What a fetcher returned.
pub enum Fetched {
    NotModified,
    New { bytes: Vec<u8>, sig_b64: String },
}

/// Transport abstraction: HTTP in production, in-memory in tests.
pub trait Fetcher {
    /// `current_hash` is the sha256 hex of the installed artifact, sent as a
    /// conditional so an unchanged artifact costs one 304.
    fn fetch(&self, current_hash: Option<&str>) -> anyhow::Result<Fetched>;
}

impl CacheStore {
    pub fn open(root: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(root)?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// A sibling store rooted in a subdirectory of this store's root — how
    /// the OSS tier lives beside the commercial one (po-scnmv.13) without
    /// touching the commercial layout.
    pub fn subdir_store(&self, name: &str) -> anyhow::Result<CacheStore> {
        CacheStore::open(&self.root.join(name))
    }

    /// sha256 hex of the currently installed artifact bytes, if any.
    pub fn current_hash(&self) -> Option<String> {
        std::fs::read(self.dir("current").join(ARTIFACT))
            .ok()
            .map(|b| sha256_hex(&b))
    }

    fn quarantine(&self, bytes: &[u8], sig_b64: &str) {
        let rejected = self.dir("rejected");
        let _ = std::fs::create_dir_all(&rejected);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = std::fs::write(rejected.join(format!("{stamp}-{ARTIFACT}")), bytes);
        let _ = std::fs::write(rejected.join(format!("{stamp}-{SIG}")), sig_b64);
        self.prune_rejected();
    }

    /// Quarantine a whole slot by renaming its files (preserves the exact
    /// bytes that failed verification, no re-read) and remove the slot.
    fn quarantine_slot(&self, slot: &str) {
        let rejected = self.dir("rejected");
        let _ = std::fs::create_dir_all(&rejected);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let dir = self.dir(slot);
        let _ = std::fs::rename(
            dir.join(ARTIFACT),
            rejected.join(format!("{stamp}-{ARTIFACT}")),
        );
        let _ = std::fs::rename(dir.join(SIG), rejected.join(format!("{stamp}-{SIG}")));
        let _ = std::fs::remove_dir_all(&dir);
        self.prune_rejected();
    }

    /// Keep `rejected/` bounded: a broken or hostile server must not grow it
    /// without limit. Oldest entries go first (millisecond-stamp prefixes
    /// sort lexicographically within a fixed digit width, and even across
    /// widths "old enough to matter" beats false precision here).
    fn prune_rejected(&self) {
        let rejected = self.dir("rejected");
        let Ok(entries) = std::fs::read_dir(&rejected) else {
            return;
        };
        let mut names: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        let excess = names.len().saturating_sub(REJECTED_KEEP * 2);
        for path in names.into_iter().take(excess) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// The one wording for the one condition, wherever it is detected.
    fn schema_hint(env: &Envelope, active: &str) -> String {
        format!(
            "spec cache {} uses schema {} (this binary supports up to {SUPPORTED_SCHEMA}); \
             upgrade {BIN} to use it — continuing on {active}",
            env.content_version, env.schema
        )
    }

    /// Parse + schema-check an already-verified artifact.
    fn accept(&self, bytes: &[u8]) -> Result<Envelope, SyncOutcome> {
        let env: Envelope = serde_json::from_slice(bytes).map_err(|e| {
            self.quarantine(bytes, "");
            SyncOutcome::Rejected {
                reason: format!("verified but unparseable envelope: {e}"),
            }
        })?;
        if env.schema > SUPPORTED_SCHEMA {
            // Valid, signed, just needs a newer binary. Not quarantined, not
            // installed: current stays active, the user gets one hint line.
            return Err(SyncOutcome::SchemaTooNew {
                hint: Self::schema_hint(&env, "the current cache"),
            });
        }
        Ok(env)
    }

    /// Verify + parse + atomically install an artifact; previous current
    /// becomes last-good. A bad signature quarantines to `rejected/` and
    /// leaves the store untouched. A newer-schema artifact is not installed
    /// (current stays) — the caller gets the upgrade hint via the outcome.
    pub fn install(&self, bytes: &[u8], sig_b64: &str, keyset: &Keyset) -> SyncOutcome {
        if let Err(e) = keyset.verify_detached(bytes, Some(sig_b64)) {
            self.quarantine(bytes, sig_b64);
            return SyncOutcome::Rejected {
                reason: e.to_string(),
            };
        }
        let env = match self.accept(bytes) {
            Ok(env) => env,
            Err(outcome) => return outcome,
        };

        // Stage in a temp dir, then swap: incoming -> current -> last-good.
        // Rename is atomic per path; a crash mid-sequence leaves a verifiable
        // copy in either current or last-good, and load() re-verifies anyway.
        let staged = self.dir("incoming");
        let res: anyhow::Result<()> = (|| {
            let _ = std::fs::remove_dir_all(&staged);
            std::fs::create_dir_all(&staged)?;
            std::fs::write(staged.join(ARTIFACT), bytes)?;
            std::fs::write(staged.join(SIG), sig_b64)?;
            let current = self.dir("current");
            let last_good = self.dir("last-good");
            if current.exists() {
                let _ = std::fs::remove_dir_all(&last_good);
                std::fs::rename(&current, &last_good)?;
            }
            std::fs::rename(&staged, &current)?;
            Ok(())
        })();
        match res {
            Ok(()) => SyncOutcome::Installed {
                content_version: env.content_version,
            },
            Err(e) => SyncOutcome::InstallFailed {
                reason: e.to_string(),
            },
        }
    }

    /// Read + verify one slot; missing sig file = failed sig.
    fn load_slot(&self, slot: &str, keyset: &Keyset) -> anyhow::Result<(Vec<u8>, Envelope)> {
        let dir = self.dir(slot);
        let bytes = std::fs::read(dir.join(ARTIFACT))?;
        let sig = std::fs::read_to_string(dir.join(SIG)).ok();
        keyset.verify_detached(&bytes, sig.as_deref())?;
        let env: Envelope = serde_json::from_slice(&bytes)?;
        Ok((bytes, env))
    }

    /// Load for a scan: verify at load, fall back to last-good on any
    /// failure (quarantining the bad slot), never scan on unverified data.
    pub fn load(&self, keyset: &Keyset, today: &str) -> anyhow::Result<Loaded> {
        let mut upgrade_hint = None;
        match self.load_slot("current", keyset) {
            Ok((bytes, env)) if env.schema <= SUPPORTED_SCHEMA => {
                return Ok(Loaded {
                    staleness_note: staleness_note(&env.content_version, today),
                    artifact_sha256: sha256_hex(&bytes),
                    envelope: env,
                    source: LoadSource::Current,
                    upgrade_hint: None,
                });
            }
            Ok((_, env)) => {
                // Signed and intact but too new for this binary.
                upgrade_hint = Some(Self::schema_hint(&env, "last-good"));
            }
            Err(_) if self.dir("current").exists() => {
                // Bad current: quarantine it by rename (the exact bytes that
                // failed, no re-read) and fall through to last-good.
                self.quarantine_slot("current");
            }
            Err(_) => {}
        }
        let (bytes, env) = self.load_slot("last-good", keyset).map_err(|e| {
            // A tampered last-good deserves the same forensic capture.
            if self.dir("last-good").exists() {
                self.quarantine_slot("last-good");
            }
            anyhow::anyhow!(
                "no verifiable spec cache (current failed, last-good: {e}); \
                 run '{BIN} sync' or '{BIN} cache import'"
            )
        })?;
        anyhow::ensure!(
            env.schema <= SUPPORTED_SCHEMA,
            "last-good cache schema {} unsupported",
            env.schema
        );
        Ok(Loaded {
            staleness_note: staleness_note(&env.content_version, today),
            artifact_sha256: sha256_hex(&bytes),
            envelope: env,
            source: LoadSource::LastGood,
            upgrade_hint,
        })
    }

    /// Air-gapped import: identical verification, no bypass.
    pub fn import(
        &self,
        artifact: &Path,
        sig: &Path,
        keyset: &Keyset,
    ) -> anyhow::Result<SyncOutcome> {
        let bytes = std::fs::read(artifact)?;
        let sig_b64 = std::fs::read_to_string(sig)?;
        Ok(self.install(&bytes, &sig_b64, keyset))
    }
}

/// Is the offline kill switch set? (value semantics: "1" only)
pub fn offline_from_env(value: Option<&str>) -> bool {
    value == Some("1")
}

/// Days since the civil epoch for a "YYYY-MM-DD" prefix; None if malformed.
/// (Howard Hinnant's days-from-civil; no chrono dependency for one subtraction.)
fn days_from_civil(date: &str) -> Option<i64> {
    let mut it = date.splitn(3, '-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

/// Inverse of [`days_from_civil`] (Hinnant's civil-from-days). Both halves
/// of the calendar math live in this crate so they cannot drift apart.
fn civil_from_days(z: i64) -> String {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Today as "YYYY-MM-DD" (UTC), for [`CacheStore::load`]'s staleness check.
pub fn today_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    civil_from_days((secs / 86400) as i64)
}

/// Staleness note when `content_version`'s date is more than
/// [`STALENESS_DAYS`] before `today` (both "YYYY-MM-DD" prefixes).
pub fn staleness_note(content_version: &str, today: &str) -> Option<String> {
    let minted = days_from_civil(content_version.get(..10)?)?;
    let now = days_from_civil(today.get(..10)?)?;
    let age = now - minted;
    (age > STALENESS_DAYS).then(|| {
        format!(
            "spec cache is {age} days old (from {}); run '{BIN} sync' to refresh",
            &content_version[..10]
        )
    })
}

/// One sync pass: no-op when offline, hash-conditional fetch, verify,
/// install. Never returns Err — every failure mode is a reported outcome so
/// sync can run post-scan without ever blocking anything.
pub fn sync(
    store: &CacheStore,
    fetcher: &dyn Fetcher,
    keyset: &Keyset,
    offline: bool,
) -> SyncOutcome {
    if offline {
        return SyncOutcome::Offline;
    }
    match fetcher.fetch(store.current_hash().as_deref()) {
        Ok(Fetched::NotModified) => SyncOutcome::UpToDate,
        Ok(Fetched::New { bytes, sig_b64 }) => store.install(&bytes, &sig_b64, keyset),
        Err(e) => SyncOutcome::FetchFailed {
            reason: e.to_string(),
        },
    }
}

/// sha256 hex helper shared by store and fetchers.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(bytes))
}

/// HTTP fetcher against the Revelara API: hash-conditional GET on the
/// artifact, then the detached signature. Org-key auth via bearer token.
pub struct HttpFetcher {
    pub base_url: String,
    pub org_key: String,
}

impl Fetcher for HttpFetcher {
    fn fetch(&self, current_hash: Option<&str>) -> anyhow::Result<Fetched> {
        let url = format!(
            "{}/api/v1/scanner/spec-cache",
            self.base_url.trim_end_matches('/')
        );
        let auth = format!("Bearer {}", self.org_key);
        let mut req = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &auth);
        if let Some(h) = current_hash {
            req = req.set("If-None-Match", &format!("\"{h}\""));
        }
        let resp = match req.call() {
            // 304 arrives as Ok, NOT as Err: ureq reserves `Error::Status` for
            // 4xx/5xx. Checking the status here rather than in an Err arm is
            // the whole fix (po-av01j.176) — the Err arm below never fired, so
            // every conditional hit fell through, read an EMPTY body, and then
            // failed signature verification against it. That surfaced to users
            // as "signature does not verify against any pinned key": a
            // tampering message for a healthy cache hit.
            Ok(r) if r.status() == 304 => return Ok(Fetched::NotModified),
            Ok(r) => r,
            Err(ureq::Error::Status(304, _)) => return Ok(Fetched::NotModified),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        resp.into_reader().read_to_end(&mut bytes)?;
        let sig_b64 = ureq::get(&format!("{url}.sig"))
            .timeout(std::time::Duration::from_secs(30))
            .set("Authorization", &auth)
            .call()?
            .into_string()?;
        Ok(Fetched::New { bytes, sig_b64 })
    }
}

/// Subdirectory under the cache root holding the OSS ruleset tier's store
/// (po-scnmv.13). Sibling of `current/`/`last-good/`/`rejected/`, so the
/// commercial store's layout is untouched and existing installs keep working.
pub const OSS_DIR: &str = "oss";

/// Unauthenticated fetcher for the OSS ruleset tier: the vocabulary-lanes
/// artifact (CDLA-Permissive-2.0, license embedded in the envelope) that the
/// public binary syncs with no account. Same verification discipline as the
/// commercial tier — the keyset does not care who paid.
pub struct OssHttpFetcher {
    pub base_url: String,
}

impl Fetcher for OssHttpFetcher {
    fn fetch(&self, current_hash: Option<&str>) -> anyhow::Result<Fetched> {
        let url = format!(
            "{}/api/v1/scanner/spec-cache/oss",
            self.base_url.trim_end_matches('/')
        );
        let mut req = ureq::get(&url).timeout(std::time::Duration::from_secs(30));
        if let Some(h) = current_hash {
            req = req.set("If-None-Match", &format!("\"{h}\""));
        }
        let resp = match req.call() {
            // Same 304-in-the-Ok-arm rule as the commercial fetcher
            // (po-av01j.176): checking only an Err arm reads an empty body
            // and fails verification with a tampering message.
            Ok(r) if r.status() == 304 => return Ok(Fetched::NotModified),
            Ok(r) => r,
            Err(ureq::Error::Status(304, _)) => return Ok(Fetched::NotModified),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        resp.into_reader().read_to_end(&mut bytes)?;
        let sig_b64 = ureq::get(&format!("{url}.sig"))
            .timeout(std::time::Duration::from_secs(30))
            .call()?
            .into_string()?;
        Ok(Fetched::New { bytes, sig_b64 })
    }
}

/// The two tiers a scan may load (po-scnmv.13). Either may be absent — a
/// no-key install has only the OSS tier, an old install only the commercial
/// one. Both absent is the only fatal state, decided by the caller.
pub struct TieredLoaded {
    pub oss: Option<Loaded>,
    pub commercial: Option<Loaded>,
}

impl TieredLoaded {
    /// Whether any tier loaded.
    pub fn any(&self) -> bool {
        self.oss.is_some() || self.commercial.is_some()
    }

    /// The specs to feed the engine: a base payload plus an optional overlay
    /// the engine merges over it (higher confidence wins). The OSS tier is
    /// the base and the commercial tier the overlay, so a keyed install
    /// layers judgment lanes over the public vocabulary baseline.
    pub fn spec_texts(&self) -> anyhow::Result<Option<(String, Option<String>)>> {
        match (&self.oss, &self.commercial) {
            (None, None) => Ok(None),
            (Some(o), None) => Ok(Some((serde_json::to_string(&o.envelope.specs)?, None))),
            (None, Some(c)) => Ok(Some((serde_json::to_string(&c.envelope.specs)?, None))),
            (Some(o), Some(c)) => Ok(Some((
                serde_json::to_string(&o.envelope.specs)?,
                Some(serde_json::to_string(&c.envelope.specs)?),
            ))),
        }
    }

    /// The judgments corpus rides ONLY in the commercial tier — the OSS
    /// artifact is vocabulary and never grades anything.
    pub fn judgments(&self) -> Option<serde_json::Value> {
        self.commercial
            .as_ref()
            .and_then(|c| c.envelope.judgments.clone())
    }
}

/// Load both tiers, tolerating either store being absent or unloadable.
/// Each present tier is fully verified (signature at load, as always); a
/// tier that fails verification is treated as absent, never as trusted.
pub fn load_tiered(
    commercial: &CacheStore,
    oss: &CacheStore,
    keyset: &Keyset,
    today: &str,
) -> TieredLoaded {
    TieredLoaded {
        oss: oss.load(keyset, today).ok(),
        commercial: commercial.load(keyset, today).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_halves_round_trip() {
        for day in [-719468, 0, 11017, 20664, 30000] {
            let s = civil_from_days(day);
            assert_eq!(days_from_civil(&s), Some(day), "round trip failed for {s}");
        }
        assert_eq!(civil_from_days(20664), "2026-07-30");
    }

    #[test]
    fn shipped_dev_keyset_parses() {
        // A malformed pinned key would brick every subcommand at startup.
        assert!(Keyset::from_hex(DEV_KEYSET_HEX).is_ok());
    }

    // --- tiered load (po-scnmv.13) ---
    //
    // Tests cannot produce signed artifacts (the pinned keyset has no private
    // half in this repo, by design), so the matrix exercises the layering
    // seam above the stores: TieredLoaded built from constructed envelopes.
    // The store paths themselves are covered live by the flywheel acceptance
    // harness (server-side repo, scripts/flywheel_acceptance.sh step 7).

    fn loaded_with(specs: serde_json::Value, judgments: Option<serde_json::Value>) -> Loaded {
        Loaded {
            envelope: serde_json::from_value(serde_json::json!({
                "schema": 1,
                "content_version": "2026-08-17.test",
                "specs": specs,
                "judgments": judgments,
            }))
            .expect("test envelope"),
            source: LoadSource::Current,
            artifact_sha256: String::new(),
            upgrade_hint: None,
            staleness_note: None,
        }
    }

    #[test]
    fn tiered_neither_loadable_is_the_only_fatal_state() {
        let t = TieredLoaded {
            oss: None,
            commercial: None,
        };
        assert!(!t.any());
        assert!(t.spec_texts().unwrap().is_none());
    }

    #[test]
    fn tiered_oss_only_scans_on_the_baseline() {
        let t = TieredLoaded {
            oss: Some(loaded_with(serde_json::json!({"server": [1]}), None)),
            commercial: None,
        };
        let (base, overlay) = t.spec_texts().unwrap().unwrap();
        assert!(base.contains("server"));
        assert!(overlay.is_none());
        assert!(t.judgments().is_none());
    }

    #[test]
    fn tiered_commercial_only_keeps_old_installs_working() {
        let t = TieredLoaded {
            oss: None,
            commercial: Some(loaded_with(
                serde_json::json!({"apis": [1]}),
                Some(serde_json::json!([{"api": "x"}])),
            )),
        };
        let (base, overlay) = t.spec_texts().unwrap().unwrap();
        assert!(base.contains("apis"));
        assert!(overlay.is_none());
        assert!(t.judgments().is_some());
    }

    #[test]
    fn tiered_both_layers_commercial_over_oss() {
        let t = TieredLoaded {
            oss: Some(loaded_with(serde_json::json!({"server": [1]}), None)),
            commercial: Some(loaded_with(
                serde_json::json!({"apis": [1]}),
                Some(serde_json::json!([{"api": "x"}])),
            )),
        };
        let (base, overlay) = t.spec_texts().unwrap().unwrap();
        assert!(base.contains("server"), "OSS tier is the base");
        assert!(
            overlay.expect("overlay").contains("apis"),
            "commercial overlays"
        );
        assert!(
            t.judgments().is_some(),
            "judgments come from the commercial tier"
        );
    }
}
