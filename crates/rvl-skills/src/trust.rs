//! Trust-on-first-use pinning of the plugin signing key (po-se7vv).
//!
//! The server hands out its own Ed25519 verifying key, so a signature that
//! verifies against it proves nothing when the server, or the path to it,
//! is the attacker. The first verified install from a server records that
//! server's key here; every later fetch must present the same key. A
//! different key is refused until the user names its fingerprint, the way
//! SSH treats a changed host key.
//!
//! The key is NOT compiled in (unlike the spec cache's `PINNED_KEYSET_HEX`):
//! it comes from KMS and rotates, and a self-hosted server signs with its
//! own key, so no constant in the binary is right for every server.
//!
//! Layout (default `~/.revelara/trusted_keys.json`), one entry per server:
//!
//! ```text
//! {"servers": {"https://api.revelara.ai": {"public_key": "<hex>", "first_trusted": "YYYY-MM-DD"}}}
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The env variable that names the fingerprint of a changed key to trust.
pub const TRUST_ENV: &str = "RVL_TRUST_PLUGIN_SIGNING_KEY";

/// One server's recorded key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustedKey {
    /// The Ed25519 verifying key, hex.
    public_key: String,
    /// "YYYY-MM-DD" this key was first trusted.
    first_trusted: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustFile {
    #[serde(default)]
    servers: BTreeMap<String, TrustedKey>,
}

/// What a fetched key means against the recorded one.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// No key recorded for this server yet.
    FirstUse,
    /// The fetched key is the recorded key.
    Known,
    /// The key changed and the user named the new fingerprint.
    Replaced { previous: String },
}

/// The fingerprint a user compares and passes to [`TRUST_ENV`].
pub fn fingerprint(key: &[u8; 32]) -> String {
    format!("sha256:{}", rvl_cache::sha256_hex(key))
}

/// Servers are keyed by base URL, less any trailing slash.
fn server_id(base_url: &str) -> &str {
    base_url.trim_end_matches('/')
}

/// The on-disk trusted-key file. Opening does no I/O, so commands that
/// never fetch a key never create it.
pub struct TrustStore {
    path: PathBuf,
}

impl TrustStore {
    pub fn at(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// An unreadable or malformed file is an error, never "no key yet":
    /// treating it as empty would trust whatever key is served next.
    fn read(&self) -> anyhow::Result<TrustFile> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(TrustFile::default()),
            Err(e) => anyhow::bail!(
                "cannot read trusted signing keys at {}: {e}",
                self.path.display()
            ),
        };
        serde_json::from_slice(&bytes).map_err(|e| {
            anyhow::anyhow!(
                "trusted signing keys at {} are malformed ({e}); fix the file, or delete it \
                 to trust each server's key again on the next install",
                self.path.display()
            )
        })
    }

    /// The key recorded for `base_url`, if any.
    pub fn pinned(&self, base_url: &str) -> anyhow::Result<Option<[u8; 32]>> {
        let Some(entry) = self.read()?.servers.remove(server_id(base_url)) else {
            return Ok(None);
        };
        let raw: [u8; 32] = hex::decode(&entry.public_key)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "trusted signing key for {} in {} is not a 32-byte hex key",
                    server_id(base_url),
                    self.path.display()
                )
            })?;
        Ok(Some(raw))
    }

    /// Record `key` as the trusted key for `base_url`, replacing any
    /// previous one (read-modify-write, staged and renamed into place).
    pub fn pin(&self, base_url: &str, key: &[u8; 32]) -> anyhow::Result<()> {
        let mut file = self.read()?;
        file.servers.insert(
            server_id(base_url).to_string(),
            TrustedKey {
                public_key: hex::encode(key),
                first_trusted: rvl_cache::today_utc(),
            },
        );
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&file)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Judge a fetched key against the recorded one. Writes nothing: the
    /// caller pins only after the content verifies against `fetched`.
    /// `accept` is the fingerprint from [`TRUST_ENV`], if set.
    pub fn decide(
        &self,
        base_url: &str,
        fetched: &[u8; 32],
        accept: Option<&str>,
    ) -> anyhow::Result<Decision> {
        let Some(pinned) = self.pinned(base_url)? else {
            return Ok(Decision::FirstUse);
        };
        if &pinned == fetched {
            return Ok(Decision::Known);
        }
        let expected = fingerprint(&pinned);
        let actual = fingerprint(fetched);
        if accept.is_some_and(|a| a.trim().eq_ignore_ascii_case(&actual)) {
            return Ok(Decision::Replaced { previous: expected });
        }
        anyhow::bail!(
            "the plugin signing key for {server} changed: expected {expected}, got {actual}. \
             Nothing was installed. A changed key is a planned rotation or a compromised \
             server or connection. Confirm the new fingerprint with the server's operator, \
             then re-run with {TRUST_ENV}={actual} to trust it. Trusted keys are in {path}",
            server = server_id(base_url),
            path = self.path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "https://api.example.test";

    fn store(dir: &tempfile::TempDir) -> TrustStore {
        TrustStore::at(&dir.path().join(".revelara").join("trusted_keys.json"))
    }

    #[test]
    fn fingerprint_golden_value_is_pinned() {
        // A user copies this string into the trust env var, so it must read
        // the same from every build (po-av01j.235).
        assert_eq!(
            fingerprint(&[7; 32]),
            "sha256:4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }

    #[test]
    fn an_unknown_server_is_first_use_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        assert_eq!(
            s.decide(SERVER, &[1; 32], None).unwrap(),
            Decision::FirstUse
        );
        assert!(!dir.path().join(".revelara").exists());
    }

    #[test]
    fn a_pinned_key_is_known_with_or_without_a_trailing_slash() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.pin(SERVER, &[1; 32]).unwrap();
        assert_eq!(s.decide(SERVER, &[1; 32], None).unwrap(), Decision::Known);
        let slashed = format!("{SERVER}/");
        assert_eq!(s.decide(&slashed, &[1; 32], None).unwrap(), Decision::Known);
    }

    #[test]
    fn a_changed_key_is_refused_with_both_fingerprints() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.pin(SERVER, &[1; 32]).unwrap();
        let err = s.decide(SERVER, &[2; 32], None).unwrap_err().to_string();
        assert!(err.contains(&fingerprint(&[1; 32])), "got: {err}");
        assert!(err.contains(&fingerprint(&[2; 32])), "got: {err}");
        assert!(err.contains(TRUST_ENV), "got: {err}");
        assert_eq!(s.pinned(SERVER).unwrap(), Some([1; 32]));
    }

    #[test]
    fn only_the_fingerprint_of_the_served_key_accepts_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.pin(SERVER, &[1; 32]).unwrap();
        for wrong in ["1", "yes", &fingerprint(&[1; 32]), &fingerprint(&[3; 32])] {
            assert!(s.decide(SERVER, &[2; 32], Some(wrong)).is_err(), "{wrong}");
        }
        let right = fingerprint(&[2; 32]).to_uppercase();
        assert_eq!(
            s.decide(SERVER, &[2; 32], Some(&right)).unwrap(),
            Decision::Replaced {
                previous: fingerprint(&[1; 32])
            }
        );
    }

    #[test]
    fn servers_are_pinned_independently() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.pin(SERVER, &[1; 32]).unwrap();
        s.pin("https://self-hosted.example.test", &[2; 32]).unwrap();
        assert_eq!(s.pinned(SERVER).unwrap(), Some([1; 32]));
        assert_eq!(
            s.pinned("https://self-hosted.example.test").unwrap(),
            Some([2; 32])
        );
    }

    #[test]
    fn a_malformed_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.pin(SERVER, &[1; 32]).unwrap();
        std::fs::write(&s.path, b"{not json").unwrap();
        let err = s.decide(SERVER, &[2; 32], None).unwrap_err().to_string();
        assert!(err.contains("malformed"), "got: {err}");
        assert!(s.pin(SERVER, &[2; 32]).is_err());

        std::fs::write(
            &s.path,
            br#"{"servers":{"https://api.example.test":{"public_key":"abcd","first_trusted":"2026-10-04"}}}"#,
        )
        .unwrap();
        assert!(s.decide(SERVER, &[2; 32], None).is_err());
    }
}
