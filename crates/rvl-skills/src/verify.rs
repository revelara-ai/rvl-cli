//! Plugin tarball integrity verification, mirroring rvl-cli's
//! `internal/plugin/verify.go`: an `integrity.manifest.json` inside the
//! tarball carries per-file sha256 hashes and an Ed25519 signature over the
//! canonical sorted `path:hash\n` lines. Verification is fail-closed; the
//! caller decides policy for a server without signing support.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The integrity.manifest.json included in every plugin tarball.
#[derive(Debug, Deserialize)]
pub struct IntegrityManifest {
    pub version: String,
    #[serde(default)]
    pub signed_at: String,
    pub algorithm: String,
    #[serde(default)]
    pub key_id: String,
    pub files: BTreeMap<String, String>,
    pub signature: String,
}

/// File name of the manifest inside the tarball.
pub const MANIFEST_NAME: &str = "integrity.manifest.json";

/// Reject tarball entry names that would escape the extraction root:
/// absolute paths, `..` components, or empty names.
pub fn safe_rel_path(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "empty entry name in tarball");
    anyhow::ensure!(
        !name.starts_with('/') && !name.starts_with('\\'),
        "absolute path in tarball: {name}"
    );
    anyhow::ensure!(
        name.split(['/', '\\']).all(|c| c != ".."),
        "path traversal in tarball: {name}"
    );
    Ok(())
}

/// Read a gzipped tarball into path -> content (regular files only).
/// Every entry name is checked with [`safe_rel_path`].
pub fn extract_tarball(data: &[u8]) -> anyhow::Result<BTreeMap<String, Vec<u8>>> {
    let gz = flate2::read::GzDecoder::new(data);
    let mut archive = tar::Archive::new(gz);
    let mut files = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        // Tarballs commonly prefix entries with "./"; normalize before the
        // safety check so the manifest's plain paths match.
        let name = name.strip_prefix("./").unwrap_or(&name).to_string();
        safe_rel_path(&name)?;
        let mut content = Vec::with_capacity(entry.size() as usize);
        std::io::Read::read_to_end(&mut entry, &mut content)?;
        files.insert(name, content);
    }
    Ok(files)
}

/// The canonical signing input: sorted `path:hash\n` lines. Must stay
/// byte-identical to the backend's `buildCanonicalInput`.
fn canonical_input(files: &BTreeMap<String, String>) -> Vec<u8> {
    let mut out = String::new();
    for (path, hash) in files {
        out.push_str(path);
        out.push(':');
        out.push_str(hash);
        out.push('\n');
    }
    out.into_bytes()
}

/// Verify a plugin tarball end to end: manifest present, EdDSA signature
/// over the canonical input verifies with `public_key`, every listed file's
/// sha256 matches, and no file in the tarball is untracked by the manifest.
pub fn verify_tarball(
    data: &[u8],
    public_key: &ed25519_dalek::VerifyingKey,
) -> anyhow::Result<IntegrityManifest> {
    let files = extract_tarball(data)?;

    let manifest_bytes = files.get(MANIFEST_NAME).ok_or_else(|| {
        anyhow::anyhow!("tarball missing {MANIFEST_NAME} — plugin may be unsigned")
    })?;
    let manifest: IntegrityManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|e| anyhow::anyhow!("parse integrity manifest: {e}"))?;

    anyhow::ensure!(
        manifest.algorithm == "EdDSA",
        "unsupported signing algorithm: {}",
        manifest.algorithm
    );

    let sig_raw: [u8; 64] = hex::decode(&manifest.signature)
        .map_err(|e| anyhow::anyhow!("decode signature: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_raw);
    ed25519_dalek::Verifier::verify(public_key, &canonical_input(&manifest.files), &sig).map_err(
        |_| anyhow::anyhow!("signature verification failed — plugin may have been tampered with"),
    )?;

    // Every manifest-listed file must exist with a matching sha256.
    for (path, expected) in &manifest.files {
        let content = files.get(path).ok_or_else(|| {
            anyhow::anyhow!("manifest lists {path:?} but file not found in tarball")
        })?;
        let actual = format!("sha256:{}", rvl_cache::sha256_hex(content));
        anyhow::ensure!(
            &actual == expected,
            "hash mismatch for {path:?}: expected {expected}, got {actual}"
        );
    }

    // No file may ride along untracked (the manifest itself excepted).
    for path in files.keys() {
        if path == MANIFEST_NAME {
            continue;
        }
        anyhow::ensure!(
            manifest.files.contains_key(path),
            "file {path:?} in tarball but not tracked in manifest"
        );
    }

    Ok(manifest)
}

#[cfg(test)]
pub(crate) mod testutil {
    use ed25519_dalek::Signer;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use sha2::Digest;
    use std::io::Write as _;

    /// Build a signed plugin tarball fixture: files + a matching
    /// integrity.manifest.json signed with a fresh Ed25519 key. Returns the
    /// gzipped tarball bytes and the verifying key.
    pub fn build_signed_tarball(
        version: &str,
        files: &[(&str, &[u8])],
    ) -> (Vec<u8>, ed25519_dalek::VerifyingKey) {
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let tarball = build_tarball_with_key(version, files, &signing, files);
        (tarball, signing.verifying_key())
    }

    /// Lower-level fixture: sign `manifest_files` but ship `ship_files`,
    /// letting tests produce tampered/untracked/mismatched tarballs.
    pub fn build_tarball_with_key(
        version: &str,
        manifest_files: &[(&str, &[u8])],
        signing: &ed25519_dalek::SigningKey,
        ship_files: &[(&str, &[u8])],
    ) -> Vec<u8> {
        let mut entries: Vec<(String, String)> = manifest_files
            .iter()
            .map(|(name, content)| {
                let h = hex::encode(sha2::Sha256::digest(content));
                (name.to_string(), format!("sha256:{h}"))
            })
            .collect();
        entries.sort();
        let mut canonical = String::new();
        for (path, hash) in &entries {
            canonical.push_str(path);
            canonical.push(':');
            canonical.push_str(hash);
            canonical.push('\n');
        }
        let sig = signing.sign(canonical.as_bytes());
        let files_json: serde_json::Map<String, serde_json::Value> = entries
            .into_iter()
            .map(|(p, h)| (p, serde_json::Value::String(h)))
            .collect();
        let manifest = serde_json::json!({
            "version": version,
            "signed_at": "2026-08-04T00:00:00Z",
            "algorithm": "EdDSA",
            "key_id": "test-key",
            "files": files_json,
            "signature": hex::encode(sig.to_bytes()),
            "provenance": {"commit_sha": "test"}
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();

        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = tar::Builder::new(gz);
        for (name, content) in ship_files {
            append_file(&mut tar, name, content);
        }
        append_file(&mut tar, super::MANIFEST_NAME, &manifest_bytes);
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap()
    }

    fn append_file<W: std::io::Write>(tar: &mut tar::Builder<W>, name: &str, content: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, content).unwrap();
    }

    /// Convenience: a fresh signing key for negative tests.
    pub fn fresh_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)
    }

    /// Gzip arbitrary bytes — fixture for parse-failure tests.
    pub fn gzip(data: &[u8]) -> Vec<u8> {
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(data).unwrap();
        gz.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    const SKILL: &[u8] = b"---\nname: rvl-scan\n---\nScan things.\n";

    #[test]
    fn verify_ok_roundtrip() {
        let (tarball, key) = build_signed_tarball(
            "0.2.0",
            &[("rvl-scan/SKILL.md", SKILL), ("AGENTS.md", b"hi")],
        );
        let manifest = verify_tarball(&tarball, &key).expect("verification should pass");
        assert_eq!(manifest.version, "0.2.0");
        assert_eq!(manifest.files.len(), 2);
        let files = extract_tarball(&tarball).unwrap();
        assert_eq!(
            files.get("rvl-scan/SKILL.md").map(|v| v.as_slice()),
            Some(SKILL)
        );
        assert!(files.contains_key(MANIFEST_NAME));
    }

    #[test]
    fn tampered_file_fails_hash_check() {
        let signing = fresh_key();
        let tarball = build_tarball_with_key(
            "0.2.0",
            &[("rvl-scan/SKILL.md", SKILL)],
            &signing,
            &[("rvl-scan/SKILL.md", b"EVIL CONTENT")],
        );
        let err = verify_tarball(&tarball, &signing.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"), "got: {err}");
    }

    #[test]
    fn untracked_file_fails() {
        let signing = fresh_key();
        let tarball = build_tarball_with_key(
            "0.2.0",
            &[("rvl-scan/SKILL.md", SKILL)],
            &signing,
            &[("rvl-scan/SKILL.md", SKILL), ("extra.md", b"sneaky")],
        );
        let err = verify_tarball(&tarball, &signing.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("not tracked"), "got: {err}");
    }

    #[test]
    fn wrong_key_fails_signature() {
        let (tarball, _key) = build_signed_tarball("0.2.0", &[("rvl-scan/SKILL.md", SKILL)]);
        let other = fresh_key().verifying_key();
        let err = verify_tarball(&tarball, &other).unwrap_err();
        assert!(err.to_string().contains("signature"), "got: {err}");
    }

    #[test]
    fn missing_manifest_fails() {
        let signing = fresh_key();
        // A tarball with a payload file but no integrity manifest at all.
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        let mut header = tar::Header::new_gnu();
        header.set_size(SKILL.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "rvl-scan/SKILL.md", SKILL)
            .unwrap();
        let tarball = tar.into_inner().unwrap().finish().unwrap();
        let err = verify_tarball(&tarball, &signing.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("unsigned"), "got: {err}");
    }

    #[test]
    fn garbage_input_fails_cleanly() {
        let key = fresh_key().verifying_key();
        assert!(verify_tarball(b"not a tarball", &key).is_err());
        assert!(verify_tarball(&gzip(b"not a tar"), &key).is_err());
    }

    #[test]
    fn safe_rel_path_rejects_escapes() {
        assert!(safe_rel_path("rvl-scan/SKILL.md").is_ok());
        assert!(safe_rel_path("a/b/c.md").is_ok());
        assert!(safe_rel_path("/etc/passwd").is_err());
        assert!(safe_rel_path("../evil.md").is_err());
        assert!(safe_rel_path("a/../../evil.md").is_err());
        assert!(safe_rel_path("").is_err());
    }
}
