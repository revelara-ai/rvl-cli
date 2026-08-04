//! Backend fetch surface for plugin content. GET-only by construction: the
//! trait exposes exactly three read operations against the same endpoints
//! rvl-cli's plugin flow uses, and nothing here can upload anything —
//! that is the privacy stance of this whole surface, enforced by the type.
//!
//! Endpoints (auth: `Authorization: Bearer <org key>` where noted):
//! - `GET /api/v1/plugin`                     -> {version, semver} (auth)
//! - `GET /api/v1/plugin/download?editor=..`  -> tar.gz + X-Plugin-SemVer +
//!   X-Checksum headers (auth)
//! - `GET /api/v1/plugin/signing-key`         -> {algorithm, public_key}

use crate::semver::semver_base;
use serde::Deserialize;

/// A downloaded plugin tarball plus its wire metadata.
pub struct TarballDownload {
    pub bytes: Vec<u8>,
    /// Content semver (X-Plugin-SemVer, base portion).
    pub version: String,
    /// "sha256:<hex>" transport checksum (X-Checksum), when the server
    /// sent one.
    pub checksum: Option<String>,
}

/// Read access to the backend plugin system. HTTP in production, in-memory
/// in tests. Implementations must not perform any non-GET request.
pub trait Fetcher {
    /// The served plugin content semver.
    fn fetch_version(&self) -> anyhow::Result<String>;
    /// The Ed25519 signing key (32 bytes). Err covers "unavailable" too:
    /// the caller decides fail-closed policy.
    fn fetch_signing_key(&self) -> anyhow::Result<[u8; 32]>;
    /// The plugin tarball in `editor` layout.
    fn fetch_tarball(&self, editor: &str) -> anyhow::Result<TarballDownload>;
}

#[derive(Deserialize)]
struct VersionResponse {
    #[serde(default)]
    version: String,
    #[serde(default)]
    semver: String,
}

/// Pick the served semver out of the `GET /api/v1/plugin` response body:
/// prefer the dedicated `semver` field (new servers), fall back to the
/// full version with build metadata stripped (old servers).
pub fn parse_version_response(body: &[u8]) -> anyhow::Result<String> {
    let resp: VersionResponse = serde_json::from_slice(body)?;
    let v = if !resp.semver.is_empty() {
        resp.semver
    } else {
        semver_base(&resp.version).to_string()
    };
    anyhow::ensure!(!v.is_empty(), "plugin version response had no version");
    Ok(v)
}

#[derive(Deserialize)]
struct SigningKeyResponse {
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    public_key: String,
}

/// Parse the signing-key response; only EdDSA/32-byte keys are accepted.
pub fn parse_signing_key_response(body: &[u8]) -> anyhow::Result<[u8; 32]> {
    let resp: SigningKeyResponse = serde_json::from_slice(body)?;
    anyhow::ensure!(
        resp.algorithm == "EdDSA" && !resp.public_key.is_empty(),
        "signing key response missing algorithm or public_key"
    );
    hex::decode(&resp.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key has wrong length (want 32 bytes)"))
}

/// HTTP fetcher against the Revelara API, sharing base URL + org key with
/// the spec-cache fetcher's config resolution.
pub struct HttpFetcher {
    pub base_url: String,
    pub org_key: String,
}

impl HttpFetcher {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url.trim_end_matches('/'))
    }
    fn auth(&self) -> String {
        format!("Bearer {}", self.org_key)
    }
}

impl Fetcher for HttpFetcher {
    fn fetch_version(&self) -> anyhow::Result<String> {
        let resp = ureq::get(&self.url("/api/v1/plugin"))
            .set("Authorization", &self.auth())
            .call()?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut body)?;
        parse_version_response(&body)
    }

    fn fetch_signing_key(&self) -> anyhow::Result<[u8; 32]> {
        // Public endpoint; no auth header needed (the key is not secret).
        let resp = ureq::get(&self.url("/api/v1/plugin/signing-key")).call()?;
        let mut body = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut body)?;
        parse_signing_key_response(&body)
    }

    fn fetch_tarball(&self, editor: &str) -> anyhow::Result<TarballDownload> {
        let url = format!("{}?editor={editor}", self.url("/api/v1/plugin/download"));
        let resp = ureq::get(&url).set("Authorization", &self.auth()).call()?;
        let version = resp
            .header("X-Plugin-SemVer")
            .or_else(|| resp.header("X-Plugin-Version"))
            .map(|v| semver_base(v).to_string())
            .unwrap_or_default();
        let checksum = resp.header("X-Checksum").map(str::to_string);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut bytes)?;
        anyhow::ensure!(!bytes.is_empty(), "empty plugin tarball from server");
        anyhow::ensure!(
            !version.is_empty(),
            "server did not send X-Plugin-SemVer/X-Plugin-Version"
        );
        Ok(TarballDownload {
            bytes,
            version,
            checksum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_response_prefers_semver_field() {
        let v = parse_version_response(br#"{"version":"0.2.0+abc","semver":"0.2.0"}"#).unwrap();
        assert_eq!(v, "0.2.0");
        // Old servers: no semver field, strip build metadata.
        let v = parse_version_response(br#"{"version":"0.2.0+abc"}"#).unwrap();
        assert_eq!(v, "0.2.0");
        assert!(parse_version_response(br#"{}"#).is_err());
    }

    #[test]
    fn signing_key_response_is_strict() {
        let key_hex = "ab".repeat(32);
        let body = format!(r#"{{"algorithm":"EdDSA","public_key":"{key_hex}"}}"#);
        assert_eq!(
            parse_signing_key_response(body.as_bytes()).unwrap(),
            [0xabu8; 32]
        );
        // Wrong algorithm, missing key, wrong length: all rejected.
        let bad = format!(r#"{{"algorithm":"RSA","public_key":"{key_hex}"}}"#);
        assert!(parse_signing_key_response(bad.as_bytes()).is_err());
        assert!(parse_signing_key_response(br#"{"algorithm":"EdDSA"}"#).is_err());
        assert!(
            parse_signing_key_response(br#"{"algorithm":"EdDSA","public_key":"abcd"}"#).is_err()
        );
    }
}
