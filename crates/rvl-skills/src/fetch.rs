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
//! - `GET /api/v1/plugin/editors`             -> [{name, displayName, tier}]

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
    /// The supported editor targets (`GET /api/v1/plugin/editors`).
    fn fetch_editors(&self) -> anyhow::Result<Vec<EditorInfo>>;
}

/// One supported editor target, as served by `GET /api/v1/plugin/editors`.
#[derive(Debug, Clone, Deserialize)]
pub struct EditorInfo {
    /// Stable identifier, also the `?editor=` query parameter.
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "displayName")]
    pub display_name: String,
    /// Tier ordinal the server uses to gate editor availability.
    #[serde(default)]
    pub tier: i64,
}

/// Parse the `GET /api/v1/plugin/editors` response (a bare JSON array).
pub fn parse_editors_response(body: &[u8]) -> anyhow::Result<Vec<EditorInfo>> {
    let editors: Vec<EditorInfo> = serde_json::from_slice(body)?;
    anyhow::ensure!(!editors.is_empty(), "editors response listed no editors");
    Ok(editors)
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
    /// The cache scope of this server + org key; see
    /// [`crate::store::cache_scope`].
    pub fn cache_scope(&self) -> Option<String> {
        crate::store::cache_scope(&self.base_url, &self.org_key)
    }
}

/// The agent for one request. Each setting holds a behavior this fetcher was
/// written against, where the ureq 3 default is different (po-av01j.236):
/// a 30 s connect timeout (ureq 3 has none), `proxy(None)` because ureq 3
/// reads the proxy variables from the environment by default, and
/// `max_redirects(5)`, the ureq 2 limit. A 4xx/5xx stays an error.
fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(std::time::Duration::from_secs(30)))
        .proxy(None)
        .max_redirects(5)
        .build()
        .into()
}

type Response = ureq::http::Response<ureq::Body>;

/// The full body, with no size limit (a plugin tarball can be large).
fn read_body(resp: Response) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_body().into_reader(), &mut body)?;
    Ok(body)
}

fn header<'a>(resp: &'a Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

impl Fetcher for HttpFetcher {
    fn fetch_version(&self) -> anyhow::Result<String> {
        let resp = http_agent()
            .get(self.url("/api/v1/plugin"))
            .header("Authorization", self.auth())
            .call()?;
        parse_version_response(&read_body(resp)?)
    }

    fn fetch_signing_key(&self) -> anyhow::Result<[u8; 32]> {
        // Public endpoint; no auth header needed (the key is not secret).
        let resp = http_agent()
            .get(self.url("/api/v1/plugin/signing-key"))
            .call()?;
        parse_signing_key_response(&read_body(resp)?)
    }

    fn fetch_tarball(&self, editor: &str) -> anyhow::Result<TarballDownload> {
        let url = format!("{}?editor={editor}", self.url("/api/v1/plugin/download"));
        let resp = http_agent()
            .get(&url)
            .header("Authorization", self.auth())
            .call()?;
        let version = header(&resp, "X-Plugin-SemVer")
            .or_else(|| header(&resp, "X-Plugin-Version"))
            .map(|v| semver_base(v).to_string())
            .unwrap_or_default();
        let checksum = header(&resp, "X-Checksum").map(str::to_string);
        let bytes = read_body(resp)?;
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

    fn fetch_editors(&self) -> anyhow::Result<Vec<EditorInfo>> {
        // Public endpoint; no auth header needed (the list is not secret).
        let resp = http_agent()
            .get(self.url("/api/v1/plugin/editors"))
            .call()?;
        parse_editors_response(&read_body(resp)?)
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
    fn editors_response_parses_wire_field_names() {
        let body = br#"[{"name":"claude","displayName":"Claude Code","tier":1},
                        {"name":"codex","displayName":"OpenAI Codex","tier":2}]"#;
        let editors = parse_editors_response(body).unwrap();
        assert_eq!(editors.len(), 2);
        assert_eq!(editors[0].name, "claude");
        assert_eq!(editors[0].display_name, "Claude Code");
        assert_eq!(editors[0].tier, 1);
        // Empty and malformed bodies are rejected.
        assert!(parse_editors_response(b"[]").is_err());
        assert!(parse_editors_response(b"not json").is_err());
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
