//! Authenticated HTTP client mirroring rvl-cli's `internal/api` package:
//! same headers, same timeouts, same status-code handling, and the same
//! user-facing error messages (401 vs 403 are deliberately distinct; the
//! spec's `{error, message}` envelope is preferred over raw bodies).

use crate::config::DataConfig;
use crate::{Failure, BIN};
use serde::Deserialize;
use std::time::Duration;

/// Default per-request timeout, matching rvl-cli's `MakeAPIRequest`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Client {
    pub api_url: String,
    pub api_key: String,
    /// Resolved org UUID; set when `org_name` resolution ran.
    pub org_id: Option<String>,
}

impl Client {
    /// GET/POST/PATCH with the default 30s timeout. `url` is absolute.
    /// The error string is the exact user-facing message rvl-cli prints.
    pub fn request(&self, method: &str, url: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
        self.request_with_timeout(method, url, body, DEFAULT_TIMEOUT)
    }

    pub fn request_with_timeout(
        &self,
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut req = ureq::request(method, url)
            .timeout(timeout)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {}", self.api_key));
        if let Some(org) = &self.org_id {
            req = req.set("X-Organization-ID", org);
        }
        let result = match body {
            Some(b) => req.send_bytes(b),
            None => req.call(),
        };
        match result {
            Ok(resp) => read_body(resp).map_err(|e| format!("read response body: {e}")),
            Err(ureq::Error::Status(code, resp)) => {
                let body = read_body(resp).unwrap_or_default();
                Err(status_error(code, &body))
            }
            Err(ureq::Error::Transport(t)) => Err(format!("request failed: {t}")),
        }
    }
}

fn read_body(resp: ureq::Response) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut buf)?;
    Ok(buf)
}

/// The user-facing message for a non-2xx status, mirroring rvl-cli's
/// `MakeAPIRequestWithTimeout` (po-l5nfr / po-cj4s7 / po-ug34g).
fn status_error(code: u16, body: &[u8]) -> String {
    match code {
        401 => format!(
            "authentication failed (401) - run '{BIN} login' to reconfigure \
             (API key may be expired or for a different environment)"
        ),
        403 => format!(
            "forbidden (403) - your API key authenticated but lacks access to this \
             resource; check '{BIN} config show' for the active organization, then fix \
             it with '{BIN} config set org_name <name>' or the RVL_ORG_NAME environment \
             variable"
        ),
        _ => match extract_api_error_message(body) {
            Some(msg) => format!("server error ({code}): {msg}"),
            None => format!("server error ({code}): {}", String::from_utf8_lossy(body)),
        },
    }
}

/// Parse the spec's `{error, message}` envelope; `None` when the body is
/// not JSON-shaped or does not carry it.
pub fn extract_api_error_message(body: &[u8]) -> Option<String> {
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        error: String,
        #[serde(default)]
        message: String,
    }
    if body.is_empty() {
        return None;
    }
    let env: Envelope = serde_json::from_slice(body).ok()?;
    match (env.error.is_empty(), env.message.is_empty()) {
        (false, false) => Some(format!("{}: {}", env.error, env.message)),
        (true, false) => Some(env.message),
        (false, true) => Some(env.error),
        (true, true) => None,
    }
}

#[derive(Deserialize)]
struct OrgsResponse {
    #[serde(default)]
    organizations: Vec<Org>,
}

#[derive(Deserialize)]
struct Org {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

/// Resolve an org name to its UUID by listing the caller's orgs, mirroring
/// rvl-cli's `ResolveOrganizationID` (10s timeout, Bearer only).
pub fn resolve_organization_id(cfg: &DataConfig) -> Result<Option<String>, String> {
    if cfg.org_name.is_empty() {
        return Ok(None);
    }
    let url = format!("{}/api/v1/organizations", cfg.api_url);
    let result = ureq::get(&url)
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {}", cfg.api_key))
        .call();
    let resp = match result {
        Ok(r) => r,
        Err(ureq::Error::Status(code, _)) => {
            return Err(format!("fetch organizations failed (status {code})"))
        }
        Err(ureq::Error::Transport(t)) => return Err(format!("fetch organizations: {t}")),
    };
    let body = read_body(resp).map_err(|e| format!("read response body: {e}"))?;
    let orgs: OrgsResponse =
        serde_json::from_slice(&body).map_err(|e| format!("parse organizations: {e}"))?;

    for org in &orgs.organizations {
        if org.name.to_lowercase() == cfg.org_name.to_lowercase() {
            return Ok(Some(org.id.clone()));
        }
    }
    if orgs.organizations.is_empty() {
        return Err(
            "no organizations are accessible with this API key. Your account may not \
             be associated with an organization, or the API key was issued for a \
             different environment. Visit https://app.revelara.ai/settings/api-keys \
             to reconfigure, or contact support@revelara.ai"
                .to_string(),
        );
    }
    let names: Vec<&str> = orgs.organizations.iter().map(|o| o.name.as_str()).collect();
    Err(format!(
        "organization \"{}\" not found; available: {}",
        cfg.org_name,
        names.join(", ")
    ))
}

/// Check credentials against a cheap endpoint, mirroring rvl-cli's
/// `ValidateCredentials`.
pub fn validate_credentials(client: &Client) -> Result<(), String> {
    let url = format!("{}/api/v1/risks/stats", client.api_url);
    let mut req = ureq::get(&url)
        .timeout(Duration::from_secs(10))
        .set("Authorization", &format!("Bearer {}", client.api_key));
    if let Some(org) = &client.org_id {
        req = req.set("X-Organization-ID", org);
    }
    match req.call() {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(code @ (401 | 403), _)) => {
            Err(format!("authentication failed (status {code})"))
        }
        Err(ureq::Error::Status(code, _)) => Err(format!("server error (status {code})")),
        Err(ureq::Error::Transport(t)) => Err(format!("connection failed: {t}")),
    }
}

/// The org's known team slugs from `GET /api/v1/teams/slugs` (po-77b6w.1),
/// consumed by the pre-submit did-you-mean. Best-effort by design: `None` on
/// any failure (unreachable server, old server without the endpoint, auth
/// problem) so callers skip the check instead of blocking a submission —
/// agents must be able to run headless. `None` means "unknown", `Some(vec![])`
/// means "the org has no teams yet".
pub fn fetch_team_slugs(client: &Client) -> Option<Vec<String>> {
    if client.api_key.is_empty() || client.api_url.is_empty() {
        return None;
    }
    let url = format!("{}/api/v1/teams/slugs", client.api_url);
    let mut req = ureq::get(&url)
        .timeout(Duration::from_secs(5))
        .set("Authorization", &format!("Bearer {}", client.api_key));
    if let Some(org) = &client.org_id {
        req = req.set("X-Organization-ID", org);
    }
    let body = read_body(req.call().ok()?).ok()?;

    #[derive(Deserialize)]
    struct SlugsResponse {
        #[serde(default)]
        slugs: Option<Vec<String>>,
    }
    let parsed: SlugsResponse = serde_json::from_slice(&body).ok()?;
    Some(parsed.slugs.unwrap_or_default())
}

/// Load config and resolve the org, mirroring `api.LoadAndResolveConfig`:
/// every failure is a printed message + exit 1.
pub fn load_and_resolve() -> Result<(DataConfig, Client), Failure> {
    let cfg = match crate::config::load() {
        Ok(c) => c,
        Err(e) => return Err(Failure::runtime(format!("Error loading config: {e}"))),
    };
    let Some(cfg) = cfg else {
        return Err(Failure::runtime(format!(
            "Error: Not configured. Run '{BIN} login' first, or set RVL_API_KEY for \
             headless/CI use."
        )));
    };
    let org_id = match resolve_organization_id(&cfg) {
        Ok(id) => id,
        Err(e) => return Err(Failure::runtime(format!("Error: {e}"))),
    };
    let client = Client {
        api_url: cfg.api_url.clone(),
        api_key: cfg.api_key.clone(),
        org_id,
    };
    Ok((cfg, client))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_prefers_code_and_message() {
        assert_eq!(
            extract_api_error_message(br#"{"error":"not_found","message":"risk missing"}"#),
            Some("not_found: risk missing".to_string())
        );
        assert_eq!(
            extract_api_error_message(br#"{"message":"just text"}"#),
            Some("just text".to_string())
        );
        assert_eq!(
            extract_api_error_message(br#"{"error":"boom"}"#),
            Some("boom".to_string())
        );
        assert_eq!(extract_api_error_message(br#"{}"#), None);
        assert_eq!(extract_api_error_message(b"not json"), None);
        assert_eq!(extract_api_error_message(b""), None);
    }

    #[test]
    fn status_errors_distinguish_401_and_403() {
        let e401 = status_error(401, b"");
        assert!(e401.contains("authentication failed (401)"));
        assert!(e401.contains("login"));
        let e403 = status_error(403, b"");
        assert!(e403.contains("forbidden (403)"));
        assert!(e403.contains("RVL_ORG_NAME"));
        let e500 = status_error(500, br#"{"error":"db","message":"down"}"#);
        assert_eq!(e500, "server error (500): db: down");
        let e422 = status_error(422, b"plain body");
        assert_eq!(e422, "server error (422): plain body");
    }
}
