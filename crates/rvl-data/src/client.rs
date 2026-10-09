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
        let auth = format!("Bearer {}", self.api_key);
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Authorization", auth.as_str()),
        ];
        if let Some(org) = &self.org_id {
            headers.push(("X-Organization-ID", org));
        }
        match send(method, url, &headers, body, timeout) {
            Ok(resp) if is_error_status(&resp) => {
                let code = resp.status().as_u16();
                let body = read_body(resp).unwrap_or_default();
                Err(status_error(code, &body))
            }
            Ok(resp) => read_body(resp).map_err(|e| format!("read response body: {e}")),
            Err(e) => Err(format!("request failed: {e}")),
        }
    }
}

pub(crate) type Response = ureq::http::Response<ureq::Body>;

/// A transport failure: the request got no HTTP response. The message
/// starts with the URL, because the ureq error does not name it.
#[derive(Debug)]
pub(crate) struct TransportError {
    url: String,
    source: ureq::Error,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.url, self.source)
    }
}

/// The agent for one call. Each setting holds a behavior the callers were
/// written against, where the ureq 3 default is different (po-av01j.236):
/// - `http_status_as_error(false)`: a 4xx/5xx comes back as a response, so
///   its body and headers stay readable. The ureq 3 status error drops them.
///   Callers must check [`is_error_status`].
/// - `proxy(None)`: ureq 3 reads the proxy variables from the environment
///   by default. This client never did.
/// - `max_redirects(5)`: the ureq 2 limit.
///
/// The agent is not shared, so no connection is used again for a later call.
fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .proxy(None)
        .max_redirects(5)
        .build()
        .into()
}

/// Send one request and return the response for ANY status. `timeout` is
/// the limit for the full call, the read of the body included.
pub(crate) fn send(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<Response, TransportError> {
    let mut req = ureq::http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        req = req.header(*name, *value);
    }
    let agent = agent(timeout);
    // A POST, PUT or PATCH with no body goes out as an empty body of a known
    // length (`Content-Length: 0`, as Go's net/http sends it). With `()`,
    // ureq 3 sends such a request as `Transfer-Encoding: chunked`.
    let body = match body {
        None if matches!(method, "POST" | "PUT" | "PATCH") => Some(&[][..]),
        other => other,
    };
    let result = match body {
        Some(b) => req
            .body(b)
            .map_err(ureq::Error::from)
            .and_then(|r| agent.run(r)),
        None => req
            .body(())
            .map_err(ureq::Error::from)
            .and_then(|r| agent.run(r)),
    };
    result.map_err(|source| TransportError {
        url: url.to_string(),
        source,
    })
}

/// 4xx and 5xx, the statuses ureq 2 gave back as `Error::Status`.
pub(crate) fn is_error_status(resp: &Response) -> bool {
    resp.status().as_u16() >= 400
}

/// The full body, with no size limit.
pub(crate) fn read_body(resp: Response) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_body().into_reader(), &mut buf)?;
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
    let auth = format!("Bearer {}", cfg.api_key);
    let resp = match send(
        "GET",
        &url,
        &[("Authorization", &auth)],
        None,
        Duration::from_secs(10),
    ) {
        Ok(r) if is_error_status(&r) => {
            return Err(format!(
                "fetch organizations failed (status {})",
                r.status().as_u16()
            ))
        }
        Ok(r) => r,
        Err(e) => return Err(format!("fetch organizations: {e}")),
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
    let auth = format!("Bearer {}", client.api_key);
    let mut headers = vec![("Authorization", auth.as_str())];
    if let Some(org) = &client.org_id {
        headers.push(("X-Organization-ID", org));
    }
    match send("GET", &url, &headers, None, Duration::from_secs(10)) {
        Ok(resp) => match resp.status().as_u16() {
            code @ (401 | 403) => Err(format!("authentication failed (status {code})")),
            code if code >= 400 => Err(format!("server error (status {code})")),
            _ => Ok(()),
        },
        Err(e) => Err(format!("connection failed: {e}")),
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
    let auth = format!("Bearer {}", client.api_key);
    let mut headers = vec![("Authorization", auth.as_str())];
    if let Some(org) = &client.org_id {
        headers.push(("X-Organization-ID", org));
    }
    let resp = send("GET", &url, &headers, None, Duration::from_secs(5)).ok()?;
    if is_error_status(&resp) {
        return None;
    }
    let body = read_body(resp).ok()?;

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
