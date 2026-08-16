//! Slice (b): `evidence submit` / `list` / `verify`, ported from rvl-cli
//! `internal/commands/evidence.go`. All three JSON modes print the server
//! body verbatim; the submit request body mirrors Go's sorted-key
//! `map[string]string` marshal byte-for-byte.

use crate::client::Client;
use crate::control;
use crate::display;
use crate::gojson::{compact, query_encode, G};
use crate::{CmdResult, Failure, BIN};
use rvl_core::flag::{absent_if_empty, EmptyFlag};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum EvidenceCmd {
    /// Submit evidence for a control
    Submit {
        /// Control code (e.g., RC-018)
        #[arg(long)]
        control: Option<String>,
        /// Evidence type (code, test, dashboard, document, configuration, runbook, other)
        #[arg(long = "type")]
        evidence_type: Option<String>,
        /// Evidence name
        #[arg(long)]
        name: Option<String>,
        /// URL or identifier (optional)
        #[arg(long)]
        url: Option<String>,
        /// Description (optional)
        #[arg(long)]
        description: Option<String>,
        /// Git commit hash (auto-detected if not provided)
        #[arg(long)]
        git_hash: Option<String>,
        /// Team slug the evidence is scoped to (who exercises the practice)
        #[arg(long)]
        team: Option<String>,
        /// Service name the evidence covers; combinable with --team (AND).
        /// Without --team/--service the evidence lands org-wide (global)
        #[arg(long)]
        service: Option<String>,
        /// Output raw JSON response
        #[arg(long)]
        format: Option<String>,
    },
    /// List evidence records
    List {
        /// Filter by control code
        #[arg(long)]
        control: Option<String>,
        /// Filter by evidence type
        #[arg(long = "type")]
        evidence_type: Option<String>,
        /// Filter by status (not_configured, configured, sample, verified)
        #[arg(long)]
        status: Option<String>,
        /// Filter to evidence scoped to this team
        #[arg(long)]
        team: Option<String>,
        /// Filter to evidence covering this service
        #[arg(long)]
        service: Option<String>,
        /// Filter by scope state (team, service, global, unknown)
        #[arg(long = "scope-state")]
        scope_state: Option<String>,
        /// Max records (default: 20)
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Output raw JSON response
        #[arg(long)]
        format: Option<String>,
    },
    /// Verify evidence
    Verify {
        /// Evidence ID
        id: String,
        /// Output raw JSON response
        #[arg(long)]
        format: Option<String>,
    },
}

#[derive(Debug, Default, Deserialize)]
pub struct EvidenceItem {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub evidence_type: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub url_or_identifier: String,
    #[serde(default)]
    pub git_hash: Option<String>,
    #[serde(default)]
    pub status: String,
    /// Evidence scope (team | service | global | unknown). An EMPTY string
    /// means an older server that predates scoping — rendered as nothing,
    /// which is deliberately distinct from `unknown` (a grandfathered row
    /// the server knows about but cannot attribute).
    #[serde(default)]
    pub scope_state: String,
    #[serde(default)]
    pub team_slug: Option<String>,
    #[serde(default)]
    pub service_name: Option<String>,
}

/// Whether `s` is a known evidence scope state (mirrors the server's
/// `EvidenceScopeState` enum).
pub fn valid_scope_state(s: &str) -> bool {
    matches!(s, "team" | "service" | "global" | "unknown")
}

/// Renders an evidence record's scope for text output. Global scope (the
/// default) and pre-scoping servers (empty `scope_state`) render nothing;
/// grandfathered `unknown` rows are flagged for re-scoping.
pub fn evidence_scope_label(e: &EvidenceItem) -> String {
    match e.scope_state.as_str() {
        "unknown" => "unknown scope (needs re-scoping)".to_string(),
        "team" | "service" => {
            let mut parts: Vec<String> = Vec::new();
            if let Some(t) = e.team_slug.as_deref() {
                if !t.is_empty() {
                    parts.push(format!("team={t}"));
                }
            }
            if let Some(s) = e.service_name.as_deref() {
                if !s.is_empty() {
                    parts.push(format!("service={s}"));
                }
            }
            parts.join(" ")
        }
        _ => String::new(),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ListEvidenceResponse {
    #[serde(default)]
    evidence: Vec<EvidenceItem>,
    #[serde(default)]
    total: i64,
}

pub fn run(cmd: EvidenceCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            EvidenceCmd::Submit {
                control,
                evidence_type,
                name,
                url,
                description,
                git_hash,
                team,
                service,
                format,
            } => {
                // EMPTY-FLAG SEMANTICS (po-av01j.192), read off evidence.go:
                //  * --control/--type/--name: :142/:146/:150 reject an empty
                //    value with "is required" (exit 2) — `require` below
                //    already treats Some("") as missing, so `--control=` and
                //    `--control ''` both fail exactly as in Go.
                //  * --url/--description: :197/:198 put both keys in the POST
                //    body unconditionally, so an empty value is TRANSMITTED.
                //  * --git-hash: :136 re-runs `git rev-parse HEAD` when the
                //    value is empty, i.e. empty == omitted.
                //  * --format: :129 guards ValidateFormat with `!= ""`.
                let format = absent_if_empty(format);
                validate_format(&format)?;
                let control = require(control, "--control is required (e.g., --control=RC-018)")?;
                let evidence_type = require(
                    evidence_type,
                    "--type is required (code, test, dashboard, document, configuration, runbook, other)",
                )?;
                let name = require(name, "--name is required")?;
                check_not_risk_code(&control)?;
                let git_hash = absent_if_empty(git_hash)
                    .or_else(detect_git_hash)
                    .unwrap_or_default();
                let (_, client) = crate::client::load_and_resolve()?;
                submit_output(
                    &client,
                    &control,
                    &evidence_type,
                    &name,
                    url.empty_is_value().unwrap_or(""),
                    description.empty_is_value().unwrap_or(""),
                    &git_hash,
                    team.empty_is_absent().unwrap_or(""),
                    service.empty_is_absent().unwrap_or(""),
                    format.empty_is_absent(),
                )
            }
            EvidenceCmd::List {
                control,
                evidence_type,
                status,
                team,
                service,
                scope_state,
                limit,
                format,
            } => {
                // evidence.go:304/:298/:283 guard --control/--type/--status
                // with `!= ""`, and the `--status=` guard skips the enum
                // check as well, so an empty filter is no filter at all.
                // --team/--service/--scope-state are rvl-native filters and
                // follow the same rule. `--limit=` errors in clap's typed
                // parse, as Atoi("") does at evidence.go:258.
                let control = absent_if_empty(control);
                let evidence_type = absent_if_empty(evidence_type);
                let status = absent_if_empty(status);
                let team = absent_if_empty(team);
                let service = absent_if_empty(service);
                let scope_state = absent_if_empty(scope_state);
                let format = absent_if_empty(format);
                validate_format(&format)?;
                validate_status(&status)?;
                validate_scope_state(&scope_state)?;
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(
                    &client,
                    control.as_deref(),
                    evidence_type.as_deref(),
                    status.as_deref(),
                    team.as_deref(),
                    service.as_deref(),
                    scope_state.as_deref(),
                    limit,
                    format.as_deref(),
                )
            }
            EvidenceCmd::Verify { id, format } => {
                // evidence.go:381, the same guarded validator.
                let format = absent_if_empty(format);
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                verify_output(&client, &id, format.empty_is_absent())
            }
        }
    })();
    crate::finish(res)
}

fn require(v: Option<String>, msg: &str) -> Result<String, Failure> {
    match v {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(Failure::usage(format!("Error: {msg}"))),
    }
}

/// rvl-cli validates evidence --format as json-only (po-i24do.11).
fn validate_format(format: &Option<String>) -> Result<(), Failure> {
    match format.as_deref() {
        None | Some("json") => Ok(()),
        Some(f) => Err(Failure::usage(format!(
            "Error: invalid --format \"{f}\" (valid: json)"
        ))),
    }
}

fn validate_status(status: &Option<String>) -> Result<(), Failure> {
    match status.as_deref() {
        None | Some("not_configured") | Some("configured") | Some("sample") | Some("verified") => {
            Ok(())
        }
        Some(s) => Err(Failure::usage(format!(
            "Error: invalid --status value \"{s}\"; must be one of: not_configured, configured, sample, verified"
        ))),
    }
}

/// `--scope-state` is validated client-side against the server enum.
fn validate_scope_state(scope_state: &Option<String>) -> Result<(), Failure> {
    match scope_state.as_deref() {
        None => Ok(()),
        Some(s) if valid_scope_state(s) => Ok(()),
        Some(s) => Err(Failure::usage(format!(
            "Error: invalid --scope-state value \"{s}\"; must be one of: team, service, global, unknown"
        ))),
    }
}

fn check_not_risk_code(code: &str) -> Result<(), Failure> {
    if code.starts_with("R-") && !code.starts_with("RC-") {
        return Err(Failure::usage(format!(
            "Note: \"{code}\" is a risk code, not a control code (RC-XXX).\n\
             Evidence is submitted per control. Use \"{BIN} risk show {code}\" to find mapped controls."
        )));
    }
    Ok(())
}

fn detect_git_hash() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!hash.is_empty()).then_some(hash)
}

/// The POST /api/v1/evidence body: byte-identical to Go's sorted-key
/// `map[string]string` marshal (git_hash only when present).
///
/// `team`/`service` are only sent when set, so unscoped submissions keep
/// working against older servers that predate scoping. They are combinable
/// (AND): team = who exercises the practice, service = what it covers;
/// neither means org-wide (global) evidence.
#[allow(clippy::too_many_arguments)]
pub fn submit_body(
    control_id: &str,
    evidence_type: &str,
    name: &str,
    url: &str,
    description: &str,
    git_hash: &str,
    team: &str,
    service: &str,
) -> String {
    let mut fields = vec![
        ("control_id".to_string(), G::Str(control_id.into())),
        ("description".to_string(), G::Str(description.into())),
    ];
    if !git_hash.is_empty() {
        fields.push(("git_hash".to_string(), G::Str(git_hash.into())));
    }
    fields.push(("name".to_string(), G::Str(name.into())));
    if !service.is_empty() {
        fields.push(("service".to_string(), G::Str(service.into())));
    }
    if !team.is_empty() {
        fields.push(("team".to_string(), G::Str(team.into())));
    }
    fields.push(("type".to_string(), G::Str(evidence_type.into())));
    fields.push(("url_or_identifier".to_string(), G::Str(url.into())));
    // Fields are constructed pre-sorted (Go map marshal sorts keys).
    compact(&G::Obj(fields))
}

#[allow(clippy::too_many_arguments)]
pub fn submit_output(
    client: &Client,
    control_code: &str,
    evidence_type: &str,
    name: &str,
    url: &str,
    description: &str,
    git_hash: &str,
    team: &str,
    service: &str,
    format: Option<&str>,
) -> CmdResult {
    let control = control::fetch_control_by_code(client, control_code)?;

    if !control.expected_evidence_types.is_empty()
        && !control
            .expected_evidence_types
            .iter()
            .any(|et| et == evidence_type)
    {
        eprintln!(
            "Note: {control_code} expects evidence types: {} (submitting \"{evidence_type}\" anyway)",
            control.expected_evidence_types.join(", ")
        );
    }

    let body = submit_body(
        &control.id,
        evidence_type,
        name,
        url,
        description,
        git_hash,
        team,
        service,
    );
    let api_url = format!("{}/api/v1/evidence", client.api_url);
    // An unknown --team/--service is a 400 whose message lists the org's
    // known slugs/services; it passes through verbatim.
    let resp = client
        .request("POST", &api_url, Some(body.as_bytes()))
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    let evidence: EvidenceItem = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let mut out = String::new();
    let _ = writeln!(out, "Evidence submitted successfully.");
    let _ = writeln!(out, "  ID:      {}", evidence.id);
    let _ = writeln!(out, "  Control: {control_code} ({})", control.name);
    let _ = writeln!(out, "  Type:    {}", evidence.evidence_type);
    let _ = writeln!(out, "  Name:    {}", evidence.name);
    let _ = writeln!(out, "  Status:  {}", evidence.status);
    let scope = evidence_scope_label(&evidence);
    if !scope.is_empty() {
        let _ = writeln!(out, "  Scope:   {scope}");
    } else if evidence.scope_state == "global" {
        let _ = writeln!(out, "  Scope:   org-wide (global)");
    }
    if !url.is_empty() {
        let _ = writeln!(out, "  URL:     {url}");
    }
    if let Some(h) = &evidence.git_hash {
        if !h.is_empty() {
            let _ = writeln!(out, "  Commit:  {h}");
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub fn list_output(
    client: &Client,
    control: Option<&str>,
    evidence_type: Option<&str>,
    status: Option<&str>,
    team: Option<&str>,
    service: Option<&str>,
    scope_state: Option<&str>,
    limit: u32,
    format: Option<&str>,
) -> CmdResult {
    let control_id = match control {
        Some(code) => Some(
            control::find_control_id_by_code(client, code)
                .map_err(|e| Failure::runtime(format!("Error: {e}")))?,
        ),
        None => None,
    };
    let url = list_url(
        &client.api_url,
        limit,
        evidence_type,
        status,
        control_id.as_deref(),
        team,
        service,
        scope_state,
    );

    // An unknown --team/--service is a 400 whose message lists the org's
    // known slugs/services; it passes through verbatim.
    let resp = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let list: ListEvidenceResponse = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let mut out = String::new();
    if list.evidence.is_empty() {
        let _ = writeln!(out, "No evidence found.");
        return Ok(out);
    }
    let _ = writeln!(out, "Found {} evidence records:\n", list.total);
    for e in &list.evidence {
        let commit = match &e.git_hash {
            Some(h) if !h.is_empty() => {
                format!(" @ {}", display::cut_at_boundary(h, 8))
            }
            _ => String::new(),
        };
        let id = if e.id.len() > 8 {
            format!("{}...", display::cut_at_boundary(&e.id, 8))
        } else {
            e.id.clone()
        };
        let _ = writeln!(
            out,
            "  {id} {} [{}] {}{commit}",
            display::format_evidence_status(&e.status),
            e.evidence_type,
            e.name
        );
        let scope = evidence_scope_label(e);
        if !scope.is_empty() {
            let _ = writeln!(out, "    Scope: {scope}");
        }
        if !e.url_or_identifier.is_empty() {
            let _ = writeln!(out, "    URL: {}", e.url_or_identifier);
        }
    }
    Ok(out)
}

/// The GET /api/v1/evidence query. `url.Values`-encoded (sorted keys,
/// escaped values) so service names with spaces — or a stray `&`/`%` —
/// cannot smuggle extra params.
#[allow(clippy::too_many_arguments)]
pub fn list_url(
    base: &str,
    limit: u32,
    evidence_type: Option<&str>,
    status: Option<&str>,
    control_id: Option<&str>,
    team: Option<&str>,
    service: Option<&str>,
    scope_state: Option<&str>,
) -> String {
    let mut pairs = vec![("limit", limit.to_string())];
    let mut push = |key: &'static str, val: Option<&str>| {
        if let Some(v) = val {
            if !v.is_empty() {
                pairs.push((key, v.to_string()));
            }
        }
    };
    push("type", evidence_type);
    push("status", status);
    push("control_id", control_id);
    push("team", team);
    push("service", service);
    push("scope_state", scope_state);
    format!("{base}/api/v1/evidence?{}", query_encode(&pairs))
}

pub fn verify_output(client: &Client, id: &str, format: Option<&str>) -> CmdResult {
    let url = format!("{}/api/v1/evidence/{id}/verify", client.api_url);
    let resp = client
        .request("POST", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&resp)));
    }

    let evidence: EvidenceItem = serde_json::from_slice(&resp)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    let mut out = String::new();
    let _ = writeln!(out, "Evidence {id} verified.");
    let _ = writeln!(out, "  Name:   {}", evidence.name);
    let _ = writeln!(out, "  Status: {}", evidence.status);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_body_matches_go_map_marshal() {
        // Go marshals map[string]string with sorted keys; git_hash only
        // when set.
        // Go HTML-escapes & inside JSON strings (SetEscapeHTML default).
        assert_eq!(
            submit_body(
                "uuid-1",
                "code",
                "CB impl",
                "https://x",
                "desc & more",
                "abc123",
                "",
                ""
            ),
            r#"{"control_id":"uuid-1","description":"desc \u0026 more","git_hash":"abc123","name":"CB impl","type":"code","url_or_identifier":"https://x"}"#
        );
        assert_eq!(
            submit_body("uuid-1", "code", "n", "", "", "", "", ""),
            r#"{"control_id":"uuid-1","description":"","name":"n","type":"code","url_or_identifier":""}"#
        );
    }

    #[test]
    fn submit_body_carries_scope_flags() {
        // team/service are combinable (AND) and sort between name and type.
        assert_eq!(
            submit_body(
                "cid",
                "code",
                "n",
                "u",
                "d",
                "abc123",
                "platform",
                "shared-postgres"
            ),
            r#"{"control_id":"cid","description":"d","git_hash":"abc123","name":"n","service":"shared-postgres","team":"platform","type":"code","url_or_identifier":"u"}"#
        );
        // Team only.
        let body = submit_body("cid", "code", "n", "u", "d", "abc123", "payments", "");
        assert!(body.contains(r#""team":"payments""#), "{body}");
        assert!(!body.contains(r#""service""#), "{body}");
        // Service only.
        let body = submit_body("cid", "code", "n", "u", "d", "abc123", "", "checkout-api");
        assert!(body.contains(r#""service":"checkout-api""#), "{body}");
        assert!(!body.contains(r#""team""#), "{body}");
        // Neither: no scope keys at all (org-wide/global).
        let body = submit_body("cid", "code", "n", "u", "d", "abc123", "", "");
        assert!(!body.contains("team"), "{body}");
        assert!(!body.contains("service"), "{body}");
        // Base fields always survive.
        assert!(body.contains(r#""control_id":"cid""#), "{body}");
        assert!(body.contains(r#""git_hash":"abc123""#), "{body}");
    }

    #[test]
    fn list_url_encodes_scope_filters() {
        let url = list_url(
            "https://api.example.com",
            20,
            Some("code"),
            Some("verified"),
            Some("cid-1"),
            Some("payments"),
            Some("checkout api"),
            Some("team"),
        );
        for want in [
            "limit=20",
            "type=code",
            "status=verified",
            "control_id=cid-1",
            "team=payments",
            "service=checkout+api",
            "scope_state=team",
        ] {
            assert!(url.contains(want), "url {url} missing {want}");
        }
    }

    #[test]
    fn list_url_omits_empty_scope_filters() {
        let url = list_url(
            "https://api.example.com",
            20,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(url, "https://api.example.com/api/v1/evidence?limit=20");
        for absent in ["team=", "service=", "scope_state="] {
            assert!(!url.contains(absent), "url {url} must not contain {absent}");
        }
    }

    #[test]
    fn scope_state_enum_matches_the_server() {
        for ok in ["team", "service", "global", "unknown"] {
            assert!(valid_scope_state(ok), "{ok} should be valid");
        }
        for bad in ["", "org", "TEAM", "all"] {
            assert!(!valid_scope_state(bad), "{bad} should be invalid");
        }
        let f = validate_scope_state(&Some("org".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: invalid --scope-state value \"org\"; must be one of: team, service, global, unknown"
        );
        assert!(validate_scope_state(&None).is_ok());
        assert!(validate_scope_state(&Some("unknown".into())).is_ok());
    }

    #[test]
    fn scope_label_distinguishes_empty_from_unknown() {
        let item = |state: &str, team: Option<&str>, svc: Option<&str>| EvidenceItem {
            scope_state: state.to_string(),
            team_slug: team.map(str::to_string),
            service_name: svc.map(str::to_string),
            ..Default::default()
        };
        // Pre-scoping server (empty scope_state): renders nothing.
        assert_eq!(evidence_scope_label(&EvidenceItem::default()), "");
        // Global is silent too, but for a different reason.
        assert_eq!(evidence_scope_label(&item("global", None, None)), "");
        // Grandfathered rows the server knows it cannot attribute.
        assert_eq!(
            evidence_scope_label(&item("unknown", None, None)),
            "unknown scope (needs re-scoping)"
        );
        assert_eq!(
            evidence_scope_label(&item("team", Some("payments"), None)),
            "team=payments"
        );
        assert_eq!(
            evidence_scope_label(&item("service", None, Some("checkout-api"))),
            "service=checkout-api"
        );
        assert_eq!(
            evidence_scope_label(&item("team", Some("payments"), Some("checkout-api"))),
            "team=payments service=checkout-api"
        );
        // Empty strings inside the pointers contribute nothing.
        assert_eq!(evidence_scope_label(&item("team", Some(""), Some(""))), "");
    }

    #[test]
    fn required_flags_are_usage_errors() {
        let f = require(None, "--control is required (e.g., --control=RC-018)").unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: --control is required (e.g., --control=RC-018)"
        );
    }

    #[test]
    fn status_filter_is_validated() {
        assert!(validate_status(&Some("verified".into())).is_ok());
        let f = validate_status(&Some("bogus".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert!(f.msg.contains("must be one of"));
    }

    #[test]
    fn risk_code_guard() {
        assert!(check_not_risk_code("RC-018").is_ok());
        let f = check_not_risk_code("R-001").unwrap_err();
        assert_eq!(f.code, 2);
        assert!(f.msg.contains("Evidence is submitted per control"));
    }
}
