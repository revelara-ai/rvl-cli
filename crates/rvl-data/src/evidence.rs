//! Slice (b): `evidence submit` / `list` / `verify`, ported from rvl-cli
//! `internal/commands/evidence.go`. All three JSON modes print the server
//! body verbatim; the submit request body mirrors Go's sorted-key
//! `map[string]string` marshal byte-for-byte.

use crate::client::Client;
use crate::control;
use crate::display;
use crate::gojson::{compact, G};
use crate::{CmdResult, Failure, BIN};
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
                format,
            } => {
                validate_format(&format)?;
                let control = require(control, "--control is required (e.g., --control=RC-018)")?;
                let evidence_type = require(
                    evidence_type,
                    "--type is required (code, test, dashboard, document, configuration, runbook, other)",
                )?;
                let name = require(name, "--name is required")?;
                check_not_risk_code(&control)?;
                let git_hash = git_hash.or_else(detect_git_hash).unwrap_or_default();
                let (_, client) = crate::client::load_and_resolve()?;
                submit_output(
                    &client,
                    &control,
                    &evidence_type,
                    &name,
                    url.as_deref().unwrap_or(""),
                    description.as_deref().unwrap_or(""),
                    &git_hash,
                    format.as_deref(),
                )
            }
            EvidenceCmd::List {
                control,
                evidence_type,
                status,
                limit,
                format,
            } => {
                validate_format(&format)?;
                validate_status(&status)?;
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(
                    &client,
                    control.as_deref(),
                    evidence_type.as_deref(),
                    status.as_deref(),
                    limit,
                    format.as_deref(),
                )
            }
            EvidenceCmd::Verify { id, format } => {
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                verify_output(&client, &id, format.as_deref())
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
pub fn submit_body(
    control_id: &str,
    evidence_type: &str,
    name: &str,
    url: &str,
    description: &str,
    git_hash: &str,
) -> String {
    let mut fields = vec![
        ("control_id".to_string(), G::Str(control_id.into())),
        ("description".to_string(), G::Str(description.into())),
    ];
    if !git_hash.is_empty() {
        fields.push(("git_hash".to_string(), G::Str(git_hash.into())));
    }
    fields.push(("name".to_string(), G::Str(name.into())));
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

    let body = submit_body(&control.id, evidence_type, name, url, description, git_hash);
    let api_url = format!("{}/api/v1/evidence", client.api_url);
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

pub fn list_output(
    client: &Client,
    control: Option<&str>,
    evidence_type: Option<&str>,
    status: Option<&str>,
    limit: u32,
    format: Option<&str>,
) -> CmdResult {
    // rvl-cli builds this query by string concatenation in a fixed order
    // (limit, type, status, control_id) rather than url.Values; mirror it.
    let mut url = format!("{}/api/v1/evidence?limit={limit}", client.api_url);
    if let Some(t) = evidence_type {
        url.push_str(&format!("&type={t}"));
    }
    if let Some(s) = status {
        url.push_str(&format!("&status={s}"));
    }
    if let Some(code) = control {
        let control_id = control::find_control_id_by_code(client, code)
            .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
        url.push_str(&format!("&control_id={control_id}"));
    }

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
        if !e.url_or_identifier.is_empty() {
            let _ = writeln!(out, "    URL: {}", e.url_or_identifier);
        }
    }
    Ok(out)
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
                "abc123"
            ),
            r#"{"control_id":"uuid-1","description":"desc \u0026 more","git_hash":"abc123","name":"CB impl","type":"code","url_or_identifier":"https://x"}"#
        );
        assert_eq!(
            submit_body("uuid-1", "code", "n", "", "", ""),
            r#"{"control_id":"uuid-1","description":"","name":"n","type":"code","url_or_identifier":""}"#
        );
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
