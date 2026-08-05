//! `control list` / `control show`, ported from rvl-cli
//! `internal/commands/control.go`. Both JSON modes are raw server-body
//! passthrough (byte-identical by construction).

use crate::client::Client;
use crate::display;
use crate::gojson::{path_escape, query_encode};
use crate::{CmdResult, Failure, BIN};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum ControlCmd {
    /// List controls in the catalog
    List {
        /// Filter by category (fault_tolerance, monitoring, ...)
        #[arg(long)]
        category: Option<String>,
        /// Maximum results (default 200; server caps at 1000)
        #[arg(long, default_value_t = 200, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// Show control details by code (e.g., RC-018)
    Show {
        /// Control code (RC-XXX)
        code: String,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
}

/// A reliability control, matching the fields rvl-cli types.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Control {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub category: String,
    #[serde(default, rename = "type")]
    pub control_type: String,
    #[serde(default)]
    pub objective: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub risk_statement: String,
    #[serde(default)]
    pub test_description: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub expected_evidence_types: Vec<String>,
    #[serde(default)]
    pub treatment: String,
    #[serde(default)]
    pub weight: i64,
    #[serde(default)]
    pub linked_risks: Vec<ControlLinkedRisk>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct ControlLinkedRisk {
    #[serde(default)]
    pub risk_code: String,
}

#[derive(Debug, Default, Deserialize)]
struct ListControlsResponse {
    #[serde(default)]
    controls: Vec<Control>,
    #[serde(default)]
    total: i64,
}

pub fn run(cmd: ControlCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            ControlCmd::List {
                category,
                limit,
                format,
            } => {
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(&client, category.as_deref(), limit, format.as_deref())
            }
            ControlCmd::Show { code, format } => {
                validate_format(&format)?;
                check_not_risk_code(&code)?;
                let (_, client) = crate::client::load_and_resolve()?;
                show_output(&client, &code, format.as_deref())
            }
        }
    })();
    crate::finish(res)
}

/// rvl-cli validates control --format as table|json (po-i24do.11).
fn validate_format(format: &Option<String>) -> Result<(), Failure> {
    match format.as_deref() {
        None | Some("table") | Some("json") => Ok(()),
        Some(f) => Err(Failure::usage(format!(
            "Error: invalid --format \"{f}\" (valid: table, json)"
        ))),
    }
}

/// R-XXX passed where RC-XXX is expected: point at the right command.
fn check_not_risk_code(code: &str) -> Result<(), Failure> {
    if code.starts_with("R-") && !code.starts_with("RC-") {
        return Err(Failure::usage(format!(
            "Note: \"{code}\" is a risk code, not a control code (RC-XXX).\n\
             Use \"{BIN} risk show {code}\" to see its mapped controls."
        )));
    }
    Ok(())
}

pub fn list_output(
    client: &Client,
    category: Option<&str>,
    limit: u32,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs = vec![("limit", limit.to_string())];
    if let Some(c) = category {
        pairs.push(("category", c.to_string()));
    }
    let url = format!(
        "{}/api/v1/controls?{}",
        client.api_url,
        query_encode(&pairs)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        // Raw server body verbatim: the wrapped {controls, total, page,
        // limit} shape passes through byte-identically.
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let resp: ListControlsResponse = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    let mut out = String::new();
    if resp.controls.is_empty() {
        if category.is_some() {
            eprintln!("No controls match the requested category.");
            eprintln!("Hint: run `{BIN} control list` (no filter) to see the catalog,");
            eprintln!("or check spelling - categories use underscore_case slugs.");
        } else {
            let _ = writeln!(out, "No controls found.");
        }
        return Ok(out);
    }
    let _ = writeln!(out, "Found {} controls:\n", resp.total);
    for c in &resp.controls {
        let _ = writeln!(
            out,
            "{:<8} {:<14} {}/10 {:<12} [{}] {}",
            c.control_code,
            display::format_control_type(&c.control_type),
            c.weight,
            display::format_weight_tier(c.weight),
            display::format_category(&c.category),
            c.name
        );
    }
    if resp.total > resp.controls.len() as i64 {
        eprintln!(
            "\nNote: showing {} of {} total controls. Use --limit (max 1000) or --category to narrow.",
            resp.controls.len(),
            resp.total
        );
    }
    Ok(out)
}

pub fn show_output(client: &Client, code: &str, format: Option<&str>) -> CmdResult {
    let url = format!(
        "{}/api/v1/controls/by-code/{}",
        client.api_url,
        path_escape(code)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let c: Control = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    let mut out = String::new();
    let _ = writeln!(out, "Control: {} - {}", c.control_code, c.name);
    let _ = writeln!(out, "Category: {}", display::format_category(&c.category));
    let _ = writeln!(out, "Type: {}", c.control_type);
    let _ = writeln!(
        out,
        "Weight: {}/10 ({})",
        c.weight,
        display::format_weight_tier(c.weight)
    );
    if !c.treatment.is_empty() {
        let _ = writeln!(out, "Treatment: {}", c.treatment);
    }
    let section = |label: &str, text: &str, out: &mut String| {
        if !text.is_empty() {
            let _ = writeln!(out, "\n{label}:\n  {}", display::wrap_text(text, 78, "  "));
        }
    };
    section("Description", &c.description, &mut out);
    section("Objective", &c.objective, &mut out);
    section("Risk Statement", &c.risk_statement, &mut out);
    section("Test Description", &c.test_description, &mut out);
    section("Remediation", &c.remediation, &mut out);
    if !c.expected_evidence_types.is_empty() {
        let _ = writeln!(
            out,
            "\nExpected Evidence: {}",
            c.expected_evidence_types.join(", ")
        );
    }
    if !c.linked_risks.is_empty() {
        let codes: Vec<&str> = c
            .linked_risks
            .iter()
            .map(|r| r.risk_code.as_str())
            .collect();
        let _ = writeln!(out, "\nRelated Risks: {}", codes.join(", "));
    }
    Ok(out)
}

/// Look up a control's UUID by its RC-XXX code (used by evidence list).
pub fn find_control_id_by_code(client: &Client, code: &str) -> Result<String, String> {
    let url = format!(
        "{}/api/v1/controls/by-code/{}",
        client.api_url,
        path_escape(code)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| format!("control {code} not found: {e}"))?;
    #[derive(Deserialize)]
    struct IdOnly {
        #[serde(default)]
        id: String,
    }
    let c: IdOnly =
        serde_json::from_slice(&body).map_err(|e| format!("parse control response: {e}"))?;
    if c.id.is_empty() {
        return Err(format!("control {code} not found"));
    }
    Ok(c.id)
}

/// Fetch and parse a full control by code (used by evidence submit).
pub fn fetch_control_by_code(client: &Client, code: &str) -> Result<Control, Failure> {
    let url = format!(
        "{}/api/v1/controls/by-code/{}",
        client.api_url,
        path_escape(code)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: control {code} not found: {e}")))?;
    let c: Control = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing control response: {e}")))?;
    if c.id.is_empty() {
        return Err(Failure::runtime(format!("Error: control {code} not found")));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_code_guard_points_at_risk_show() {
        let f = check_not_risk_code("R-001").unwrap_err();
        assert_eq!(f.code, 2);
        assert!(f.msg.contains("risk code, not a control code"));
        assert!(check_not_risk_code("RC-018").is_ok());
    }

    #[test]
    fn format_validation_matches_rvl_cli() {
        let f = validate_format(&Some("jsonn".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: invalid --format \"jsonn\" (valid: table, json)"
        );
        assert!(validate_format(&Some("json".into())).is_ok());
        assert!(validate_format(&None).is_ok());
    }
}
