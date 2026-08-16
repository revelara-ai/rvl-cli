//! `control list` / `control show`, ported from rvl-cli
//! `internal/commands/control.go`. Both JSON modes are raw server-body
//! passthrough (byte-identical by construction).

use crate::client::Client;
use crate::display;
use crate::gojson::{compact, compact_raw, path_escape, query_encode, G};
use crate::{CmdResult, Failure, BIN};
use rvl_core::flag::{absent_if_empty, EmptyFlag};
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
        /// Show the scope-status breakdown filtered to this team
        #[arg(long)]
        team: Option<String>,
        /// Show the scope-status breakdown filtered to this service
        #[arg(long)]
        service: Option<String>,
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

/// Mirrors the Revelara API's `ControlScopeStatusResponse`: the per-team
/// breakdown plus the WORST-OF org rollup. `unknown_evidence` counts
/// grandfathered rows flagged for re-scoping; they are never credited to
/// any scope.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ControlScopeStatus {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub org_status: String,
    #[serde(default)]
    pub teams: Vec<ControlTeamScopeStatus>,
    #[serde(default)]
    pub unknown_evidence: i64,
}

/// One team's row in the scope-status breakdown.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct ControlTeamScopeStatus {
    #[serde(default)]
    pub team_slug: String,
    #[serde(default)]
    pub team_name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub direct_evidence: i64,
    #[serde(default)]
    pub inherited_evidence: i64,
    #[serde(default)]
    pub global_evidence: i64,
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
                // control.go:163 wraps ValidateFormat in `if format != ""`,
                // so `--format=` renders the table while `--format=xyz` still
                // exits 2. Normalizing BEFORE the validator reproduces that
                // guard instead of re-deriving it inside every validator.
                // control.go:176 guards --category the same way; `--limit=`
                // is rejected by clap's typed parse, as Atoi("") is at
                // control.go:128.
                let format = absent_if_empty(format);
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(
                    &client,
                    category.empty_is_absent(),
                    limit,
                    format.empty_is_absent(),
                )
            }
            ControlCmd::Show {
                code,
                team,
                service,
                format,
            } => {
                // control.go:251, same guarded validator. --team/--service
                // are rvl-native scope filters and follow the filter rule.
                let format = absent_if_empty(format);
                validate_format(&format)?;
                check_not_risk_code(&code)?;
                let (_, client) = crate::client::load_and_resolve()?;
                show_output(
                    &client,
                    &code,
                    team.empty_is_absent(),
                    service.empty_is_absent(),
                    format.empty_is_absent(),
                )
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

/// GET /api/v1/controls/by-code/{code}/scope-status with optional
/// team/service filters. Returns the parsed response plus the raw body
/// (for `--format=json` passthrough). An unknown team/service is a 400
/// whose message lists the org's known slugs/services — the client
/// surfaces that message verbatim, so callers must not swallow the error.
pub fn fetch_control_scope_status(
    client: &Client,
    code: &str,
    team: Option<&str>,
    service: Option<&str>,
) -> Result<(ControlScopeStatus, Vec<u8>), Failure> {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    if let Some(t) = team {
        if !t.is_empty() {
            pairs.push(("team", t.to_string()));
        }
    }
    if let Some(s) = service {
        if !s.is_empty() {
            pairs.push(("service", s.to_string()));
        }
    }
    let mut url = format!(
        "{}/api/v1/controls/by-code/{}/scope-status",
        client.api_url,
        path_escape(code)
    );
    if !pairs.is_empty() {
        url.push('?');
        url.push_str(&query_encode(&pairs));
    }
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let st: ControlScopeStatus = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error: parse scope-status response: {e}")))?;
    Ok((st, body))
}

/// The per-team scope breakdown plus the worst-of org rollup.
pub fn render_control_scope_status(st: &ControlScopeStatus) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Scope Status (per team):");
    if st.teams.is_empty() {
        let _ = writeln!(
            out,
            "  (no teams in scope - the org has no teams yet, or the filter matched none)"
        );
    } else {
        let _ = writeln!(
            out,
            "  {:<20} {:<10} {:>7} {:>10} {:>7}",
            "TEAM", "STATUS", "DIRECT", "INHERITED", "GLOBAL"
        );
        for t in &st.teams {
            let _ = writeln!(
                out,
                "  {:<20} {:<10} {:>7} {:>10} {:>7}",
                t.team_slug, t.status, t.direct_evidence, t.inherited_evidence, t.global_evidence
            );
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "Org status (worst-of): {}", st.org_status);
    if st.unknown_evidence > 0 {
        let _ = writeln!(
            out,
            "Note: {} evidence record(s) have unknown scope (grandfathered; re-scope them - they are never credited to any team).",
            st.unknown_evidence
        );
    }
    out
}

/// The one-line org scope summary shown on a plain `control show` when the
/// control has scoped (non-global) evidence, or "" when everything is
/// org-wide and there is nothing scoped to surface.
pub fn org_scope_summary_line(st: Option<&ControlScopeStatus>) -> String {
    let Some(st) = st else {
        return String::new();
    };
    let scoped = st.unknown_evidence > 0
        || st
            .teams
            .iter()
            .any(|t| t.direct_evidence > 0 || t.inherited_evidence > 0);
    if !scoped {
        return String::new();
    }
    format!(
        "Org scope status: {} (worst-of across {} teams; {} unknown-scope records; see --team/--service)",
        st.org_status,
        st.teams.len(),
        st.unknown_evidence
    )
}

pub fn show_output(
    client: &Client,
    code: &str,
    team: Option<&str>,
    service: Option<&str>,
    format: Option<&str>,
) -> CmdResult {
    let url = format!(
        "{}/api/v1/controls/by-code/{}",
        client.api_url,
        path_escape(code)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    // With scope flags the scope-status fetch is part of what the user
    // asked for, so its errors (including the 400 that lists known team
    // slugs / services) are fatal and surfaced verbatim.
    let wants_scope = team.is_some_and(|t| !t.is_empty()) || service.is_some_and(|s| !s.is_empty());
    let scope = if wants_scope {
        Some(fetch_control_scope_status(client, code, team, service)?)
    } else {
        None
    };

    if format == Some("json") {
        if let Some((_, raw)) = &scope {
            // Combined envelope so jq pipelines get both bodies in one
            // document: {"control": <control>, "scope_status": <breakdown>}.
            let combined = compact(&G::Obj(vec![
                (
                    "control".to_string(),
                    G::Raw(compact_raw(&String::from_utf8_lossy(&body))),
                ),
                (
                    "scope_status".to_string(),
                    G::Raw(compact_raw(&String::from_utf8_lossy(raw))),
                ),
            ]));
            return Ok(format!("{combined}\n"));
        }
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

    // Scope-aware status. With --team/--service, render the full per-team
    // breakdown (already fetched above, errors fatal). Without flags, a
    // best-effort unfiltered fetch adds a one-line org scope summary when
    // the control has scoped evidence; older servers without the endpoint
    // degrade silently to the classic output.
    if let Some((st, _)) = &scope {
        let _ = writeln!(out);
        out.push_str(&render_control_scope_status(st));
        return Ok(out);
    }
    if let Ok((st, _)) = fetch_control_scope_status(client, code, None, None) {
        let line = org_scope_summary_line(Some(&st));
        if !line.is_empty() {
            let _ = writeln!(out);
            let _ = writeln!(out, "{line}");
        }
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

    fn scope_status_fixture() -> ControlScopeStatus {
        ControlScopeStatus {
            control_code: "RC-018".into(),
            // Worst-of: one team is evidenced, one is absent -> absent.
            org_status: "absent".into(),
            teams: vec![
                ControlTeamScopeStatus {
                    team_slug: "payments".into(),
                    team_name: "Payments".into(),
                    status: "evidenced".into(),
                    direct_evidence: 2,
                    inherited_evidence: 1,
                    global_evidence: 0,
                },
                ControlTeamScopeStatus {
                    team_slug: "platform".into(),
                    team_name: "Platform".into(),
                    status: "absent".into(),
                    ..Default::default()
                },
            ],
            unknown_evidence: 3,
        }
    }

    #[test]
    fn scope_status_render_has_teams_counts_and_worst_of() {
        let out = render_control_scope_status(&scope_status_fixture());
        for want in [
            "payments",
            "platform",
            "evidenced",
            "absent",
            "Org status (worst-of): absent",
            "3 evidence record(s) have unknown scope",
        ] {
            assert!(out.contains(want), "render missing {want} in:\n{out}");
        }
        // Direct/inherited/global counts for the evidenced team.
        assert!(
            out.contains("payments             evidenced        2          1       0"),
            "counts row wrong in:\n{out}"
        );
    }

    #[test]
    fn scope_status_render_with_no_teams() {
        let out = render_control_scope_status(&ControlScopeStatus {
            control_code: "RC-018".into(),
            org_status: "evidenced".into(),
            ..Default::default()
        });
        assert!(out.contains("no teams"), "{out}");
        assert!(out.contains("Org status (worst-of): evidenced"), "{out}");
        // No unknown-scope note when the count is zero.
        assert!(!out.contains("unknown scope"), "{out}");
    }

    #[test]
    fn org_scope_summary_line_only_when_something_is_scoped() {
        assert_eq!(
            org_scope_summary_line(Some(&scope_status_fixture())),
            "Org scope status: absent (worst-of across 2 teams; 3 unknown-scope records; see --team/--service)"
        );
        // Only global evidence: nothing scoped, so no line.
        assert_eq!(
            org_scope_summary_line(Some(&ControlScopeStatus {
                org_status: "evidenced".into(),
                teams: vec![ControlTeamScopeStatus {
                    team_slug: "payments".into(),
                    status: "evidenced".into(),
                    global_evidence: 2,
                    ..Default::default()
                }],
                ..Default::default()
            })),
            ""
        );
        // No teams, no unknown records.
        assert_eq!(
            org_scope_summary_line(Some(&ControlScopeStatus {
                org_status: "evidenced".into(),
                ..Default::default()
            })),
            ""
        );
        // Unknown-scope records alone are enough to surface the line.
        assert_eq!(
            org_scope_summary_line(Some(&ControlScopeStatus {
                org_status: "evidenced".into(),
                unknown_evidence: 1,
                ..Default::default()
            })),
            "Org scope status: evidenced (worst-of across 0 teams; 1 unknown-scope records; see --team/--service)"
        );
        assert_eq!(org_scope_summary_line(None), "");
    }
}
