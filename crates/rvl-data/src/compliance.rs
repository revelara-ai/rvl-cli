//! `compliance report`: the compliance readiness scorecard, ported from
//! rvl-cli `internal/commands/report.go` (po-av01j.185 item 2).
//!
//! NAME COLLISION, RULED: rvl-cli spells this `rvl report`. This binary
//! already uses `report` for the scan privacy-payload preview — a
//! different, local-only command whose whole point is showing what would
//! leave the machine. Rather than take the name back (breaking the newer
//! command) or drop the scorecard (an unratified retirement of a live,
//! documented capability), the scorecard moves one level down to
//! `rvl compliance report`. Flags and output are otherwise byte-faithful
//! to rvl-cli: `--framework`, `--set`, `--format`, the same column widths,
//! the same closing readiness/supporting disclaimer.

use crate::client::Client;
use crate::gojson::path_escape;
use crate::{display, CmdResult, Failure, BIN};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum ComplianceCmd {
    /// Compliance readiness scorecard: the controls you should implement
    /// for a framework and your current readiness. Readiness/supporting
    /// framing only, never certification.
    Report {
        /// Framework key (default soc2)
        #[arg(long)]
        framework: Option<String>,
        /// Which controls to score: starter (default) or full
        #[arg(long)]
        set: Option<String>,
        /// Output format: table (default) or json for the raw server body
        #[arg(long)]
        format: Option<String>,
    },
}

/// One control row on the scorecard; mirrors the server's
/// `apispec.ReadinessControl`.
#[derive(Debug, Default, Deserialize)]
pub struct ReadinessControl {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub name: String,
    /// pass | partial | fail | not_assessed
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub criteria: Vec<String>,
    #[serde(default)]
    pub url: String,
}

/// Mirrors the server's `apispec.ReadinessScorecard`.
#[derive(Debug, Default, Deserialize)]
pub struct ReadinessScorecard {
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub set: String,
    #[serde(default)]
    pub readiness_pct: f64,
    #[serde(default)]
    pub controls_total: i64,
    #[serde(default)]
    pub controls_passing: i64,
    #[serde(default)]
    pub controls_partial: i64,
    #[serde(default)]
    pub controls_failing: i64,
    #[serde(default)]
    pub controls_not_assessed: i64,
    #[serde(default)]
    pub controls: Vec<ReadinessControl>,
}

pub fn run(cmd: ComplianceCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            ComplianceCmd::Report {
                framework,
                set,
                format,
            } => {
                // rvl-cli validates --set BEFORE it loads credentials, so a
                // typo'd set reports the typo rather than "not logged in".
                let set = normalize_set(set.as_deref())?;
                let (_, client) = crate::client::load_and_resolve()?;
                report_output(&client, framework.as_deref(), Some(&set), format.as_deref())
            }
        }
    })();
    crate::finish(res)
}

/// `--set` lower-cased and checked against the two the server scores.
pub fn normalize_set(set: Option<&str>) -> Result<String, Failure> {
    let set = set.unwrap_or("starter").trim().to_lowercase();
    if set != "starter" && set != "full" {
        return Err(Failure::usage(format!(
            "Error: --set expects 'starter' or 'full', got {set:?}"
        )));
    }
    Ok(set)
}

pub fn report_output(
    client: &Client,
    framework: Option<&str>,
    set: Option<&str>,
    format: Option<&str>,
) -> CmdResult {
    let framework = framework.unwrap_or("soc2").trim().to_lowercase();
    let set = normalize_set(set)?;

    let url = format!(
        "{}/api/v1/compliance/{}/readiness?set={}",
        client.api_url,
        path_escape(&framework),
        set
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }
    let sc: ReadinessScorecard = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_scorecard(&sc))
}

/// The table rvl-cli's `renderScorecard` prints, column for column.
pub fn render_scorecard(sc: &ReadinessScorecard) -> String {
    let set_label = if sc.set == "full" {
        "Full Mapped Set"
    } else {
        "Starter Set"
    };
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} Readiness - {}\n",
        sc.framework.to_uppercase(),
        set_label
    );
    let _ = writeln!(
        out,
        "Readiness: {:.1}%  ({}/{} passing)",
        sc.readiness_pct, sc.controls_passing, sc.controls_total
    );
    let _ = writeln!(
        out,
        "  passing {}   partial {}   failing {}   not assessed {}\n",
        sc.controls_passing, sc.controls_partial, sc.controls_failing, sc.controls_not_assessed
    );

    if sc.controls.is_empty() {
        let _ = writeln!(out, "No controls in scope for this set.");
        return out;
    }
    for c in &sc.controls {
        let _ = writeln!(
            out,
            "{:<8} {:<13} {:<40} {}",
            c.control_code,
            status_badge(&c.status),
            truncate(&c.name, 40),
            c.criteria.join(", ")
        );
    }
    let _ = writeln!(
        out,
        "\nThis is a SOC 2 readiness / supporting-evidence view - not a certification or"
    );
    let _ = writeln!(
        out,
        "attestation. Run `{BIN} control show <RC-XXX>` for remediation guidance."
    );
    out
}

/// rvl-cli's report.go carries its OWN `truncate`, distinct from
/// `display.TruncateText`: it appends the single-character ellipsis "…"
/// (not "..."), so the truncated cell is exactly `max` runes wide and the
/// `%-40s` column never shifts. Reusing `display::truncate_text` here would
/// silently narrow the name by two characters and change every long row.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    if max <= 1 {
        return display::cut_at_boundary(s, max).to_string();
    }
    format!("{}…", display::cut_at_boundary(s, max - 1))
}

fn status_badge(status: &str) -> &'static str {
    match status {
        "pass" => "PASS",
        "partial" => "PARTIAL",
        "fail" => "FAIL",
        _ => "NOT ASSESSED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(code: &str, status: &str, name: &str, criteria: &[&str]) -> ReadinessControl {
        ReadinessControl {
            control_code: code.into(),
            name: name.into(),
            status: status.into(),
            criteria: criteria.iter().map(|s| (*s).to_string()).collect(),
            url: String::new(),
        }
    }

    #[test]
    fn scorecard_matches_the_rvl_cli_layout() {
        let sc = ReadinessScorecard {
            framework: "soc2".into(),
            set: "starter".into(),
            readiness_pct: 9.5,
            controls_total: 21,
            controls_passing: 2,
            controls_partial: 2,
            controls_failing: 9,
            controls_not_assessed: 8,
            controls: vec![
                ctl("RC-001", "pass", "SLO-Tied Alerting", &["CC4.1", "CC7.2"]),
                ctl("RC-005", "not_assessed", "On-Call Coverage", &["CC7.3"]),
            ],
        };
        let got = render_scorecard(&sc);
        assert_eq!(
            got,
            "SOC2 Readiness - Starter Set\n\
             \n\
             Readiness: 9.5%  (2/21 passing)\n\
             \x20 passing 2   partial 2   failing 9   not assessed 8\n\
             \n\
             RC-001   PASS          SLO-Tied Alerting                        CC4.1, CC7.2\n\
             RC-005   NOT ASSESSED  On-Call Coverage                         CC7.3\n\
             \n\
             This is a SOC 2 readiness / supporting-evidence view - not a certification or\n\
             attestation. Run `rvl control show <RC-XXX>` for remediation guidance.\n"
        );
    }

    #[test]
    fn full_set_switches_the_label() {
        let sc = ReadinessScorecard {
            framework: "soc2".into(),
            set: "full".into(),
            ..Default::default()
        };
        let got = render_scorecard(&sc);
        assert!(
            got.starts_with("SOC2 Readiness - Full Mapped Set\n"),
            "{got}"
        );
        assert!(got.contains("No controls in scope for this set."));
    }

    #[test]
    fn long_control_names_are_ellipsized_at_forty() {
        let sc = ReadinessScorecard {
            framework: "soc2".into(),
            set: "starter".into(),
            controls: vec![ctl(
                "RC-070",
                "fail",
                "Third-Party Dependency Reliability Management",
                &["A1.2"],
            )],
            ..Default::default()
        };
        let got = render_scorecard(&sc);
        assert!(
            got.contains("Third-Party Dependency Reliability Mana… A1.2"),
            "{got}"
        );
    }

    #[test]
    fn unknown_statuses_fall_back_to_not_assessed() {
        assert_eq!(status_badge("pass"), "PASS");
        assert_eq!(status_badge("partial"), "PARTIAL");
        assert_eq!(status_badge("fail"), "FAIL");
        assert_eq!(status_badge("not_assessed"), "NOT ASSESSED");
        assert_eq!(status_badge("something-new"), "NOT ASSESSED");
    }
}
