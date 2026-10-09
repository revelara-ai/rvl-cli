//! `factor list` / `factor show`: the causal factor catalog, in the same
//! form as `control list` / `control show`. Both JSON modes are raw
//! server-body passthrough. The wire shapes are the `CausalFactor*` schemas
//! of the Revelara API.

use crate::client::Client;
use crate::display;
use crate::gojson::{null_as_default, path_escape, query_encode};
use crate::{CmdResult, Failure, BIN};
use rvl_core::flag::{absent_if_empty, EmptyFlag};
use serde::Deserialize;
use std::fmt::Write as _;

/// Printed wherever a public count is shown. A count is the number of
/// public reports that describe the condition, so a reader must not take it
/// for a frequency.
const PUBLIC_COUNTS_NOTE: &str =
    "Public counts are reports that describe the condition. They are not a rate of occurrence.";

#[derive(clap::Subcommand)]
pub enum FactorCmd {
    /// List causal factors in the catalog
    List {
        /// Filter by category number (1-7)
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=7))]
        category: Option<u8>,
        /// Only the factors in the Reliability Top 10
        #[arg(long)]
        top10: bool,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
    /// Show causal factor details by code (e.g., CF-0021)
    Show {
        /// Causal factor code (CF-XXXX)
        code: String,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
}

/// One entry of the causal factor catalog: a contributing condition found
/// in public incident reports.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct Factor {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub definition: String,
    #[serde(default)]
    pub category: i64,
    #[serde(default)]
    pub category_name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub tags: Vec<String>,
    /// Curation note. Empty when there is none.
    #[serde(default)]
    pub note: String,
    /// `active`, `merged` or `retired`.
    #[serde(default)]
    pub status: String,
    /// The code this entry was merged into. Empty unless `status` is `merged`.
    #[serde(default)]
    pub merged_into: String,
    #[serde(default)]
    pub code_addressable: bool,
    #[serde(default)]
    pub public_incidents: i64,
    #[serde(default)]
    pub public_organizations: i64,
    /// Slot in the Reliability Top 10 of the current edition.
    #[serde(default)]
    pub top10_slot: Option<i64>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorGuard {
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub text: String,
}

/// A quote from a public incident report.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorQuote {
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub reported_on: String,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub text: String,
}

/// A reliability control linked to a causal factor.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorControl {
    #[serde(default)]
    pub control_code: String,
    #[serde(default)]
    pub control_name: String,
    /// `prevents`, `detects`, `mitigates`, or `induces` (the control can
    /// cause the factor).
    #[serde(default)]
    pub relation: String,
    #[serde(default)]
    pub note: String,
    /// True when the adjudication did not agree on the link.
    #[serde(default)]
    pub contested: bool,
}

/// One of the caller's risks that reaches the factor through a control.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorRiskRef {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub risk_code: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub score: i64,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub via_control: String,
}

/// A causal factor with its card fields, quotes, controls and the caller's
/// related risks.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorDetail {
    #[serde(default)]
    pub factor: Factor,
    #[serde(default)]
    pub edition: String,
    /// What the code or the change looks like when the factor applies.
    /// Empty when the entry has no card.
    #[serde(default)]
    pub tell: String,
    #[serde(default)]
    pub card_status: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub guards: Vec<FactorGuard>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub quotes: Vec<FactorQuote>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub controls: Vec<FactorControl>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub related_risks: Vec<FactorRiskRef>,
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct FactorList {
    #[serde(default, deserialize_with = "null_as_default")]
    pub factors: Vec<Factor>,
    #[serde(default)]
    pub total: i64,
    #[serde(default)]
    pub edition: String,
}

pub fn run(cmd: FactorCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            FactorCmd::List {
                category,
                top10,
                format,
            } => {
                // Same guard as `control list`: `--format=` renders the
                // table and `--format=xyz` exits 2. clap rejects a
                // --category outside 1 to 7 before this function runs.
                let format = absent_if_empty(format);
                validate_format(&format)?;
                let (_, client) = crate::client::load_and_resolve()?;
                list_output(&client, category, top10, format.empty_is_absent())
            }
            FactorCmd::Show { code, format } => {
                let format = absent_if_empty(format);
                validate_format(&format)?;
                check_not_other_code(&code)?;
                let (_, client) = crate::client::load_and_resolve()?;
                show_output(&client, &code, format.empty_is_absent())
            }
        }
    })();
    crate::finish(res)
}

/// The same message form as `control --format`.
fn validate_format(format: &Option<String>) -> Result<(), Failure> {
    match format.as_deref() {
        None | Some("table") | Some("json") => Ok(()),
        Some(f) => Err(Failure::usage(format!(
            "Error: invalid --format \"{f}\" (valid: table, json)"
        ))),
    }
}

/// A control code (RC-XXX) or a risk code (R-XXX) passed where CF-XXXX is
/// expected: point at the right command. Case is ignored, as it is for the
/// factor code itself.
fn check_not_other_code(code: &str) -> Result<(), Failure> {
    let upper = code.to_ascii_uppercase();
    let (kind, command) = if upper.starts_with("RC-") {
        ("control", "control show")
    } else if upper.starts_with("R-") {
        ("risk", "risk show")
    } else {
        return Ok(());
    };
    Err(Failure::usage(format!(
        "Note: \"{code}\" is a {kind} code, not a causal factor code (CF-XXXX).\n\
         Use \"{BIN} {command} {code}\" to see it."
    )))
}

pub fn list_output(
    client: &Client,
    category: Option<u8>,
    top10: bool,
    format: Option<&str>,
) -> CmdResult {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    if let Some(c) = category {
        pairs.push(("category", c.to_string()));
    }
    if top10 {
        pairs.push(("top10", "true".to_string()));
    }
    let mut url = format!("{}/api/v1/causal-factors", client.api_url);
    if !pairs.is_empty() {
        url.push('?');
        url.push_str(&query_encode(&pairs));
    }
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        // Raw server body verbatim.
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let resp: FactorList = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_list(&resp))
}

/// The table of `factor list`: the edition and the count wording, then one
/// row per factor.
pub fn render_list(resp: &FactorList) -> String {
    let mut out = String::new();
    if resp.factors.is_empty() {
        let _ = writeln!(out, "No causal factors found.");
        return out;
    }
    let _ = write!(out, "Found {} causal factors", resp.total);
    if !resp.edition.is_empty() {
        let _ = write!(out, " (edition {})", resp.edition);
    }
    let _ = writeln!(out, ":");
    let _ = writeln!(out, "{PUBLIC_COUNTS_NOTE}\n");
    let _ = writeln!(
        out,
        "{:<8} {:<5} {:>9} {:>5} {:>3}  NAME",
        "CODE", "TOP10", "INCIDENTS", "ORGS", "CAT"
    );
    for f in &resp.factors {
        let slot = f.top10_slot.map(|s| s.to_string()).unwrap_or_default();
        let _ = writeln!(
            out,
            "{:<8} {:<5} {:>9} {:>5} {:>3}  {}",
            f.code, slot, f.public_incidents, f.public_organizations, f.category, f.name
        );
    }
    out
}

pub fn show_output(client: &Client, code: &str, format: Option<&str>) -> CmdResult {
    // The code goes out as the user typed it; the server ignores its case.
    let url = format!(
        "{}/api/v1/causal-factors/{}",
        client.api_url,
        path_escape(code)
    );
    let body = client.request("GET", &url, None).map_err(|e| {
        // The client formats every other status as "server error (<n>): ...".
        if e.starts_with("server error (404)") {
            Failure::runtime(format!("Error: causal factor {code} not found: {e}"))
        } else {
            Failure::runtime(format!("Error: {e}"))
        }
    })?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let detail: FactorDetail = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;
    Ok(render_detail(&detail))
}

/// The relations of a control to a factor, in print order, with the heading
/// of each. `induces` is the reverse direction: the control can cause the
/// factor.
const RELATIONS: [(&str, &str); 4] = [
    ("prevents", "Prevents"),
    ("detects", "Detects"),
    ("mitigates", "Mitigates"),
    ("induces", "Can induce"),
];

/// The text of `factor show`. A section with no rows is not printed.
pub fn render_detail(d: &FactorDetail) -> String {
    let f = &d.factor;
    let mut out = String::new();
    let _ = writeln!(out, "Causal factor: {} - {}", f.code, f.name);
    if f.category_name.is_empty() {
        let _ = writeln!(out, "Category: {}", f.category);
    } else {
        let _ = writeln!(out, "Category: {} ({})", f.category, f.category_name);
    }
    let _ = writeln!(out, "Status: {}", f.status);
    if !f.merged_into.is_empty() {
        let _ = writeln!(out, "Merged into {}", f.merged_into);
    }
    let section = |label: &str, text: &str, out: &mut String| {
        if !text.is_empty() {
            let _ = writeln!(out, "\n{label}:\n  {}", display::wrap_text(text, 78, "  "));
        }
    };
    section("Definition", &f.definition, &mut out);
    section("Curation note", &f.note, &mut out);

    let _ = writeln!(out);
    if let Some(slot) = f.top10_slot {
        let _ = write!(out, "Reliability Top 10: #{slot}");
        if !d.edition.is_empty() {
            let _ = write!(out, " (edition {})", d.edition);
        }
        let _ = writeln!(out);
    }
    let _ = writeln!(
        out,
        "Public reports: {} public incident reports from {} organizations",
        f.public_incidents, f.public_organizations
    );
    let _ = writeln!(out, "  {PUBLIC_COUNTS_NOTE}");

    if !d.quotes.is_empty() {
        let _ = writeln!(out, "\nQuotes:");
        for q in &d.quotes {
            let _ = writeln!(out, "  {}, {}", q.organization, q.reported_on);
            let _ = writeln!(out, "    {}", display::wrap_text(&q.text, 76, "    "));
            if !q.source_url.is_empty() {
                let _ = writeln!(out, "    {}", q.source_url);
            }
        }
    }

    if !d.controls.is_empty() {
        let _ = writeln!(out, "\nControls:");
        let mut group = |heading: &str, rows: Vec<&FactorControl>| {
            if rows.is_empty() {
                return;
            }
            let _ = writeln!(out, "  {heading}:");
            for c in rows {
                let contested = if c.contested { " (contested)" } else { "" };
                let _ = writeln!(out, "    {}  {}{contested}", c.control_code, c.control_name);
            }
        };
        for (relation, heading) in RELATIONS {
            group(
                heading,
                d.controls
                    .iter()
                    .filter(|c| c.relation == relation)
                    .collect(),
            );
        }
        // A relation this version does not know is still shown, so a newer
        // server cannot make a link disappear.
        group(
            "Other",
            d.controls
                .iter()
                .filter(|c| RELATIONS.iter().all(|(r, _)| c.relation != *r))
                .collect(),
        );
    }

    section("Tell", &d.tell, &mut out);
    if !d.guards.is_empty() {
        let _ = writeln!(out, "\nGuards:");
        let mut guards: Vec<&FactorGuard> = d.guards.iter().collect();
        guards.sort_by_key(|g| g.position);
        for g in guards {
            let _ = writeln!(out, "  {}. {}", g.position, g.text);
        }
    }

    if !d.related_risks.is_empty() {
        let _ = writeln!(out, "\nRelated risks (your organization):");
        for r in &d.related_risks {
            let _ = writeln!(
                out,
                "  {:<8} {:>3}  {} (via {})",
                r.risk_code, r.score, r.title, r.via_control
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn factor_fixture() -> Factor {
        Factor {
            code: "CF-0021".into(),
            name: "Unbounded retry".into(),
            definition: "A caller retries with no limit.".into(),
            category: 3,
            category_name: "Load and capacity".into(),
            status: "active".into(),
            public_incidents: 42,
            public_organizations: 17,
            top10_slot: Some(2),
            ..Default::default()
        }
    }

    #[test]
    fn format_validation_has_the_control_message_form() {
        let f = validate_format(&Some("yaml".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: invalid --format \"yaml\" (valid: table, json)"
        );
        assert!(validate_format(&Some("table".into())).is_ok());
        assert!(validate_format(&None).is_ok());
    }

    #[test]
    fn a_control_or_risk_code_gets_a_usage_error_that_names_the_command() {
        let f = check_not_other_code("RC-018").unwrap_err();
        assert_eq!(f.code, 2);
        assert!(f.msg.contains("is a control code"), "{}", f.msg);
        assert!(f.msg.contains("rvl control show RC-018"), "{}", f.msg);

        let f = check_not_other_code("r-001").unwrap_err();
        assert_eq!(f.code, 2);
        assert!(f.msg.contains("is a risk code"), "{}", f.msg);
        assert!(f.msg.contains("rvl risk show r-001"), "{}", f.msg);

        assert!(check_not_other_code("CF-0021").is_ok());
        assert!(check_not_other_code("cf-0021").is_ok());
    }

    #[test]
    fn list_render_has_the_public_count_wording_and_the_edition() {
        let out = render_list(&FactorList {
            factors: vec![
                factor_fixture(),
                Factor {
                    code: "CF-0107".into(),
                    name: "Stale runbook".into(),
                    category: 6,
                    public_incidents: 5,
                    public_organizations: 4,
                    ..Default::default()
                },
            ],
            total: 2,
            edition: "2026.2".into(),
        });
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], "Found 2 causal factors (edition 2026.2):");
        assert_eq!(
            lines[1],
            "Public counts are reports that describe the condition. They are not a rate of occurrence."
        );
        assert_eq!(lines[3], "CODE     TOP10 INCIDENTS  ORGS CAT  NAME");
        assert_eq!(
            lines[4],
            "CF-0021  2            42    17   3  Unbounded retry"
        );
        // A factor outside the Top 10 has a blank slot.
        assert_eq!(
            lines[5],
            "CF-0107                5     4   6  Stale runbook"
        );
    }

    #[test]
    fn list_render_of_no_factors() {
        assert_eq!(
            render_list(&FactorList::default()),
            "No causal factors found.\n"
        );
    }

    #[test]
    fn detail_render_of_a_bare_entry_prints_no_empty_section() {
        let out = render_detail(&FactorDetail {
            factor: Factor {
                top10_slot: None,
                ..factor_fixture()
            },
            edition: "2026.2".into(),
            ..Default::default()
        });
        assert_eq!(
            out,
            "Causal factor: CF-0021 - Unbounded retry\n\
             Category: 3 (Load and capacity)\n\
             Status: active\n\
             \n\
             Definition:\n  A caller retries with no limit.\n\
             \n\
             Public reports: 42 public incident reports from 17 organizations\n  \
             Public counts are reports that describe the condition. They are not a rate of occurrence.\n"
        );
    }

    #[test]
    fn detail_render_groups_controls_by_relation_and_marks_a_contested_link() {
        let control = |code: &str, relation: &str, contested: bool| FactorControl {
            control_code: code.into(),
            control_name: format!("Name of {code}"),
            relation: relation.into(),
            contested,
            ..Default::default()
        };
        let out = render_detail(&FactorDetail {
            factor: factor_fixture(),
            controls: vec![
                control("RC-040", "induces", true),
                control("RC-018", "mitigates", false),
                control("RC-070", "amplifies", false),
                control("RC-012", "prevents", false),
            ],
            ..Default::default()
        });
        let controls = out
            .split("\nControls:\n")
            .nth(1)
            .expect("a Controls section");
        assert_eq!(
            controls,
            "  Prevents:\n    RC-012  Name of RC-012\n  \
             Mitigates:\n    RC-018  Name of RC-018\n  \
             Can induce:\n    RC-040  Name of RC-040 (contested)\n  \
             Other:\n    RC-070  Name of RC-070\n"
        );
    }

    #[test]
    fn detail_render_sorts_guards_and_names_the_merge_target() {
        let out = render_detail(&FactorDetail {
            factor: Factor {
                status: "merged".into(),
                merged_into: "CF-0030".into(),
                ..factor_fixture()
            },
            tell: "A loop with no attempt counter.".into(),
            guards: vec![
                FactorGuard {
                    position: 2,
                    text: "Add jitter.".into(),
                },
                FactorGuard {
                    position: 1,
                    text: "Cap the attempts.".into(),
                },
            ],
            ..Default::default()
        });
        assert!(
            out.contains("Status: merged\nMerged into CF-0030\n"),
            "{out}"
        );
        assert!(
            out.contains("\nTell:\n  A loop with no attempt counter.\n"),
            "{out}"
        );
        assert!(
            out.contains("\nGuards:\n  1. Cap the attempts.\n  2. Add jitter.\n"),
            "{out}"
        );
    }
}
