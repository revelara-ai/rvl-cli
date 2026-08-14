//! Slice: `incident search`, ported from rvl-cli
//! `internal/commands/incident.go`.
//!
//! The plugin scan workflow (scan.md Step 3C) invokes
//! `incident search "{slug} {stack_context}" --limit=5 --format=json`
//! verbatim, so flags, defaults, endpoint, and output text mirror rvl-cli
//! exactly.
//!
//! JSON parity: `--format=json` prints the server body verbatim (raw
//! passthrough), so there is no re-marshal path in this module.

use crate::client::Client;
use crate::display;
use crate::gojson::query_encode;
use crate::{CmdResult, Failure};
use serde::Deserialize;
use std::fmt::Write as _;

#[derive(clap::Subcommand)]
pub enum IncidentCmd {
    /// Semantic search across indexed postmortems
    Search {
        /// Search query (words are joined with spaces)
        #[arg(required = true)]
        query: Vec<String>,
        /// Maximum results (default 10, max 50)
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        /// Output format: table (default) or json
        #[arg(long)]
        format: Option<String>,
    },
}

/// One GET /api/v1/incidents/search response item — the exact typed subset
/// rvl-cli carries (the table reads a subset; JSON mode prints the raw
/// body, so the extra fields document the wire shape).
#[derive(Debug, Default, Clone, Deserialize)]
pub struct IncidentSearchResult {
    #[serde(default)]
    pub short_name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub incident_date: Option<String>,
    #[serde(default)]
    pub mttr_minutes: Option<i64>,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub relevance_score: f64,
}

#[derive(Debug, Default, Deserialize)]
pub struct IncidentSearchResponse {
    #[serde(default)]
    pub results: Vec<IncidentSearchResult>,
    #[serde(default)]
    pub total: i64,
}

pub fn run(cmd: IncidentCmd) -> std::process::ExitCode {
    let res = (|| -> CmdResult {
        match cmd {
            IncidentCmd::Search {
                query,
                limit,
                format,
            } => {
                validate_format(&format)?;
                let query = query.join(" ");
                if query.is_empty() {
                    return Err(Failure::usage("Error: search query required"));
                }
                let (_, client) = crate::client::load_and_resolve()?;
                search_output(&client, &query, limit, format.as_deref())
            }
        }
    })();
    crate::finish(res)
}

fn validate_format(format: &Option<String>) -> Result<(), Failure> {
    match format.as_deref() {
        None | Some("table") | Some("json") => Ok(()),
        Some(f) => Err(Failure::usage(format!(
            "Error: invalid --format \"{f}\" (valid: table, json)"
        ))),
    }
}

pub fn search_output(client: &Client, query: &str, limit: u32, format: Option<&str>) -> CmdResult {
    let pairs = vec![("limit", limit.to_string()), ("q", query.to_string())];
    let url = format!(
        "{}/api/v1/incidents/search?{}",
        client.api_url,
        query_encode(&pairs)
    );
    let body = client
        .request("GET", &url, None)
        .map_err(|e| Failure::runtime(format!("Error: {e}")))?;

    if format == Some("json") {
        return Ok(format!("{}\n", String::from_utf8_lossy(&body)));
    }

    let resp: IncidentSearchResponse = serde_json::from_slice(&body)
        .map_err(|e| Failure::runtime(format!("Error parsing response: {e}")))?;

    let mut out = String::new();
    // Go's %q on the query: quoted with " and \ escaped, which Rust's
    // Debug formatting for strings reproduces for the queries the CLI sees.
    let _ = writeln!(out, "Found {} result(s) for {:?}:\n", resp.total, query);
    out.push_str(&format_search_table(&resp.results));
    Ok(out)
}

const INCIDENT_TITLE_MAX_LEN: usize = 60;

/// Renders results as the text table rvl-cli prints.
pub fn format_search_table(results: &[IncidentSearchResult]) -> String {
    if results.is_empty() {
        return "No incidents found.\n".to_string();
    }
    let mut sb = String::new();
    let _ = writeln!(
        sb,
        "  {:<10}  {:<4}  {:<7}  {:<width$}  Source",
        "ID",
        "Rel.",
        "Sev.",
        "Title",
        width = INCIDENT_TITLE_MAX_LEN
    );
    let _ = writeln!(
        sb,
        "  {}  {}  {}  {}  {}",
        "-".repeat(10),
        "-".repeat(4),
        "-".repeat(7),
        "-".repeat(INCIDENT_TITLE_MAX_LEN),
        "-".repeat(6)
    );
    for r in results {
        // The Go original slices bytes (title[:59] + "…"); Rust must not
        // split a code point, so back off to a char boundary.
        let title = if r.title.len() > INCIDENT_TITLE_MAX_LEN {
            format!(
                "{}…",
                display::cut_at_boundary(&r.title, INCIDENT_TITLE_MAX_LEN - 1)
            )
        } else {
            r.title.clone()
        };
        let sev = if r.severity.is_empty() {
            "-"
        } else {
            &r.severity
        };
        let _ = writeln!(
            sb,
            "  {:<10}  {:.2}  {:<7}  {:<width$}  {}",
            r.short_name,
            r.relevance_score,
            sev,
            title,
            r.source_url,
            width = INCIDENT_TITLE_MAX_LEN
        );
    }
    sb
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_validated() {
        assert!(validate_format(&None).is_ok());
        assert!(validate_format(&Some("table".into())).is_ok());
        assert!(validate_format(&Some("json".into())).is_ok());
        let f = validate_format(&Some("yaml".into())).unwrap_err();
        assert_eq!(f.code, 2);
        assert_eq!(
            f.msg,
            "Error: invalid --format \"yaml\" (valid: table, json)"
        );
    }

    #[test]
    fn empty_results_render_no_incidents_line() {
        assert_eq!(format_search_table(&[]), "No incidents found.\n");
    }

    #[test]
    fn table_renders_columns_and_dashes_the_go_way() {
        let results = vec![IncidentSearchResult {
            short_name: "INC-1234".into(),
            title: "Redis failover".into(),
            severity: "sev1".into(),
            source_url: "https://example.com/pm".into(),
            relevance_score: 0.87,
            ..Default::default()
        }];
        let got = format_search_table(&results);
        let mut lines = got.lines();
        assert_eq!(
            lines.next().unwrap(),
            format!(
                "  {:<10}  {:<4}  {:<7}  {:<60}  Source",
                "ID", "Rel.", "Sev.", "Title"
            )
        );
        assert_eq!(
            lines.next().unwrap(),
            format!(
                "  {}  {}  {}  {}  {}",
                "-".repeat(10),
                "-".repeat(4),
                "-".repeat(7),
                "-".repeat(60),
                "-".repeat(6)
            )
        );
        let row = lines.next().unwrap();
        assert!(row.starts_with("  INC-1234    0.87  sev1   "), "{row}");
        assert!(row.ends_with("https://example.com/pm"), "{row}");
    }

    #[test]
    fn missing_severity_prints_dash() {
        let results = vec![IncidentSearchResult {
            short_name: "INC-1".into(),
            title: "T".into(),
            relevance_score: 0.5,
            ..Default::default()
        }];
        let got = format_search_table(&results);
        assert!(got.contains("  0.50  -      "), "{got}");
    }

    #[test]
    fn long_titles_truncate_with_ellipsis_at_60_bytes() {
        let results = vec![IncidentSearchResult {
            short_name: "INC-2".into(),
            title: "x".repeat(80),
            relevance_score: 0.9,
            ..Default::default()
        }];
        let got = format_search_table(&results);
        let want = format!("{}…", "x".repeat(59));
        assert!(got.contains(&want), "{got}");
        assert!(!got.contains(&"x".repeat(60)), "{got}");
    }

    #[test]
    fn truncation_respects_utf8_boundaries() {
        // 'é' is 2 bytes: 40 of them = 80 bytes; the 59-byte cut would land
        // mid-char and must back off instead of panicking.
        let results = vec![IncidentSearchResult {
            short_name: "INC-3".into(),
            title: "é".repeat(40),
            relevance_score: 0.9,
            ..Default::default()
        }];
        let got = format_search_table(&results);
        assert!(got.contains(&format!("{}…", "é".repeat(29))), "{got}");
    }
}
