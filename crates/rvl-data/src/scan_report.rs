//! `rvl scan report <engine-doc>`: the sections of the scan report that are
//! pure data, in the Markdown of the scan skill's report.
//!
//! The skill copied these rows by hand from the scan document (`rvl scan
//! --out`) into a template. This command prints them, so the skill writes
//! only the sections that need judgment: the lens findings, the adjudicated
//! sites, the recommended actions. Three sections are data:
//!
//! - Gate: every engine row, in the section the engine put it in. A row is
//!   never reworded, and never left out: a suppressed row is shown with a
//!   flag.
//! - Coverage: the engine line and the language roll-call.
//! - Not Assessable From Code: the practice controls among the control codes
//!   that the findings files submit, with the interview that covers each.

use crate::scan_digest::{check_schema, field, list, py_str, read_json, truthy};
use crate::scan_finalize::findings_files;
use anyhow::{anyhow, bail, Result};
use serde_json::Value;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

/// The sections of the gate, in report order: the `severity` of a row, and
/// the heading of its section.
const SECTIONS: [(&str, &str); 3] = [
    ("blocking", "BLOCKING"),
    ("advisory", "ADVISORY"),
    ("suppressed", "SUPPRESSED"),
];

/// The abstain levers of `coverage.abstain`, in report order.
const LEVERS: [&str; 4] = ["no_spec", "bounds", "judge", "other"];

/// Controls that are practices (schedules, documents, habits), which a code
/// scan cannot evidence, and the interview skill that assesses each group.
const PRACTICE_ROUTING: [(&str, &[&str]); 5] = [
    ("/rvl:assess-alert-hygiene", &["RC-003", "RC-004", "RC-029"]),
    (
        "/rvl:assess-incident-readiness",
        &["RC-005", "RC-007", "RC-008", "RC-066", "RC-068"],
    ),
    (
        "/rvl:assess-incident-learning",
        &["RC-009", "RC-010", "RC-011", "RC-038", "RC-065"],
    ),
    (
        "/rvl:assess-recovery-readiness",
        &["RC-031", "RC-032", "RC-071"],
    ),
    (
        "/rvl:assess-reliability-governance",
        &["RC-012", "RC-039", "RC-047", "RC-072"],
    ),
];

fn count(v: &Value, key: &str, what: &str) -> Result<u64> {
    field(v, key, what)?
        .as_u64()
        .ok_or_else(|| anyhow!("\"{key}\" of {what} is not a count"))
}

/// One row of the gate. The five fields are the engine's text, unchanged.
fn gate_row(x: &Value, what: &str, section: &str) -> Result<String> {
    let text = |key: &str| field(x, key, what).map(py_str);
    let id = text("id")?;
    let mut row = format!(
        "  [{id}] {} — {} · {} · fix: {}",
        text("class")?,
        text("site")?,
        text("control")?,
        text("fix")?,
    );
    let flag = |key: &str| x.get(key).is_some_and(truthy);
    if flag("suppressed") {
        row.push_str(" (suppressed)");
    } else if section == "suppressed" {
        // The engine keeps a row it judged low value out of the gate with no
        // waiver. Say so, or the row reads as one that a person waived.
        row.push_str(" (low value)");
    }
    if flag("gate_exempt") {
        row.push_str(" (gate-exempt)");
    }
    row.push('\n');
    if section == "blocking" {
        writeln!(
            row,
            "    waive: `rvl suppress {id} --reason=\"...\"` or a `# rvl:allow` comment on the line"
        )?;
    }
    Ok(row)
}

fn gate(doc: &Value, s: &mut String) -> Result<()> {
    const DOC: &str = "the scan document";
    let mut rows: [Vec<String>; 3] = Default::default();
    for (i, x) in list(doc, "findings", DOC)?.iter().enumerate() {
        let what = format!("finding {} of {DOC}", i + 1);
        let severity = field(x, "severity", &what)?;
        let Some(n) = SECTIONS
            .iter()
            .position(|(name, _)| severity.as_str() == Some(name))
        else {
            // No section to print it in, and a row is never dropped.
            bail!(
                "{what} has severity {}; this command prints blocking, advisory and suppressed rows and does not drop another",
                py_str(severity)
            );
        };
        rows[n].push(gate_row(x, &what, SECTIONS[n].0)?);
    }
    writeln!(
        s,
        "### Gate (deterministic engine) — exit {}",
        py_str(field(doc, "exit", DOC)?)
    )?;
    for ((_, heading), rows) in SECTIONS.iter().zip(&rows) {
        writeln!(s, "{heading} ({}):", rows.len())?;
        rows.iter().for_each(|row| s.push_str(row));
    }
    Ok(())
}

/// One language of the roll-call, as the COVERAGE block of `rvl scan` words
/// it (`render_lang_status`).
fn lang_part(x: &Value, what: &str) -> Result<String> {
    let text = |key: &str| field(x, key, what).map(py_str);
    let (lang, state, detail) = (text("lang")?, text("state")?, text("detail")?);
    Ok(match state.as_str() {
        "scanned" => format!("{lang} {detail} sites"),
        "partial" => format!("{lang} {detail}"),
        "abstained" => format!("{lang} abstained"),
        "failed" => format!("{lang} FAILED"),
        "unsupported" => format!("{lang} not supported ({detail})"),
        "not_installed" => format!("{lang} helper not installed"),
        "skipped" => {
            format!("{lang} skipped ({detail}, test material only; --include-tests scans it)")
        }
        // A state added after this build: show what the document says.
        other => format!("{lang} {other} ({detail})"),
    })
}

fn coverage(doc: &Value, s: &mut String) -> Result<()> {
    const COV: &str = "\"coverage\"";
    let cov = field(doc, "coverage", "the scan document")?;
    let resolved = count(cov, "resolved", COV)?;
    let total = count(cov, "total", COV)?;
    // The denominator is the sites the extractors retrieved, not every call
    // in the repository, so the percentage is always quoted with it.
    let pct = match total {
        0 => "nothing retrieved".to_string(),
        _ => format!("{}% of retrieved", resolved.saturating_mul(100) / total),
    };
    let abstain = field(cov, "abstain", COV)?;
    let levers = LEVERS
        .iter()
        .map(|lever| {
            Ok(format!(
                "{lever} {}",
                count(abstain, lever, "\"coverage.abstain\"")?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let langs = list(cov, "lang_status", COV)?
        .iter()
        .enumerate()
        .map(|(i, x)| {
            lang_part(
                x,
                &format!("language {} of \"coverage.lang_status\"", i + 1),
            )
        })
        .collect::<Result<Vec<_>>>()?;

    writeln!(s, "\n### Coverage")?;
    writeln!(
        s,
        "Engine: {resolved}/{total} retrieved API surfaces resolved ({pct}) · abstains: {}",
        levers.join(" · ")
    )?;
    if langs.is_empty() {
        // An incremental scan reuses its index and runs no roll-call.
        writeln!(
            s,
            "Languages: (the scan document has no language roll-call)"
        )?;
    } else {
        writeln!(s, "Languages: {}", langs.join(" · "))?;
    }
    Ok(())
}

/// Every control code of the findings files of `scan_dir`: what `rvl scan
/// --scan-dir` submits.
fn submitted_codes(scan_dir: &Path) -> Result<Vec<String>> {
    let files = findings_files(scan_dir)?;
    if files.is_empty() {
        bail!(
            "{} has no 03-findings-*.json; run `rvl scan finalize` on it first",
            scan_dir.display()
        );
    }
    let mut codes = Vec::new();
    for path in files {
        let doc = read_json(&path)?;
        for x in list(&doc, "findings", &path.display().to_string())? {
            if let Some(Value::Array(row)) = x.get("control_codes") {
                codes.extend(row.iter().map(py_str));
            }
        }
    }
    Ok(codes)
}

/// The rows of the routing table that `codes` touch, each with only the
/// codes that are present. No section when no practice control is touched.
fn routing(codes: &[String], s: &mut String) -> Result<()> {
    let rows: Vec<(&str, Vec<&str>)> = PRACTICE_ROUTING
        .iter()
        .filter_map(|(skill, controls)| {
            let touched: Vec<&str> = controls
                .iter()
                .copied()
                .filter(|c| codes.iter().any(|code| code == c))
                .collect();
            (!touched.is_empty()).then_some((*skill, touched))
        })
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    writeln!(s, "\n### Not Assessable From Code")?;
    writeln!(
        s,
        "These gaps touch practice controls that only the team can attest to; run the interview:"
    )?;
    for (skill, touched) in rows {
        writeln!(s, "- `{skill}` ({})", touched.join(", "))?;
    }
    Ok(())
}

/// Print the data sections of the report of `engine_doc` to `out`, with the
/// practice-control routing rows when `scan_dir` is given. Nothing is printed
/// when an input is refused.
pub fn run(engine_doc: &Path, scan_dir: Option<&Path>, out: &mut dyn Write) -> Result<()> {
    let doc = read_json(engine_doc)?;
    check_schema(&doc, engine_doc)?;

    let mut s = String::new();
    gate(&doc, &mut s)?;
    coverage(&doc, &mut s)?;
    if let Some(dir) = scan_dir {
        routing(&submitted_codes(dir)?, &mut s)?;
    }
    out.write_all(s.as_bytes())?;
    Ok(())
}
