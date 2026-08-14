//! Client-side finding normalization for scan submission (po-gli2z),
//! ported from rvl-cli `internal/commands/scan_normalize.go`.
//!
//! The STPA fields on scan findings (uca_type, causal_factors,
//! loss_scenario, loss_category, estimated_fix_complexity, constraint_type)
//! used to be guarded only by a transform step in the scan skill PROMPT,
//! which agents may skip. When skipped, type-mismatched fields either
//! killed the submit at the server boundary or were silently dropped
//! server-side, so a beta user's scans came back "green" while the STPA
//! view had no data.
//!
//! DESIGN DECISION (submit + warn, never silently drop, never reject the
//! finding): a finding whose STPA field cannot be coerced is still
//! submitted, with only the invalid field removed. Rejecting the whole
//! finding would recreate the original failure mode (valid reliability
//! data lost because of one malformed optional field), and failing the
//! scan would block CI on data that is advisory. Instead the loss is made
//! impossible to miss: a per-finding [dropped] line naming the finding and
//! field, an STPA-loss warning banner, and counts in the submit summary.

use crate::gojson::fmt_go_f64;
use serde_json::{json, Map, Value};

/// Mirrors the STPA field spec in the server-side scan skill ("STPA
/// fields"). Fixed iteration order (rvl-cli iterates a Go map; the set of
/// issues is identical, only their relative order is pinned here).
const STPA_ENUM_VALUES: &[(&str, &[&str])] = &[
    (
        "uca_type",
        &[
            "not_provided",
            "providing_incorrectly",
            "wrong_timing",
            "wrong_duration",
        ],
    ),
    ("loss_category", &["zero_tolerance", "error_budget_managed"]),
    ("estimated_fix_complexity", &["low", "medium", "high"]),
    ("constraint_type", &["primary", "secondary"]),
];

/// The full set of STPA fields; a dropped field in this set means STPA
/// data was lost and trips the warning banner.
const STPA_FIELD_SET: &[&str] = &[
    "uca_type",
    "causal_factors",
    "loss_scenario",
    "loss_category",
    "estimated_fix_complexity",
    "constraint_type",
];

fn is_stpa_field(field: &str) -> bool {
    STPA_FIELD_SET.contains(&field)
}

/// One per-finding normalization event: "coerced" or "dropped".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueAction {
    Coerced,
    Dropped,
}

impl IssueAction {
    fn as_str(self) -> &'static str {
        match self {
            IssueAction::Coerced => "coerced",
            IssueAction::Dropped => "dropped",
        }
    }
}

/// One per-finding normalization event.
#[derive(Debug, Clone)]
pub struct FindingIssue {
    /// 0-based index into the findings slice.
    pub index: usize,
    /// Finding title (or a positional fallback).
    pub title: String,
    pub field: String,
    pub action: IssueAction,
    pub detail: String,
}

/// Aggregated normalization results for the submit summary and the loss
/// banner.
#[derive(Debug, Default)]
pub struct FindingNormReport {
    pub total: usize,
    /// Findings carrying at least one STPA field.
    pub with_stpa: usize,
    /// Findings with >=1 coerced field.
    pub coerced_findings: usize,
    /// Findings with >=1 dropped field.
    pub dropped_findings: usize,
    /// Total dropped fields.
    pub dropped_fields: usize,
    pub issues: Vec<FindingIssue>,
}

impl FindingNormReport {
    /// Whether any STPA field was dropped (as opposed to coerced): the
    /// condition that means the product STPA view is missing data the
    /// agent produced.
    pub fn stpa_lost(&self) -> bool {
        self.issues
            .iter()
            .any(|is| is.action == IssueAction::Dropped && is_stpa_field(&is.field))
    }
}

/// Per-finding issue recorder (the Go version's `note` closure).
struct Recorder<'a> {
    index: usize,
    title: String,
    coerced: bool,
    dropped: usize,
    issues: &'a mut Vec<FindingIssue>,
}

impl Recorder<'_> {
    fn note(&mut self, action: IssueAction, field: &str, detail: String) {
        self.issues.push(FindingIssue {
            index: self.index,
            title: self.title.clone(),
            field: field.to_string(),
            action,
            detail,
        });
        match action {
            IssueAction::Coerced => self.coerced = true,
            IssueAction::Dropped => self.dropped += 1,
        }
    }
}

/// The Go `%T` spelling for a JSON value that went through `interface{}`,
/// so the stderr diagnostics match rvl-cli's.
fn go_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "<nil>",
        Value::Bool(_) => "bool",
        Value::Number(_) => "float64",
        Value::String(_) => "string",
        Value::Array(_) => "[]interface {}",
        Value::Object(_) => "map[string]interface {}",
    }
}

/// Go's `fmt.Sprint` for the scalar shapes the coercions stringify.
fn go_sprint(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => fmt_go_f64(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Validate and coerce known problem fields on raw findings in place.
/// Coercions: evidence string/[]string -> evidence objects, causal_factors
/// string -> array, loss_scenario array -> joined string, enum
/// casing/whitespace, numeric-as-string risk_score and evidence
/// line_number. Uncoercible fields are removed and recorded as dropped.
pub fn normalize_findings(findings: &mut [Value]) -> FindingNormReport {
    let mut rep = FindingNormReport {
        total: findings.len(),
        ..Default::default()
    };

    for (i, raw) in findings.iter_mut().enumerate() {
        let Some(m) = raw.as_object_mut() else {
            continue;
        };

        let mut title = m
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if title.is_empty() {
            title = format!("finding #{}", i + 1);
        }

        // Count STPA presence before any drop, so the summary reflects
        // what the agent produced, not what survived.
        if STPA_FIELD_SET
            .iter()
            .any(|f| m.get(*f).is_some_and(|v| !v.is_null()))
        {
            rep.with_stpa += 1;
        }

        let mut rec = Recorder {
            index: i,
            title,
            coerced: false,
            dropped: 0,
            issues: &mut rep.issues,
        };

        normalize_evidence(m, &mut rec);
        normalize_causal_factors(m, &mut rec);
        normalize_loss_scenario(m, &mut rec);
        normalize_stpa_enums(m, &mut rec);
        normalize_risk_score(m, &mut rec);

        if rec.coerced {
            rep.coerced_findings += 1;
        }
        if rec.dropped > 0 {
            rep.dropped_findings += 1;
            rep.dropped_fields += rec.dropped;
        }
    }
    rep
}

/// Coerce evidence emitted as a bare string or a string array into
/// evidence objects, and fix numeric-as-string line_number on evidence
/// objects.
fn normalize_evidence(m: &mut Map<String, Value>, rec: &mut Recorder) {
    match m.get("evidence") {
        Some(Value::String(s)) => {
            let s = s.clone();
            if s.is_empty() {
                m.insert("evidence".into(), Value::Array(vec![]));
            } else {
                m.insert(
                    "evidence".into(),
                    json!([{"type": "code", "description": s}]),
                );
            }
            rec.note(
                IssueAction::Coerced,
                "evidence",
                "bare string wrapped into evidence object array".into(),
            );
        }
        Some(Value::Array(_)) => {
            let Some(ev) = m.get_mut("evidence").and_then(Value::as_array_mut) else {
                return;
            };
            for (j, item) in ev.iter_mut().enumerate() {
                match item {
                    Value::String(it) => {
                        if it.is_empty() {
                            continue;
                        }
                        let desc = it.clone();
                        *item = json!({"type": "code", "description": desc});
                        rec.note(
                            IssueAction::Coerced,
                            "evidence",
                            format!("string item {j} wrapped into evidence object"),
                        );
                    }
                    Value::Object(it) => {
                        if let Some(Value::String(ln)) = it.get("line_number") {
                            let ln = ln.clone();
                            if let Ok(n) = ln.trim().parse::<i64>() {
                                it.insert("line_number".into(), Value::from(n));
                                rec.note(
                                    IssueAction::Coerced,
                                    "evidence",
                                    format!("line_number {ln:?} converted to number"),
                                );
                            } else {
                                it.remove("line_number");
                                rec.note(
                                    IssueAction::Dropped,
                                    "evidence",
                                    format!("non-numeric line_number {ln:?} removed"),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Coerce a bare-string causal_factors into a one-element array and
/// stringify scalar items; uncoercible shapes are removed and reported.
fn normalize_causal_factors(m: &mut Map<String, Value>, rec: &mut Recorder) {
    match m.get("causal_factors") {
        None | Some(Value::Null) => {}
        Some(Value::String(cf)) => {
            let cf = cf.clone();
            if cf.is_empty() {
                m.remove("causal_factors");
                return;
            }
            m.insert("causal_factors".into(), json!([cf]));
            rec.note(
                IssueAction::Coerced,
                "causal_factors",
                "bare string wrapped into array".into(),
            );
        }
        Some(Value::Array(cf)) => {
            let cf = cf.clone();
            let mut out = Vec::with_capacity(cf.len());
            for (j, item) in cf.iter().enumerate() {
                match item {
                    Value::String(_) => out.push(item.clone()),
                    Value::Number(_) | Value::Bool(_) => {
                        out.push(Value::String(go_sprint(item)));
                        rec.note(
                            IssueAction::Coerced,
                            "causal_factors",
                            format!("scalar item {j} stringified"),
                        );
                    }
                    _ => rec.note(
                        IssueAction::Dropped,
                        "causal_factors",
                        format!("item {j} is not a string ({}); removed", go_type_name(item)),
                    ),
                }
            }
            m.insert("causal_factors".into(), Value::Array(out));
        }
        Some(other) => {
            let t = go_type_name(other);
            rec.note(
                IssueAction::Dropped,
                "causal_factors",
                format!("expected array of strings, got {t}; removed"),
            );
            m.remove("causal_factors");
        }
    }
}

/// Coerce an array-of-strings loss_scenario into a joined string and
/// stringify scalars; other shapes are removed.
fn normalize_loss_scenario(m: &mut Map<String, Value>, rec: &mut Recorder) {
    match m.get("loss_scenario") {
        None | Some(Value::Null) | Some(Value::String(_)) => {}
        Some(Value::Array(ls)) => {
            let ls = ls.clone();
            let mut parts = Vec::with_capacity(ls.len());
            for item in &ls {
                let Value::String(s) = item else {
                    rec.note(
                        IssueAction::Dropped,
                        "loss_scenario",
                        format!(
                            "array contains non-string ({}); removed",
                            go_type_name(item)
                        ),
                    );
                    m.remove("loss_scenario");
                    return;
                };
                if !s.is_empty() {
                    parts.push(s.clone());
                }
            }
            m.insert("loss_scenario".into(), Value::String(parts.join("; ")));
            rec.note(
                IssueAction::Coerced,
                "loss_scenario",
                "string array joined into one string".into(),
            );
        }
        Some(v @ (Value::Number(_) | Value::Bool(_))) => {
            let s = go_sprint(v);
            m.insert("loss_scenario".into(), Value::String(s));
            rec.note(
                IssueAction::Coerced,
                "loss_scenario",
                "scalar stringified".into(),
            );
        }
        Some(other) => {
            let t = go_type_name(other);
            rec.note(
                IssueAction::Dropped,
                "loss_scenario",
                format!("expected string, got {t}; removed"),
            );
            m.remove("loss_scenario");
        }
    }
}

/// Lowercase/trim the four STPA enum fields, map spaces and hyphens to
/// underscores, and drop values outside the allowed sets with a
/// per-finding issue.
fn normalize_stpa_enums(m: &mut Map<String, Value>, rec: &mut Recorder) {
    for (field, allowed) in STPA_ENUM_VALUES {
        let Some(v) = m.get(*field) else { continue };
        if v.is_null() {
            continue;
        }
        let Value::String(s) = v else {
            let t = go_type_name(v);
            rec.note(
                IssueAction::Dropped,
                field,
                format!("expected string, got {t}; removed"),
            );
            m.remove(*field);
            continue;
        };
        let s = s.clone();
        let norm: String = s
            .trim()
            .to_lowercase()
            .chars()
            .map(|c| if c == ' ' || c == '-' { '_' } else { c })
            .collect();
        if norm.is_empty() {
            // Empty carries no data; removing it is not loss.
            m.remove(*field);
            continue;
        }
        if !allowed.contains(&norm.as_str()) {
            rec.note(
                IssueAction::Dropped,
                field,
                format!(
                    "invalid value {s:?} (expected {}); removed",
                    allowed.join("|")
                ),
            );
            m.remove(*field);
            continue;
        }
        if norm != s {
            m.insert((*field).into(), Value::String(norm.clone()));
            rec.note(
                IssueAction::Coerced,
                field,
                format!("{s:?} normalized to {norm:?}"),
            );
        }
    }
}

/// Fix numeric-as-string risk_score values.
fn normalize_risk_score(m: &mut Map<String, Value>, rec: &mut Recorder) {
    let Some(Value::String(s)) = m.get("risk_score") else {
        return;
    };
    let s = s.clone();
    let trimmed = s.trim();
    if let Ok(n) = trimmed.parse::<i64>() {
        m.insert("risk_score".into(), Value::from(n));
        rec.note(
            IssueAction::Coerced,
            "risk_score",
            format!("{s:?} converted to number"),
        );
        return;
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        m.insert("risk_score".into(), Value::from(f as i64));
        rec.note(
            IssueAction::Coerced,
            "risk_score",
            format!("{s:?} converted to number"),
        );
        return;
    }
    rec.note(
        IssueAction::Dropped,
        "risk_score",
        format!("non-numeric value {s:?} removed"),
    );
    m.remove("risk_score");
}

/// One stderr line per coerced/dropped field, naming the finding and field
/// (the user must be able to see exactly what changed or was lost).
pub fn print_normalization_issues(rep: &FindingNormReport) {
    for is in &rep.issues {
        eprintln!(
            "  [{}] finding #{} ({}): {}: {}",
            is.action.as_str(),
            is.index + 1,
            is.title,
            is.field,
            is.detail
        );
    }
}

/// The one-line counts for the submit summary: total findings, findings
/// with STPA fields, coerced, dropped.
pub fn normalization_summary(rep: &FindingNormReport) -> String {
    format!(
        "{} total, {} with STPA fields, {} coerced, {} with dropped field(s)",
        rep.total, rep.with_stpa, rep.coerced_findings, rep.dropped_findings
    )
}

/// The unmissable warning block when STPA data was dropped. Deliberately
/// loud: the original bug was a green scan with an empty STPA view.
pub fn print_stpa_loss_banner(rep: &FindingNormReport) {
    if !rep.stpa_lost() {
        return;
    }
    let line = "=".repeat(68);
    eprintln!("{line}");
    eprintln!("WARNING: STPA DATA LOST");
    eprintln!(
        "{} field(s) on {} finding(s) could not be coerced and were removed",
        rep.dropped_fields, rep.dropped_findings
    );
    eprintln!("before submission. The affected findings were submitted WITHOUT");
    eprintln!("that STPA data, so the STPA view will be missing it. See the");
    eprintln!("[dropped] lines above for the exact findings and fields; fix the");
    eprintln!("source JSON and re-submit to backfill.");
    eprintln!("{line}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ported from rvl-cli scan_normalize_test.go: same fixtures, same
    /// pinned contract (coerce where possible, drop only the invalid
    /// field, never the finding, never fail the scan).
    fn finding(overrides: &[(&str, Value)]) -> Value {
        let mut m = serde_json::json!({
            "component": "api",
            "title": "Missing timeout on outbound call",
            "category": "resilience",
            "likelihood": "high",
            "impact": "high",
            "narrative": "n",
            "risk_score": 61,
            "priority": "high",
        });
        for (k, v) in overrides {
            m[*k] = v.clone();
        }
        m
    }

    #[test]
    fn evidence_string_coerced() {
        let mut fs = vec![finding(&[(
            "evidence",
            Value::from("internal/api/handler.go:145 has no timeout"),
        )])];
        let rep = normalize_findings(&mut fs);

        let ev = fs[0]["evidence"].as_array().expect("evidence is array");
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0]["type"], "code");
        assert_eq!(
            ev[0]["description"],
            "internal/api/handler.go:145 has no timeout"
        );
        assert_eq!(rep.coerced_findings, 1);
        assert_eq!(rep.dropped_fields, 0);
    }

    #[test]
    fn evidence_string_items_coerced() {
        let mut fs = vec![finding(&[(
            "evidence",
            serde_json::json!([
                "bare string item",
                {"type": "code", "path": "a.go", "description": "ok"}
            ]),
        )])];
        let rep = normalize_findings(&mut fs);

        let ev = fs[0]["evidence"].as_array().unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0]["description"], "bare string item");
        assert_eq!(ev[0]["type"], "code");
        assert_eq!(rep.coerced_findings, 1);
    }

    #[test]
    fn evidence_line_number_string_coerced() {
        let mut fs = vec![finding(&[(
            "evidence",
            serde_json::json!([{"type": "code", "path": "a.go", "line_number": "145"}]),
        )])];
        let rep = normalize_findings(&mut fs);

        assert_eq!(fs[0]["evidence"][0]["line_number"], 145);
        assert_eq!(rep.coerced_findings, 1);
    }

    #[test]
    fn causal_factors_string_coerced() {
        let mut fs = vec![finding(&[
            ("uca_type", Value::from("not_provided")),
            (
                "causal_factors",
                Value::from("single factor as bare string"),
            ),
        ])];
        let rep = normalize_findings(&mut fs);

        let cf = fs[0]["causal_factors"].as_array().unwrap();
        assert_eq!(cf.len(), 1);
        assert_eq!(cf[0], "single factor as bare string");
        assert_eq!(rep.with_stpa, 1);
        assert_eq!(rep.coerced_findings, 1);
        assert!(!rep.stpa_lost(), "coercion is not loss");
    }

    #[test]
    fn enum_casing_coerced() {
        let mut fs = vec![finding(&[
            ("uca_type", Value::from("Not Provided")),
            ("loss_category", Value::from("ZERO_TOLERANCE")),
            ("estimated_fix_complexity", Value::from(" Medium ")),
            ("constraint_type", Value::from("Primary")),
        ])];
        let rep = normalize_findings(&mut fs);

        for (field, want) in [
            ("uca_type", "not_provided"),
            ("loss_category", "zero_tolerance"),
            ("estimated_fix_complexity", "medium"),
            ("constraint_type", "primary"),
        ] {
            assert_eq!(fs[0][field], want, "{field}");
        }
        assert_eq!(rep.coerced_findings, 1);
        assert!(!rep.stpa_lost());
    }

    #[test]
    fn invalid_enum_dropped_with_issue() {
        let mut fs = vec![finding(&[
            ("uca_type", Value::from("banana")),
            ("loss_category", Value::from("zero_tolerance")),
        ])];
        let rep = normalize_findings(&mut fs);

        assert!(fs[0].get("uca_type").is_none(), "invalid uca_type removed");
        assert_eq!(fs[0]["loss_category"], "zero_tolerance");
        assert_eq!(rep.dropped_fields, 1);
        assert!(rep.stpa_lost(), "an STPA field was dropped");
        // The issue must name the finding and the field so the user can
        // see exactly what was lost.
        let issue = &rep.issues[0];
        assert_eq!(issue.field, "uca_type");
        assert_eq!(issue.action, IssueAction::Dropped);
        assert!(issue.title.contains("Missing timeout"), "{}", issue.title);
        assert!(issue.detail.contains("banana"), "{}", issue.detail);
        assert!(issue.detail.contains("not_provided"), "{}", issue.detail);
    }

    #[test]
    fn all_enum_fields_validated() {
        let mut fs = vec![finding(&[
            ("uca_type", Value::from("wrong_timing")),
            ("loss_category", Value::from("sometimes_bad")), // invalid
            ("estimated_fix_complexity", Value::from("extreme")), // invalid
            ("constraint_type", Value::from("tertiary")),    // invalid
        ])];
        let rep = normalize_findings(&mut fs);

        assert_eq!(rep.dropped_fields, 3, "issues: {:?}", rep.issues);
        assert_eq!(fs[0]["uca_type"], "wrong_timing", "valid value survives");
        for field in [
            "loss_category",
            "estimated_fix_complexity",
            "constraint_type",
        ] {
            assert!(fs[0].get(field).is_none(), "invalid {field} removed");
        }
    }

    #[test]
    fn loss_scenario_array_joined() {
        let mut fs = vec![finding(&[(
            "loss_scenario",
            serde_json::json!(["step one", "step two"]),
        )])];
        let rep = normalize_findings(&mut fs);

        let ls = fs[0]["loss_scenario"].as_str().unwrap();
        assert!(ls.contains("step one") && ls.contains("step two"), "{ls}");
        assert_eq!(rep.coerced_findings, 1);
    }

    #[test]
    fn risk_score_string_coerced() {
        let mut fs = vec![finding(&[("risk_score", Value::from("82"))])];
        let rep = normalize_findings(&mut fs);
        assert_eq!(fs[0]["risk_score"], 82);
        assert_eq!(rep.coerced_findings, 1);
    }

    #[test]
    fn uncoercible_causal_factors_dropped() {
        let mut fs = vec![finding(&[(
            "causal_factors",
            serde_json::json!({"not": "an array"}),
        )])];
        let rep = normalize_findings(&mut fs);

        assert!(fs[0].get("causal_factors").is_none());
        assert_eq!(rep.dropped_fields, 1);
        assert!(rep.stpa_lost());
    }

    #[test]
    fn report_counts() {
        let clean = finding(&[]); // no STPA, nothing to coerce
        let stpa_clean = finding(&[
            ("uca_type", Value::from("not_provided")),
            ("causal_factors", serde_json::json!(["a", "b"])),
            ("loss_scenario", Value::from("scenario")),
        ]);
        let stpa_coerced = finding(&[
            ("uca_type", Value::from("Wrong Timing")),
            ("causal_factors", Value::from("bare string")),
        ]);
        let stpa_dropped = finding(&[("uca_type", Value::from("invalid_enum_value"))]);

        let mut fs = vec![clean, stpa_clean, stpa_coerced, stpa_dropped];
        let rep = normalize_findings(&mut fs);

        assert_eq!(rep.total, 4);
        assert_eq!(rep.with_stpa, 3);
        assert_eq!(rep.coerced_findings, 1);
        assert_eq!(rep.dropped_findings, 1);
        assert_eq!(rep.dropped_fields, 1);
    }

    #[test]
    fn valid_finding_untouched() {
        let mut fs = vec![finding(&[
            ("uca_type", Value::from("providing_incorrectly")),
            ("causal_factors", serde_json::json!(["factor"])),
            ("loss_scenario", Value::from("a scenario")),
            ("loss_category", Value::from("error_budget_managed")),
            ("estimated_fix_complexity", Value::from("low")),
            ("constraint_type", Value::from("secondary")),
            (
                "evidence",
                serde_json::json!([{"type": "code", "path": "a.go", "line_number": 10}]),
            ),
        ])];
        let rep = normalize_findings(&mut fs);

        assert!(rep.issues.is_empty(), "issues: {:?}", rep.issues);
        assert_eq!(rep.coerced_findings, 0);
        assert_eq!(rep.dropped_fields, 0);
        assert_eq!(rep.with_stpa, 1);
    }

    #[test]
    fn non_map_entries_skipped() {
        let mut fs = vec![
            Value::from("not a map"),
            Value::from(3.0),
            Value::Null,
            finding(&[]),
        ];
        let rep = normalize_findings(&mut fs);
        assert_eq!(rep.total, 4);
        assert!(!rep.stpa_lost());
    }

    #[test]
    fn empty_enum_removed_silently() {
        // An empty string carries no data: removing it is not loss and
        // must not trip the loss banner.
        let mut fs = vec![finding(&[("uca_type", Value::from(""))])];
        let rep = normalize_findings(&mut fs);
        assert!(fs[0].get("uca_type").is_none());
        assert!(!rep.stpa_lost());
        assert_eq!(rep.dropped_fields, 0);
    }
}
