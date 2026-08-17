//! Human-output helpers ported from rvl-cli's `internal/display`.
//! Human-readable output is allowed to improve, but these keep the table
//! renders familiar during the migration.

/// `[STATUS]` badge for a risk status.
pub fn format_status(status: &str) -> String {
    format!("[{}]", status.to_uppercase())
}

/// `[TYPE]` badge for a control type.
pub fn format_control_type(control_type: &str) -> String {
    format!("[{}]", control_type.to_uppercase())
}

/// Human tier label for a control weight (1-10).
pub fn format_weight_tier(weight: i64) -> &'static str {
    match weight {
        w if w >= 9 => "Critical",
        w if w >= 7 => "Required",
        w if w >= 5 => "Important",
        w if w >= 3 => "Recommended",
        _ => "Advisory",
    }
}

/// snake_case -> Title Case.
pub fn format_category(category: &str) -> String {
    category
        .split('_')
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(first) => first.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Validation-status badge for knowledge facts.
pub fn format_validation_status(status: &str) -> String {
    match status {
        "analyst_validated" => "[VALIDATED]".to_string(),
        "auto_extracted" => "[AUTO]".to_string(),
        _ => format!("[{}]", status.to_uppercase()),
    }
}

/// Evidence-status badge.
pub fn format_evidence_status(status: &str) -> String {
    match status {
        "not_configured" => "[NOT CONFIGURED]".to_string(),
        _ => format!("[{}]", status.to_uppercase()),
    }
}

/// Flatten newlines and truncate to `max_len` (in bytes, like the Go
/// original) with an ellipsis, never splitting a UTF-8 character.
pub fn truncate_text(text: &str, max_len: usize) -> String {
    let flat = text.replace('\n', " ");
    if flat.len() <= max_len {
        return flat;
    }
    if max_len < 3 {
        return cut_at_boundary(&flat, max_len).to_string();
    }
    format!("{}...", cut_at_boundary(&flat, max_len - 3))
}

/// Truncate to at most `n` bytes on a char boundary (the Go code slices
/// bytes; Rust must not split a code point).
pub fn cut_at_boundary(s: &str, n: usize) -> &str {
    if s.len() <= n {
        return s;
    }
    let mut end = n;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Title truncation used across the risk tables: cut to `n` bytes and
/// append "..." when the original was longer.
pub fn truncate_title(s: &str, n: usize) -> String {
    if s.len() > n {
        format!("{}...", cut_at_boundary(s, n))
    } else {
        s.to_string()
    }
}

/// Word-wrap `text` to `width`, joining lines with `\n` + `indent`
/// (matches display.WrapText).
pub fn wrap_text(text: &str, width: usize, indent: &str) -> String {
    let words: Vec<&str> = text.split_whitespace().collect();
    if words.is_empty() {
        return String::new();
    }
    let budget = width.saturating_sub(indent.len());
    let mut lines: Vec<String> = Vec::new();
    let mut current = words[0].to_string();
    for word in &words[1..] {
        if current.len() + 1 + word.len() <= budget {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(current);
            current = word.to_string();
        }
    }
    lines.push(current);
    lines.join(&format!("\n{indent}"))
}

/// UCA type for human display (underscores to spaces, Title Case).
pub fn format_uca_type(uca_type: &str) -> String {
    uca_type
        .replace('_', " ")
        .split(' ')
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(first) => first.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// STPA markers parsed out of an enriched narrative.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StpaContext {
    pub uca_type: String,
    pub loss_scenario: String,
    pub causal_factors: Vec<String>,
    /// The narrative with the marker blocks removed.
    pub clean_narrative: String,
}

const UCA_MARKER: &str = "**Unsafe Control Action:**";
const LOSS_MARKER: &str = "**Loss Scenario:**";
const FACTORS_MARKER: &str = "**Causal Factors:**";

/// The marker's whole match (marker + leading whitespace + rest of that
/// line) and the captured tail, mirroring Go's
/// `\*\*Marker:\*\*\s*(.+)`: `\s*` is greedy and crosses newlines, `.`
/// does not, so the capture is the first non-blank line after the marker.
fn match_marker_line<'a>(text: &'a str, marker: &str) -> Option<(&'a str, &'a str)> {
    let start = text.find(marker)?;
    let after = start + marker.len();
    let rest = &text[after..];
    let ws = rest.len() - rest.trim_start().len();
    let tail = &rest[ws..];
    if tail.is_empty() {
        return None;
    }
    let line_end = tail.find('\n').unwrap_or(tail.len());
    let line = &tail[..line_end];
    Some((&text[start..after + ws + line_end], line.trim()))
}

/// Extract STPA markers from an enriched narrative; `None` when the
/// narrative carries none (rvl-cli `display.ParseSTPAContext`).
pub fn parse_stpa_context(narrative: &str) -> Option<StpaContext> {
    if narrative.is_empty() {
        return None;
    }
    let mut ctx = StpaContext::default();
    let mut clean = narrative.to_string();

    if let Some((whole, captured)) = match_marker_line(narrative, UCA_MARKER) {
        ctx.uca_type = captured.to_string();
        clean = clean.replacen(whole, "", 1);
    }
    if let Some((whole, captured)) = match_marker_line(narrative, LOSS_MARKER) {
        ctx.loss_scenario = captured.to_string();
        clean = clean.replacen(whole, "", 1);
    }
    if let Some(at) = narrative.find(FACTORS_MARKER) {
        let block = &narrative[at + FACTORS_MARKER.len()..];
        clean = clean.replacen(&narrative[at..], "", 1);
        for line in block.split('\n') {
            if let Some(item) = line.trim().strip_prefix("- ") {
                ctx.causal_factors.push(item.to_string());
            }
        }
    }

    if ctx.uca_type.is_empty() && ctx.loss_scenario.is_empty() && ctx.causal_factors.is_empty() {
        return None;
    }
    ctx.clean_narrative = clean.trim().to_string();
    Some(ctx)
}

/// The STPA causal question a UCA type answers.
pub fn format_uca_category(uca_type: &str) -> &'static str {
    match uca_type.to_lowercase().replace(' ', "_").as_str() {
        "not_provided" => "What control is missing?",
        "providing_incorrectly" => "What assumption is wrong?",
        "wrong_timing" => "What feedback is delayed?",
        "wrong_duration" => "What enforcement is bypassed?",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_title_case() {
        assert_eq!(format_category("fault_tolerance"), "Fault Tolerance");
        assert_eq!(format_category("monitoring"), "Monitoring");
    }

    #[test]
    fn truncate_respects_utf8_boundaries() {
        // 'é' is 2 bytes; cutting mid-char must back off, not panic.
        let s = "ééééé"; // 10 bytes
        assert_eq!(cut_at_boundary(s, 3), "é");
        assert_eq!(truncate_title("ééééé", 5), "éé...");
        assert_eq!(truncate_title("short", 47), "short");
    }

    #[test]
    fn wrap_matches_go_shape() {
        assert_eq!(
            wrap_text("one two three four", 9, ""),
            "one two\nthree\nfour"
        );
        assert_eq!(wrap_text("", 10, ""), "");
    }

    #[test]
    fn weight_tiers() {
        assert_eq!(format_weight_tier(10), "Critical");
        assert_eq!(format_weight_tier(7), "Required");
        assert_eq!(format_weight_tier(5), "Important");
        assert_eq!(format_weight_tier(3), "Recommended");
        assert_eq!(format_weight_tier(1), "Advisory");
    }

    #[test]
    fn stpa_context_parses_all_three_markers() {
        // The exact fixture rvl-cli's display tests use.
        let narrative = "This service lacks circuit breakers on external API calls.\n\
**Unsafe Control Action:** not_provided\n\
**Loss Scenario:** Cascading failure when payment provider is unavailable\n\
**Causal Factors:**\n\
- inadequate feedback: no monitoring on retry rates\n\
- incorrect process model: assumes external services are always available";
        let ctx = parse_stpa_context(narrative).expect("markers present");
        assert_eq!(ctx.uca_type, "not_provided");
        assert_eq!(
            ctx.loss_scenario,
            "Cascading failure when payment provider is unavailable"
        );
        assert_eq!(
            ctx.causal_factors,
            vec![
                "inadequate feedback: no monitoring on retry rates".to_string(),
                "incorrect process model: assumes external services are always available"
                    .to_string(),
            ]
        );
        // The markers are stripped; the prose survives.
        assert_eq!(
            ctx.clean_narrative,
            "This service lacks circuit breakers on external API calls."
        );
    }

    #[test]
    fn stpa_context_is_none_without_markers_or_content() {
        assert!(parse_stpa_context("A plain narrative with no STPA markers.").is_none());
        assert!(parse_stpa_context("").is_none());
    }

    #[test]
    fn stpa_context_tolerates_a_single_marker() {
        let ctx = parse_stpa_context("prose\n**Loss Scenario:** everything burns").unwrap();
        assert_eq!(ctx.loss_scenario, "everything burns");
        assert!(ctx.uca_type.is_empty());
        assert!(ctx.causal_factors.is_empty());
        assert_eq!(ctx.clean_narrative, "prose");
    }
}
