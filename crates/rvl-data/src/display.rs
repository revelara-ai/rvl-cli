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
}
