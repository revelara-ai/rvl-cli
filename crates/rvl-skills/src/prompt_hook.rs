//! The Claude Code `UserPromptSubmit` hook `rvl plugin install` adds to the
//! plugin it stages: each prompt gets one reminder to run `rvl factor
//! lookup` before a file changes. A context file alone left the lookup to
//! the model's memory, and in sessions it was skipped; the reminder arrives
//! with every prompt instead.
//!
//! The hook only reminds. It never blocks (no PreToolUse deny, no exit code
//! 2), makes no network call and runs no `rvl` process: the command is a
//! shell `echo` of a fixed JSON line, so it costs one shell start.
//!
//! The reminder text has one source, the first line of the "Causal
//! factors" block of the managed AGENTS.md template.

use serde_json::{json, Value};

/// Plugin-relative path of the hooks file Claude Code reads from a plugin.
pub const HOOKS_JSON: &str = "hooks/hooks.json";

/// The managed AGENTS.md template the reminder is read from.
const AGENTS_MD: &str = include_str!("../../rvl/src/context/AGENTS.md");

/// The heading line whose first bullet is the reminder.
const CAUSAL_FACTORS_HEADING: &str = "**Causal factors:**";

/// The reminder: the first bullet under the "Causal factors" heading of the
/// AGENTS.md template, without its `- ` marker. A test pins that the
/// template has one, so the empty fallback is never installed.
pub fn reminder() -> &'static str {
    let mut lines = AGENTS_MD.lines();
    lines
        .find(|l| l.trim() == CAUSAL_FACTORS_HEADING)
        .and_then(|_| lines.next())
        .and_then(|l| l.trim().strip_prefix("- "))
        .unwrap_or_default()
}

/// The JSON line the hook prints: Claude Code adds `additionalContext` to
/// the prompt.
pub fn hook_output() -> String {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "UserPromptSubmit",
            "additionalContext": reminder(),
        }
    })
    .to_string()
}

/// The hook command: a shell `echo` of [`hook_output`] in single quotes.
pub fn hook_command() -> String {
    let output = hook_output();
    debug_assert!(!output.contains('\''), "single quote breaks the quoting");
    format!("echo '{output}'")
}

/// The plugin's `hooks/hooks.json`: `existing` (the downloaded plugin's own
/// file, when it ships one) with the reminder hook added to its
/// `UserPromptSubmit` list, once.
pub fn hooks_json(existing: Option<&[u8]>) -> anyhow::Result<Vec<u8>> {
    let mut doc: Value = match existing {
        Some(bytes) => serde_json::from_slice(bytes)
            .map_err(|e| anyhow::anyhow!("plugin {HOOKS_JSON} is not valid JSON: {e}"))?,
        None => json!({}),
    };
    let command = hook_command();
    let Some(events) = doc
        .as_object_mut()
        .map(|o| o.entry("hooks").or_insert_with(|| json!({})))
        .and_then(Value::as_object_mut)
    else {
        anyhow::bail!("plugin {HOOKS_JSON} has no \"hooks\" object");
    };
    let Some(matchers) = events
        .entry("UserPromptSubmit")
        .or_insert_with(|| json!([]))
        .as_array_mut()
    else {
        anyhow::bail!("plugin {HOOKS_JSON} has a UserPromptSubmit that is not a list");
    };
    let present = matchers
        .iter()
        .filter_map(|m| m["hooks"].as_array())
        .flatten()
        .any(|h| h["command"] == command.as_str());
    if !present {
        matchers.push(json!({
            "hooks": [{ "type": "command", "command": command, "timeout": 5 }]
        }));
    }
    let mut out = serde_json::to_vec_pretty(&doc)?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reminder_is_the_first_causal_factors_line_of_agents_md() {
        let template = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rvl/src/context/AGENTS.md"
        ))
        .unwrap();
        let lines: Vec<&str> = template.lines().collect();
        let at = lines
            .iter()
            .position(|l| l.trim() == CAUSAL_FACTORS_HEADING)
            .expect("AGENTS.md has a Causal factors block");
        assert_eq!(format!("- {}", reminder()), lines[at + 1].trim());
        assert!(
            reminder().starts_with("`rvl factor lookup \"<what the change does>\"`"),
            "{}",
            reminder()
        );
        assert!(reminder().contains("before you change a file"));
    }

    #[test]
    fn hook_output_is_claude_code_additional_context() {
        let out: Value = serde_json::from_str(&hook_output()).unwrap();
        assert_eq!(
            out["hookSpecificOutput"]["hookEventName"],
            "UserPromptSubmit"
        );
        assert_eq!(out["hookSpecificOutput"]["additionalContext"], reminder());
        assert!(!hook_output().contains('\''));
        assert!(!hook_output().contains('\n'));
    }

    #[test]
    fn hooks_json_adds_the_reminder_once_and_keeps_other_hooks() {
        let fresh: Value = serde_json::from_slice(&hooks_json(None).unwrap()).unwrap();
        let hooks = &fresh["hooks"]["UserPromptSubmit"][0]["hooks"];
        assert_eq!(hooks[0]["type"], "command");
        assert_eq!(hooks[0]["command"], hook_command().as_str());
        assert_eq!(
            fresh["hooks"].as_object().unwrap().len(),
            1,
            "no other event"
        );

        // Merging into a file that already has it does not add a copy.
        let again: Value = serde_json::from_slice(
            &hooks_json(Some(&serde_json::to_vec(&fresh).unwrap())).unwrap(),
        )
        .unwrap();
        assert_eq!(again, fresh);

        let shipped = br#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"true"}]}],
            "UserPromptSubmit":[{"hooks":[{"type":"command","command":"other"}]}]}}"#;
        let merged: Value = serde_json::from_slice(&hooks_json(Some(shipped)).unwrap()).unwrap();
        assert_eq!(merged["hooks"]["Stop"][0]["hooks"][0]["command"], "true");
        let ups = merged["hooks"]["UserPromptSubmit"].as_array().unwrap();
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0]["hooks"][0]["command"], "other");
        assert_eq!(ups[1]["hooks"][0]["command"], hook_command().as_str());

        assert!(hooks_json(Some(b"not json")).is_err());
        assert!(hooks_json(Some(br#"{"hooks":[]}"#)).is_err());
    }
}
