//! RC-006 runbook-currency facts: each runbook's YAML front matter, the
//! CODEOWNERS rule that owns its path, and the committed repository rulesets
//! that require review. RETRIEVAL only, like the rest of the inventory: an
//! owner is recorded as named or not, never by name.
//!
//! CODEOWNERS and ruleset semantics follow GitHub's documentation: the first
//! CODEOWNERS file of `.github/`, the root and `docs/` is the one in effect;
//! the last matching pattern wins; a pattern with no owners leaves its paths
//! unowned; `!` negation and `[ ]` ranges are unsupported (the line is
//! skipped); a pattern that starts with `#` is escaped as `\#`. A ruleset is
//! the JSON GitHub exports: `target`, `enforcement`,
//! `conditions.ref_name.include`/`exclude` and a `rules` array whose
//! `pull_request` entry carries `require_code_owner_review` and
//! `required_approving_review_count`.

use crate::RulesetFacts;
use rvl_core::civil::{civil_from_days, days_from_civil};
use serde_yaml::Value;

/// Front-matter keys that name a runbook's owner.
const OWNER_KEYS: &[&str] = &["owner", "owners", "owner_slack"];

/// Front-matter keys that date a runbook's last review or test.
const REVIEW_KEYS: &[&str] = &["last_reviewed", "last_reviewed_on", "tested_on"];

/// CODEOWNERS locations in the order GitHub searches them; the first found is
/// the one in effect.
pub(crate) const CODEOWNERS_PATHS: &[&str] =
    &[".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"];

/// Ref names a ruleset's `ref_name.include` uses for the default branch: the
/// two special values GitHub defines, and the two conventional default-branch
/// names, since a checkout does not say which branch is the default.
const DEFAULT_BRANCH_REFS: &[&str] = &[
    "~DEFAULT_BRANCH",
    "~ALL",
    "refs/heads/main",
    "refs/heads/master",
];

/// A markdown file name that indexes a runbook directory rather than being a
/// runbook.
pub(crate) fn is_index(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("readme") || lower == "index.md" || lower == "_index.md"
}

/// Whether the front matter names an owner, and its latest valid review date.
/// A file with no `---` front-matter block names neither.
pub(crate) fn front_matter(text: &str) -> (bool, Option<String>) {
    let mut lines = text.trim_start_matches('\u{feff}').lines();
    if lines.next().map(str::trim_end) != Some("---") {
        return (false, None);
    }
    let mut block = String::new();
    let mut closed = false;
    for line in lines {
        if matches!(line.trim_end(), "---" | "...") {
            closed = true;
            break;
        }
        block.push_str(line);
        block.push('\n');
    }
    let Some(doc) = closed
        .then(|| serde_yaml::from_str::<Value>(&block).ok())
        .flatten()
    else {
        return (false, None);
    };
    let owner = OWNER_KEYS
        .iter()
        .any(|k| doc.get(k).is_some_and(names_someone));
    let reviewed = REVIEW_KEYS
        .iter()
        .filter_map(|k| doc.get(k).and_then(Value::as_str))
        .filter(|d| is_date(d))
        .max()
        .map(str::to_string);
    (owner, reviewed)
}

fn names_someone(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.trim().is_empty(),
        Value::Sequence(items) => items.iter().any(names_someone),
        _ => false,
    }
}

/// A real calendar date spelled YYYY-MM-DD (2026-02-31 is not one).
pub(crate) fn is_date(s: &str) -> bool {
    s.len() == 10
        && s.bytes().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
        && days_from_civil(s).map(civil_from_days).as_deref() == Some(s)
}

/// One CODEOWNERS rule: its pattern and whether it names any owner.
pub(crate) struct OwnerRule {
    pattern: String,
    owned: bool,
}

/// The rules of a CODEOWNERS file, in file order. A line with unsupported
/// syntax is skipped, as GitHub skips it.
pub(crate) fn codeowners_rules(text: &str) -> Vec<OwnerRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace().take_while(|t| !t.starts_with('#'));
        let Some(raw) = tokens.next() else { continue };
        let pattern = raw
            .strip_prefix('\\')
            .filter(|p| p.starts_with('#'))
            .unwrap_or(raw);
        if pattern.starts_with('!') || pattern.contains('[') {
            continue;
        }
        rules.push(OwnerRule {
            pattern: pattern.to_string(),
            owned: tokens.any(|t| t.contains('@')),
        });
    }
    rules
}

/// Whether the last rule matching `path` names an owner.
pub(crate) fn code_owned(rules: &[OwnerRule], path: &str) -> bool {
    rules
        .iter()
        .rev()
        .find(|r| pattern_matches(&r.pattern, path))
        .is_some_and(|r| r.owned)
}

/// gitignore-style matching as CODEOWNERS uses it: a leading or middle `/`
/// anchors the pattern at the root, otherwise it matches at any depth; a
/// trailing `/` matches only a directory; a pattern naming a directory owns
/// everything under it, except that a wildcard last segment (`docs/*`)
/// matches direct entries only.
fn pattern_matches(pattern: &str, path: &str) -> bool {
    let dir_only = pattern.ends_with('/');
    let p = pattern.trim_end_matches('/');
    let anchored = p.contains('/');
    let p = p.trim_start_matches('/');
    if p.is_empty() {
        return false;
    }
    let mut pat: Vec<&str> = p.split('/').collect();
    if !anchored {
        pat.insert(0, "**");
    }
    let last = pat[pat.len() - 1];
    let file_level = last != "**" && last.contains(['*', '?']);
    let segs: Vec<&str> = path.split('/').collect();
    (1..=segs.len()).any(|n| {
        let whole = n == segs.len();
        if (dir_only && whole) || (file_level && !whole) {
            return false;
        }
        glob(&pat, &segs[..n])
    })
}

fn glob(pat: &[&str], segs: &[&str]) -> bool {
    match pat.split_first() {
        None => segs.is_empty(),
        Some((&"**", rest)) => (0..=segs.len()).any(|i| glob(rest, &segs[i..])),
        Some((first, rest)) => {
            !segs.is_empty()
                && segment_matches(first.as_bytes(), segs[0].as_bytes())
                && glob(rest, &segs[1..])
        }
    }
}

/// `*` and `?` within one path segment.
fn segment_matches(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| segment_matches(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && segment_matches(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && segment_matches(rest, &s[1..]),
    }
}

/// The facts of one committed `.github/rulesets/*.json` file.
pub(crate) fn ruleset(path: String, text: &str) -> RulesetFacts {
    let doc = serde_json::from_str::<serde_json::Value>(text).ok();
    let Some(rules) = doc
        .as_ref()
        .and_then(|d| d.get("rules"))
        .and_then(|r| r.as_array())
    else {
        return RulesetFacts {
            path,
            ..Default::default()
        };
    };
    let doc = doc.as_ref().expect("rules came from it");
    let refs = |key: &str| -> bool {
        doc.pointer(&format!("/conditions/ref_name/{key}"))
            .and_then(|v| v.as_array())
            .is_some_and(|a| {
                a.iter()
                    .filter_map(|r| r.as_str())
                    .any(|r| DEFAULT_BRANCH_REFS.contains(&r))
            })
    };
    let str_at = |key: &str| doc.get(key).and_then(|v| v.as_str());
    let default_branch = str_at("target").unwrap_or("branch") == "branch"
        && str_at("enforcement") == Some("active")
        && refs("include")
        && !refs("exclude");
    let requires_review = rules.iter().any(|r| {
        let param = |k: &str| r.pointer(&format!("/parameters/{k}")).cloned();
        r.get("type").and_then(|t| t.as_str()) == Some("pull_request")
            && (param("require_code_owner_review").and_then(|v| v.as_bool()) == Some(true)
                || param("required_approving_review_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    >= 1)
    });
    RulesetFacts {
        path,
        parsed: true,
        default_branch,
        requires_review,
    }
}
