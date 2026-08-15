//! `.revelara.yaml` waiver/suppression engine (po-3t3oj.27).
//!
//! A faithful Rust port of rvl-cli's `internal/agentscan/waiver.go` matching
//! and expiry engine, reading and writing the SAME on-disk file rvl-cli reads,
//! so one `.revelara.yaml` waivers list behaves identically for both scanners.
//!
//! On-disk shape (mirrors rvl-cli `internal/project/config.go`): waivers live
//! under the `scanner.waivers` list, each entry `{matcher, paths, expires,
//! reason}`. The `matcher` slug is the waiver KEY; rvl-cli maps it onto its
//! engine's `Rule` (see `mapWaivers`). rvl uses the readable class key
//! `"{client_type}.{method}"` (e.g. `db.RLSPool.QueryRow`) as its matcher,
//! which is a DISJOINT namespace from rvl-cli's agent-lens rule slugs
//! (missing-timeout, etc.). As the `mapWaivers` comment documents, disjoint
//! namespaces mean each scanner only ever matches its own entries in the shared
//! list, so no false cross-scanner suppression can occur.
//!
//! Glob semantics mirror `waiverMatchesPath`: Go `path.Match` forward-slash
//! matching plus a `**/` prefix that matches the basename at any depth. Rule
//! match is case-insensitive; empty `paths` matches any file.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// One `(matcher, paths, expiry, reason)` suppression. Field names carry the
/// engine's meaning; `matcher` is serialized/deserialized to match rvl-cli's
/// on-disk `.revelara.yaml` key (`scanner.waivers[].matcher`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiver {
    /// The waiver key. For rvl this is the class key `client_type.method`.
    /// Serialized as `matcher` to interoperate with rvl-cli.
    #[serde(rename = "matcher")]
    pub rule: String,
    /// Forward-slash globs scoping the waiver; empty matches any file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// `YYYY-MM-DD` date after which the waiver is inert; empty is open-ended.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expires: String,
    /// Human reason, for audit accountability.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Deserialization view of `.revelara.yaml`: only the `scanner.waivers` list is
/// read; every other key (project, components, scanner.base_ref, scanner.agent)
/// is ignored here and preserved on append via a `Value` round-trip.
#[derive(Debug, Default, Deserialize)]
struct WaiverFile {
    #[serde(default)]
    scanner: ScannerSection,
}

#[derive(Debug, Default, Deserialize)]
struct ScannerSection {
    #[serde(default)]
    waivers: Vec<Waiver>,
    #[serde(default)]
    bounds: Vec<DeclaredBound>,
}

/// One out-of-code bound declaration (po-3t3oj.30): a human assertion that a
/// client type's calls are bounded by something no retrieval can see
/// (statement_timeout on the prod database, an infra-level deadline). Narrow
/// by design: exact `client_type` only, `whole_call` only — a declaration is
/// the strongest possible claim, so anything weaker stays a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredBound {
    pub client_type: String,
    #[serde(default)]
    pub bounds: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Same `YYYY-MM-DD` semantics as waivers; empty is open-ended.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub expires: String,
}

/// Load the active whole-call bound declarations from `.revelara.yaml`.
/// Missing/unparseable file or section is simply empty — a declaration is an
/// opt-in extra, never load-bearing for the scan itself.
pub fn load_declared_bounds(path: &Path, today: &str) -> Vec<DeclaredBound> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    if text.trim().is_empty() {
        return Vec::new();
    }
    let Ok(f) = serde_yaml::from_str::<WaiverFile>(&text) else {
        return Vec::new();
    };
    f.scanner
        .bounds
        .into_iter()
        .filter(|b| {
            !b.client_type.is_empty()
                && b.bounds == "whole_call"
                && expiry_active(&b.expires, today)
        })
        .collect()
}

/// Whether `w` is still in force at `today` ("YYYY-MM-DD"). Mirrors
/// `waiverActive`: an empty or unparseable `Expires` is open-ended (active);
/// otherwise active while `today <= expires`. ISO dates sort lexically, so a
/// string compare is exact once both sides are well-formed `YYYY-MM-DD`.
pub fn waiver_active(w: &Waiver, today: &str) -> bool {
    expiry_active(&w.expires, today)
}

/// Shared expiry rule for waivers and bound declarations.
fn expiry_active(expires: &str, today: &str) -> bool {
    let expires = expires.trim();
    if expires.is_empty() {
        return true;
    }
    if !is_ymd(expires) {
        // Unparseable expiry is treated as open-ended, like time.Parse err.
        return true;
    }
    today.trim() <= expires
}

/// Validate a `YYYY-MM-DD` shape (digits + dashes at fixed positions). Range
/// validation is unnecessary: any malformed value is treated as open-ended by
/// `waiver_active`, matching rvl-cli's parse-error branch.
fn is_ymd(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// Match one glob against one path, mirroring `waiverMatchesPath` for a single
/// pattern: `path.Match` on the full path, plus a `**/` prefix that matches the
/// basename at any depth (so `**/*.go` waives `pkg/foo/bar.go`).
pub fn glob_match(pattern: &str, path: &str) -> bool {
    if path_match(pattern, path) {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("**/") {
        if path_match(suffix, basename(path)) {
            return true;
        }
    }
    false
}

/// True when some ACTIVE waiver's matcher equals `class_rule` (case-insensitive)
/// AND the waiver's paths are empty or a glob matches `site_path`. Mirrors
/// `matchWaiver` + `ApplyWaivers`: an empty rule never matches, the first active
/// covering waiver wins.
pub fn is_waived(class_rule: &str, site_path: &str, waivers: &[Waiver], today: &str) -> bool {
    let rule = class_rule.trim().to_ascii_lowercase();
    if rule.is_empty() {
        return false;
    }
    for w in waivers {
        if !waiver_active(w, today) {
            continue;
        }
        if rule != w.rule.trim().to_ascii_lowercase() {
            continue;
        }
        if w.paths.is_empty() || w.paths.iter().any(|g| glob_match(g, site_path)) {
            return true;
        }
    }
    false
}

/// Load `scanner.waivers` from `.revelara.yaml`. A missing, empty, or
/// unparseable file yields an empty list, never an error: a broken config must
/// not fail a scan (it just suppresses nothing).
pub fn load_waivers(path: &Path) -> Vec<Waiver> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    if text.trim().is_empty() {
        return Vec::new();
    }
    match serde_yaml::from_str::<WaiverFile>(&text) {
        Ok(f) => f.scanner.waivers,
        Err(_) => Vec::new(),
    }
}

/// Append a waiver to `.revelara.yaml` under `scanner.waivers`, preserving every
/// other key. The whole document is round-tripped through `serde_yaml::Value`
/// so `project`, `components`, `scanner.base_ref`, `scanner.agent`, and anything
/// else rvl-cli owns survive untouched. Creates the file (and the `scanner`
/// map / `waivers` list) when absent.
pub fn append_waiver(path: &Path, w: &Waiver) -> anyhow::Result<()> {
    use serde_yaml::{Mapping, Value};

    let mut root: Value = match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => serde_yaml::from_str(&text)
            .with_context(|| format!("parsing existing {}", path.display()))?,
        _ => Value::Mapping(Mapping::new()),
    };

    let map = root
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("{} is not a YAML mapping", path.display()))?;

    // Ensure `scanner:` exists and is a mapping.
    let needs_scanner = match map.get("scanner") {
        None => true,
        Some(v) => v.is_null(),
    };
    if needs_scanner {
        map.insert(
            Value::String("scanner".into()),
            Value::Mapping(Mapping::new()),
        );
    }
    let scanner = map
        .get_mut("scanner")
        .expect("scanner ensured above")
        .as_mapping_mut()
        .ok_or_else(|| anyhow::anyhow!("`scanner` in {} is not a mapping", path.display()))?;

    let entry = serde_yaml::to_value(w)?;
    match scanner.get_mut("waivers") {
        Some(Value::Sequence(seq)) => seq.push(entry),
        Some(v) if v.is_null() => *v = Value::Sequence(vec![entry]),
        Some(_) => anyhow::bail!("`scanner.waivers` in {} is not a list", path.display()),
        None => {
            scanner.insert(
                Value::String("waivers".into()),
                Value::Sequence(vec![entry]),
            );
        }
    }

    let serialized = serde_yaml::to_string(&root)?;
    std::fs::write(path, serialized).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// The last `/`-separated element of a path (Go `path.Base`, simplified for the
/// forward-slash paths a retriever emits; no trailing-slash or empty handling
/// is needed here).
fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

// --- Go `path.Match` port (path/match.go), forward-slash semantics ---
//
// A direct port so the two waiver engines agree byte-for-byte on globs. `*`
// matches a run of non-`/` characters, `?` one non-`/` character, `[...]` a
// character class; a malformed pattern is treated as a non-match (rvl-cli
// swallows the error the same way at the call site).

fn path_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    go_match(&p, &n)
}

fn go_match(pattern: &[char], name: &[char]) -> bool {
    let mut pattern = pattern;
    let mut name = name;
    'pattern: while !pattern.is_empty() {
        let (star, chunk, rest) = scan_chunk(pattern);
        pattern = rest;
        if star && chunk.is_empty() {
            // Trailing `*` matches the rest of name unless it contains a `/`.
            return !name.contains(&'/');
        }
        if let Some(t) = match_chunk(chunk, name) {
            if t.is_empty() || !pattern.is_empty() {
                name = t;
                continue;
            }
        }
        if star {
            let mut i = 0;
            while i < name.len() && name[i] != '/' {
                if let Some(t) = match_chunk(chunk, &name[i + 1..]) {
                    if pattern.is_empty() && !t.is_empty() {
                        i += 1;
                        continue;
                    }
                    name = t;
                    continue 'pattern;
                }
                i += 1;
            }
        }
        return false;
    }
    name.is_empty()
}

/// Leading `*`s, then the run up to the next unescaped, non-class `*`.
fn scan_chunk(pattern: &[char]) -> (bool, &[char], &[char]) {
    let mut star = false;
    let mut pattern = pattern;
    while !pattern.is_empty() && pattern[0] == '*' {
        pattern = &pattern[1..];
        star = true;
    }
    let mut inrange = false;
    let mut i = 0;
    while i < pattern.len() {
        match pattern[i] {
            '\\' => {
                if i + 1 < pattern.len() {
                    i += 1;
                }
            }
            '[' => inrange = true,
            ']' => inrange = false,
            // An unescaped, non-class `*` ends the chunk.
            '*' if !inrange => break,
            _ => {}
        }
        i += 1;
    }
    (star, &pattern[..i], &pattern[i..])
}

/// Match a star-free chunk at the head of `s`. Returns the remainder of `s` on
/// success, `None` on failure or malformed class.
fn match_chunk<'a>(chunk: &[char], s: &'a [char]) -> Option<&'a [char]> {
    let mut chunk = chunk;
    let mut s = s;
    let mut failed = false;
    while !chunk.is_empty() {
        if !failed && s.is_empty() {
            failed = true;
        }
        match chunk[0] {
            '[' => {
                let mut r = '\0';
                if !failed {
                    r = s[0];
                    s = &s[1..];
                }
                chunk = &chunk[1..];
                let mut negated = false;
                if !chunk.is_empty() && chunk[0] == '^' {
                    negated = true;
                    chunk = &chunk[1..];
                }
                let mut matched = false;
                let mut nrange = 0;
                loop {
                    if !chunk.is_empty() && chunk[0] == ']' && nrange > 0 {
                        chunk = &chunk[1..];
                        break;
                    }
                    let (lo, rest) = get_esc(chunk)?;
                    chunk = rest;
                    let mut hi = lo;
                    if !chunk.is_empty() && chunk[0] == '-' {
                        let (h, rest2) = get_esc(&chunk[1..])?;
                        hi = h;
                        chunk = rest2;
                    }
                    if lo <= r && r <= hi {
                        matched = true;
                    }
                    nrange += 1;
                }
                if matched == negated {
                    failed = true;
                }
            }
            '?' => {
                if !failed {
                    if s[0] == '/' {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
            '\\' => {
                chunk = &chunk[1..];
                if chunk.is_empty() {
                    return None;
                }
                if !failed {
                    if chunk[0] != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
            c => {
                if !failed {
                    if c != s[0] {
                        failed = true;
                    }
                    s = &s[1..];
                }
                chunk = &chunk[1..];
            }
        }
    }
    if failed {
        None
    } else {
        Some(s)
    }
}

/// Read one (possibly `\`-escaped) character from the head of a char-class body.
fn get_esc(chunk: &[char]) -> Option<(char, &[char])> {
    if chunk.is_empty() || chunk[0] == '-' || chunk[0] == ']' {
        return None;
    }
    let mut chunk = chunk;
    if chunk[0] == '\\' {
        chunk = &chunk[1..];
        if chunk.is_empty() {
            return None;
        }
    }
    let r = chunk[0];
    let nchunk = &chunk[1..];
    if nchunk.is_empty() {
        return None;
    }
    Some((r, nchunk))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(rule: &str, paths: &[&str], expires: &str) -> Waiver {
        Waiver {
            rule: rule.into(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            expires: expires.into(),
            reason: String::new(),
        }
    }

    // --- glob_match ---

    #[test]
    fn glob_star_matches_within_a_directory() {
        assert!(glob_match("internal/*.go", "internal/foo.go"));
        // `*` does not cross a separator.
        assert!(!glob_match("internal/*.go", "internal/sub/foo.go"));
    }

    #[test]
    fn glob_double_star_prefix_matches_basename_at_any_depth() {
        assert!(glob_match("**/*.go", "pkg/foo/bar.go"));
        assert!(glob_match("**/*.go", "bar.go"));
        assert!(glob_match("**/client.go", "internal/billing/client.go"));
        assert!(!glob_match("**/*.go", "pkg/foo/bar.py"));
    }

    #[test]
    fn glob_exact_path_matches_only_itself() {
        assert!(glob_match("internal/db/pool.go", "internal/db/pool.go"));
        assert!(!glob_match("internal/db/pool.go", "internal/db/other.go"));
    }

    #[test]
    fn glob_question_mark_is_single_non_separator() {
        assert!(glob_match("a?c.go", "abc.go"));
        assert!(!glob_match("a?c.go", "a/c.go"));
    }

    // --- waiver_active ---

    #[test]
    fn empty_expiry_is_open_ended() {
        assert!(waiver_active(&w("r", &[], ""), "2026-08-02"));
        assert!(waiver_active(&w("r", &[], "   "), "2026-08-02"));
    }

    #[test]
    fn unparseable_expiry_is_open_ended() {
        assert!(waiver_active(&w("r", &[], "not-a-date"), "2026-08-02"));
        assert!(waiver_active(
            &w("r", &[], "2026-13-99garbage"),
            "2026-08-02"
        ));
    }

    #[test]
    fn expiry_active_until_and_including_the_date() {
        let x = w("r", &[], "2026-12-31");
        assert!(waiver_active(&x, "2026-08-02"), "before expiry: active");
        assert!(waiver_active(&x, "2026-12-31"), "on expiry day: active");
        assert!(!waiver_active(&x, "2027-01-01"), "after expiry: inert");
    }

    // --- is_waived ---

    #[test]
    fn is_waived_matches_rule_case_insensitively_with_empty_paths() {
        let ws = vec![w("db.RLSPool.QueryRow", &[], "")];
        assert!(is_waived(
            "db.RLSPool.QueryRow",
            "internal/x.go",
            &ws,
            "2026-08-02"
        ));
        assert!(is_waived(
            "DB.rlspool.queryrow",
            "internal/x.go",
            &ws,
            "2026-08-02"
        ));
        assert!(!is_waived(
            "db.RLSPool.Query",
            "internal/x.go",
            &ws,
            "2026-08-02"
        ));
    }

    #[test]
    fn is_waived_respects_path_scope() {
        let ws = vec![w("rule.x", &["**/*.go"], "")];
        assert!(is_waived("rule.x", "pkg/a/b.go", &ws, "2026-08-02"));
        assert!(!is_waived("rule.x", "pkg/a/b.py", &ws, "2026-08-02"));
    }

    #[test]
    fn is_waived_ignores_expired_waivers() {
        let ws = vec![w("rule.x", &[], "2020-01-01")];
        assert!(!is_waived("rule.x", "a.go", &ws, "2026-08-02"));
    }

    #[test]
    fn is_waived_empty_rule_never_matches() {
        let ws = vec![w("", &[], "")];
        assert!(!is_waived("", "a.go", &ws, "2026-08-02"));
    }

    // --- load / append round-trip ---

    #[test]
    fn append_creates_file_with_scanner_waivers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".revelara.yaml");
        append_waiver(
            &path,
            &Waiver {
                rule: "db.RLSPool.QueryRow".into(),
                paths: vec![],
                expires: "".into(),
                reason: "spike".into(),
            },
        )
        .unwrap();
        let loaded = load_waivers(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].rule, "db.RLSPool.QueryRow");
        assert_eq!(loaded[0].reason, "spike");
        // Serialized under the rvl-cli-compatible key.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("scanner:"), "nested under scanner");
        assert!(text.contains("matcher: db.RLSPool.QueryRow"), "matcher key");
    }

    #[test]
    fn append_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".revelara.yaml");
        std::fs::write(
            &path,
            "project: myproj\n\
             components:\n\
             - name: api\n  \
               path: .\n\
             scanner:\n  \
               base_ref: origin/develop\n",
        )
        .unwrap();

        append_waiver(&path, &w("rule.one", &["internal/**"], "2026-12-31")).unwrap();
        append_waiver(&path, &w("rule.two", &[], "")).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        // Unrelated keys survive.
        assert!(text.contains("project: myproj"), "project preserved");
        assert!(
            text.contains("base_ref: origin/develop"),
            "base_ref preserved"
        );
        assert!(text.contains("name: api"), "components preserved");
        // Both waivers land under scanner.waivers.
        let loaded = load_waivers(&path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].rule, "rule.one");
        assert_eq!(loaded[0].paths, vec!["internal/**".to_string()]);
        assert_eq!(loaded[1].rule, "rule.two");
    }

    #[test]
    fn load_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.yaml");
        assert!(load_waivers(&path).is_empty());
    }

    #[test]
    fn load_ignores_unrelated_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".revelara.yaml");
        std::fs::write(&path, "project: x\ncomponents: []\n").unwrap();
        assert!(load_waivers(&path).is_empty());
    }
}
