//! G5 content-pattern retriever: language-agnostic secret detection (RC-043).
//!
//! A pure-Rust reimplementation of the gitleaks-class core (curated token-shape
//! rules + Shannon-entropy scoring + allowlist hooks), run IN-PROCESS rather
//! than as an external pinned helper. The goindex/pyindex/tsindex helper model
//! exists because language frontends need external toolchains; content-pattern
//! scanning needs none, and an external binary would re-buy the per-target
//! cross-compile packaging cost the README documents for goindex. In-tree Rust
//! also keeps the privacy stance auditable by construction for the open-source
//! release.
//!
//! PRIVACY CONTRACT (mirrors `report.rs`): the raw secret VALUE never leaves
//! the matcher. [`ContentFinding`] is structurally incapable of carrying it —
//! there is no field for the matched text, the line source, or any snippet
//! beyond a masked preview of at most the first four characters. Do NOT add
//! one. The audit tests serialize findings and packet sites built from planted
//! tokens and assert the raw token never appears.
//!
//! Findings ride the existing packet schema ([`rvl_core::Site`]) with
//! `client_type = "secret"` and `method = <rule id>`, so triage, the waiver
//! engine (`secret.<rule_id>` class rules), and rendering all apply unchanged
//! and every finding is born control-mapped to RC-043 downstream.

use regex::Regex;
use rvl_core::Site;
use std::path::Path;

/// One content finding, redacted at birth. There is deliberately NO field the
/// raw secret value could ride in (see the module PRIVACY CONTRACT).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentFinding {
    pub rule_id: String,
    pub description: String,
    /// "high" | "medium"
    pub severity: String,
    /// Repo-relative, forward-slash path.
    pub file: String,
    pub line: u32,
    /// Shannon entropy of the matched value, bits per char.
    pub entropy: f64,
    /// Masked preview: at most the first 4 chars + an ellipsis.
    pub masked: String,
}

/// One detection rule: a well-known token shape, or the generic high-entropy
/// assignment pattern. `entropy_min` gates rules whose shape alone is too weak
/// (the generic rule, the AWS 40-char secret) — a match below it is dropped.
struct Rule {
    id: &'static str,
    description: &'static str,
    severity: &'static str,
    pattern: Regex,
    /// Capture group holding the secret value (0 = whole match).
    secret_group: usize,
    entropy_min: Option<f64>,
    /// The generic rule runs only where no specific rule matched the line:
    /// one secret is one finding, never one per overlapping rule.
    generic: bool,
}

/// The curated ruleset. Shapes follow the gitleaks-class canon: provider
/// prefixes are stable public identifiers, so matching them is high-signal.
/// Stripe deliberately matches LIVE keys only — test keys in docs/fixtures are
/// the canonical false positive and carry no production exposure.
fn ruleset() -> &'static [Rule] {
    use std::sync::OnceLock;
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        let re = |p: &str| Regex::new(p).expect("static rule regex");
        vec![
            Rule {
                id: "aws_access_key_id",
                description: "hardcoded AWS access key ID",
                severity: "high",
                pattern: re(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
                secret_group: 1,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "aws_secret_access_key",
                description: "hardcoded AWS secret access key",
                severity: "high",
                pattern: re(r#"(?i)\baws[\w.\-]{0,30}["']?\s*(?::=|=>|=|:)\s*["']([A-Za-z0-9/+=]{40})["']"#),
                secret_group: 1,
                entropy_min: Some(3.0),
                generic: false,
            },
            Rule {
                id: "github_token",
                description: "hardcoded GitHub token",
                severity: "high",
                pattern: re(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
                secret_group: 1,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "gcp_api_key",
                description: "hardcoded GCP API key",
                severity: "high",
                pattern: re(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
                secret_group: 1,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "slack_token",
                description: "hardcoded Slack token",
                severity: "high",
                pattern: re(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,250})\b"),
                secret_group: 1,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "stripe_secret_key",
                description: "hardcoded Stripe live secret key",
                severity: "high",
                pattern: re(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,99})\b"),
                secret_group: 1,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "private_key_pem",
                description: "private key material committed to source",
                severity: "high",
                pattern: re(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
                secret_group: 0,
                entropy_min: None,
                generic: false,
            },
            Rule {
                id: "generic_api_key",
                description: "high-entropy literal assigned to a secret-named variable",
                severity: "medium",
                pattern: re(r#"(?i)\b(?:api[_\-]?key|apikey|secret|token|passwd|password|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key)\b["']?\s*(?::=|=>|=|:)\s*["']([A-Za-z0-9+/_\-.=]{16,80})["']"#),
                secret_group: 1,
                entropy_min: Some(3.5),
                generic: true,
            },
        ]
    })
}

/// Placeholder shapes that mean "this is not a real credential": documentation
/// examples, template/interpolation slots, and masked-out runs. Checked against
/// the matched VALUE and, for the textual markers, the whole line — AWS's
/// documented `...EXAMPLE` key must never flag no matter which rule caught it.
fn allowlisted(value: &str, line: &str) -> bool {
    use std::sync::OnceLock;
    static MARKERS: OnceLock<Regex> = OnceLock::new();
    let markers = MARKERS.get_or_init(|| {
        Regex::new(
            r"(?i)example|placeholder|change[_\-]?me|dummy|sample|fake|deadbeef|your[_\-]|xxxx|\*\*\*",
        )
        .expect("static allowlist regex")
    });
    if markers.is_match(value) || markers.is_match(line) {
        return true;
    }
    // Interpolation / template slots: ${VAR}, {{ var }}, <VAR>.
    value.contains("${")
        || (value.starts_with("{{") && value.ends_with("}}"))
        || (value.starts_with('<') && value.ends_with('>'))
}

/// Inline allow pragma. `gitleaks:allow` is honored too so a repo migrating
/// from gitleaks keeps its suppressions.
fn inline_allow(line: &str) -> bool {
    line.contains("rvlscan:allow") || line.contains("gitleaks:allow")
}

/// Shannon entropy of `s` in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let n = s.chars().count() as f64;
    -counts
        .values()
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Masked preview: at most the first 4 chars + an ellipsis. Enough to see
/// WHICH kind of token was caught (provider prefixes are public identifiers),
/// never enough to reconstruct it.
fn mask(secret: &str) -> String {
    let prefix: String = secret.chars().take(4).collect();
    format!("{prefix}\u{2026}")
}

/// Scan one file's text content. `rel_path` is the repo-relative path used in
/// findings. Line-oriented: token shapes and assignments are single-line
/// constructs (a PEM body spans lines, but its HEADER — all we match — never
/// does).
pub fn scan_bytes(rel_path: &str, content: &str) -> Vec<ContentFinding> {
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        if inline_allow(line) {
            continue;
        }
        let mut specific_hit = false;
        for pass_generic in [false, true] {
            for rule in ruleset().iter().filter(|r| r.generic == pass_generic) {
                // One secret is one finding: the generic rule yields to any
                // specific rule that already matched this line.
                if rule.generic && specific_hit {
                    continue;
                }
                for caps in rule.pattern.captures_iter(line) {
                    let value = caps
                        .get(rule.secret_group)
                        .map(|m| m.as_str())
                        .unwrap_or_default();
                    if allowlisted(value, line) {
                        continue;
                    }
                    let entropy = shannon_entropy(value);
                    if let Some(min) = rule.entropy_min {
                        if entropy < min {
                            continue;
                        }
                    }
                    if !rule.generic {
                        specific_hit = true;
                    }
                    out.push(ContentFinding {
                        rule_id: rule.id.to_string(),
                        description: rule.description.to_string(),
                        severity: rule.severity.to_string(),
                        file: rel_path.to_string(),
                        line: (idx + 1) as u32,
                        entropy,
                        masked: mask(value),
                    });
                }
            }
        }
    }
    out
}

/// Directories never worth descending into: VCS metadata, vendored and build
/// output. A secret in vendored third-party code is that project's leak, not
/// this repo's.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".terraform",
    ".idea",
    ".vscode",
];

/// Machine-generated dependency lockfiles: hashes in them are checksums, not
/// credentials, and they are the classic entropy-rule false positive.
const SKIP_FILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.sum",
    "poetry.lock",
    "Pipfile.lock",
    "composer.lock",
    "Gemfile.lock",
];

/// Extensions that are binary or otherwise unscannable content.
const SKIP_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "svg", "pdf", "zip", "gz", "tgz", "tar", "bz2",
    "xz", "7z", "jar", "war", "class", "so", "dylib", "dll", "exe", "bin", "dat", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "mov", "avi", "wasm", "pyc", "o", "a", "rlib", "map",
];

/// Files over this size are skipped: token shapes live in source and config,
/// not in megabyte blobs, and the cap keeps the hook-path scan cheap.
const MAX_FILE_BYTES: u64 = 1_048_576;

/// Whether this path should be content-scanned at all.
fn scannable(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if SKIP_FILES.contains(&name) {
        return false;
    }
    // Minified assets: generated, huge lines, classic FP source.
    if name.ends_with(".min.js") || name.ends_with(".min.css") {
        return false;
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if SKIP_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
            return false;
        }
    }
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_FILE_BYTES {
            return false;
        }
    }
    true
}

/// A NUL byte in the head of the file marks it binary (the git heuristic).
fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

/// Walk `root` and scan every non-binary, non-vendored, non-lockfile text
/// file. Findings carry repo-relative forward-slash paths and are sorted
/// (file, line, rule) so output is deterministic.
pub fn scan_root(root: &Path) -> Vec<ContentFinding> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else if ft.is_file() && scannable(&path) {
                let Ok(bytes) = std::fs::read(&path) else {
                    continue;
                };
                if looks_binary(&bytes) {
                    continue;
                }
                let text = String::from_utf8_lossy(&bytes);
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.extend(scan_bytes(&rel, &text));
            }
        }
    }
    out.sort_by(|a, b| {
        (a.file.as_str(), a.line, a.rule_id.as_str()).cmp(&(
            b.file.as_str(),
            b.line,
            b.rule_id.as_str(),
        ))
    });
    out
}

/// Convert findings to packet-schema sites: `client_type` "secret", `method`
/// the rule id, `snippet` the masked preview ONLY. Everything else stays at
/// its zero value — a content site must never carry source (see the module
/// PRIVACY CONTRACT).
pub fn to_sites(findings: &[ContentFinding], snapshot_id: &str) -> Vec<Site> {
    findings
        .iter()
        .map(|f| Site {
            snapshot_id: snapshot_id.to_string(),
            file_path: f.file.clone(),
            line_number: f.line,
            method: f.rule_id.clone(),
            client_type: "secret".to_string(),
            snippet: f.masked.clone(),
            lang: "content".to_string(),
            ..Default::default()
        })
        .collect()
}
