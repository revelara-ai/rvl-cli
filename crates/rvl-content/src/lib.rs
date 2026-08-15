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
    /// A vocabulary the VALUE must match. Used by the weak-credential rule,
    /// where shape and entropy both say "uninteresting" and the words say
    /// otherwise.
    value_must_match: Option<Regex>,
    /// Drop values whose SHAPE is a NAME rather than a generated credential
    /// (see [`name_shaped`]). Set on the entropy-gated generic rule, whose
    /// character-distribution score cannot tell an identifier from a token.
    reject_name_shaped: bool,
    /// The value must be a quoted string LITERAL when the file is written in
    /// a language that always quotes them (see [`quoted_literal`] and
    /// [`requires_quoted_literal`]). Set on the weak-credential rule, whose
    /// unquoted branch exists for .ini/.env config and must not swallow a
    /// bare identifier on the right-hand side of an assignment.
    require_string_literal: bool,
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
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "aws_secret_access_key",
                description: "hardcoded AWS secret access key",
                severity: "high",
                pattern: re(r#"(?i)\baws[\w.\-]{0,30}["']?\s*(?::=|=>|=|:)\s*["']([A-Za-z0-9/+=]{40})["']"#),
                secret_group: 1,
                entropy_min: Some(3.0),
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "github_token",
                description: "hardcoded GitHub token",
                severity: "high",
                pattern: re(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b"),
                secret_group: 1,
                entropy_min: None,
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "gcp_api_key",
                description: "hardcoded GCP API key",
                severity: "high",
                pattern: re(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
                secret_group: 1,
                entropy_min: None,
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "slack_token",
                description: "hardcoded Slack token",
                severity: "high",
                pattern: re(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,250})\b"),
                secret_group: 1,
                entropy_min: None,
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "stripe_secret_key",
                description: "hardcoded Stripe live secret key",
                severity: "high",
                pattern: re(r"\b((?:sk|rk)_live_[0-9A-Za-z]{20,99})\b"),
                secret_group: 1,
                entropy_min: None,
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "private_key_pem",
                description: "private key material committed to source",
                severity: "high",
                pattern: re(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"),
                secret_group: 0,
                entropy_min: None,
                value_must_match: None,
                reject_name_shaped: false,
                require_string_literal: false,
                generic: false,
            },
            Rule {
                id: "generic_api_key",
                description: "high-entropy literal assigned to a secret-named variable",
                severity: "medium",
                pattern: re(r#"(?i)\b(?:api[_\-]?key|apikey|secret|token|passwd|password|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|private[_\-]?key)\b["']?\s*(?::=|=>|=|:)\s*["']([A-Za-z0-9+/_\-.=]{16,80})["']"#),
                secret_group: 1,
                entropy_min: Some(3.5),
                value_must_match: None,
                // Entropy is a character-distribution score, and IDENTIFIERS
                // score well on it: `AUDIO_STT_AZURE_API_KEY` is 3.6 bits/char.
                // Found on open-webui, where config key-name mapping tables
                // produced 20 sites that are every one of them a name.
                reject_name_shaped: true,
                require_string_literal: false,
                generic: true,
            },
            // WEAK AND SHIPPED BEATS STRONG AND COMMITTED. The generic rule
            // above gates on HIGH entropy, which selects for randomly-generated
            // values -- usually fixtures and examples -- and selects AGAINST
            // human-chosen defaults, which are the ones that ship and get used.
            //
            // Found on mlflow, where the lane reported a test fixture and a
            // docs config while missing `admin_password = password1234` in
            // basic_auth.ini and the fallback key-encryption passphrase in
            // crypto.py. Neither reached the entropy gate; both failed the
            // PATTERN, for three separate reasons this rule fixes:
            //   - a leading \b stopped the keyword matching inside snake_case
            //     identifiers (admin_password, db_password), which is the
            //     dominant naming convention in Python, Go, Ruby and config
            //   - "passphrase" was absent from the vocabulary
            //   - the value had to be QUOTED and >=16 chars, excluding both
            //     .ini/.env/.properties style and short weak passwords
            //
            // Severity stays medium/advisory. A blocking severity needs a
            // recorded human approval under the HITL policy, and this rule's
            // discrimination has not been measured across the corpus yet.
            Rule {
                id: "weak_default_credential",
                description: "weak or default credential assigned to a secret-named setting",
                severity: "medium",
                pattern: re(
                    r#"(?i)[a-z0-9_.\-]*(?:passphrase|password|passwd|secret|api[_\-]?key|auth[_\-]?token|access[_\-]?token)\s*["']?\s*(?::=|=>|=|:)\s*["']?([A-Za-z0-9._\-]{4,80})["']?\s*$"#,
                ),
                secret_group: 1,
                entropy_min: None,
                // A dotted value is a CODE REFERENCE, not a literal:
                // `password = request.authorization.password` reads a value, it
                // does not set one, and the dotted form sailed through the
                // character class on the first version of this rule. Requiring
                // no interior dot also costs nothing, since real weak
                // credentials do not contain them.
                value_must_match: Some(re(
                    r#"(?i)^(?:[a-z0-9_\-]*(?:pass(?:word|wd|phrase)|letmein|qwerty|welcome|changeit|admin|root|default|insecure|notsecure)[a-z0-9_\-]*|[a-z_\-]*[0-9]{4,}[a-z0-9_\-]*)$"#,
                )),
                reject_name_shaped: false,
                // The unquoted branch of the pattern above exists for
                // .ini/.env/.properties, where an unquoted value IS the
                // literal. In a language that always quotes its strings, an
                // unquoted right-hand side is an EXPRESSION:
                // `auth_row.password = new_password` sets a column from a
                // parameter and contains no literal at all, yet it satisfied
                // both the pattern and the `*password*` vocabulary. Six
                // open-webui sites, in Python and TypeScript, were that shape.
                require_string_literal: true,
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

/// Values whose SHAPE is a NAME — an identifier, a config path, a phrase —
/// rather than a generated credential. Shannon entropy scores character
/// distribution, so it cannot make this distinction on its own: the env var
/// name `AUDIO_STT_AZURE_API_KEY` scores 3.62 bits/char, over the generic
/// rule's 3.5 gate.
///
/// Three shapes, each of which requires a SEPARATOR, so a single opaque run of
/// characters — what base64, hex and every provider token actually look like —
/// is never excluded by any of them:
///
///   1. SCREAMING_SNAKE_CASE with at least one underscore. An env var name.
///      (`{'audio.stt.azure.api_key': 'AUDIO_STT_AZURE_API_KEY'}` — the dict
///      KEY makes the site read as secret-named, the VALUE is a name.)
///   2. A dotted path of lowercase identifier segments. A config path.
///      (`{'API_KEY': 'audio.tts.api_key'}` — the same mapping table, read in
///      the other direction.)
///   3. Two or more purely ALPHABETIC tokens joined by `.`/`_`/`-`, with no
///      digit anywhere. A name or a natural-language phrase: `current-password`
///      in an HTML autocomplete attribute, `Anwendungs-DN-Passwort` in an i18n
///      translation file.
///
/// The narrowing is bounded by the separator requirement and, for (3), by the
/// absence of any digit: a generated credential is one opaque token, or it
/// carries mixed case WITH digits. The residual miss is a word-list passphrase
/// used as an api key (`api_key = "zebra-mango-tulip-quartz"`); a passphrase
/// naming itself as one (`...-passphrase-...`) is still caught by the
/// weak-credential rule's vocabulary, which does not use this check.
fn name_shaped(value: &str) -> bool {
    use std::sync::OnceLock;
    static SHAPES: OnceLock<Vec<Regex>> = OnceLock::new();
    let shapes = SHAPES.get_or_init(|| {
        [
            // 1. SCREAMING_SNAKE_CASE (>= 1 underscore).
            r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$",
            // 2. dotted lowercase config path (>= 1 dot).
            r"^[a-z][a-z0-9]*(?:[_\-][a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:[_\-][a-z0-9]+)*)+$",
            // 3. alphabetic word sequence, no digits (>= 2 tokens).
            r"^[A-Za-z]+(?:[._\-][A-Za-z]+)+$",
        ]
        .iter()
        .map(|p| Regex::new(p).expect("static name-shape regex"))
        .collect()
    });
    shapes.iter().any(|re| re.is_match(value))
}

/// Extensions whose language ALWAYS quotes its string literals. In these files
/// an unquoted right-hand side is an expression — a variable, an attribute, a
/// call — and can never be a hardcoded credential.
///
/// Config and plain-text formats are deliberately ABSENT (.env, .ini, .cfg,
/// .conf, .properties, .yaml, .toml, shell, Dockerfile, Makefile, and every
/// unknown extension): an unquoted value there IS the literal, and that is
/// exactly where shipped weak defaults live — mlflow's `admin_password =
/// password1234` in basic_auth.ini is the case this rule was built for.
const QUOTED_LITERAL_LANGS: &[&str] = &[
    "rs", "py", "pyi", "go", "java", "kt", "kts", "scala", "groovy", "js", "jsx", "mjs", "cjs",
    "ts", "tsx", "svelte", "vue", "rb", "php", "cs", "swift", "dart", "c", "h", "cc", "cpp", "cxx",
    "hpp", "hh", "m", "mm", "ex", "exs", "erl", "lua", "pl", "pm",
];

/// Whether an unquoted value in this file can be a literal at all.
fn requires_quoted_literal(rel_path: &str) -> bool {
    Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| QUOTED_LITERAL_LANGS.contains(&e.to_ascii_lowercase().as_str()))
}

/// Whether the matched value is delimited by quotes on this line, i.e. it is a
/// string literal rather than a bare token the rule's optional-quote branch
/// picked up.
fn quoted_literal(line: &str, span: std::ops::Range<usize>) -> bool {
    let before = line[..span.start].chars().next_back();
    let after = line[span.end..].chars().next();
    matches!(
        (before, after),
        (Some('"'), Some('"')) | (Some('\''), Some('\''))
    )
}

/// Inline allow pragma. `rvl:allow` is the canonical form, chosen ahead of the
/// rvl-cli cutover (the tool is renaming rvlscan -> rvl); it lives in users'
/// source, so accepting it now means fewer files to migrate later. The older
/// `rvlscan:allow` stays honored so existing suppressions keep working, and
/// `gitleaks:allow` so a repo migrating from gitleaks keeps its suppressions.
fn inline_allow(line: &str) -> bool {
    line.contains("rvl:allow") || line.contains("rvlscan:allow") || line.contains("gitleaks:allow")
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
                    let Some(m) = caps.get(rule.secret_group) else {
                        continue;
                    };
                    let value = m.as_str();
                    if allowlisted(value, line) {
                        continue;
                    }
                    // A name is not a credential, and an expression is not a
                    // literal: both checks read the VALUE's shape only.
                    if rule.reject_name_shaped && name_shaped(value) {
                        continue;
                    }
                    if rule.require_string_literal
                        && !quoted_literal(line, m.range())
                        && requires_quoted_literal(rel_path)
                    {
                        continue;
                    }
                    let entropy = shannon_entropy(value);
                    if let Some(min) = rule.entropy_min {
                        if entropy < min {
                            continue;
                        }
                    }
                    if let Some(vocab) = &rule.value_must_match {
                        if !vocab.is_match(value) {
                            continue;
                        }
                        // `PASSWORD = "password"` names a config KEY, it does
                        // not set a credential. A value identical to the
                        // secret word itself is that shape, every time.
                        if matches!(
                            value.to_ascii_lowercase().as_str(),
                            "password" | "passwd" | "passphrase" | "secret" | "token" | "apikey"
                        ) {
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
    // Honor .gitignore (po-lqbh2): a full-tree secret scan was blocking commits
    // on gitignored .env / debug material, which git never commits — a false
    // gate that reads as a scary leak on the first run. The `ignore` walker
    // applies .gitignore / .git/info/exclude / parent ignores and treats a
    // nested .git as its own repo boundary. Two deliberate settings:
    //   - hidden(false): the gitignore filter must NOT double as a hidden-file
    //     filter, or a secret in .github/workflows (not ignored) would be
    //     missed — that was a real OpenMetadata finding.
    //   - git_global(false): the user's global gitignore is machine-specific
    //     and would make a scan's output depend on who ran it.
    // SKIP_DIRS stays as a belt-and-suspenders filter for trees that do not
    // gitignore node_modules/target/vendor.
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .parents(true)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIRS.contains(&name.as_ref())
        })
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if !scannable(path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if looks_binary(&bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        out.extend(scan_bytes(&rel, &text));
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

#[cfg(test)]
mod allow_token_tests {
    use super::*;

    #[test]
    fn all_three_allow_tokens_suppress_a_secret_on_the_line() {
        let key = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        for token in ["rvl:allow", "rvlscan:allow", "gitleaks:allow"] {
            let line = format!("token: {key}  # {token} accepted, not a real secret");
            assert!(
                scan_bytes("config.yaml", &line).is_empty(),
                "`{token}` on the line must suppress the finding"
            );
        }
        // Without a marker, the same line still fires.
        assert!(
            !scan_bytes("config.yaml", &format!("token: {key}\n")).is_empty(),
            "an unmarked secret must still fire"
        );
    }
}

#[cfg(test)]
mod gitignore_tests {
    use super::*;
    use std::fs;

    #[test]
    fn scan_root_skips_gitignored_files() {
        // po-lqbh2: a full-tree scan was blocking on .env / debug secrets that
        // git deliberately ignores. scan_root must honor .gitignore so a
        // gitignored secret is not a false gate, while a TRACKED secret still
        // fires.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join(".git")).unwrap(); // marks a repo so ignores apply
        fs::write(root.join(".gitignore"), ".env\ndebug/\n").unwrap();

        // A gitignored secrets file — must be SKIPPED.
        fs::write(
            root.join(".env"),
            "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
        )
        .unwrap();
        fs::create_dir(root.join("debug")).unwrap();
        fs::write(
            root.join("debug/notes.txt"),
            "sk_live_0123456789abcdefghij\n",
        )
        .unwrap();

        // A tracked config with a secret — must STILL fire.
        fs::write(
            root.join("config.yaml"),
            "github_token: ghp_zyxwvutsrqponmlkjihgfedcba9876543210\n",
        )
        .unwrap();

        let findings = scan_root(root);
        let files: Vec<&str> = findings.iter().map(|f| f.file.as_str()).collect();
        assert!(
            files.iter().any(|f| f.contains("config.yaml")),
            "tracked secret must fire: {files:?}"
        );
        assert!(
            !files.iter().any(|f| f.contains(".env")),
            ".env is gitignored, must be skipped: {files:?}"
        );
        assert!(
            !files.iter().any(|f| f.contains("debug/")),
            "debug/ is gitignored, must be skipped: {files:?}"
        );
    }

    #[test]
    fn scan_root_still_scans_non_ignored_dotdirs() {
        // .github is a dotdir but not ignored; secrets there (the OpenMetadata
        // case) must still be found — the gitignore filter must not double as a
        // hidden-file filter.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::write(root.join(".gitignore"), "node_modules/\n").unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(
            root.join(".github/workflows/ci.yml"),
            "env:\n  TOKEN: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n",
        )
        .unwrap();
        let findings = scan_root(root);
        assert!(
            findings
                .iter()
                .any(|f| f.file.contains(".github/workflows/ci.yml")),
            "a secret in a non-ignored dotdir must still fire: {:?}",
            findings.iter().map(|f| &f.file).collect::<Vec<_>>()
        );
    }
}
