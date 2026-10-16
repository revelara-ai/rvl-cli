//! The ONE reader of `~/.revelara/config.yaml` and of the `RVL_*` values
//! that override it. Every command (scan, sync, status, the data commands,
//! doctor, init, the agent lane) gets its server, key and organization from
//! [`resolve`]; a test in `tests/one_resolver.rs` fails when a second reader
//! appears.
//!
//! The file holds an unnamed top-level profile (`api_url`, `api_key`,
//! `org_name`, the format rvl-cli writes) and any number of named
//! `contexts`, kubectl style. Selection, highest first: the global
//! `--context` flag, `RVL_CONTEXT`, the file's `current_context`, the
//! top-level keys. A selected name that is not in `contexts` is an error that
//! lists the known names, never a fall back to another profile. The per-value
//! overrides `RVL_API_KEY` / `RVL_API_URL` / `RVL_ORG_NAME` still beat the
//! selected profile: the CI use case has no config file at all.
//!
//! SECURITY: this module reads/writes ONLY `api_url` / `api_key` /
//! `org_name` (plus the context selection and the `agent` name). Signing-key
//! material must never become a config field: the keyset is compiled into
//! the binary, and a config-file keyset would be the verification bypass the
//! distribution contract forbids. Do not add, read or plumb any key bytes
//! from this file, not even behind a flag.

use crate::{CmdResult, Failure, BIN};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

/// The production default API endpoint, matching rvl-cli's `DefaultAPIURL`.
pub const DEFAULT_API_URL: &str = "https://api.revelara.ai";

/// One server profile: the top-level keys, or one entry of `contexts`.
/// Unknown keys are tolerated and preserved-by-ignoring.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataConfig {
    #[serde(default)]
    pub api_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub org_name: String,
}

/// The read view of the whole file.
#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    #[serde(flatten)]
    top: DataConfig,
    #[serde(default)]
    current_context: String,
    #[serde(default)]
    contexts: BTreeMap<String, DataConfig>,
    /// The installed coding agent to use ("claude", "copilot", "auto").
    /// A name only: no key, no endpoint.
    #[serde(default)]
    agent: String,
}

/// The outcome of [`resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The selected context, `None` for the top-level profile.
    pub context: Option<String>,
    /// The values after the env overrides. `api_key` is empty when no key
    /// was found anywhere: deterministic scans still run, data commands
    /// report "Not configured".
    pub cfg: DataConfig,
    /// The top-level `agent` selection.
    pub agent: String,
}

/// The value of the global `--context` flag, set once by `main`.
static CONTEXT_FLAG: OnceLock<String> = OnceLock::new();

/// Record the global `--context` flag. Called once, before any command runs.
pub fn set_context_flag(name: String) {
    assert!(CONTEXT_FLAG.set(name).is_ok(), "--context flag set twice");
}

/// `~/.revelara/config.yaml`.
pub fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".revelara").join("config.yaml"))
}

fn parse_file(text: Option<&str>) -> Result<ConfigFile, String> {
    match text {
        Some(t) if !t.trim().is_empty() => serde_yaml::from_str(t).map_err(|e| e.to_string()),
        _ => Ok(ConfigFile::default()),
    }
}

fn unknown_context(name: &str, file: &ConfigFile) -> String {
    let known: Vec<&str> = file.contexts.keys().map(String::as_str).collect();
    let known = if known.is_empty() {
        "(none)".to_string()
    } else {
        known.join(", ")
    };
    format!("unknown context {name:?}; known contexts: {known}")
}

/// The selected context name: `--context` > `RVL_CONTEXT` >
/// `current_context`, or `None` for the top-level profile. `env` must
/// already treat empty values as absent.
fn selected_context(
    file: &ConfigFile,
    flag: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<String>, String> {
    assert!(flag != Some(""), "clap rejects an empty --context");
    let name = flag
        .map(str::to_string)
        .or_else(|| env("RVL_CONTEXT"))
        .or_else(|| (!file.current_context.is_empty()).then(|| file.current_context.clone()));
    match name {
        Some(n) if !file.contexts.contains_key(&n) => Err(unknown_context(&n, file)),
        n => Ok(n),
    }
}

/// Pure resolution over the (optional) file text, the `--context` flag and
/// the environment. Empty env values are treated as absent so an
/// exported-but-empty var never shadows a real file value.
pub fn resolve_from(
    file_text: Option<&str>,
    flag: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<Resolved, String> {
    let env = |name: &str| get_env(name).filter(|v| !v.is_empty());
    let file = parse_file(file_text)?;
    let context = selected_context(&file, flag, &env)?;
    let mut cfg = match &context {
        Some(name) => file.contexts[name].clone(),
        None => file.top.clone(),
    };
    if let Some(v) = env("RVL_API_KEY") {
        cfg.api_key = v;
    }
    if let Some(v) = env("RVL_API_URL") {
        cfg.api_url = v;
    }
    if let Some(v) = env("RVL_ORG_NAME") {
        cfg.org_name = v;
    }
    if cfg.api_url.is_empty() {
        if let Some(name) = &context {
            return Err(format!(
                "context {name:?} has no api_url; set it with \
                 '{BIN} config set-context {name} --url <url>'"
            ));
        }
        cfg.api_url = DEFAULT_API_URL.to_string();
    }
    Ok(Resolved {
        context,
        cfg,
        agent: file.agent,
    })
}

/// The file text: a missing file is normal (env vars may still satisfy
/// auth); any other read error is an error.
fn read_text() -> Result<Option<String>, String> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// THE resolver: file + `--context` + process environment. A present but
/// malformed file, an unknown context or a context without `api_url` is an
/// error.
pub fn resolve() -> Result<Resolved, String> {
    resolve_from(
        read_text()?.as_deref(),
        CONTEXT_FLAG.get().map(String::as_str),
        process_env,
    )
}

/// [`resolve`], with `None` when no API key was found anywhere.
pub fn load() -> Result<Option<DataConfig>, String> {
    let r = resolve()?;
    Ok((!r.cfg.api_key.is_empty()).then_some(r.cfg))
}

/// The selected context of the file on disk, for the commands that write.
fn selected_on_disk(existing: Option<&str>) -> Result<Option<String>, String> {
    selected_context(
        &parse_file(existing)?,
        CONTEXT_FLAG.get().map(String::as_str),
        &process_env,
    )
}

/// Persist the profile `login` collected into the selected context (or the
/// top-level keys), keeping every other key of the file.
pub fn save(cfg: &DataConfig) -> Result<(), String> {
    let path = config_path().ok_or("cannot determine home directory")?;
    let existing = read_text()?;
    let context = selected_on_disk(existing.as_deref())?;
    let text = edit_yaml(existing.as_deref(), context.as_deref(), |m| {
        for (k, v) in [
            ("api_url", &cfg.api_url),
            ("api_key", &cfg.api_key),
            ("org_name", &cfg.org_name),
        ] {
            m.insert(k.into(), v.as_str().into());
        }
        order_known_keys(m);
    })?;
    write_config_text(&path, &text)
}

/// Write the config file with rvl-cli's permission contract: directory
/// 0700, file 0600.
fn write_config_text(path: &Path, data: &str) -> Result<(), String> {
    let dir = path.parent().ok_or("invalid config path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    std::fs::write(path, data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

// --- `config` subcommand (show, set) — ported from rvl-cli
// `internal/commands/config_cmd.go` (po-av01j.164). ---

/// `rvl config`: view and edit CLI configuration.
#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Show current configuration (API key masked)
    Show,
    /// Set a configuration value in the selected context (keys: api_url,
    /// api_key, org_name)
    Set {
        /// Config key: api_url, api_key, or org_name
        key: String,
        /// The value to store
        value: String,
    },
    /// List the named contexts (name, API URL, organization; * marks the
    /// selected one)
    GetContexts,
    /// Make <name> the current context (writes current_context only)
    UseContext {
        /// A context from `config get-contexts`
        name: String,
    },
    /// Create or update the named context
    SetContext {
        /// Context name
        name: String,
        /// API URL (required for a new context)
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        url: Option<String>,
        /// API key
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        key: Option<String>,
        /// Organization name
        #[arg(long, value_parser = clap::builder::NonEmptyStringValueParser::new())]
        org: Option<String>,
    },
}

pub fn run(cmd: ConfigCmd) -> ExitCode {
    crate::finish(match cmd {
        ConfigCmd::Show => run_show(),
        ConfigCmd::Set { key, value } => run_set(&key, &value),
        ConfigCmd::GetContexts => read_text()
            .and_then(|t| {
                get_contexts_output(
                    t.as_deref(),
                    CONTEXT_FLAG.get().map(String::as_str),
                    process_env,
                )
            })
            .map_err(|e| Failure::runtime(format!("Error: {e}"))),
        ConfigCmd::UseContext { name } => rewrite(|existing| {
            let text =
                use_context_in_text(existing.unwrap_or(""), &name).map_err(Failure::usage)?;
            Ok((text, format!("Switched to context {name:?}.\n")))
        }),
        ConfigCmd::SetContext {
            name,
            url,
            key,
            org,
        } => rewrite(|existing| {
            let text = set_context_in_text(
                existing,
                &name,
                url.as_deref(),
                key.as_deref(),
                org.as_deref(),
            )?;
            Ok((text, format!("Context {name:?} set.\n")))
        }),
    })
}

/// Read-modify-write of the config file: `edit` maps the current text to
/// the new text and the message to print.
fn rewrite(edit: impl FnOnce(Option<&str>) -> Result<(String, String), Failure>) -> CmdResult {
    let path =
        config_path().ok_or_else(|| Failure::runtime("Error: cannot determine home directory"))?;
    let existing = read_text().map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    let (text, msg) = edit(existing.as_deref())?;
    write_config_text(&path, &text)
        .map_err(|e| Failure::runtime(format!("Error saving config: {e}")))?;
    Ok(msg)
}

/// `config show`: print the resolved configuration, with the API key
/// shown only as its `key_state`.
fn run_show() -> CmdResult {
    let cfg = load().map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    Ok(show_output(cfg.as_ref()))
}

/// The `config get-contexts` table, pure for tests. Never prints a key.
pub fn get_contexts_output(
    file_text: Option<&str>,
    flag: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let file = parse_file(file_text)?;
    if file.contexts.is_empty() {
        return Ok(format!(
            "No contexts defined. Add one with '{BIN} config set-context <name> --url <url> --key <key>'.\n"
        ));
    }
    let env = |name: &str| get_env(name).filter(|v| !v.is_empty());
    let current = selected_context(&file, flag, &env)?;
    let mut rows = vec![["CURRENT", "NAME", "API URL", "ORG"].map(String::from)];
    for (name, c) in &file.contexts {
        let mark = if current.as_deref() == Some(name) {
            "*"
        } else {
            ""
        };
        rows.push([mark, name, &c.api_url, &c.org_name].map(String::from));
    }
    let widths: Vec<usize> = (0..3)
        .map(|i| rows.iter().map(|r| r[i].len()).max().unwrap_or(0))
        .collect();
    let mut out = String::new();
    for r in &rows {
        for (i, w) in widths.iter().enumerate() {
            out.push_str(&format!("{:<w$}  ", r[i]));
        }
        out.push_str(&r[3]);
        out.push('\n');
    }
    Ok(out)
}

/// Pure core of `config use-context`: set `current_context` and change
/// nothing else.
pub fn use_context_in_text(existing: &str, name: &str) -> Result<String, String> {
    let file = parse_file(Some(existing))?;
    if !file.contexts.contains_key(name) {
        return Err(format!("Error: {}", unknown_context(name, &file)));
    }
    edit_yaml(Some(existing), None, |m| {
        m.insert("current_context".into(), name.into());
    })
}

/// Pure core of `config set-context`: create or update `contexts.<name>`
/// with the given values. A new context needs a URL, so a context never
/// silently resolves to the production default.
pub fn set_context_in_text(
    existing: Option<&str>,
    name: &str,
    url: Option<&str>,
    key: Option<&str>,
    org: Option<&str>,
) -> Result<String, Failure> {
    let runtime = |e: String| Failure::runtime(format!("Error: {e}"));
    let file = parse_file(existing).map_err(runtime)?;
    if url.is_none() && !file.contexts.contains_key(name) {
        return Err(Failure::usage(format!(
            "Error: context {name:?} is new; give its API URL with --url"
        )));
    }
    if let Some(u) = url {
        validate_api_url(u).map_err(|e| Failure::usage(format!("Error: {e}")))?;
    }
    edit_yaml(existing, Some(name), |m| {
        for (k, v) in [("api_url", url), ("api_key", key), ("org_name", org)] {
            if let Some(v) = v {
                m.insert(k.into(), v.into());
            }
        }
        order_known_keys(m);
    })
    .map_err(runtime)
}

/// The `config show` body, pure for tests: `api_url`, `api_key` as its
/// `key_state`, `org_name`.
pub fn show_output(cfg: Option<&DataConfig>) -> String {
    use std::fmt::Write as _;
    let Some(cfg) = cfg else {
        return format!(
            "No configuration found. Run '{BIN} login' first, or set RVL_API_KEY for headless/CI use.\n"
        );
    };
    let mut out = String::new();
    let _ = writeln!(out, "api_url: {}", cfg.api_url);
    let _ = writeln!(out, "api_key: {}", key_state(&cfg.api_key));
    let _ = writeln!(out, "org_name: {}", cfg.org_name);
    out
}

/// `config set <key> <value>`: validate, rewrite the selected context (or
/// the top-level keys), echo the set value (`api_key` as its `key_state`). Unlike
/// rvl-cli (which marshals its fixed struct and so drops any field it does
/// not know), the rewrite is a read-modify-write of the raw YAML mapping:
/// unknown keys already in `~/.revelara/config.yaml` are preserved verbatim.
fn run_set(key: &str, value: &str) -> CmdResult {
    rewrite(|existing| {
        let context = selected_on_disk(existing).map_err(Failure::usage)?;
        let text = set_in_text(existing, context.as_deref(), key, value)?;
        Ok((text, format!("Set {key} = {}\n", mask_set_echo(key, value))))
    })
}

/// Pure core of `config set`: validate the key/value and return the new
/// file text. Field order matches rvl-cli's marshal order (`api_url`,
/// `api_key`, `org_name`) with unknown keys following in their original
/// order. With no context, `api_url` is seeded with the production default
/// when absent, mirroring rvl-cli's `Config{APIURL: DefaultAPIURL}`
/// bootstrap; a context gets no such seed.
pub fn set_in_text(
    existing: Option<&str>,
    context: Option<&str>,
    key: &str,
    value: &str,
) -> Result<String, Failure> {
    match key {
        "api_url" => {
            validate_api_url(value).map_err(|e| Failure::usage(format!("Error: {e}")))?;
        }
        "api_key" | "org_name" => {}
        _ => {
            return Err(Failure::usage(format!(
                "Unknown config key: {key}\nValid keys: api_url, api_key, org_name"
            )))
        }
    }
    edit_yaml(existing, context, |m| {
        m.insert(key.into(), value.into());
        let api_url_empty = match m.get("api_url") {
            Some(Value::String(s)) => s.is_empty(),
            Some(_) => false,
            None => true,
        };
        if context.is_none() && api_url_empty {
            m.insert("api_url".into(), DEFAULT_API_URL.into());
        }
        order_known_keys(m);
    })
    .map_err(|e| Failure::runtime(format!("Error: {e}")))
}

/// Apply `edit` to the top-level mapping (`context` `None`) or to
/// `contexts.<context>` (created when absent), and return the new text.
/// Every key `edit` does not touch is kept.
fn edit_yaml(
    existing: Option<&str>,
    context: Option<&str>,
    edit: impl FnOnce(&mut Mapping),
) -> Result<String, String> {
    let mut root: Mapping = match existing {
        Some(t) if !t.trim().is_empty() => serde_yaml::from_str(t).map_err(|e| e.to_string())?,
        _ => Mapping::new(),
    };
    match context {
        None => edit(&mut root),
        Some(name) => {
            let contexts = root
                .entry("contexts".into())
                .or_insert_with(|| Mapping::new().into())
                .as_mapping_mut()
                .ok_or("`contexts` is not a mapping")?;
            let target = contexts
                .entry(name.into())
                .or_insert_with(|| Mapping::new().into())
                .as_mapping_mut()
                .ok_or_else(|| format!("context {name:?} is not a mapping"))?;
            edit(target);
        }
    }
    serde_yaml::to_string(&root).map_err(|e| e.to_string())
}

/// Canonical field order: known keys first (rvl-cli's marshal order), then
/// everything else in original order.
fn order_known_keys(m: &mut Mapping) {
    let mut ordered = Mapping::new();
    for known in ["api_url", "api_key", "org_name"] {
        if let Some(v) = m.shift_remove(known) {
            ordered.insert(known.into(), v);
        }
    }
    ordered.extend(std::mem::take(m));
    *m = ordered;
}

/// Echo a `config set` value: every key unchanged except `api_key`,
/// which echoes as its `key_state`.
pub fn mask_set_echo(key: &str, value: &str) -> String {
    if key == "api_key" {
        return key_state(value).to_string();
    }
    value.to_string()
}

/// The only form in which an API key is ever printed: whether it is set.
/// No character of the key reaches output, so no log can leak a part of it.
pub fn key_state(key: &str) -> &'static str {
    if key.is_empty() {
        "(not set)"
    } else {
        "(set)"
    }
}

/// Reject `api_url` values that would send the bearer API key in
/// cleartext, matching rvl-cli's `validateAPIURL`: only https://, except
/// http:// to loopback hosts (localhost, 127.0.0.1, ::1) where no key
/// ever crosses the network.
pub fn validate_api_url(raw: &str) -> Result<(), String> {
    let (scheme, rest) = raw.split_once("://").unwrap_or(("", raw));
    if scheme == "https" {
        return Ok(());
    }
    if scheme == "http" && is_loopback_host(&url_hostname(rest)) {
        return Ok(());
    }
    Err(format!(
        "api_url must use https:// (http:// is only allowed for localhost); got {raw:?}"
    ))
}

/// The hostname of a URL's post-scheme remainder: authority minus
/// userinfo, brackets, and port.
fn url_hostname(after_scheme: &str) -> String {
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or("").to_string();
    }
    match host_port.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h.to_string(),
        _ => host_port.to_string(),
    }
}

/// Loopback names/addresses, matching rvl-cli's `isLoopbackHost`.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn file_only_resolution() {
        let cfg = resolve_from(
            Some("api_url: https://x.test\napi_key: pk_file\norg_name: acme\n"),
            None,
            no_env,
        )
        .unwrap()
        .cfg;
        assert_eq!(cfg.api_url, "https://x.test");
        assert_eq!(cfg.api_key, "pk_file");
        assert_eq!(cfg.org_name, "acme");
    }

    #[test]
    fn env_beats_file_and_empty_env_is_absent() {
        let env = |name: &str| match name {
            "RVL_API_KEY" => Some("pk_env".to_string()),
            "RVL_API_URL" => Some(String::new()), // exported-but-empty
            _ => None,
        };
        let cfg = resolve_from(
            Some("api_url: https://file.test\napi_key: pk_file\n"),
            None,
            env,
        )
        .unwrap()
        .cfg;
        assert_eq!(cfg.api_key, "pk_env");
        assert_eq!(cfg.api_url, "https://file.test");
    }

    #[test]
    fn legacy_rvlscan_env_names_have_no_effect() {
        // The binary reads exactly ONE env name per value. The pre-1.0
        // `RVLSCAN_ORG_KEY` / `RVLSCAN_API_BASE` names are not aliases and
        // not a deprecation shim: they are simply not read. Setting them
        // must leave resolution exactly where `RVL_*` and the defaults put
        // it, so this asserts the RESOLVED values positively rather than
        // asserting the absence of the old name.
        let env = |name: &str| match name {
            "RVLSCAN_ORG_KEY" => Some("pk_legacy".to_string()),
            "RVLSCAN_API_BASE" => Some("https://legacy.test".to_string()),
            "RVL_API_KEY" => Some("pk_rvl".to_string()),
            _ => None,
        };
        let cfg = resolve_from(None, None, env).unwrap().cfg;
        assert_eq!(cfg.api_key, "pk_rvl");
        assert_eq!(cfg.api_url, DEFAULT_API_URL);

        // With ONLY the legacy names set, there is no key anywhere.
        let legacy_only = |name: &str| match name {
            "RVLSCAN_ORG_KEY" => Some("pk_legacy".to_string()),
            "RVLSCAN_API_BASE" => Some("https://legacy.test".to_string()),
            _ => None,
        };
        assert_eq!(
            resolve_from(None, None, legacy_only).unwrap().cfg.api_key,
            ""
        );
    }

    #[test]
    fn no_key_anywhere_is_not_configured() {
        assert_eq!(resolve_from(None, None, no_env).unwrap().cfg.api_key, "");
        assert_eq!(
            resolve_from(Some("api_url: https://x.test\n"), None, no_env)
                .unwrap()
                .cfg
                .api_key,
            ""
        );
    }

    #[test]
    fn unknown_file_keys_are_tolerated() {
        let cfg = resolve_from(Some("api_key: pk\nfuture_key: v\n"), None, no_env)
            .unwrap()
            .cfg;
        assert_eq!(cfg.api_key, "pk");
    }

    #[test]
    fn malformed_file_is_an_error() {
        assert!(resolve_from(Some("api_key: [unterminated"), None, no_env).is_err());
    }

    #[test]
    fn show_output_prints_no_part_of_the_key() {
        let cfg = DataConfig {
            api_url: "https://api.revelara.ai".into(),
            api_key: "pk_live_abcdef123456".into(),
            org_name: "acme".into(),
        };
        assert_eq!(
            show_output(Some(&cfg)),
            "api_url: https://api.revelara.ai\napi_key: (set)\norg_name: acme\n"
        );
    }

    #[test]
    fn show_output_short_key_prints_set() {
        let cfg = DataConfig {
            api_url: "u".into(),
            api_key: "short".into(),
            org_name: String::new(),
        };
        assert_eq!(
            show_output(Some(&cfg)),
            "api_url: u\napi_key: (set)\norg_name: \n"
        );
    }

    #[test]
    fn show_output_unconfigured_points_at_login() {
        let out = show_output(None);
        assert_eq!(
            out,
            "No configuration found. Run 'rvl login' first, or set RVL_API_KEY for headless/CI use.\n"
        );
    }

    #[test]
    fn set_unknown_key_error_matches_rvl_cli_wording() {
        let err = set_in_text(None, None, "bogus", "v").unwrap_err();
        assert_eq!(
            err.msg,
            "Unknown config key: bogus\nValid keys: api_url, api_key, org_name"
        );
        assert_eq!(err.code, 2);
    }

    #[test]
    fn set_preserves_unknown_yaml_keys() {
        let existing = "api_url: https://x.test\napi_key: pk_file\nfuture_key: keep-me\n";
        let out = set_in_text(Some(existing), None, "org_name", "my-org").unwrap();
        assert_eq!(
            out,
            "api_url: https://x.test\napi_key: pk_file\norg_name: my-org\nfuture_key: keep-me\n"
        );
    }

    #[test]
    fn set_from_no_file_seeds_default_api_url() {
        let out = set_in_text(None, None, "org_name", "acme").unwrap();
        assert_eq!(out, "api_url: https://api.revelara.ai\norg_name: acme\n");
    }

    #[test]
    fn set_api_url_requires_https_except_loopback() {
        assert!(set_in_text(None, None, "api_url", "https://api.example.com").is_ok());
        assert!(set_in_text(None, None, "api_url", "http://localhost:8080").is_ok());
        assert!(set_in_text(None, None, "api_url", "http://127.0.0.1").is_ok());
        assert!(set_in_text(None, None, "api_url", "http://[::1]:8080").is_ok());
        let err = set_in_text(None, None, "api_url", "http://api.example.com").unwrap_err();
        assert_eq!(err.code, 2);
        assert_eq!(
            err.msg,
            "Error: api_url must use https:// (http:// is only allowed for localhost); got \"http://api.example.com\""
        );
        assert!(set_in_text(None, None, "api_url", "ftp://x").is_err());
    }

    #[test]
    fn set_echo_masks_only_the_api_key() {
        assert_eq!(mask_set_echo("org_name", "acme"), "acme");
        assert_eq!(mask_set_echo("api_key", "pk_live_abcdef123456"), "(set)");
        assert_eq!(mask_set_echo("api_key", ""), "(not set)");
    }

    #[test]
    fn save_yaml_shape_matches_rvl_cli() {
        let cfg = DataConfig {
            api_url: "https://api.revelara.ai".into(),
            api_key: "pk_x".into(),
            org_name: "acme".into(),
        };
        let y = serde_yaml::to_string(&cfg).unwrap();
        assert_eq!(
            y,
            "api_url: https://api.revelara.ai\napi_key: pk_x\norg_name: acme\n"
        );
    }

    // --- named contexts ---

    const TWO_CONTEXTS: &str = "\
api_url: https://top.test
api_key: pk_top
current_context: prod
contexts:
  prod:
    api_url: https://api.revelara.ai
    api_key: pk_prod
    org_name: revelara.ai
  staging:
    api_url: https://staging.example.com
    api_key: pk_mini
    org_name: dev-org
";

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn selection_order_is_flag_then_env_then_current_context() {
        let r = resolve_from(Some(TWO_CONTEXTS), None, no_env).unwrap();
        assert_eq!(r.context.as_deref(), Some("prod"));
        assert_eq!(r.cfg.api_url, "https://api.revelara.ai");

        let env = env_of(&[("RVL_CONTEXT", "staging")]);
        let r = resolve_from(Some(TWO_CONTEXTS), None, &env).unwrap();
        assert_eq!(r.context.as_deref(), Some("staging"));
        assert_eq!(r.cfg.api_url, "https://staging.example.com");
        assert_eq!(r.cfg.api_key, "pk_mini");

        let env = env_of(&[("RVL_CONTEXT", "staging")]);
        let r = resolve_from(Some(TWO_CONTEXTS), Some("prod"), &env).unwrap();
        assert_eq!(r.context.as_deref(), Some("prod"));
        assert_eq!(r.cfg.api_key, "pk_prod");
        assert_eq!(r.cfg.org_name, "revelara.ai");
    }

    #[test]
    fn no_selection_uses_the_top_level_keys() {
        let text = "api_url: https://top.test\napi_key: pk_top\ncontexts:\n  prod:\n    api_url: https://p.test\n";
        let r = resolve_from(Some(text), None, no_env).unwrap();
        assert_eq!(r.context, None);
        assert_eq!(r.cfg.api_url, "https://top.test");
        assert_eq!(r.cfg.api_key, "pk_top");
    }

    #[test]
    fn per_value_env_beats_the_selected_context() {
        let env = env_of(&[("RVL_API_KEY", "pk_env"), ("RVL_ORG_NAME", "env-org")]);
        let r = resolve_from(Some(TWO_CONTEXTS), Some("staging"), &env).unwrap();
        assert_eq!(r.cfg.api_url, "https://staging.example.com");
        assert_eq!(r.cfg.api_key, "pk_env");
        assert_eq!(r.cfg.org_name, "env-org");
    }

    #[test]
    fn unknown_context_errors_with_the_known_names() {
        let err = resolve_from(Some(TWO_CONTEXTS), Some("qa"), no_env).unwrap_err();
        assert_eq!(err, "unknown context \"qa\"; known contexts: prod, staging");
        let env = env_of(&[("RVL_CONTEXT", "nope")]);
        assert!(resolve_from(Some(TWO_CONTEXTS), None, &env).is_err());
        let err = resolve_from(Some("api_key: pk\n"), Some("prod"), no_env).unwrap_err();
        assert_eq!(err, "unknown context \"prod\"; known contexts: (none)");
        let err = resolve_from(None, Some("prod"), no_env).unwrap_err();
        assert_eq!(err, "unknown context \"prod\"; known contexts: (none)");
    }

    #[test]
    fn a_context_without_api_url_is_an_error_not_the_production_url() {
        let text = "contexts:\n  bare:\n    api_key: pk\n";
        let err = resolve_from(Some(text), Some("bare"), no_env).unwrap_err();
        assert!(err.contains("context \"bare\" has no api_url"), "{err}");
    }

    #[test]
    fn old_single_server_file_still_resolves() {
        let r = resolve_from(
            Some("api_url: https://x.test\napi_key: pk_file\norg_name: acme\nagent: claude\n"),
            None,
            no_env,
        )
        .unwrap();
        assert_eq!(r.context, None);
        assert_eq!(r.cfg.api_url, "https://x.test");
        assert_eq!(r.cfg.org_name, "acme");
        assert_eq!(r.agent, "claude");
    }

    #[test]
    fn use_context_changes_only_current_context() {
        let out = use_context_in_text(TWO_CONTEXTS, "staging").unwrap();
        assert_eq!(
            out,
            TWO_CONTEXTS.replace("current_context: prod", "current_context: staging")
        );
        let out = use_context_in_text(
            "api_url: https://x.test\nfuture: keep\ncontexts:\n  a:\n    api_url: https://a.test\n",
            "a",
        )
        .unwrap();
        assert_eq!(
            out,
            "api_url: https://x.test\nfuture: keep\ncontexts:\n  a:\n    api_url: https://a.test\ncurrent_context: a\n"
        );
        let err = use_context_in_text(TWO_CONTEXTS, "qa").unwrap_err();
        assert!(err.contains("known contexts: prod, staging"), "{err}");
    }

    #[test]
    fn set_context_creates_and_updates_one_context() {
        let out = set_context_in_text(None, "dev", Some("https://dev.test"), Some("pk_dev"), None)
            .unwrap();
        assert_eq!(
            out,
            "contexts:\n  dev:\n    api_url: https://dev.test\n    api_key: pk_dev\n"
        );
        let out =
            set_context_in_text(Some(TWO_CONTEXTS), "prod", None, None, Some("other")).unwrap();
        assert_eq!(
            out,
            TWO_CONTEXTS.replace("org_name: revelara.ai", "org_name: other")
        );
        let err = set_context_in_text(None, "dev", None, Some("pk"), None).unwrap_err();
        assert_eq!(err.code, 2);
        assert!(err.msg.contains("--url"), "{}", err.msg);
        let err =
            set_context_in_text(None, "dev", Some("http://example.com"), None, None).unwrap_err();
        assert_eq!(err.code, 2);
    }

    #[test]
    fn set_writes_into_the_selected_context() {
        let out = set_in_text(Some(TWO_CONTEXTS), Some("staging"), "org_name", "new-org").unwrap();
        assert_eq!(
            out,
            TWO_CONTEXTS.replace("org_name: dev-org", "org_name: new-org")
        );
    }

    #[test]
    fn get_contexts_marks_the_current_and_never_prints_a_key() {
        let out = get_contexts_output(Some(TWO_CONTEXTS), None, no_env).unwrap();
        assert_eq!(
            out,
            "CURRENT  NAME     API URL                      ORG\n\
             *        prod     https://api.revelara.ai      revelara.ai\n\
             \x20        staging  https://staging.example.com  dev-org\n"
        );
        assert!(!out.contains("pk_"));
        let out = get_contexts_output(Some(TWO_CONTEXTS), Some("staging"), no_env).unwrap();
        assert!(out.contains("*        staging"), "{out}");
        assert!(get_contexts_output(None, None, no_env)
            .unwrap()
            .starts_with("No contexts"));
    }

    #[test]
    fn key_material_is_not_reachable_from_config() {
        // SECURITY REGRESSION GUARD: a profile carries ONLY api_url /
        // api_key / org_name. Naming every field stops compiling when a
        // field is added, which forces a review against the distribution
        // contract. A file that tries to smuggle a keyset is ignored.
        let DataConfig {
            api_url: _,
            api_key: _,
            org_name: _,
        } = DataConfig::default();
        let smuggled = "api_key: pk_x\nkeyset: deadbeef\nsigning_key: nope\ncontexts:\n  a:\n    api_url: https://a.test\n    keyset_hex: cafebabe\n";
        let r = resolve_from(Some(smuggled), Some("a"), no_env).unwrap();
        assert_eq!(
            r.cfg,
            DataConfig {
                api_url: "https://a.test".into(),
                ..DataConfig::default()
            }
        );
    }
}
