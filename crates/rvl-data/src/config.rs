//! rvl-cli-parity configuration for the data commands.
//!
//! Same file (`~/.revelara/config.yaml`), same keys (`api_url`, `api_key`,
//! `org_name`), same env override contract (`RVL_API_KEY` / `RVL_API_URL` /
//! `RVL_ORG_NAME` beat the file; the CI use case has no config file at all).
//! The rvlscan-specific `RVLSCAN_API_BASE` / `RVLSCAN_ORG_KEY` overrides used
//! by the scan surface are honored at the top of the chain so one binary has
//! one consistent story.
//!
//! SECURITY: this module reads/writes ONLY `api_url` / `api_key` /
//! `org_name`. Signing-key material must never become a config field (see
//! the shared-config security contract in the rvlscan crate).

use crate::{CmdResult, Failure, BIN};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The production default API endpoint, matching rvl-cli's `DefaultAPIURL`.
pub const DEFAULT_API_URL: &str = "https://api.revelara.ai";

/// The subset of `~/.revelara/config.yaml` the data commands use. Unknown
/// keys are tolerated and preserved-by-ignoring (rvl-cli owns the file).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataConfig {
    #[serde(default)]
    pub api_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub org_name: String,
}

/// `~/.revelara/config.yaml`.
pub fn config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(".revelara").join("config.yaml"))
}

/// Pure config resolution: overlay env vars on the (optional) file text.
/// Empty env values are treated as absent so an exported-but-empty var
/// never shadows a real file value. Returns `None` when no API key was
/// found anywhere — the caller surfaces "Not configured".
pub fn resolve_from(
    file_text: Option<&str>,
    get_env: impl Fn(&str) -> Option<String>,
) -> Result<Option<DataConfig>, String> {
    let mut cfg: DataConfig = match file_text {
        Some(text) => serde_yaml::from_str(text).map_err(|e| e.to_string())?,
        None => DataConfig::default(),
    };
    let env = |name: &str| get_env(name).filter(|v| !v.is_empty());
    if let Some(v) = env("RVLSCAN_ORG_KEY").or_else(|| env("RVL_API_KEY")) {
        cfg.api_key = v;
    }
    if let Some(v) = env("RVLSCAN_API_BASE").or_else(|| env("RVL_API_URL")) {
        cfg.api_url = v;
    }
    if let Some(v) = env("RVL_ORG_NAME") {
        cfg.org_name = v;
    }
    if cfg.api_url.is_empty() {
        cfg.api_url = DEFAULT_API_URL.to_string();
    }
    if cfg.api_key.is_empty() {
        return Ok(None);
    }
    Ok(Some(cfg))
}

/// Load config from disk + env, mirroring rvl-cli's `config.LoadConfig`:
/// a missing file is normal (env vars may still satisfy auth); a present
/// but malformed file is an error.
pub fn load() -> Result<Option<DataConfig>, String> {
    let text = match config_path() {
        Some(p) => match std::fs::read_to_string(&p) {
            Ok(t) => Some(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        },
        None => None,
    };
    resolve_from(text.as_deref(), |name| std::env::var(name).ok())
}

/// Persist config the way rvl-cli's `config.SaveConfig` does: YAML with
/// `api_url` / `api_key` / `org_name`, directory 0700, file 0600.
pub fn save(cfg: &DataConfig) -> Result<(), String> {
    let path = config_path().ok_or("cannot determine home directory")?;
    let data = serde_yaml::to_string(cfg).map_err(|e| e.to_string())?;
    write_config_text(&path, &data)
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

/// `rvlscan config`: view and edit CLI configuration.
#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Show current configuration (API key masked)
    Show,
    /// Set a configuration value (keys: api_url, api_key, org_name)
    Set {
        /// Config key: api_url, api_key, or org_name
        key: String,
        /// The value to store
        value: String,
    },
}

pub fn run(cmd: ConfigCmd) -> ExitCode {
    crate::finish(match cmd {
        ConfigCmd::Show => run_show(),
        ConfigCmd::Set { key, value } => run_set(&key, &value),
    })
}

/// `config show`: print the resolved configuration with the API key
/// masked exactly the way rvl-cli does (`abcd...wxyz`, or `(set)` for
/// short keys).
fn run_show() -> CmdResult {
    let cfg = load().map_err(|e| Failure::runtime(format!("Error: {e}")))?;
    Ok(show_output(cfg.as_ref()))
}

/// The `config show` body, pure for tests. Mirrors rvl-cli's field order
/// and masking: `api_url`, masked `api_key`, `org_name`.
pub fn show_output(cfg: Option<&DataConfig>) -> String {
    use std::fmt::Write as _;
    let Some(cfg) = cfg else {
        return format!(
            "No configuration found. Run '{BIN} login' first, or set RVL_API_KEY for headless/CI use.\n"
        );
    };
    let mut out = String::new();
    let _ = writeln!(out, "api_url: {}", cfg.api_url);
    if cfg.api_key.len() > 8 {
        let _ = writeln!(
            out,
            "api_key: {}...{}",
            &cfg.api_key[..4],
            &cfg.api_key[cfg.api_key.len() - 4..]
        );
    } else {
        let _ = writeln!(out, "api_key: (set)");
    }
    let _ = writeln!(out, "org_name: {}", cfg.org_name);
    out
}

/// `config set <key> <value>`: validate, rewrite the file, echo the set
/// value (masked for `api_key`). Unlike rvl-cli (which marshals its fixed
/// struct and so drops any field it does not know), the rewrite is a
/// read-modify-write of the raw YAML mapping: unknown keys already in
/// `~/.revelara/config.yaml` are preserved verbatim.
fn run_set(key: &str, value: &str) -> CmdResult {
    let path =
        config_path().ok_or_else(|| Failure::runtime("Error: cannot determine home directory"))?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Failure::runtime(format!("Error: {e}"))),
    };
    let text = set_in_text(existing.as_deref(), key, value)?;
    write_config_text(&path, &text)
        .map_err(|e| Failure::runtime(format!("Error saving config: {e}")))?;
    Ok(format!("Set {key} = {}\n", mask_set_echo(key, value)))
}

/// Pure core of `config set`: validate the key/value and return the new
/// file text. Field order matches rvl-cli's marshal order (`api_url`,
/// `api_key`, `org_name`) with unknown keys following in their original
/// order. `api_url` is seeded with the production default when absent,
/// mirroring rvl-cli's `Config{APIURL: DefaultAPIURL}` bootstrap.
pub fn set_in_text(existing: Option<&str>, key: &str, value: &str) -> Result<String, Failure> {
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
    use serde_yaml::{Mapping, Value};
    let mut map: Mapping = match existing {
        Some(t) if !t.trim().is_empty() => {
            serde_yaml::from_str(t).map_err(|e| Failure::runtime(format!("Error: {e}")))?
        }
        _ => Mapping::new(),
    };
    map.insert(
        Value::String(key.to_string()),
        Value::String(value.to_string()),
    );
    let api_url_key = Value::String("api_url".to_string());
    let api_url_empty = match map.get(&api_url_key) {
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
        None => true,
    };
    if api_url_empty {
        map.insert(api_url_key, Value::String(DEFAULT_API_URL.to_string()));
    }
    // Canonical field order: known keys first (rvl-cli's marshal order),
    // then everything else in original file order.
    let mut ordered = Mapping::new();
    for known in ["api_url", "api_key", "org_name"] {
        let k = Value::String(known.to_string());
        if let Some(v) = map.get(&k) {
            ordered.insert(k, v.clone());
        }
    }
    for (k, v) in &map {
        if !ordered.contains_key(k) {
            ordered.insert(k.clone(), v.clone());
        }
    }
    serde_yaml::to_string(&ordered).map_err(|e| Failure::runtime(format!("Error: {e}")))
}

/// Mask sensitive values before echoing them back, matching rvl-cli's
/// `maskConfigValue`: `api_key` echoes as its first 8 chars + `...` (or
/// `[set]` when short); every other key echoes unchanged.
pub fn mask_set_echo(key: &str, value: &str) -> String {
    if key != "api_key" {
        return value.to_string();
    }
    if value.len() > 12 && value.is_char_boundary(8) {
        return format!("{}...", &value[..8]);
    }
    "[set]".to_string()
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
            no_env,
        )
        .unwrap()
        .unwrap();
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
        let cfg = resolve_from(Some("api_url: https://file.test\napi_key: pk_file\n"), env)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.api_key, "pk_env");
        assert_eq!(cfg.api_url, "https://file.test");
    }

    #[test]
    fn rvlscan_env_beats_rvl_env() {
        let env = |name: &str| match name {
            "RVLSCAN_ORG_KEY" => Some("pk_scan".to_string()),
            "RVL_API_KEY" => Some("pk_rvl".to_string()),
            _ => None,
        };
        let cfg = resolve_from(None, env).unwrap().unwrap();
        assert_eq!(cfg.api_key, "pk_scan");
        assert_eq!(cfg.api_url, DEFAULT_API_URL);
    }

    #[test]
    fn no_key_anywhere_is_not_configured() {
        assert_eq!(resolve_from(None, no_env).unwrap(), None);
        assert_eq!(
            resolve_from(Some("api_url: https://x.test\n"), no_env).unwrap(),
            None
        );
    }

    #[test]
    fn unknown_file_keys_are_tolerated() {
        let cfg = resolve_from(Some("api_key: pk\nfuture_key: v\n"), no_env)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.api_key, "pk");
    }

    #[test]
    fn malformed_file_is_an_error() {
        assert!(resolve_from(Some("api_key: [unterminated"), no_env).is_err());
    }

    #[test]
    fn show_output_masks_the_key_exactly_like_rvl_cli() {
        let cfg = DataConfig {
            api_url: "https://api.revelara.ai".into(),
            api_key: "pk_live_abcdef123456".into(),
            org_name: "acme".into(),
        };
        assert_eq!(
            show_output(Some(&cfg)),
            "api_url: https://api.revelara.ai\napi_key: pk_l...3456\norg_name: acme\n"
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
            "No configuration found. Run 'rvlscan login' first, or set RVL_API_KEY for headless/CI use.\n"
        );
    }

    #[test]
    fn set_unknown_key_error_matches_rvl_cli_wording() {
        let err = set_in_text(None, "bogus", "v").unwrap_err();
        assert_eq!(
            err.msg,
            "Unknown config key: bogus\nValid keys: api_url, api_key, org_name"
        );
        assert_eq!(err.code, 2);
    }

    #[test]
    fn set_preserves_unknown_yaml_keys() {
        let existing = "api_url: https://x.test\napi_key: pk_file\nfuture_key: keep-me\n";
        let out = set_in_text(Some(existing), "org_name", "my-org").unwrap();
        assert_eq!(
            out,
            "api_url: https://x.test\napi_key: pk_file\norg_name: my-org\nfuture_key: keep-me\n"
        );
    }

    #[test]
    fn set_from_no_file_seeds_default_api_url() {
        let out = set_in_text(None, "org_name", "acme").unwrap();
        assert_eq!(out, "api_url: https://api.revelara.ai\norg_name: acme\n");
    }

    #[test]
    fn set_api_url_requires_https_except_loopback() {
        assert!(set_in_text(None, "api_url", "https://api.example.com").is_ok());
        assert!(set_in_text(None, "api_url", "http://localhost:8080").is_ok());
        assert!(set_in_text(None, "api_url", "http://127.0.0.1").is_ok());
        assert!(set_in_text(None, "api_url", "http://[::1]:8080").is_ok());
        let err = set_in_text(None, "api_url", "http://api.example.com").unwrap_err();
        assert_eq!(err.code, 2);
        assert_eq!(
            err.msg,
            "Error: api_url must use https:// (http:// is only allowed for localhost); got \"http://api.example.com\""
        );
        assert!(set_in_text(None, "api_url", "ftp://x").is_err());
    }

    #[test]
    fn set_echo_masks_only_the_api_key() {
        assert_eq!(mask_set_echo("org_name", "acme"), "acme");
        assert_eq!(
            mask_set_echo("api_key", "pk_live_abcdef123456"),
            "pk_live_..."
        );
        assert_eq!(mask_set_echo("api_key", "short"), "[set]");
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
}
