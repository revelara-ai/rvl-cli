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

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    let dir = path.parent().ok_or("invalid config path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let data = serde_yaml::to_string(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
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
