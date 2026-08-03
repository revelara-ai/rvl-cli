//! Shared `~/.revelara/config.yaml` loading.
//!
//! rvlscan reads the SAME config file the sibling `rvl-cli` writes, so a user
//! who ran `rvl config set api_key <key>` does not have to export anything to
//! run `rvlscan sync`. This mirrors rvl-cli's format VERBATIM: a YAML document
//! with `api_url`, `api_key`, and `org_name` keys. rvlscan consumes only
//! `api_url` and `api_key`; `org_name` (and any future rvl-cli keys) are
//! tolerated and ignored — rvl-cli owns them.
//!
//! ============================ SECURITY CONTRACT ============================
//! The signing KEYSET MUST NEVER become a config field. It is compiled into the
//! binary on purpose (`DEV_KEYSET_HEX`); a config-file keyset would be exactly
//! the verification bypass the distribution contract forbids. This module reads
//! ONLY `api_url` / `api_key`. Do NOT add, read, or plumb any key material
//! (signing keys, verification keys, keyset hex) from the config file — not
//! now, not "just for dev", not behind a flag. If you find yourself adding a
//! third field here that carries key bytes, stop: that is the bug.
//! ==========================================================================

use serde::Deserialize;

/// The subset of `~/.revelara/config.yaml` that rvlscan consumes.
///
/// `#[serde(default)]` makes both fields optional and — crucially — the struct
/// does NOT use `deny_unknown_fields`, so `org_name` and any future rvl-cli
/// keys deserialize successfully and are simply dropped, never an error.
///
/// SECURITY: the fields here are EXACTLY `{api_url, api_key}`. There is
/// deliberately no field that can carry signing/verification key material. See
/// the module-level security contract.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SharedConfig {
    pub api_url: Option<String>,
    pub api_key: Option<String>,
}

impl SharedConfig {
    /// Parse a YAML document into a `SharedConfig`. Any parse error (malformed
    /// YAML, wrong shape) collapses to `SharedConfig::default()` — a broken
    /// shared file must NEVER fail a scan. Factored out from file I/O so the
    /// parse-and-fallback behavior is unit-testable without touching disk.
    fn from_yaml_str(text: &str) -> Self {
        serde_yaml::from_str(text).unwrap_or_default()
    }
}

/// Read `$HOME/.revelara/config.yaml` and return the api_url/api_key it carries.
///
/// A missing file is NORMAL (CI runs purely on env vars) and returns an empty
/// `SharedConfig`. A present-but-unreadable or malformed file also returns the
/// empty default: a broken shared config must not crash a scan. Uses
/// `std::env::var_os("HOME")` so a missing HOME is handled gracefully.
pub fn load_shared_config() -> SharedConfig {
    let Some(home) = std::env::var_os("HOME") else {
        return SharedConfig::default();
    };
    let path = std::path::Path::new(&home)
        .join(".revelara")
        .join("config.yaml");
    match std::fs::read_to_string(&path) {
        Ok(text) => SharedConfig::from_yaml_str(&text),
        // Missing file is the common, expected case; any other read error is
        // still non-fatal — degrade to env-only rather than aborting the scan.
        Err(_) => SharedConfig::default(),
    }
}

/// Return the first `Some(non-empty)` value from `vals`, else `None`.
///
/// An empty string is treated as ABSENT: an exported-but-empty
/// `RVLSCAN_ORG_KEY=""` must not shadow a real value from a lower-precedence
/// source. Pure and filesystem-free so precedence layering is unit-testable.
pub fn first_nonempty(vals: &[Option<String>]) -> Option<String> {
    vals.iter().flatten().find(|s| !s.is_empty()).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_nonempty_env_specific_wins() {
        // env-specific beats env-shared beats file beats default.
        let got = first_nonempty(&[
            Some("specific".into()),
            Some("shared".into()),
            Some("file".into()),
            Some("default".into()),
        ]);
        assert_eq!(got.as_deref(), Some("specific"));
    }

    #[test]
    fn first_nonempty_env_shared_beats_file() {
        let got = first_nonempty(&[
            None,
            Some("shared".into()),
            Some("file".into()),
            Some("default".into()),
        ]);
        assert_eq!(got.as_deref(), Some("shared"));
    }

    #[test]
    fn first_nonempty_file_beats_default() {
        let got = first_nonempty(&[None, None, Some("file".into()), Some("default".into())]);
        assert_eq!(got.as_deref(), Some("file"));
    }

    #[test]
    fn first_nonempty_falls_through_to_default() {
        let got = first_nonempty(&[None, None, None, Some("default".into())]);
        assert_eq!(got.as_deref(), Some("default"));
    }

    #[test]
    fn first_nonempty_empty_string_is_absent() {
        // An exported-but-empty env var must NOT shadow a real file value.
        let got = first_nonempty(&[
            Some(String::new()), // RVLSCAN_ORG_KEY=""
            Some(String::new()), // RVL_API_KEY=""
            Some("filekey".into()),
            None,
        ]);
        assert_eq!(got.as_deref(), Some("filekey"));
    }

    #[test]
    fn first_nonempty_all_absent_is_none() {
        assert_eq!(first_nonempty(&[None, Some(String::new()), None]), None);
    }

    #[test]
    fn parses_all_three_keys_ignoring_org_name() {
        // A full rvl-cli doc: org_name is tolerated and dropped, never an error.
        let text = "api_url: https://example.test\napi_key: pk_filekey\norg_name: acme-corp\n";
        let cfg = SharedConfig::from_yaml_str(text);
        assert_eq!(cfg.api_url.as_deref(), Some("https://example.test"));
        assert_eq!(cfg.api_key.as_deref(), Some("pk_filekey"));
    }

    #[test]
    fn parses_only_api_key_leaving_url_none() {
        let cfg = SharedConfig::from_yaml_str("api_key: pk_only\n");
        assert_eq!(cfg.api_key.as_deref(), Some("pk_only"));
        assert_eq!(cfg.api_url, None);
    }

    #[test]
    fn parses_empty_doc_to_all_none() {
        assert_eq!(SharedConfig::from_yaml_str("{}"), SharedConfig::default());
        assert_eq!(SharedConfig::from_yaml_str(""), SharedConfig::default());
    }

    #[test]
    fn tolerates_unknown_future_keys() {
        // rvl-cli may add keys later; they must not break rvlscan parsing.
        let text = "api_key: pk_x\nsome_future_key: whatever\nnested:\n  a: 1\n";
        let cfg = SharedConfig::from_yaml_str(text);
        assert_eq!(cfg.api_key.as_deref(), Some("pk_x"));
    }

    #[test]
    fn malformed_yaml_returns_default_no_panic() {
        // A broken shared file must degrade to empty, never crash a scan.
        let cfg = SharedConfig::from_yaml_str("this: is: not: valid: yaml: [unterminated");
        assert_eq!(cfg, SharedConfig::default());
    }

    #[test]
    fn keyset_is_not_reachable_from_config() {
        // SECURITY REGRESSION GUARD: the config struct must carry ONLY
        // api_url/api_key and never any key material. This test constructs a
        // fully-populated SharedConfig by naming EVERY field explicitly; if a
        // future edit adds a third field (e.g. a keyset), this stops compiling
        // and forces a review against the distribution contract. A YAML doc
        // that tries to smuggle a keyset must be silently ignored.
        let cfg = SharedConfig {
            api_url: Some("https://example.test".into()),
            api_key: Some("pk_x".into()),
        };
        assert_eq!(cfg.api_url.as_deref(), Some("https://example.test"));
        assert_eq!(cfg.api_key.as_deref(), Some("pk_x"));

        let smuggled = "api_key: pk_x\nkeyset: deadbeef\nkeyset_hex: cafebabe\nsigning_key: nope\n";
        let parsed = SharedConfig::from_yaml_str(smuggled);
        assert_eq!(parsed.api_key.as_deref(), Some("pk_x"));
        // The only fields observable are api_url/api_key; there is no accessor
        // for any smuggled key material because no such field exists.
        assert_eq!(parsed.api_url, None);
    }
}
