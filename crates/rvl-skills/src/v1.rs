//! READ-ONLY view of rvl-cli's v1 install metadata, for day-one continuity
//! after the CLI cutover: every existing user's install was recorded by
//! rvl-cli in `~/.revelara/plugins.json`, a JSON ARRAY of
//! `{"editor","version","installed","location"}` objects
//! (rvl-cli `internal/plugin/types.go` `PluginInfo`). rvl reads these
//! records as a fallback wherever its own store has none; it NEVER writes
//! them — adoption happens by performing a normal v2 install, which records
//! in the v2 store and takes precedence from then on.

use serde::Deserialize;
use std::path::Path;

/// One v1 install record (rvl-cli `PluginInfo`, wire field names).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct V1PluginInfo {
    #[serde(default)]
    pub editor: String,
    #[serde(default)]
    pub version: String,
    /// ISO8601 install timestamp (display data only).
    #[serde(default)]
    pub installed: String,
    #[serde(default)]
    pub location: String,
}

/// Read all v1 install records under `home`: `~/.revelara/plugins.json`, and
/// only that.
///
/// rvl-cli also fell back to a pre-rename config directory. That fallback is
/// NOT ported (user ruling 2026-08-15, po-av01j.185 item 9): pre-rename
/// config directories, project config files, and the pre-rename API URL
/// self-heal are all dropped together, so a user still on one of them looks
/// unauthenticated and re-runs login — a visible failure at the auth
/// boundary, not a silent one. Keeping this one read path alive would have
/// made that support inconsistently half-present: install records adopted,
/// credentials not.
///
/// Best-effort: a missing or corrupt file yields an empty list — this is
/// display/fallback data, not a trust surface.
pub fn read_v1_installs(home: &Path) -> Vec<V1PluginInfo> {
    let Ok(data) = std::fs::read(home.join(".revelara").join("plugins.json")) else {
        return Vec::new();
    };
    serde_json::from_slice(&data).unwrap_or_default()
}

/// The v1 record for one editor, if any.
pub fn v1_install(home: &Path, editor: &str) -> Option<V1PluginInfo> {
    read_v1_installs(home)
        .into_iter()
        .find(|p| p.editor == editor)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORDS: &str = r#"[
      {"editor":"claude","version":"0.9.0",
       "installed":"2026-08-01T10:00:00Z","location":"/home/x/plug"},
      {"editor":"gemini","version":"0.9.0",
       "installed":"2026-08-01T10:00:00Z","location":"/home/x/.gemini"}
    ]"#;

    #[test]
    fn reads_the_v1_array_schema() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".revelara")).unwrap();
        std::fs::write(home.path().join(".revelara/plugins.json"), RECORDS).unwrap();

        let all = read_v1_installs(home.path());
        assert_eq!(all.len(), 2);
        let claude = v1_install(home.path(), "claude").unwrap();
        assert_eq!(claude.version, "0.9.0");
        assert_eq!(claude.location, "/home/x/plug");
        assert!(v1_install(home.path(), "codex").is_none());
    }

    /// The pre-rename config directory is NOT read (user ruling 2026-08-15).
    #[test]
    fn pre_rename_config_dir_is_not_a_fallback() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".relynce")).unwrap();
        std::fs::write(home.path().join(".relynce/plugins.json"), RECORDS).unwrap();
        assert!(read_v1_installs(home.path()).is_empty());
    }

    #[test]
    fn missing_or_corrupt_metadata_yields_empty() {
        let home = tempfile::tempdir().unwrap();
        assert!(read_v1_installs(home.path()).is_empty());

        std::fs::create_dir_all(home.path().join(".revelara")).unwrap();
        std::fs::write(home.path().join(".revelara/plugins.json"), "not json").unwrap();
        assert!(read_v1_installs(home.path()).is_empty());
    }
}
