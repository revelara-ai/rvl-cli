//! READ-ONLY view of rvl-cli's v1 install metadata, for day-one continuity
//! after the CLI cutover: every existing user's install was recorded by
//! rvl-cli in `~/.revelara/plugins.json` (legacy `~/.relynce/plugins.json`),
//! a JSON ARRAY of `{"editor","version","installed","location"}` objects
//! (rvl-cli `internal/plugin/types.go` `PluginInfo`). rvlscan reads these
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

/// Read all v1 install records under `home`. Mirrors rvl-cli's
/// `GetInstalledPlugins` lookup order: `.revelara/plugins.json` first, and
/// the legacy `.relynce/plugins.json` only when the primary cannot be read.
/// Best-effort: a missing or corrupt file yields an empty list — this is
/// display/fallback data, not a trust surface.
pub fn read_v1_installs(home: &Path) -> Vec<V1PluginInfo> {
    for dir in [".revelara", ".relynce"] {
        let Ok(data) = std::fs::read(home.join(dir).join("plugins.json")) else {
            continue;
        };
        return serde_json::from_slice(&data).unwrap_or_default();
    }
    Vec::new()
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

    #[test]
    fn falls_back_to_legacy_relynce_location() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".relynce")).unwrap();
        std::fs::write(home.path().join(".relynce/plugins.json"), RECORDS).unwrap();
        assert_eq!(read_v1_installs(home.path()).len(), 2);

        // The primary location wins once it exists (rvl-cli lookup order).
        std::fs::create_dir_all(home.path().join(".revelara")).unwrap();
        std::fs::write(home.path().join(".revelara/plugins.json"), "[]").unwrap();
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
