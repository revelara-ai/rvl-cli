//! Installed agent-lens listing: the `plugin agents` surface. Mirrors
//! rvl-cli's `ListInstalledAgents` source of truth exactly: agents are read
//! from the INSTALLED files on disk (never the network) — for Claude Code
//! the `agents/` directory under the recorded install location, for
//! directory harnesses the harness's fixed agents directory under `$HOME`.
//!
//! OUTPUT CONTRACT (`plugin agents --json`), parsed by the plugin scan
//! skill as the source of truth for available lenses:
//! `{"agents":[{"id":"...","description":"..."}]}`

use rvl_core::BIN;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::store::SkillsStore;

/// One installed agent lens: `<id>.md` plus its frontmatter description.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentEntry {
    pub id: String,
    pub description: String,
}

/// The wire shape of `plugin agents --json`. Field order matters for the
/// byte-level contract; serde serializes struct fields in declaration order.
#[derive(Debug, Serialize)]
pub struct AgentsOutput {
    pub agents: Vec<AgentEntry>,
}

/// Which install record anchored an agents-directory resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSource {
    /// rvl's own store (installed.json in the skills cache).
    V2,
    /// rvl-cli's v1 metadata (~/.revelara/plugins.json), read-only fallback.
    V1,
}

/// Resolve the directory holding installed agent files for `editor`,
/// anchored on the install record (rvl-cli `installedAgentsDir` parity):
/// Claude Code keeps agents under its recorded install location; the other
/// harnesses use their fixed agents directory under `home`. rvl's own
/// store wins; when it has no record, the v1 rvl-cli record is the
/// fallback so upgraded users keep their lens listing on day one.
pub fn installed_agents_dir(
    store: &SkillsStore,
    home: &Path,
    editor: &str,
) -> anyhow::Result<(PathBuf, RecordSource)> {
    // Claude anchors on the record's location; everything else resolves to
    // a fixed home-relative agents dir regardless of which record proved
    // the install exists.
    let resolve =
        |location: &str, source: RecordSource| -> anyhow::Result<(PathBuf, RecordSource)> {
            if editor == "claude" {
                return Ok((PathBuf::from(location).join("agents"), source));
            }
            let Some(h) = crate::harness::by_name(editor) else {
                anyhow::bail!(
                    "unsupported harness: {editor} (supported: {})",
                    crate::harness::supported_names().join(", ")
                );
            };
            let Some(dir) = h.agents_dir() else {
                anyhow::bail!("harness {editor:?} does not expose a separate agents directory");
            };
            Ok((home.join(dir), source))
        };

    if let Some(info) = store.read_installed().get(editor) {
        return resolve(&info.location, RecordSource::V2);
    }
    if let Some(p) = crate::v1::v1_install(home, editor) {
        return resolve(&p.location, RecordSource::V1);
    }
    anyhow::bail!(
        "no Revelara skills installed for harness {editor:?} (run: {BIN} plugin install {editor})"
    )
}

/// List the agent lens files in `dir`: regular `<id>.md` files with the
/// YAML frontmatter `description:` value, sorted by id.
pub fn list_agents(dir: &Path) -> anyhow::Result<Vec<AgentEntry>> {
    let mut agents = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".md") else {
            continue;
        };
        let description = std::fs::read_to_string(entry.path())
            .map(|c| frontmatter_description(&c))
            .unwrap_or_default();
        agents.push(AgentEntry {
            id: id.to_string(),
            description,
        });
    }
    agents.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(agents)
}

/// The YAML frontmatter `description:` value of an agent markdown file
/// ("" when absent). Deliberately line-based with a single quote layer
/// stripped — the same tolerance as rvl-cli's reader, not a YAML parser.
pub fn frontmatter_description(content: &str) -> String {
    let mut in_frontmatter = false;
    for line in content.lines() {
        if line == "---" {
            if in_frontmatter {
                return String::new(); // frontmatter closed without a description
            }
            in_frontmatter = true;
            continue;
        }
        if !in_frontmatter {
            continue;
        }
        if let Some(rest) = line.strip_prefix("description:") {
            let val = rest.trim();
            let unquoted = val
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| val.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')));
            return unquoted.unwrap_or(val).to_string();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InstalledInfo;

    fn store_with(dir: &Path, harness: &str, location: &Path) -> SkillsStore {
        let store = SkillsStore::open(dir).unwrap();
        store
            .record_installed(
                harness,
                InstalledInfo {
                    version: "0.2.0".into(),
                    location: location.display().to_string(),
                    installed_at: "2026-08-13".into(),
                },
            )
            .unwrap();
        store
    }

    #[test]
    fn json_output_contract_is_exact() {
        let agents = vec![AgentEntry {
            id: "rvl-golang-pro".into(),
            description: "Go reliability lens".into(),
        }];
        assert_eq!(
            serde_json::to_string(&AgentsOutput { agents }).unwrap(),
            r#"{"agents":[{"id":"rvl-golang-pro","description":"Go reliability lens"}]}"#
        );
        // The empty shape stays parseable JSON with the same key.
        assert_eq!(
            serde_json::to_string(&AgentsOutput { agents: Vec::new() }).unwrap(),
            r#"{"agents":[]}"#
        );
    }

    #[test]
    fn claude_agents_resolve_under_the_recorded_install_location() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let location = home.join(".revelara/marketplace/plugins/revelara");
        let agents_dir = location.join("agents");
        std::fs::create_dir_all(&agents_dir).unwrap();
        std::fs::write(
            agents_dir.join("rvl-rust-pro.md"),
            "---\nname: rvl-rust-pro\ndescription: \"Rust reliability lens\"\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(agents_dir.join("rvl-golang-pro.md"), "no frontmatter").unwrap();
        std::fs::write(agents_dir.join("notes.txt"), "not an agent").unwrap();
        std::fs::create_dir_all(agents_dir.join("sub.md")).unwrap(); // dir, skipped

        let store = store_with(&dir.path().join("cache"), "claude", &location);
        let (resolved, source) = installed_agents_dir(&store, &home, "claude").unwrap();
        assert_eq!(resolved, agents_dir);
        assert_eq!(source, RecordSource::V2);

        let agents = list_agents(&resolved).unwrap();
        assert_eq!(
            agents,
            vec![
                AgentEntry {
                    id: "rvl-golang-pro".into(),
                    description: String::new(),
                },
                AgentEntry {
                    id: "rvl-rust-pro".into(),
                    description: "Rust reliability lens".into(),
                },
            ],
            "sorted by id, .txt and directories skipped, quotes stripped"
        );
    }

    #[test]
    fn dir_harness_agents_resolve_under_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let store = store_with(&dir.path().join("cache"), "gemini", &home.join(".gemini"));
        assert_eq!(
            installed_agents_dir(&store, &home, "gemini").unwrap(),
            (home.join(".gemini/agents"), RecordSource::V2)
        );
    }

    fn write_v1_records(home: &Path, records: &str) {
        std::fs::create_dir_all(home.join(".revelara")).unwrap();
        std::fs::write(home.join(".revelara/plugins.json"), records).unwrap();
    }

    #[test]
    fn v1_record_is_the_fallback_when_the_v2_store_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let v1_location = home.join(".claude/plugins/cache/revelara-api/revelara/0.9.0");
        write_v1_records(
            &home,
            &format!(
                r#"[{{"editor":"claude","version":"0.9.0",
                     "installed":"2026-08-01T10:00:00Z","location":{loc}}},
                    {{"editor":"gemini","version":"0.9.0",
                     "installed":"2026-08-01T10:00:00Z","location":""}}]"#,
                loc = serde_json::json!(v1_location.to_str().unwrap())
            ),
        );

        let store = SkillsStore::open(&dir.path().join("cache")).unwrap();
        assert_eq!(
            installed_agents_dir(&store, &home, "claude").unwrap(),
            (v1_location.join("agents"), RecordSource::V1),
            "claude anchors on the v1 record's location"
        );
        assert_eq!(
            installed_agents_dir(&store, &home, "gemini").unwrap(),
            (home.join(".gemini/agents"), RecordSource::V1),
            "tier-2 resolves to the fixed home-relative agents dir"
        );
        // A harness with no record in EITHER store still errors.
        assert!(installed_agents_dir(&store, &home, "cursor").is_err());
    }

    #[test]
    fn v2_record_wins_over_a_v1_record_for_the_same_harness() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let v2_location = home.join(".revelara/marketplace/plugins/revelara");
        write_v1_records(
            &home,
            r#"[{"editor":"claude","version":"0.9.0",
                 "installed":"2026-08-01T10:00:00Z","location":"/stale/v1/path"}]"#,
        );
        let store = store_with(&dir.path().join("cache"), "claude", &v2_location);
        assert_eq!(
            installed_agents_dir(&store, &home, "claude").unwrap(),
            (v2_location.join("agents"), RecordSource::V2),
            "the adopted v2 record must shadow the stale v1 location"
        );
    }

    #[test]
    fn harness_without_agents_dir_and_uninstalled_harness_both_error() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let store = store_with(&dir.path().join("cache"), "codex", &home.join(".agents"));

        let err = installed_agents_dir(&store, &home, "codex").unwrap_err();
        assert!(err.to_string().contains("agents directory"), "got: {err}");

        let err = installed_agents_dir(&store, &home, "gemini").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no Revelara skills installed"), "got: {msg}");
        assert!(msg.contains("plugin install gemini"), "got: {msg}");
    }

    #[test]
    fn frontmatter_description_edge_cases() {
        assert_eq!(
            frontmatter_description("---\ndescription: plain value\n---\n"),
            "plain value"
        );
        assert_eq!(
            frontmatter_description("---\ndescription: 'single quoted'\n---\n"),
            "single quoted"
        );
        // Description outside frontmatter is ignored; closed frontmatter
        // without one yields "".
        assert_eq!(
            frontmatter_description("---\nname: x\n---\ndescription: body text\n"),
            ""
        );
        assert_eq!(frontmatter_description("description: no frontmatter\n"), "");
        assert_eq!(frontmatter_description(""), "");
    }
}
