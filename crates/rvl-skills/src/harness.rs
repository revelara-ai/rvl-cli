//! Harness adapters: where and how verified skill files land in each
//! coding-agent environment. One trait, a data-driven directory adapter for
//! the universal harnesses, and a custom Claude Code adapter (marketplace
//! layout shared with rvl-cli, so either tool can update the other's
//! install). Adding a harness = one more registry entry or trait impl.
//!
//! Install is pure file placement — detection and installation never launch
//! any agent. Registration commands for Claude Code are *returned* to the
//! caller (the CLI layer decides whether to run them).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::verify::safe_rel_path;

/// What an install did, for reporting and drift tracking.
#[derive(Debug)]
pub struct InstallReceipt {
    /// Where the files went.
    pub location: PathBuf,
    /// Regular files written.
    pub files_written: usize,
    /// Post-install action the CLI layer should run or surface (e.g. the
    /// `claude plugin marketplace add` registration for Claude Code).
    pub register: Option<Registration>,
    /// One-line "what now" note for the user.
    pub note: &'static str,
}

/// A registration step: commands (argv form) that wire the installed files
/// into the harness's own plugin system. Never executed by this crate.
#[derive(Debug)]
pub struct Registration {
    /// The binary the commands run (e.g. "claude").
    pub binary: &'static str,
    /// Each command as argv (binary excluded). Commands are best-effort in
    /// order; the first (cleanup) may fail harmlessly.
    pub commands: Vec<Vec<String>>,
}

/// A coding-agent environment rvlscan can install the workflow skills into.
pub trait Harness {
    /// Registry key, also the `installed.json` key (e.g. "claude").
    fn name(&self) -> &'static str;
    /// Human name for messages (e.g. "Claude Code").
    fn display_name(&self) -> &'static str;
    /// The backend's `?editor=` parameter for this harness's tarball layout.
    fn editor_param(&self) -> &'static str;
    /// Is this harness present on the machine? Pure filesystem check under
    /// `home` (no PATH probing, no process launches).
    fn detect(&self, home: &Path) -> bool;
    /// Idempotently place already-verified files into the harness. Repeat
    /// installs of the same content converge to the same on-disk state.
    fn install(
        &self,
        home: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        version: &str,
    ) -> anyhow::Result<InstallReceipt>;
}

/// Universal adapter: tarball content extracted under `home/<install_dir>`,
/// detected by `home/<config_dir>` existing. Mirrors rvl-cli's editor
/// registry entries for the same names.
pub struct DirHarness {
    pub name: &'static str,
    pub display_name: &'static str,
    pub editor_param: &'static str,
    pub config_dir: &'static str,
    pub install_dir: &'static str,
    pub note: &'static str,
}

/// Write `files` under `root`, checking every path stays inside it. The
/// integrity manifest is written too (parity with rvl plugin extraction; it
/// also lets a human audit exactly what was installed).
fn write_files(root: &Path, files: &BTreeMap<String, Vec<u8>>) -> anyhow::Result<usize> {
    // Validate every path BEFORE writing anything: no partial install on a
    // hostile name.
    for name in files.keys() {
        safe_rel_path(name)?;
    }
    let mut written = 0;
    for (name, content) in files {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        written += 1;
    }
    Ok(written)
}

impl Harness for DirHarness {
    fn name(&self) -> &'static str {
        self.name
    }
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    fn editor_param(&self) -> &'static str {
        self.editor_param
    }
    fn detect(&self, home: &Path) -> bool {
        home.join(self.config_dir).is_dir()
    }
    fn install(
        &self,
        home: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        _version: &str,
    ) -> anyhow::Result<InstallReceipt> {
        let root = home.join(self.install_dir);
        let files_written = write_files(&root, files)?;
        Ok(InstallReceipt {
            location: root,
            files_written,
            register: None,
            note: self.note,
        })
    }
}

/// Claude Code: the tarball is a marketplace plugin (`.claude-plugin/
/// plugin.json` + `commands/` + `agents/`). It is staged into the SAME local
/// marketplace rvl-cli uses (`~/.revelara/marketplace`), the marketplace
/// manifest is (re)written with the installed version, and the returned
/// [`Registration`] carries the `claude plugin` commands that activate it.
pub struct ClaudeHarness;

/// Marketplace identity shared with rvl-cli — keep in sync with
/// rvl-cli/internal/plugin/claude.go so both tools manage one install.
pub const CLAUDE_MARKETPLACE_NAME: &str = "revelara-local";
pub const CLAUDE_PLUGIN_NAME: &str = "revelara";

fn claude_marketplace_json(version: &str) -> String {
    format!(
        r#"{{
  "$schema": "https://anthropic.com/claude-code/marketplace.schema.json",
  "name": "{CLAUDE_MARKETPLACE_NAME}",
  "description": "Revelara plugin for reliability risk analysis",
  "owner": {{
    "name": "Revelara",
    "email": "team@revelara.ai"
  }},
  "plugins": [
    {{
      "name": "{CLAUDE_PLUGIN_NAME}",
      "version": "{version}",
      "description": "Reliability risk analysis and incident prevention for engineering teams",
      "author": {{
        "name": "Revelara",
        "email": "team@revelara.ai"
      }},
      "source": "./plugins/{CLAUDE_PLUGIN_NAME}",
      "category": "development",
      "homepage": "https://docs.revelara.ai"
    }}
  ]
}}"#
    )
}

impl Harness for ClaudeHarness {
    fn name(&self) -> &'static str {
        "claude"
    }
    fn display_name(&self) -> &'static str {
        "Claude Code"
    }
    fn editor_param(&self) -> &'static str {
        "claude"
    }
    fn detect(&self, home: &Path) -> bool {
        home.join(".claude").is_dir()
    }
    fn install(
        &self,
        home: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        version: &str,
    ) -> anyhow::Result<InstallReceipt> {
        let marketplace = home.join(".revelara").join("marketplace");
        let plugin_dir = marketplace.join("plugins").join(CLAUDE_PLUGIN_NAME);
        // Clean slate like rvl-cli: a stale file from an older version must
        // not survive next to the new content.
        if marketplace.exists() {
            std::fs::remove_dir_all(&marketplace)?;
        }
        std::fs::create_dir_all(&plugin_dir)?;
        let files_written = write_files(&plugin_dir, files)?;

        let manifest_dir = marketplace.join(".claude-plugin");
        std::fs::create_dir_all(&manifest_dir)?;
        std::fs::write(
            manifest_dir.join("marketplace.json"),
            claude_marketplace_json(version),
        )?;

        let marketplace_str = marketplace.display().to_string();
        Ok(InstallReceipt {
            location: plugin_dir,
            files_written,
            register: Some(Registration {
                binary: "claude",
                commands: vec![
                    vec![
                        "plugin".into(),
                        "marketplace".into(),
                        "remove".into(),
                        CLAUDE_MARKETPLACE_NAME.into(),
                    ],
                    vec![
                        "plugin".into(),
                        "marketplace".into(),
                        "add".into(),
                        marketplace_str,
                    ],
                    vec![
                        "plugin".into(),
                        "install".into(),
                        format!("{CLAUDE_PLUGIN_NAME}@{CLAUDE_MARKETPLACE_NAME}"),
                    ],
                ],
            }),
            note: "Commands available after registration: /rvl:scan, /rvl:fix, /rvl:ask, ... \
                   Restart Claude Code to load them.",
        })
    }
}

/// All harnesses rvlscan knows how to install into, Claude Code first. The
/// universal entries mirror rvl-cli's registry paths for the same editors.
pub fn registry() -> Vec<Box<dyn Harness>> {
    vec![
        Box::new(ClaudeHarness),
        Box::new(DirHarness {
            name: "codex",
            display_name: "OpenAI Codex",
            editor_param: "codex",
            config_dir: ".codex",
            install_dir: ".agents/skills",
            note: "Skills are auto-discovered by Codex CLI.",
        }),
        Box::new(DirHarness {
            name: "gemini",
            display_name: "Google Gemini CLI",
            editor_param: "gemini",
            config_dir: ".gemini",
            install_dir: ".gemini",
            note: "Skills and agents are auto-discovered by Gemini CLI.",
        }),
        Box::new(DirHarness {
            name: "cursor",
            display_name: "Cursor",
            editor_param: "cursor",
            config_dir: ".cursor",
            install_dir: ".cursor",
            note: "Skills and agents are auto-discovered by Cursor.",
        }),
        Box::new(DirHarness {
            name: "copilot",
            display_name: "GitHub Copilot",
            editor_param: "copilot",
            config_dir: ".copilot",
            install_dir: ".copilot",
            note: "Skills and agents are auto-discovered by Copilot CLI.",
        }),
        Box::new(DirHarness {
            name: "windsurf",
            display_name: "Windsurf",
            editor_param: "windsurf",
            config_dir: ".codeium/windsurf",
            install_dir: ".codeium/windsurf/skills",
            note: "Skills are auto-discovered by Windsurf.",
        }),
    ]
}

/// Look one harness up by name.
pub fn by_name(name: &str) -> Option<Box<dyn Harness>> {
    registry().into_iter().find(|h| h.name() == name)
}

/// Harness names detected under `home`, registry order (Claude first).
pub fn detect_installed(home: &Path) -> Vec<String> {
    registry()
        .iter()
        .filter(|h| h.detect(home))
        .map(|h| h.name().to_string())
        .collect()
}

/// All supported harness names, registry order.
pub fn supported_names() -> Vec<&'static str> {
    registry().iter().map(|h| h.name()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(entries: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(n, c)| (n.to_string(), c.to_vec()))
            .collect()
    }

    #[test]
    fn detection_is_config_dir_based_claude_first() {
        let home = tempfile::tempdir().unwrap();
        assert!(detect_installed(home.path()).is_empty());

        std::fs::create_dir_all(home.path().join(".gemini")).unwrap();
        assert_eq!(detect_installed(home.path()), vec!["gemini"]);

        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        assert_eq!(detect_installed(home.path()), vec!["claude", "gemini"]);
    }

    #[test]
    fn dir_harness_install_is_idempotent() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("gemini").unwrap();
        let content = files(&[
            ("skills/rvl-scan/SKILL.md", b"scan skill".as_slice()),
            ("agents/rvl-golang-pro.md", b"lens".as_slice()),
        ]);

        let first = h.install(home.path(), &content, "0.2.0").unwrap();
        let second = h.install(home.path(), &content, "0.2.0").unwrap();
        assert_eq!(first.files_written, 2);
        assert_eq!(second.files_written, 2);
        assert_eq!(first.location, home.path().join(".gemini"));
        assert_eq!(
            std::fs::read(home.path().join(".gemini/skills/rvl-scan/SKILL.md")).unwrap(),
            b"scan skill"
        );
        assert!(first.register.is_none());
    }

    #[test]
    fn update_overwrites_stale_content() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("codex").unwrap();
        h.install(
            home.path(),
            &files(&[("rvl-scan/SKILL.md", b"v1".as_slice())]),
            "0.1.0",
        )
        .unwrap();
        h.install(
            home.path(),
            &files(&[("rvl-scan/SKILL.md", b"v2".as_slice())]),
            "0.2.0",
        )
        .unwrap();
        assert_eq!(
            std::fs::read(home.path().join(".agents/skills/rvl-scan/SKILL.md")).unwrap(),
            b"v2"
        );
    }

    #[test]
    fn claude_install_stages_marketplace_and_returns_registration() {
        let home = tempfile::tempdir().unwrap();
        let h = ClaudeHarness;
        let content = files(&[
            (".claude-plugin/plugin.json", b"{}".as_slice()),
            ("commands/scan.md", b"scan".as_slice()),
            ("agents/rvl-golang-pro.md", b"lens".as_slice()),
        ]);
        let receipt = h.install(home.path(), &content, "0.2.0").unwrap();

        let plugin_dir = home.path().join(".revelara/marketplace/plugins/revelara");
        assert_eq!(receipt.location, plugin_dir);
        assert_eq!(
            std::fs::read(plugin_dir.join("commands/scan.md")).unwrap(),
            b"scan"
        );
        let manifest = std::fs::read_to_string(
            home.path()
                .join(".revelara/marketplace/.claude-plugin/marketplace.json"),
        )
        .unwrap();
        assert!(manifest.contains(r#""version": "0.2.0""#), "{manifest}");
        assert!(manifest.contains(CLAUDE_MARKETPLACE_NAME));

        let reg = receipt.register.expect("claude requires registration");
        assert_eq!(reg.binary, "claude");
        assert_eq!(reg.commands.len(), 3);
        assert!(reg.commands[2].contains(&"revelara@revelara-local".to_string()));
    }

    #[test]
    fn claude_reinstall_removes_stale_files() {
        let home = tempfile::tempdir().unwrap();
        let h = ClaudeHarness;
        h.install(
            home.path(),
            &files(&[("commands/old.md", b"old".as_slice())]),
            "0.1.0",
        )
        .unwrap();
        h.install(
            home.path(),
            &files(&[("commands/new.md", b"new".as_slice())]),
            "0.2.0",
        )
        .unwrap();
        let plugin_dir = home.path().join(".revelara/marketplace/plugins/revelara");
        assert!(!plugin_dir.join("commands/old.md").exists());
        assert!(plugin_dir.join("commands/new.md").exists());
    }

    #[test]
    fn install_refuses_traversal_paths() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("codex").unwrap();
        let evil = files(&[
            ("../evil.md", b"x".as_slice()),
            ("ok.md", b"fine".as_slice()),
        ]);
        assert!(h.install(home.path(), &evil, "0.1.0").is_err());
        // Nothing written: validation happens before any file lands.
        assert!(!home.path().join("evil.md").exists());
        assert!(!home.path().join(".agents/skills/ok.md").exists());
    }
}
