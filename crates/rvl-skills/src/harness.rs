//! Harness adapters: where and how verified skill files land in each
//! coding-agent environment. One trait, a data-driven directory adapter for
//! the universal harnesses, and a custom Claude Code adapter (marketplace
//! layout shared with rvl-cli, so either tool can update the other's
//! install). Adding a harness = one more registry entry or trait impl.
//!
//! Install is pure file placement — detection and installation never launch
//! any agent. Registration commands for Claude Code are *returned* to the
//! caller (the CLI layer decides whether to run them).

use rvl_core::BIN;
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

/// What a removal did, for reporting.
#[derive(Debug)]
pub struct RemoveReceipt {
    /// The root the removal operated on.
    pub location: PathBuf,
    /// Files deleted, when the harness removes file-by-file; None when a
    /// whole staging directory was dropped (Claude Code marketplace).
    pub files_removed: Option<usize>,
    /// Post-removal commands that unwire the harness's own plugin
    /// registration (e.g. `claude plugin uninstall`). Best-effort by
    /// nature; never executed by this crate.
    pub register: Option<Registration>,
}

/// A coding-agent environment rvl can install the workflow skills into.
pub trait Harness {
    /// Registry key, also the `installed.json` key (e.g. "claude").
    fn name(&self) -> &'static str;
    /// Human name for messages (e.g. "Claude Code").
    fn display_name(&self) -> &'static str;
    /// The backend's `?editor=` parameter for this harness's tarball layout.
    fn editor_param(&self) -> &'static str;
    /// Directory (relative to home) holding this harness's installed agent
    /// lens files, when the harness keeps them at a fixed location (mirrors
    /// rvl-cli's Registry.AgentsDir). None for harnesses without a separate
    /// agents directory; Claude Code resolves agents via its recorded
    /// install location instead.
    fn agents_dir(&self) -> Option<&'static str>;
    /// Directory (relative to a PROJECT root) a `--project` install writes
    /// into, mirroring rvl-cli's `Registry.LocalDir`. None means this
    /// harness has no project-local layout and `--project` must refuse it
    /// (Claude Code, whose install is a user-level marketplace).
    fn local_dir(&self) -> Option<&'static str> {
        None
    }
    /// One-line "what now" note shown after an install.
    fn note(&self) -> &'static str {
        ""
    }
    /// Is this harness present on the machine? Pure filesystem check under
    /// `home` (no PATH probing, no process launches).
    fn detect(&self, home: &Path) -> bool;
    /// Post-install hook run after a GLOBAL install lands (rvl-cli
    /// `Registry.PostInstall`). Returns a line to show the user when it
    /// changed something. Never run for `--project` installs, matching
    /// rvl-cli. Failures are warnings: the skills themselves installed.
    fn post_install(&self, _home: &Path) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
    /// Hook run after the harness's own registration commands SUCCEEDED
    /// (Claude Code's stale-cache prune). Skipped when registration was
    /// skipped or could not run, mirroring rvl-cli, which prunes only after
    /// `claude plugin install` returns cleanly.
    fn post_register(&self, _home: &Path) -> anyhow::Result<Option<String>> {
        Ok(None)
    }
    /// Idempotently place already-verified files into the harness. Repeat
    /// installs of the same content converge to the same on-disk state.
    fn install(
        &self,
        home: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        version: &str,
    ) -> anyhow::Result<InstallReceipt>;
    /// Remove installed skills. `files` is the installed-file inventory from
    /// the cached tarball, when available; directory harnesses need it so
    /// they delete exactly what was installed and never the editor's own
    /// configuration. Removal is idempotent: already-absent files are fine.
    fn remove(
        &self,
        home: &Path,
        files: Option<&BTreeMap<String, Vec<u8>>>,
    ) -> anyhow::Result<RemoveReceipt>;
}

/// A post-install hook: configures the harness itself after the files land
/// (Gemini's `experimental.enableAgents`). Returns a line to show the user
/// when it actually changed something.
pub type PostInstallHook = fn(&Path) -> anyhow::Result<Option<String>>;

/// Universal adapter: tarball content extracted under `home/<install_dir>`,
/// detected by `home/<config_dir>` existing. Mirrors rvl-cli's editor
/// registry entries for the same names.
pub struct DirHarness {
    pub name: &'static str,
    pub display_name: &'static str,
    pub editor_param: &'static str,
    pub config_dir: &'static str,
    pub install_dir: &'static str,
    /// Fixed agents directory relative to home (rvl-cli Registry.AgentsDir
    /// parity); None when the harness has no separate agents directory.
    pub agents_dir: Option<&'static str>,
    /// Project-root-relative directory for `--project` installs (rvl-cli
    /// Registry.LocalDir parity); None when the harness has no project-local
    /// layout.
    pub local_dir: Option<&'static str>,
    /// Post-install hook for global installs (rvl-cli Registry.PostInstall).
    pub post_install: Option<PostInstallHook>,
    pub note: &'static str,
}

/// A [`DirHarness`] with the optional fields defaulted, so the registry
/// below reads as data instead of boilerplate.
const fn dir(
    name: &'static str,
    display_name: &'static str,
    config_dir: &'static str,
    install_dir: &'static str,
    note: &'static str,
) -> DirHarness {
    DirHarness {
        name,
        display_name,
        // Every harness's tarball layout is selected by its own name, the
        // way rvl-cli passes the registry key as `?editor=`.
        editor_param: name,
        config_dir,
        install_dir,
        agents_dir: None,
        local_dir: None,
        post_install: None,
        note,
    }
}

/// The universal "skills are auto-discovered" note, used by the tier-3
/// harnesses that have no editor-specific invocation.
const AUTO_NOTE: &str = "Skills are auto-discovered; try: \
                         \"scan this codebase for reliability risks\"";

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
    fn agents_dir(&self) -> Option<&'static str> {
        self.agents_dir
    }
    fn local_dir(&self) -> Option<&'static str> {
        self.local_dir
    }
    fn note(&self) -> &'static str {
        self.note
    }
    fn detect(&self, home: &Path) -> bool {
        home.join(self.config_dir).is_dir()
    }
    fn post_install(&self, home: &Path) -> anyhow::Result<Option<String>> {
        match self.post_install {
            Some(hook) => hook(home),
            None => Ok(None),
        }
    }
    fn install(
        &self,
        home: &Path,
        files: &BTreeMap<String, Vec<u8>>,
        _version: &str,
    ) -> anyhow::Result<InstallReceipt> {
        install_files_at(&home.join(self.install_dir), files, self.note)
    }
    fn remove(
        &self,
        home: &Path,
        files: Option<&BTreeMap<String, Vec<u8>>>,
    ) -> anyhow::Result<RemoveReceipt> {
        remove_files_at(&home.join(self.install_dir), files, self.name)
    }
}

/// Place `files` under `root`. Shared by the global install and the
/// `--project` install, which differ only in the root they compute.
pub fn install_files_at(
    root: &Path,
    files: &BTreeMap<String, Vec<u8>>,
    note: &'static str,
) -> anyhow::Result<InstallReceipt> {
    let files_written = write_files(root, files)?;
    Ok(InstallReceipt {
        location: root.to_path_buf(),
        files_written,
        register: None,
        note,
    })
}

/// Delete exactly the tarball's files under `root`, then prune the empty
/// directories they leave behind. Shared by global and `--project` removal.
///
/// The install root can be the editor's own config dir (e.g. `.gemini`) or
/// a directory the repo also uses (`.agents/skills`), so a blanket delete is
/// off the table: only the exact files the tarball placed may go, and only
/// empty directories below the root get pruned.
pub fn remove_files_at(
    root: &Path,
    files: Option<&BTreeMap<String, Vec<u8>>>,
    name: &str,
) -> anyhow::Result<RemoveReceipt> {
    let Some(files) = files else {
        anyhow::bail!(
            "no cached plugin tarball for {name}: cannot determine which files were \
             installed. Re-run '{BIN} plugin install {name}' once to reseed the \
             cache, then remove; or delete the Revelara files under {root} manually",
            root = root.display()
        );
    };
    for name in files.keys() {
        safe_rel_path(name)?;
    }
    let mut removed = 0usize;
    let mut dirs: Vec<PathBuf> = Vec::new();
    for name in files.keys() {
        let path = root.join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut parent = path.parent();
        while let Some(p) = parent {
            if p == root || !p.starts_with(root) {
                break;
            }
            dirs.push(p.to_path_buf());
            parent = p.parent();
        }
    }
    // Deepest first (a parent is a lexicographic prefix of its children,
    // so reverse-sorted order visits children before parents); non-empty
    // directories fail remove_dir and are left alone by design.
    dirs.sort();
    dirs.dedup();
    dirs.reverse();
    for d in dirs {
        let _ = std::fs::remove_dir(&d);
    }
    Ok(RemoveReceipt {
        location: root.to_path_buf(),
        files_removed: Some(removed),
        register: None,
    })
}

/// rvl-cli's `EnableGeminiSubagents`: without `experimental.enableAgents`
/// the lens files land but Gemini CLI never runs a subagent, so the install
/// silently does half its job. Read-modify-write so every other setting the
/// user has survives; a no-op when it is already true.
pub fn gemini_enable_subagents(home: &Path) -> anyhow::Result<Option<String>> {
    let settings_path = home.join(".gemini").join("settings.json");
    let mut settings: serde_json::Value = std::fs::read(&settings_path)
        .ok()
        .and_then(|d| serde_json::from_slice(&d).ok())
        .unwrap_or_else(|| serde_json::Value::Object(Default::default()));
    if !settings.is_object() {
        settings = serde_json::Value::Object(Default::default());
    }
    let obj = settings.as_object_mut().expect("object above");
    let experimental = obj
        .entry("experimental")
        .or_insert_with(|| serde_json::Value::Object(Default::default()));
    if !experimental.is_object() {
        *experimental = serde_json::Value::Object(Default::default());
    }
    let exp = experimental.as_object_mut().expect("object above");
    if exp.get("enableAgents").and_then(|v| v.as_bool()) == Some(true) {
        return Ok(None);
    }
    exp.insert("enableAgents".into(), serde_json::Value::Bool(true));

    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&settings_path, serde_json::to_string_pretty(&settings)?)?;
    Ok(Some(format!(
        "enabled experimental subagents in {}",
        settings_path.display()
    )))
}

/// rvl-cli's `pruneOldCacheVersions`: Claude Code's `plugin install` creates
/// a NEW versioned cache directory every time and never removes the old
/// ones, so repeated updates accumulate stale copies and outdated skill
/// files get loaded alongside the current version. Keep only the version
/// Claude Code's own registry currently points at.
pub fn prune_claude_cache_versions(home: &Path) -> anyhow::Result<Vec<String>> {
    #[derive(serde::Deserialize)]
    struct Registry {
        #[serde(default)]
        plugins: std::collections::BTreeMap<String, Vec<Entry>>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        #[serde(rename = "installPath", default)]
        install_path: String,
    }

    let registry_file = home
        .join(".claude")
        .join("plugins")
        .join("installed_plugins.json");
    let data = std::fs::read(&registry_file)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", registry_file.display()))?;
    let reg: Registry = serde_json::from_slice(&data)
        .map_err(|e| anyhow::anyhow!("parse {}: {e}", registry_file.display()))?;

    // The registry key varies with how the plugin was installed
    // (revelara@revelara-local, rvl@revelara-api, ...), so the plugin is
    // identified by its cache path instead: <...>/revelara/<version>.
    let active = reg
        .plugins
        .values()
        .flatten()
        .map(|e| PathBuf::from(&e.install_path))
        .find(|p| {
            p.parent()
                .and_then(|d| d.file_name())
                .map(|n| n == CLAUDE_PLUGIN_NAME)
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{CLAUDE_PLUGIN_NAME} plugin not found in {}",
                registry_file.display()
            )
        })?;

    let cache_parent = active
        .parent()
        .ok_or_else(|| anyhow::anyhow!("active install path has no parent"))?;
    let active_version = active
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("active install path has no version component"))?;

    let mut pruned = Vec::new();
    for entry in std::fs::read_dir(cache_parent)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", cache_parent.display()))?
    {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entry.file_name() == active_version {
            continue;
        }
        match std::fs::remove_dir_all(entry.path()) {
            Ok(()) => pruned.push(entry.file_name().to_string_lossy().into_owned()),
            Err(e) => eprintln!(
                "warning: could not remove stale cache version {}: {e}",
                entry.file_name().to_string_lossy()
            ),
        }
    }
    pruned.sort();
    Ok(pruned)
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
    fn agents_dir(&self) -> Option<&'static str> {
        // Agents live inside the marketplace plugin dir; resolved from the
        // recorded install location, not a fixed home-relative path.
        None
    }
    fn detect(&self, home: &Path) -> bool {
        home.join(".claude").is_dir()
    }
    /// No project-local layout: the Claude install is a user-level
    /// marketplace, so `--project` must refuse it (rvl-cli parity).
    fn local_dir(&self) -> Option<&'static str> {
        None
    }
    fn post_register(&self, home: &Path) -> anyhow::Result<Option<String>> {
        let pruned = prune_claude_cache_versions(home)?;
        Ok((!pruned.is_empty()).then(|| {
            format!(
                "pruned {} stale cache version(s): {}",
                pruned.len(),
                pruned.join(", ")
            )
        }))
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
    fn remove(
        &self,
        home: &Path,
        _files: Option<&BTreeMap<String, Vec<u8>>>,
    ) -> anyhow::Result<RemoveReceipt> {
        // The marketplace directory is entirely ours (rvl-cli parity), so
        // the whole staging tree goes; the returned commands unwire Claude
        // Code's own registration of it.
        let marketplace = home.join(".revelara").join("marketplace");
        if marketplace.exists() {
            std::fs::remove_dir_all(&marketplace)?;
        }
        Ok(RemoveReceipt {
            location: marketplace,
            files_removed: None,
            register: Some(Registration {
                binary: "claude",
                commands: vec![
                    vec![
                        "plugin".into(),
                        "uninstall".into(),
                        format!("{CLAUDE_PLUGIN_NAME}@{CLAUDE_MARKETPLACE_NAME}"),
                    ],
                    vec![
                        "plugin".into(),
                        "marketplace".into(),
                        "remove".into(),
                        CLAUDE_MARKETPLACE_NAME.into(),
                    ],
                ],
            }),
        })
    }
}

/// Every harness rvl can install into, Claude Code first — the SAME 22
/// targets rvl-cli's `Registry` supports (rvl-cli
/// `internal/plugin/registry.go`), so `plugin editors` (which prints the
/// server's list) can no longer name a target `plugin install` refuses.
/// Paths mirror rvl-cli's `InstallDir` / `SkillsDir` / `AgentsDir` /
/// `LocalDir` per entry; detection is the config directory, which for
/// `goose` is also what rvl-cli's `RequireConfigDir` demands.
pub fn registry() -> Vec<Box<dyn Harness>> {
    vec![
        Box::new(ClaudeHarness),
        // --- Tier 1-2: harness-specific layouts ---
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir(
                "codex",
                "OpenAI Codex",
                ".codex",
                ".agents/skills",
                "Skills are auto-discovered by Codex CLI.",
            )
        }),
        Box::new(DirHarness {
            agents_dir: Some(".gemini/agents"),
            local_dir: Some(".gemini"),
            // Without this, the lens files land but Gemini never runs a
            // subagent — the exact half-install rvl-cli added the hook for.
            post_install: Some(gemini_enable_subagents),
            ..dir(
                "gemini",
                "Google Gemini CLI",
                ".gemini",
                ".gemini",
                "Skills and agents are auto-discovered by Gemini CLI.",
            )
        }),
        Box::new(DirHarness {
            agents_dir: Some(".cursor/agents"),
            local_dir: Some(".cursor"),
            ..dir(
                "cursor",
                "Cursor",
                ".cursor",
                ".cursor",
                "Skills and agents are auto-discovered by Cursor.",
            )
        }),
        Box::new(DirHarness {
            agents_dir: Some(".copilot/agents"),
            local_dir: Some(".copilot"),
            ..dir(
                "copilot",
                "GitHub Copilot",
                ".copilot",
                ".copilot",
                "Skills and agents are auto-discovered by Copilot CLI.",
            )
        }),
        Box::new(DirHarness {
            // Windsurf's project layout is NOT its global one.
            local_dir: Some(".windsurf/skills"),
            ..dir(
                "windsurf",
                "Windsurf",
                ".codeium/windsurf",
                ".codeium/windsurf/skills",
                "Skills are auto-discovered by Windsurf.",
            )
        }),
        Box::new(DirHarness {
            agents_dir: Some(".augment/agents"),
            local_dir: Some(".augment"),
            ..dir(
                "augment",
                "Augment Code",
                ".augment",
                ".augment",
                "Skills and agents are auto-discovered by Augment CLI.",
            )
        }),
        // --- Tier 3: universal skills directory ---
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir("cline", "Cline", ".cline", ".agents/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".roo/skills"),
            ..dir("roo", "Roo Code", ".roo", ".roo/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".openhands/skills"),
            ..dir(
                "openhands",
                "OpenHands",
                ".openhands",
                ".openhands/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".goose/skills"),
            ..dir(
                "goose",
                "Goose",
                ".config/goose",
                ".config/goose/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir("warp", "Warp", ".warp", ".agents/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".continue/skills"),
            ..dir(
                "continue",
                "Continue",
                ".continue",
                ".continue/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir("amp", "Amp", ".config/amp", ".config/amp/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".kilocode/skills"),
            ..dir(
                "kilo",
                "Kilo Code",
                ".kilocode",
                ".kilocode/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir(
                "opencode",
                "OpenCode",
                ".config/opencode",
                ".config/opencode/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".trae/skills"),
            ..dir("trae", "Trae", ".trae", ".trae/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".junie/skills"),
            ..dir("junie", "Junie", ".junie", ".junie/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".qwen/skills"),
            ..dir("qwen-code", "Qwen Code", ".qwen", ".qwen/skills", AUTO_NOTE)
        }),
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir(
                "antigravity",
                "Antigravity",
                ".gemini/antigravity",
                ".gemini/antigravity/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".agents/skills"),
            ..dir(
                "firebender",
                "Firebender",
                ".firebender",
                ".firebender/skills",
                AUTO_NOTE,
            )
        }),
        Box::new(DirHarness {
            local_dir: Some(".kiro/skills"),
            ..dir("kiro", "Kiro", ".kiro", ".kiro/skills", AUTO_NOTE)
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
    fn dir_remove_deletes_only_installed_files_and_prunes_empty_dirs() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("gemini").unwrap();
        let content = files(&[
            ("skills/rvl-scan/SKILL.md", b"scan skill".as_slice()),
            ("agents/rvl-golang-pro.md", b"lens".as_slice()),
        ]);
        h.install(home.path(), &content, "0.2.0").unwrap();
        // A user file inside the editor's config dir must survive removal.
        let user_file = home.path().join(".gemini/settings.json");
        std::fs::write(&user_file, b"{}").unwrap();

        let receipt = h.remove(home.path(), Some(&content)).unwrap();
        assert_eq!(receipt.files_removed, Some(2));
        assert!(receipt.register.is_none());
        assert!(!home.path().join(".gemini/skills").exists(), "pruned");
        assert!(!home.path().join(".gemini/agents").exists(), "pruned");
        assert!(user_file.exists(), "user config must survive");
        assert!(home.path().join(".gemini").exists(), "config dir kept");

        // Removing again is idempotent: nothing left to delete.
        let again = h.remove(home.path(), Some(&content)).unwrap();
        assert_eq!(again.files_removed, Some(0));
    }

    #[test]
    fn dir_remove_without_file_inventory_fails_actionably() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("codex").unwrap();
        let err = h.remove(home.path(), None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cached plugin tarball"), "got: {msg}");
        assert!(msg.contains("plugin install codex"), "got: {msg}");
    }

    #[test]
    fn claude_remove_drops_marketplace_and_returns_unregistration() {
        let home = tempfile::tempdir().unwrap();
        let h = ClaudeHarness;
        h.install(
            home.path(),
            &files(&[("commands/scan.md", b"scan".as_slice())]),
            "0.2.0",
        )
        .unwrap();

        let receipt = h.remove(home.path(), None).unwrap();
        assert!(!home.path().join(".revelara/marketplace").exists());
        let reg = receipt.register.expect("claude requires unregistration");
        assert_eq!(reg.binary, "claude");
        assert!(reg.commands[0].contains(&"uninstall".to_string()));
        assert!(reg.commands[0].contains(&"revelara@revelara-local".to_string()));

        // Idempotent when nothing is staged.
        assert!(h.remove(home.path(), None).is_ok());
    }

    /// The registry must cover exactly rvl-cli's 22 editors: `plugin
    /// editors` prints the server's list, so any name missing here is a
    /// target the CLI advertises and then refuses to install (po-av01j.162).
    #[test]
    fn registry_covers_every_rvl_cli_editor() {
        let mut names = supported_names();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "amp",
                "antigravity",
                "augment",
                "claude",
                "cline",
                "codex",
                "continue",
                "copilot",
                "cursor",
                "firebender",
                "gemini",
                "goose",
                "junie",
                "kilo",
                "kiro",
                "opencode",
                "openhands",
                "qwen-code",
                "roo",
                "trae",
                "warp",
                "windsurf",
            ]
        );
        assert_eq!(names.len(), 22);
    }

    /// Install/config/local paths must match rvl-cli's registry entry for
    /// the same name, or an install lands where the harness never looks.
    #[test]
    fn paths_mirror_rvl_cli_registry() {
        let cases: &[(&str, &str, Option<&str>)] = &[
            // (name, install_dir, local_dir)
            ("codex", ".agents/skills", Some(".agents/skills")),
            ("gemini", ".gemini", Some(".gemini")),
            ("cursor", ".cursor", Some(".cursor")),
            ("copilot", ".copilot", Some(".copilot")),
            // Windsurf's project layout is deliberately NOT its global one.
            (
                "windsurf",
                ".codeium/windsurf/skills",
                Some(".windsurf/skills"),
            ),
            ("augment", ".augment", Some(".augment")),
            ("goose", ".config/goose/skills", Some(".goose/skills")),
            (
                "opencode",
                ".config/opencode/skills",
                Some(".agents/skills"),
            ),
            ("amp", ".config/amp/skills", Some(".agents/skills")),
            (
                "antigravity",
                ".gemini/antigravity/skills",
                Some(".agents/skills"),
            ),
            ("kilo", ".kilocode/skills", Some(".kilocode/skills")),
            ("qwen-code", ".qwen/skills", Some(".qwen/skills")),
        ];
        let home = tempfile::tempdir().unwrap();
        for (name, install_dir, local_dir) in cases {
            let h = by_name(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(h.local_dir(), *local_dir, "{name} local_dir");
            // install() is the only place install_dir is observable.
            let receipt = h
                .install(home.path(), &files(&[("rvl-scan/SKILL.md", b"x")]), "1.0.0")
                .unwrap();
            assert_eq!(
                receipt.location,
                home.path().join(install_dir),
                "{name} install_dir"
            );
        }
    }

    /// Claude Code has no project-local layout: `--project` must refuse it
    /// rather than scatter a user-level marketplace into a repo.
    #[test]
    fn claude_has_no_project_local_layout() {
        assert_eq!(by_name("claude").unwrap().local_dir(), None);
    }

    #[test]
    fn goose_is_detected_by_its_config_dir() {
        let home = tempfile::tempdir().unwrap();
        assert!(!detect_installed(home.path()).contains(&"goose".to_string()));
        std::fs::create_dir_all(home.path().join(".config/goose")).unwrap();
        assert!(detect_installed(home.path()).contains(&"goose".to_string()));
    }

    #[test]
    fn gemini_hook_enables_subagents_without_clobbering_settings() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(home.path().join(".gemini")).unwrap();
        std::fs::write(
            home.path().join(".gemini/settings.json"),
            r#"{"theme":"dark","experimental":{"other":1}}"#,
        )
        .unwrap();

        let note = gemini_enable_subagents(home.path()).unwrap();
        assert!(note.unwrap().contains("subagents"));

        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(home.path().join(".gemini/settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["experimental"]["enableAgents"], serde_json::json!(true));
        assert_eq!(v["experimental"]["other"], serde_json::json!(1));
        assert_eq!(v["theme"], serde_json::json!("dark"));

        // Already enabled: a no-op, so a repeat install says nothing.
        assert_eq!(gemini_enable_subagents(home.path()).unwrap(), None);
    }

    #[test]
    fn gemini_hook_creates_settings_when_absent_or_corrupt() {
        let home = tempfile::tempdir().unwrap();
        assert!(gemini_enable_subagents(home.path()).unwrap().is_some());
        let v: serde_json::Value = serde_json::from_slice(
            &std::fs::read(home.path().join(".gemini/settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v["experimental"]["enableAgents"], serde_json::json!(true));

        // A corrupt file is replaced rather than left blocking subagents.
        std::fs::write(home.path().join(".gemini/settings.json"), b"not json").unwrap();
        assert!(gemini_enable_subagents(home.path()).unwrap().is_some());
    }

    /// The gemini harness must actually CARRY the hook: wiring it in the
    /// registry is the half that makes the install complete.
    #[test]
    fn gemini_install_runs_the_subagent_hook() {
        let home = tempfile::tempdir().unwrap();
        let h = by_name("gemini").unwrap();
        h.install(
            home.path(),
            &files(&[("skills/rvl-scan/SKILL.md", b"x")]),
            "1.0.0",
        )
        .unwrap();
        assert!(h.post_install(home.path()).unwrap().is_some());
        // codex has no hook.
        assert!(by_name("codex")
            .unwrap()
            .post_install(home.path())
            .unwrap()
            .is_none());
    }

    /// Claude Code's `plugin install` adds a new versioned cache dir every
    /// time and never removes the old ones, so repeated updates load stale
    /// skill files alongside the current version.
    #[test]
    fn claude_prune_keeps_only_the_active_cache_version() {
        let home = tempfile::tempdir().unwrap();
        let cache = home
            .path()
            .join(".claude/plugins/cache/revelara-local/revelara");
        for v in ["0.1.0", "0.2.0", "0.3.0"] {
            std::fs::create_dir_all(cache.join(v)).unwrap();
            std::fs::write(cache.join(v).join("marker"), v).unwrap();
        }
        std::fs::create_dir_all(home.path().join(".claude/plugins")).unwrap();
        std::fs::write(
            home.path().join(".claude/plugins/installed_plugins.json"),
            format!(
                r#"{{"plugins":{{"revelara@revelara-local":[{{"installPath":"{}"}}]}}}}"#,
                cache.join("0.3.0").display()
            ),
        )
        .unwrap();

        let pruned = prune_claude_cache_versions(home.path()).unwrap();
        assert_eq!(pruned, vec!["0.1.0", "0.2.0"]);
        assert!(cache.join("0.3.0/marker").exists(), "active version kept");
        assert!(!cache.join("0.1.0").exists());
        assert!(!cache.join("0.2.0").exists());

        // Idempotent: a second prune has nothing left to do.
        assert!(prune_claude_cache_versions(home.path()).unwrap().is_empty());
        // And it is reachable through the harness hook.
        assert!(ClaudeHarness.post_register(home.path()).unwrap().is_none());
    }

    #[test]
    fn claude_prune_reports_a_missing_or_foreign_registry() {
        let home = tempfile::tempdir().unwrap();
        let err = prune_claude_cache_versions(home.path()).unwrap_err();
        assert!(err.to_string().contains("installed_plugins.json"), "{err}");

        std::fs::create_dir_all(home.path().join(".claude/plugins")).unwrap();
        std::fs::write(
            home.path().join(".claude/plugins/installed_plugins.json"),
            r#"{"plugins":{"someone-else@market":[{"installPath":"/tmp/other/1.0.0"}]}}"#,
        )
        .unwrap();
        let err = prune_claude_cache_versions(home.path()).unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
    }

    /// A project-local install writes under the REPO, and removal takes back
    /// exactly what it wrote — never the repo's own files.
    #[test]
    fn project_local_install_and_remove_use_local_dir() {
        let repo = tempfile::tempdir().unwrap();
        let h = by_name("cursor").unwrap();
        let content = files(&[
            ("skills/rvl-scan/SKILL.md", b"scan".as_slice()),
            ("agents/rvl-golang-pro.md", b"lens".as_slice()),
        ]);
        let root = repo.path().join(h.local_dir().unwrap());
        let receipt = install_files_at(&root, &content, h.note()).unwrap();
        assert_eq!(receipt.location, repo.path().join(".cursor"));
        assert_eq!(receipt.files_written, 2);
        assert!(repo
            .path()
            .join(".cursor/skills/rvl-scan/SKILL.md")
            .exists());

        // A file the repo owns inside the same tree must survive.
        let repo_file = repo.path().join(".cursor/rules.md");
        std::fs::write(&repo_file, b"ours").unwrap();

        let rm = remove_files_at(&root, Some(&content), h.name()).unwrap();
        assert_eq!(rm.files_removed, Some(2));
        assert!(!repo.path().join(".cursor/skills").exists());
        assert!(repo_file.exists(), "repo-owned file must survive");
    }

    #[test]
    fn agents_dirs_mirror_rvl_cli_registry() {
        assert_eq!(by_name("claude").unwrap().agents_dir(), None);
        assert_eq!(by_name("codex").unwrap().agents_dir(), None);
        assert_eq!(
            by_name("gemini").unwrap().agents_dir(),
            Some(".gemini/agents")
        );
        assert_eq!(
            by_name("cursor").unwrap().agents_dir(),
            Some(".cursor/agents")
        );
        assert_eq!(
            by_name("copilot").unwrap().agents_dir(),
            Some(".copilot/agents")
        );
        assert_eq!(by_name("windsurf").unwrap().agents_dir(), None);
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
