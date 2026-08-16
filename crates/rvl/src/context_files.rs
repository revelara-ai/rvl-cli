//! The REVELARA MANAGED BLOCK in `AGENTS.md` / `CLAUDE.md`, ported from
//! rvl-cli `internal/plugin/agentsmd.go` + `internal/plugin/claudemd.go`
//! (po-av01j.163).
//!
//! This block is how an agent harness with NO slash commands discovers `rvl`
//! at all: it is plain markdown that every AGENTS.md-reading runtime picks up
//! ambiently. rvl-cli writes it from `init` AND from every `plugin
//! install`/`plugin update`, so the wording tracks plugin content; this port
//! keeps both entry points.
//!
//! Marker-based, deliberately: [`BLOCK_START`] / [`BLOCK_END`] are how the
//! block is FOUND on a later run and replaced in place, which is what makes
//! re-running idempotent instead of appending a second copy. The markers are
//! byte-identical to rvl-cli's, so a repo initialized by either binary is
//! maintained by the other.
//!
//! Content is GENERATED, not static: the served copy under
//! `~/.revelara/marketplace/plugins/revelara/<name>` wins when present, so
//! context wording ships with plugin updates (rvl-cli po-pw4p6). The embedded
//! templates are the offline fallback and are byte-identical copies of
//! rvl-cli's.
//!
//! Edits INSIDE the block do not survive: the region between the markers is
//! replaced wholesale, exactly as rvl-cli does, which is what the marker text
//! ("DO NOT EDIT") announces. Content outside the markers is never touched.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Managed-block markers. Byte-identical to rvl-cli's `claudeMdBlockStart` /
/// `claudeMdBlockEnd`; AGENTS.md shares them (rvl-cli `agentsMdBlockStart`).
pub const BLOCK_START: &str = "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->";
pub const BLOCK_END: &str = "<!-- END REVELARA MANAGED BLOCK -->";

/// Pre-rename markers written by older rvl-cli builds. Recognized ONLY so an
/// existing block is REPLACED rather than duplicated (rvl-cli
/// `claudeMdBlockStartOld`). This is not legacy *config* support — nothing is
/// read from a legacy path; it is duplicate-block avoidance in a file that
/// lives in the user's own repository.
const BLOCK_START_OLD: &str = "<!-- BEGIN RELYNCE MANAGED BLOCK - DO NOT EDIT -->";
const BLOCK_END_OLD: &str = "<!-- END RELYNCE MANAGED BLOCK -->";

/// The section heading older `rvl init` builds wrote before markers existed.
/// Migrated in place for the same duplicate-avoidance reason (rvl-cli
/// `legacyAgentsMdHeading`).
const LEGACY_AGENTS_HEADING: &str = "## Revelara";

/// Editor-agnostic block body (rvl-cli `agentsMdTemplate`). Verbatim copy —
/// AGENTS.md is read by runtimes with no agent-specific capabilities, so it
/// must assume nothing beyond running shell commands.
const AGENTS_MD_TEMPLATE: &str = include_str!("context/AGENTS.md");

/// Claude-specific additions appended to the shared body for CLAUDE.md
/// (rvl-cli `claudemd_extras.md`): expert-agent routing via the Task tool,
/// which the agent-neutral AGENTS.md must not mention.
const CLAUDE_MD_EXTRAS: &str = include_str!("context/CLAUDE_EXTRAS.md");

/// What [`ensure_agents_md`] / [`ensure_claude_md`] did (rvl-cli returns these
/// same four strings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Created,
    Appended,
    Updated,
    Skipped,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Created => "created",
            Action::Appended => "appended",
            Action::Updated => "updated",
            Action::Skipped => "skipped",
        }
    }
}

/// State of AGENTS.md in `git_root` (rvl-cli `AgentsMdState`), used by the
/// interactive `init` path to phrase the right prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// No AGENTS.md at all.
    Missing,
    /// Exists, with no Revelara block or legacy section.
    Unmanaged,
    /// Has a managed block (or a legacy `## Revelara` section).
    Managed,
}

/// The served template named `name` from the installed plugin content, or
/// `None` when there is no usable copy on disk (rvl-cli `installedTemplate`).
fn installed_template(home: &Path, name: &str) -> Option<String> {
    let p = home
        .join(".revelara")
        .join("marketplace")
        .join("plugins")
        .join("revelara")
        .join(name);
    let s = std::fs::read_to_string(p).ok()?;
    if s.trim().is_empty() {
        return None;
    }
    Some(s)
}

/// Home directory used to look up served templates. `None` disables the
/// lookup (the embedded fallback is then authoritative).
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// AGENTS.md block body: served copy if installed, else the embedded template.
fn agents_md_body(home: Option<&Path>) -> String {
    home.and_then(|h| installed_template(h, "AGENTS.md"))
        .unwrap_or_else(|| AGENTS_MD_TEMPLATE.to_string())
}

/// CLAUDE.md block body: served copy if installed, else the embedded
/// composition of the shared body plus the Claude extras. The fallback mirrors
/// the backend's own composition (rvl-cli `claudeMdTemplate`).
fn claude_md_body(home: Option<&Path>) -> String {
    if let Some(served) = home.and_then(|h| installed_template(h, "CLAUDE.md")) {
        return served.trim().to_string();
    }
    format!(
        "{}\n\n{}",
        AGENTS_MD_TEMPLATE.trim(),
        CLAUDE_MD_EXTRAS.trim()
    )
}

/// Wrap a body in the managed markers, with the trailing newline rvl-cli
/// writes.
fn managed_block(body: &str) -> String {
    format!("{BLOCK_START}\n{}\n{BLOCK_END}\n", body.trim())
}

/// Whether `content` carries a pre-marker `## Revelara` heading on its own line.
fn has_legacy_agents_section(content: &str) -> bool {
    content.lines().any(|l| l.trim() == LEGACY_AGENTS_HEADING)
}

/// Report the AGENTS.md state under `git_root` (rvl-cli `AgentsMdState`).
pub fn agents_md_state(git_root: &Path) -> State {
    let Ok(content) = std::fs::read_to_string(git_root.join("AGENTS.md")) else {
        return State::Missing;
    };
    if content.contains(BLOCK_START) || has_legacy_agents_section(&content) {
        State::Managed
    } else {
        State::Unmanaged
    }
}

/// Replace the managed region of `content` (whose start marker is at
/// `start_idx` and end marker ends at `end_idx`) with `block`, swallowing the
/// newline that follows the end marker so the file does not grow a blank line
/// per run.
fn splice(content: &str, start_idx: usize, mut end_idx: usize, block: &str) -> String {
    if content[end_idx..].starts_with('\n') {
        end_idx += 1;
    }
    format!("{}{block}{}", &content[..start_idx], &content[end_idx..])
}

/// Create or update the managed block in `path`.
///
/// * missing file -> written with the block alone (`Created`)
/// * block present (current or pre-rename markers) -> replaced in place
///   (`Updated`); this is what makes a re-run idempotent
/// * start marker without an end marker -> `Err`, never a guessed repair
/// * legacy `## Revelara` section (AGENTS.md only, `migrate_legacy_section`)
///   -> replaced in place (`Updated`)
/// * otherwise, with `yes_all` -> appended after a blank line (`Appended`);
///   without it -> `Skipped`, leaving the file untouched for the caller to
///   prompt about
fn ensure_block(
    path: &Path,
    block: &str,
    yes_all: bool,
    migrate_legacy_section: bool,
) -> anyhow::Result<Action> {
    let label = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "context file".to_string());

    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::write(path, block)?;
            return Ok(Action::Created);
        }
        Err(e) => return Err(e.into()),
    };

    // Pre-rename markers are normalized to the current ones first, so the
    // single splice path below handles both.
    let content = if !content.contains(BLOCK_START) && content.contains(BLOCK_START_OLD) {
        content
            .replacen(BLOCK_START_OLD, BLOCK_START, 1)
            .replacen(BLOCK_END_OLD, BLOCK_END, 1)
    } else {
        content
    };

    if let Some(start_idx) = content.find(BLOCK_START) {
        let Some(end_at) = content.find(BLOCK_END) else {
            anyhow::bail!("{label} has start marker but no end marker — manual fix needed");
        };
        let updated = splice(&content, start_idx, end_at + BLOCK_END.len(), block);
        if updated != content {
            std::fs::write(path, updated)?;
        }
        return Ok(Action::Updated);
    }

    if migrate_legacy_section && has_legacy_agents_section(&content) {
        std::fs::write(path, replace_legacy_section(&content, block))?;
        return Ok(Action::Updated);
    }

    if !yes_all {
        return Ok(Action::Skipped);
    }

    let mut updated = content.clone();
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push('\n');
    updated.push_str(block);
    std::fs::write(path, updated)?;
    Ok(Action::Appended)
}

/// Replace the legacy `## Revelara` section (heading through the next level-2
/// heading or EOF; `###` subheadings belong to the section) with `block`
/// (rvl-cli `replaceLegacyAgentsMdSection`).
fn replace_legacy_section(content: &str, block: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_section = false;
    let mut replaced = false;

    for line in content.split('\n') {
        let trimmed = line.trim();
        if !replaced && trimmed == LEGACY_AGENTS_HEADING {
            in_section = true;
            replaced = true;
            out.push(block.trim_end_matches('\n').to_string());
            continue;
        }
        if in_section {
            if trimmed.starts_with("## ") && !trimmed.starts_with("###") {
                in_section = false;
                out.push(line.to_string());
            }
            continue;
        }
        out.push(line.to_string());
    }

    let mut updated = out.join("\n");
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated
}

/// Create or update `<git_root>/AGENTS.md` (rvl-cli `plugin.EnsureAgentsMd`).
pub fn ensure_agents_md(git_root: &Path, yes_all: bool) -> anyhow::Result<Action> {
    let block = managed_block(&agents_md_body(home_dir().as_deref()));
    ensure_block(&git_root.join("AGENTS.md"), &block, yes_all, true)
}

/// Create or update `<git_root>/CLAUDE.md` (rvl-cli `plugin.EnsureClaudeMd`).
pub fn ensure_claude_md(git_root: &Path, yes_all: bool) -> anyhow::Result<Action> {
    let block = managed_block(&claude_md_body(home_dir().as_deref()));
    ensure_block(&git_root.join("CLAUDE.md"), &block, yes_all, false)
}

/// The post-install context-file step (rvl-cli `installContextFiles` +
/// `EnsureAgentsMdForInstall`): install or refresh the AGENTS.md block in the
/// git repository containing `start_dir`.
///
/// Skipped silently when `skip` is set — the caller that owns the skip
/// (`--no-context-files`) reports it itself. Outside a git repository this
/// prints a notice and does nothing. Failures are WARNINGS: the plugin itself
/// installed fine, and a context file is not worth failing an install over.
pub fn install_context_files(start_dir: &Path, skip: bool, out: &mut dyn Write) {
    if skip {
        return;
    }
    let Some(git_root) = crate::hook::git_toplevel(start_dir).ok() else {
        let _ = writeln!(
            out,
            "Note: not inside a git repository — skipping AGENTS.md setup \
             (run this from your project, or run '{} init' there)",
            rvl_data::BIN
        );
        return;
    };
    match ensure_agents_md(&git_root, true) {
        Err(e) => {
            let _ = writeln!(out, "Warning: could not set up AGENTS.md: {e}");
        }
        Ok(Action::Skipped) => {}
        Ok(action) => {
            let _ = writeln!(out, "✓ AGENTS.md: {}", action.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block() -> String {
        managed_block(AGENTS_MD_TEMPLATE)
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    /// The exact files rvl-cli writes into an empty repo, captured by
    /// running its own `plugin.EnsureAgentsMd` / `plugin.EnsureClaudeMd`
    /// against a fresh directory with no served plugin content on disk (so
    /// both sides use their baked-in fallback). Byte parity here is the
    /// whole point: a repo initialized by either binary must be maintained
    /// by the other without the block churning.
    const GOLDEN_AGENTS_MD: &str = include_str!("context/rvl_cli_agents_md.golden");
    const GOLDEN_CLAUDE_MD: &str = include_str!("context/rvl_cli_claude_md.golden");

    #[test]
    fn written_files_are_byte_identical_to_rvl_cli() {
        let d = tempfile::tempdir().unwrap();

        assert_eq!(
            managed_block(&agents_md_body(None)),
            GOLDEN_AGENTS_MD,
            "AGENTS.md block drifted from rvl-cli"
        );
        assert_eq!(
            managed_block(&claude_md_body(None)),
            GOLDEN_CLAUDE_MD,
            "CLAUDE.md block drifted from rvl-cli"
        );

        // And through the file-writing path, from a repo with neither file.
        ensure_block(
            &d.path().join("AGENTS.md"),
            &managed_block(&agents_md_body(None)),
            true,
            true,
        )
        .unwrap();
        ensure_block(
            &d.path().join("CLAUDE.md"),
            &managed_block(&claude_md_body(None)),
            true,
            false,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(d.path().join("AGENTS.md")).unwrap(),
            GOLDEN_AGENTS_MD
        );
        assert_eq!(
            std::fs::read_to_string(d.path().join("CLAUDE.md")).unwrap(),
            GOLDEN_CLAUDE_MD
        );
    }

    #[test]
    fn markers_are_the_rvl_cli_bytes() {
        // These strings ARE the contract: change them and every already
        // initialized repo grows a second block on its next update.
        assert_eq!(
            BLOCK_START,
            "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->"
        );
        assert_eq!(BLOCK_END, "<!-- END REVELARA MANAGED BLOCK -->");
    }

    #[test]
    fn creates_when_missing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("AGENTS.md");
        assert_eq!(
            ensure_block(&p, &block(), false, true).unwrap(),
            Action::Created
        );
        let got = std::fs::read_to_string(&p).unwrap();
        assert_eq!(got, block());
        assert!(got.ends_with("<!-- END REVELARA MANAGED BLOCK -->\n"));
    }

    #[test]
    fn rerun_is_idempotent_and_never_duplicates() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("AGENTS.md");
        ensure_block(&p, &block(), true, true).unwrap();
        let first = std::fs::read_to_string(&p).unwrap();
        for _ in 0..3 {
            assert_eq!(
                ensure_block(&p, &block(), true, true).unwrap(),
                Action::Updated
            );
        }
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(after, first);
        assert_eq!(after.matches(BLOCK_START).count(), 1);
    }

    #[test]
    fn appends_to_existing_file_only_with_yes_all() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "AGENTS.md", "# My project\n\nHello.\n");

        assert_eq!(
            ensure_block(&p, &block(), false, true).unwrap(),
            Action::Skipped
        );
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "# My project\n\nHello.\n"
        );

        assert_eq!(
            ensure_block(&p, &block(), true, true).unwrap(),
            Action::Appended
        );
        let got = std::fs::read_to_string(&p).unwrap();
        assert!(got.starts_with("# My project\n\nHello.\n\n"));
        assert!(got.contains(BLOCK_START));
    }

    #[test]
    fn append_normalizes_a_missing_trailing_newline() {
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "AGENTS.md", "no trailing newline");
        ensure_block(&p, &block(), true, true).unwrap();
        let got = std::fs::read_to_string(&p).unwrap();
        assert!(got.starts_with("no trailing newline\n\n<!-- BEGIN"));
    }

    #[test]
    fn user_edits_inside_the_block_are_replaced_and_outside_content_survives() {
        let d = tempfile::tempdir().unwrap();
        let edited = format!(
            "# Mine\n\nPreamble.\n\n{BLOCK_START}\nI HAND EDITED THIS\n{BLOCK_END}\n\n## After\n\nkeep me\n"
        );
        let p = write(d.path(), "AGENTS.md", &edited);

        assert_eq!(
            ensure_block(&p, &block(), false, true).unwrap(),
            Action::Updated
        );
        let got = std::fs::read_to_string(&p).unwrap();
        // The hand edit is gone (the marker says DO NOT EDIT, and rvl-cli
        // replaces the region wholesale).
        assert!(!got.contains("I HAND EDITED THIS"));
        // Everything outside the markers is untouched, in order.
        assert!(got.starts_with("# Mine\n\nPreamble.\n\n"));
        assert!(got.ends_with("\n## After\n\nkeep me\n"));
        assert_eq!(got.matches(BLOCK_START).count(), 1);
    }

    #[test]
    fn start_marker_without_end_marker_errors_rather_than_guessing() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "CLAUDE.md",
            &format!("{BLOCK_START}\nhalf a block\n"),
        );
        let err = ensure_block(&p, &block(), true, false).unwrap_err();
        assert!(
            err.to_string().contains("start marker but no end marker"),
            "{err}"
        );
        // The file is left exactly as found.
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            format!("{BLOCK_START}\nhalf a block\n")
        );
    }

    #[test]
    fn pre_rename_markers_are_replaced_not_duplicated() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "CLAUDE.md",
            &format!("# Mine\n\n{BLOCK_START_OLD}\nold body\n{BLOCK_END_OLD}\n"),
        );
        assert_eq!(
            ensure_block(&p, &block(), true, false).unwrap(),
            Action::Updated
        );
        let got = std::fs::read_to_string(&p).unwrap();
        assert!(!got.contains("RELYNCE MANAGED BLOCK"));
        assert!(!got.contains("old body"));
        assert_eq!(got.matches(BLOCK_START).count(), 1);
        assert!(got.starts_with("# Mine\n\n"));
    }

    #[test]
    fn legacy_revelara_section_is_migrated_in_place() {
        let d = tempfile::tempdir().unwrap();
        let p = write(
            d.path(),
            "AGENTS.md",
            "# Repo\n\n## Revelara\n\nold prose\n\n### Sub\n\nalso old\n\n## Other\n\nkeep\n",
        );
        assert_eq!(
            ensure_block(&p, &block(), false, true).unwrap(),
            Action::Updated
        );
        let got = std::fs::read_to_string(&p).unwrap();
        assert!(!got.contains("old prose"));
        assert!(!got.contains("also old"));
        assert!(got.contains("## Other\n\nkeep\n"));
        assert_eq!(got.matches(BLOCK_START).count(), 1);
    }

    #[test]
    fn claude_md_never_migrates_a_legacy_section() {
        // rvl-cli's CLAUDE.md path has no legacy-section migration; a repo
        // whose CLAUDE.md happens to have a "## Revelara" heading must get an
        // appended block, not a rewritten section.
        let d = tempfile::tempdir().unwrap();
        let p = write(d.path(), "CLAUDE.md", "## Revelara\n\nmine, not yours\n");
        assert_eq!(
            ensure_block(&p, &block(), true, false).unwrap(),
            Action::Appended
        );
        let got = std::fs::read_to_string(&p).unwrap();
        assert!(got.contains("mine, not yours"));
    }

    #[test]
    fn state_reports_missing_unmanaged_and_managed() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(agents_md_state(d.path()), State::Missing);
        write(d.path(), "AGENTS.md", "# nothing to see\n");
        assert_eq!(agents_md_state(d.path()), State::Unmanaged);
        write(d.path(), "AGENTS.md", &block());
        assert_eq!(agents_md_state(d.path()), State::Managed);
        write(d.path(), "AGENTS.md", "## Revelara\n\nold\n");
        assert_eq!(agents_md_state(d.path()), State::Managed);
    }

    #[test]
    fn served_template_wins_over_the_embedded_fallback() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".revelara/marketplace/plugins/revelara");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("AGENTS.md"), "## Revelara\n\nserved wording\n").unwrap();
        std::fs::write(dir.join("CLAUDE.md"), "## Revelara\n\nserved claude\n").unwrap();

        assert!(agents_md_body(Some(home.path())).contains("served wording"));
        assert!(claude_md_body(Some(home.path())).contains("served claude"));

        // An empty served file is not a template: fall back.
        std::fs::write(dir.join("AGENTS.md"), "   \n").unwrap();
        assert_eq!(agents_md_body(Some(home.path())), AGENTS_MD_TEMPLATE);
    }

    #[test]
    fn embedded_claude_body_is_agents_plus_extras() {
        let body = claude_md_body(None);
        assert!(body.starts_with(AGENTS_MD_TEMPLATE.trim()));
        assert!(body.ends_with(CLAUDE_MD_EXTRAS.trim()));
        // The Claude-only routing table must not leak into AGENTS.md.
        assert!(!agents_md_body(None).contains("Expert Routing"));
    }

    #[test]
    fn install_context_files_skips_silently_when_asked() {
        let mut buf: Vec<u8> = Vec::new();
        install_context_files(Path::new("."), true, &mut buf);
        assert!(buf.is_empty());
    }
}
