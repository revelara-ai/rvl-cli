//! `hook install` / `hook doctor` ported from rvl-cli
//! `internal/commands/hook.go` (po-av01j.163): install the git-hook scan
//! gate and preflight it.
//!
//! The v2 hook invokes the NATIVE deterministic gate — `rvl scan .
//! --incremental --changed-only --hook <name>` — not rvl-cli's agent-scan
//! command. The binary name written into the script is [`rvl_data::BIN`],
//! the same constant every other surface uses; it was hard-coded to the
//! post-rename name while this installer waited on the cutover, and folded
//! back into BIN when the cutover landed (po-av01j.154).
//!
//! Install is lefthook-aware, like rvl-cli's: when a lefthook config is
//! present it prints a ready-to-paste snippet instead of writing
//! `.git/hooks`, so it never fights lefthook for the hook file. Install is
//! idempotent — a hook file that already carries this binary's gate is
//! refreshed in place; an rvl-cli v1 shim is REPAIRED in place (see
//! [`crate::compat`]); a foreign hook is refused unless `--force`, which
//! backs it up to `<name>.pre-rvl`.

use crate::compat;
use clap::Subcommand;
use rvl_data::BIN;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The marker that identifies a hook file as a Revelara scan gate. Kept a
/// literal rather than built from [`BIN`] because it must ALSO match v1
/// rvl-cli agent-scan shims (which invoke `rvl scan` too), so install
/// upgrades them in place instead of refusing them as foreign hooks.
const SHIM_MARKER: &str = "rvl scan";

/// The marker that identifies a hook file as THIS binary's deterministic
/// gate, as opposed to any other `rvl scan` invocation.
///
/// [`SHIM_MARKER`] is deliberately broad — any `rvl scan` line is a scan gate
/// of some sort. Install must NOT be that broad: rvl-cli refuses ANY
/// pre-existing hook file without `--force`, and this refuses everything
/// except a file we can prove WE wrote, which keeps re-running `hook install`
/// idempotent without ever stomping a hook someone else authored.
///
/// Three states, not two (po-av01j.191):
///
/// 1. this marker present — our CURRENT gate, refreshed in place;
/// 2. [`compat::is_v1_shim`] — our OWN PREDECESSOR's gate, which we know is
///    stale, repaired in place, backed up, no `--force`;
/// 3. anything else — foreign, refused without `--force`.
///
/// po-av01j.185 item 10 put (2) in the foreign bucket, reasoning that a v1
/// shim runs `rvl scan --agent`, a coding-agent review, so rewriting it swaps
/// one gate for a different one behind the user's back. That reasoning was
/// right for a v1 binary and is void for this one: `--agent` here is a
/// documented no-op alias that runs the deterministic scan, so a v1 shim and a
/// v2 shim now do the SAME THING. Rewriting it is not swapping gates, it is
/// normalizing the spelling — and refusing left the user with a repo they
/// could not commit to and a tool telling them everything was fine. Refusing a
/// FOREIGN hook is still right, and is unchanged.
const NATIVE_GATE_MARKER: &str = "Revelara deterministic scan gate";

#[derive(Subcommand)]
pub enum HookCmd {
    /// Wire the deterministic scan gate into this repo's git hooks. With
    /// lefthook present, prints a snippet to paste into lefthook.yml;
    /// otherwise writes a hook shim into the git hooks dir. Defaults to
    /// --pre-commit when no hook is named.
    Install {
        /// Install the pre-commit hook (the default when no hook is named).
        #[arg(long)]
        pre_commit: bool,
        /// Install the pre-push hook.
        #[arg(long)]
        pre_push: bool,
        /// Overwrite (and back up) an existing non-Revelara hook file.
        #[arg(long)]
        force: bool,
    },
    /// Read-only preflight: git repo, `rvl` binary on PATH, lefthook
    /// wiring, and hook presence/executability.
    Doctor,
}

pub fn run(cmd: HookCmd) -> ExitCode {
    match cmd {
        HookCmd::Install {
            pre_commit,
            pre_push,
            force,
        } => run_install(pre_commit, pre_push, force),
        HookCmd::Doctor => run_doctor(),
    }
}

/// The native deterministic gate command for a hook (the whole point of
/// the v2 port: no agent invocation, no model calls).
fn gate_cmd(hook: &str) -> String {
    format!("{BIN} scan . --incremental --changed-only --hook {hook}")
}

/// The POSIX shim body written into `.git/hooks/<name>`.
fn shim_body(hook: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Installed by `{BIN} hook install`: Revelara deterministic scan gate.\n\
         # Exit 3 means BLOCKING findings remain; 0 is clean. No model calls.\n\
         exec {}\n",
        gate_cmd(hook)
    )
}

/// Resolve which hooks to install; defaults to pre-commit, mirroring
/// rvl-cli's `selectedHooks`.
fn selected_hooks(pre_commit: bool, pre_push: bool) -> Vec<&'static str> {
    let mut hooks = Vec::new();
    if pre_commit || !pre_push {
        hooks.push("pre-commit");
    }
    if pre_push {
        hooks.push("pre-push");
    }
    hooks
}

fn run_install(pre_commit: bool, pre_push: bool, force: bool) -> ExitCode {
    let root = match git_toplevel(Path::new(".")) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error: {e}");
            // rvl-cli exits ExitUsage here: running outside a repo is a
            // caller mistake, not a hook failure.
            return ExitCode::from(2);
        }
    };
    let hooks = selected_hooks(pre_commit, pre_push);

    if let Some(lefthook_path) = detect_lefthook(&root) {
        print_lefthook_snippet(&lefthook_path, &hooks);
        return ExitCode::SUCCESS;
    }

    let hooks_dir = match hooks_dir(&root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    for hook in hooks {
        if let Err(e) = write_hook_shim(&hooks_dir, hook, force) {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

/// Lefthook config at the repo root, if any (rvl-cli `detectLefthook`).
fn detect_lefthook(root: &Path) -> Option<PathBuf> {
    for name in [
        "lefthook.yml",
        "lefthook.yaml",
        ".lefthook.yml",
        ".lefthook.yaml",
    ] {
        let p = root.join(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Paste-ready lefthook commands for each hook (rvl-cli
/// `printLefthookSnippet`, with the native gate as the run line).
fn print_lefthook_snippet(lefthook_path: &Path, hooks: &[&str]) {
    let file = lefthook_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "lefthook.yml".to_string());
    println!(
        "Lefthook detected ({file}). Add these commands to {file} instead of writing .git/hooks:"
    );
    println!();
    for hook in hooks {
        println!("{hook}:");
        println!("  commands:");
        println!("    revelara-scan:");
        println!("      run: {}", gate_cmd(hook));
        println!();
    }
    println!("Uninstall: remove the revelara-scan command(s) from the file.");
}

/// The git hooks directory, honoring `core.hooksPath` and linked worktrees
/// via `git rev-parse --git-path hooks` (rvl-cli `hooksDir`).
fn hooks_dir(root: &Path) -> anyhow::Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--git-path", "hooks"])
        .output()?;
    anyhow::ensure!(out.status.success(), "resolve hooks dir");
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let dir = PathBuf::from(dir);
    Ok(if dir.is_absolute() {
        dir
    } else {
        root.join(dir)
    })
}

/// Write the shim for `hook` into `hooks_dir`, per the three-state rule on
/// [`NATIVE_GATE_MARKER`]: refresh our current gate in place, REPAIR our
/// predecessor's in place (backing it up), refuse a foreign hook unless
/// `force` — which backs it up to `<name>.pre-rvl` first, exactly as rvl-cli
/// `writeHookShim` does for every existing file.
fn write_hook_shim(hooks_dir: &Path, hook: &str, force: bool) -> anyhow::Result<()> {
    std::fs::create_dir_all(hooks_dir).map_err(|e| anyhow::anyhow!("create hooks dir: {e}"))?;
    let path = hooks_dir.join(hook);
    let mut repaired_v1 = false;
    if path.exists() {
        let existing = std::fs::read_to_string(&path).unwrap_or_default();
        if !existing.contains(NATIVE_GATE_MARKER) {
            // Our own predecessor: known stale, and we authored it. Repair
            // without demanding --force (po-av01j.191).
            repaired_v1 = compat::is_v1_shim(&existing);
            let what = if existing.contains(SHIM_MARKER) {
                " (it invokes a scan, but neither this binary's deterministic gate \
                 nor an rvl-cli v1 shim, so it is not ours to rewrite)"
            } else {
                ""
            };
            anyhow::ensure!(
                repaired_v1 || force,
                "{} already exists{what}; re-run with --force to overwrite \
                 (the old hook is backed up to {hook}.pre-rvl)",
                path.display()
            );
            let backup = hooks_dir.join(format!("{hook}.pre-rvl"));
            std::fs::rename(&path, &backup)
                .map_err(|e| anyhow::anyhow!("back up existing hook: {e}"))?;
        }
    }
    std::fs::write(&path, shim_body(hook)).map_err(|e| anyhow::anyhow!("write hook shim: {e}"))?;
    if repaired_v1 {
        println!(
            "Repaired {hook} hook: it was an rvl-cli v1 agent-scan shim \
             (backed up to {hook}.pre-rvl)."
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow::anyhow!("mark hook executable: {e}"))?;
    }
    println!("Installed {hook} hook: {}", path.display());
    println!("Uninstall: rm {}", path.display());
    Ok(())
}

pub(crate) fn git_toplevel(dir: &Path) -> anyhow::Result<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| anyhow::anyhow!("run git: {e}"))?;
    anyhow::ensure!(out.status.success(), "not inside a git repository");
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    anyhow::ensure!(!root.is_empty(), "not inside a git repository");
    Ok(PathBuf::from(root))
}

// --- doctor ---

/// A doctor check outcome (rvl-cli `checkStatus`).
///
/// `pub(crate)` so `rvl doctor` can FOLD IN these checks rather than
/// growing a second implementation of them (po-av01j.169): the hook state a
/// user needs is the same state whether they asked `hook doctor` or `doctor`,
/// and two copies would disagree the first time one of them was edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Status {
    Pass,
    Warn,
    Fail,
}

impl Status {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

pub(crate) struct Check {
    pub(crate) status: Status,
    pub(crate) label: String,
    pub(crate) detail: String,
}

impl Check {
    fn new(status: Status, label: impl Into<String>, detail: impl Into<String>) -> Self {
        Check {
            status,
            label: label.into(),
            detail: detail.into(),
        }
    }
}

fn run_doctor() -> ExitCode {
    let root = match git_toplevel(Path::new(".")) {
        Ok(r) => r,
        Err(_) => {
            eprintln!("FAIL  not inside a git repository");
            return ExitCode::FAILURE;
        }
    };
    let path_env = std::env::var("PATH").unwrap_or_default();
    let checks = doctor_checks(&root, &path_env);
    let mut worst = Status::Pass;
    for c in &checks {
        if c.detail.is_empty() {
            println!("{:<5} {}", c.status.as_str(), c.label);
        } else {
            println!("{:<5} {}: {}", c.status.as_str(), c.label, c.detail);
        }
        worst = worst.max(c.status);
    }
    if worst == Status::Fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// The read-only preflight, mirroring rvl-cli's `doctorChecks` output
/// structure. Takes `path_env` explicitly so tests can drive it without
/// touching the real environment.
pub(crate) fn doctor_checks(root: &Path, path_env: &str) -> Vec<Check> {
    let mut checks = Vec::new();

    // The binary the installed hooks invoke (`rvl`, the post-rename name).
    match look_path_in(BIN, path_env) {
        Some(p) => checks.push(Check::new(
            Status::Pass,
            "rvl binary",
            p.display().to_string(),
        )),
        None => checks.push(Check::new(
            Status::Fail,
            "rvl binary",
            format!("\"{BIN}\" not found on PATH; the installed hooks invoke it"),
        )),
    }

    // Lefthook wiring.
    match detect_lefthook(root) {
        Some(lp) => {
            let data = std::fs::read_to_string(&lp).unwrap_or_default();
            if compat::lefthook_has_v1_command(&data) {
                // v1's `hook install` printed `run: rvl scan --agent ...`
                // snippets for users to paste. There is no shim file to
                // inspect, so the config line is the only place this shows up.
                checks.push(Check::new(
                    Status::Warn,
                    "lefthook",
                    format!(
                        "rvl-cli v1 agent-scan command: it runs through the deprecated v1 \
                         compatibility aliases; replace the run line with \
                         `{BIN} scan . --incremental --changed-only --hook <pre-commit|pre-push>`"
                    ),
                ));
            } else if data.contains(SHIM_MARKER) {
                checks.push(Check::new(
                    Status::Pass,
                    "lefthook",
                    "scan gate command present",
                ));
            } else {
                checks.push(Check::new(
                    Status::Warn,
                    "lefthook",
                    format!(
                        "present but no scan gate command; run `{BIN} hook install` for a snippet"
                    ),
                ));
            }
        }
        None => checks.push(Check::new(
            Status::Warn,
            "lefthook",
            "not configured; hooks would be written to .git/hooks",
        )),
    }

    // Hook files: presence, ours-ness, executability.
    if let Ok(hd) = hooks_dir(root) {
        for name in ["pre-commit", "pre-push"] {
            let p = hd.join(name);
            let label = format!("{name} hook");
            match std::fs::read_to_string(&p) {
                Err(_) => checks.push(Check::new(
                    Status::Warn,
                    label,
                    format!("not installed; run `{BIN} hook install --{name}`"),
                )),
                Ok(body) if body.contains(SHIM_MARKER) => {
                    if !is_executable(&p) {
                        checks.push(Check::new(
                            Status::Fail,
                            label,
                            format!("installed but not executable; run chmod +x {}", p.display()),
                        ));
                    } else if compat::is_v1_shim(&body) {
                        // NEVER PASS on a v1 shim (po-av01j.191). Before the
                        // compatibility aliases landed this file could not run
                        // at all, and doctor called it healthy because
                        // SHIM_MARKER matched the bare literal `rvl scan`. It
                        // runs now, but on a deprecated path, and the user
                        // deserves to be told which hook and which command
                        // fixes it.
                        checks.push(Check::new(
                            Status::Warn,
                            label,
                            format!(
                                "rvl-cli v1 shim (`rvl scan --agent ...`): it runs only through \
                                 the deprecated v1 compatibility aliases; repair it with \
                                 `{BIN} hook install` (no --force needed)"
                            ),
                        ));
                    } else {
                        checks.push(Check::new(
                            Status::Pass,
                            label,
                            "native scan gate installed",
                        ));
                    }
                }
                Ok(_) => checks.push(Check::new(
                    Status::Warn,
                    label,
                    "existing hook does not call the scan gate; --force would back it up",
                )),
            }
        }
    }

    checks
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

/// Resolve `bin` against an explicit PATH string, so doctor is testable
/// (rvl-cli `lookPathIn`). A name containing a separator is stat'ed
/// directly.
fn look_path_in(bin: &str, path_env: &str) -> Option<PathBuf> {
    if bin.contains(std::path::MAIN_SEPARATOR) {
        let p = PathBuf::from(bin);
        return (p.is_file() && is_executable(&p)).then_some(p);
    }
    std::env::split_paths(path_env)
        .filter(|d| !d.as_os_str().is_empty())
        .map(|d| d.join(bin))
        .find(|p| p.is_file() && is_executable(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let out = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(tmp.path())
            .output()
            .expect("git init");
        assert!(out.status.success());
        tmp
    }

    #[test]
    fn shim_writes_the_native_gate_under_the_rvl_name() {
        let body = shim_body("pre-commit");
        assert!(body.starts_with("#!/bin/sh\n"));
        assert!(body.contains("exec rvl scan . --incremental --changed-only --hook pre-commit\n"));
        // Ratified decision: the script says `rvl`, never the pre-rename
        // binary name and never the old agent-scan invocation.
        assert!(!body.contains("rvlscan"));
        assert!(!body.contains("--agent"));
    }

    #[test]
    fn selected_hooks_defaults_to_pre_commit() {
        assert_eq!(selected_hooks(false, false), vec!["pre-commit"]);
        assert_eq!(selected_hooks(true, false), vec!["pre-commit"]);
        assert_eq!(selected_hooks(false, true), vec!["pre-push"]);
        assert_eq!(selected_hooks(true, true), vec!["pre-commit", "pre-push"]);
    }

    #[test]
    fn write_shim_is_idempotent_and_backs_up_foreign_hooks() {
        let tmp = git_repo();
        let hd = hooks_dir(tmp.path()).unwrap();

        // Fresh install, then a second install: both succeed (idempotent).
        write_hook_shim(&hd, "pre-commit", false).unwrap();
        write_hook_shim(&hd, "pre-commit", false).unwrap();
        let body = std::fs::read_to_string(hd.join("pre-commit")).unwrap();
        assert!(body.contains("--hook pre-commit"));

        // A foreign hook is refused without --force, backed up with it.
        std::fs::write(hd.join("pre-push"), "#!/bin/sh\necho custom\n").unwrap();
        assert!(write_hook_shim(&hd, "pre-push", false).is_err());
        write_hook_shim(&hd, "pre-push", true).unwrap();
        let backup = std::fs::read_to_string(hd.join("pre-push.pre-rvl")).unwrap();
        assert!(backup.contains("echo custom"));
        let hook = std::fs::read_to_string(hd.join("pre-push")).unwrap();
        assert!(hook.contains("--hook pre-push"));
    }

    /// A v1 rvl-cli shim is OUR OWN PREDECESSOR's gate, and we know it is
    /// stale, so install repairs it WITHOUT `--force` (po-av01j.191). The old
    /// file is still backed up, so nothing is destroyed.
    #[test]
    fn a_v1_shim_is_repaired_in_place_without_force() {
        let tmp = git_repo();
        let hd = hooks_dir(tmp.path()).unwrap();
        let v1 = crate::compat::V1_PRE_COMMIT_SHIM;
        std::fs::write(hd.join("pre-commit"), v1).unwrap();

        write_hook_shim(&hd, "pre-commit", false).unwrap();
        let now = std::fs::read_to_string(hd.join("pre-commit")).unwrap();
        assert!(now.contains(NATIVE_GATE_MARKER));
        assert!(!now.contains("--agent"));
        assert_eq!(
            std::fs::read_to_string(hd.join("pre-commit.pre-rvl")).unwrap(),
            v1,
            "the replaced shim must be recoverable"
        );

        // The pre-push shim too, and a second run stays idempotent.
        std::fs::write(hd.join("pre-push"), crate::compat::V1_PRE_PUSH_SHIM).unwrap();
        write_hook_shim(&hd, "pre-push", false).unwrap();
        write_hook_shim(&hd, "pre-push", false).unwrap();
        let now = std::fs::read_to_string(hd.join("pre-push")).unwrap();
        assert!(now.contains("--hook pre-push"));
    }

    /// doctor must never call a v1 shim healthy: that PASS is half of what
    /// made po-av01j.191 severe rather than merely broken.
    #[test]
    fn doctor_names_a_v1_shim_instead_of_passing_it() {
        let tmp = git_repo();
        let hd = hooks_dir(tmp.path()).unwrap();
        std::fs::write(hd.join("pre-commit"), crate::compat::V1_PRE_COMMIT_SHIM).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                hd.join("pre-commit"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let checks = doctor_checks(tmp.path(), "");
        let c = checks
            .iter()
            .find(|c| c.label == "pre-commit hook")
            .unwrap();
        assert_eq!(c.status, Status::Warn, "detail: {}", c.detail);
        assert!(c.detail.contains("rvl-cli v1 shim"), "got: {}", c.detail);
        assert!(c.detail.contains("hook install"), "got: {}", c.detail);
    }

    /// A lefthook config carrying v1's pasted `run: rvl scan --agent ...` has
    /// no shim file to inspect, so the config line is the only place the stale
    /// invocation surfaces.
    #[test]
    fn doctor_names_a_v1_lefthook_command() {
        let tmp = git_repo();
        std::fs::write(
            tmp.path().join("lefthook.yml"),
            "pre-commit:\n  commands:\n    agent-scan:\n      run: rvl scan --agent --staged\n",
        )
        .unwrap();
        let checks = doctor_checks(tmp.path(), "");
        let c = checks.iter().find(|c| c.label == "lefthook").unwrap();
        assert_eq!(c.status, Status::Warn);
        assert!(c.detail.contains("rvl-cli v1"), "got: {}", c.detail);
    }

    #[test]
    fn doctor_reports_missing_and_healthy_states() {
        let tmp = git_repo();
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&bindir).unwrap();
        std::fs::write(bindir.join("rvl"), "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bindir.join("rvl"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let path_env = bindir.display().to_string();

        // Nothing installed: binary PASS, hooks WARN missing.
        let checks = doctor_checks(tmp.path(), &path_env);
        let find = |label: &str, cs: &[Check]| -> (Status, String) {
            cs.iter()
                .find(|c| c.label == label)
                .map(|c| (c.status, c.detail.clone()))
                .unwrap_or_else(|| panic!("no {label} check"))
        };
        assert_eq!(find("rvl binary", &checks).0, Status::Pass);
        let (status, detail) = find("pre-commit hook", &checks);
        assert_eq!(status, Status::Warn);
        assert!(detail.contains("not installed"));

        // Installed: PASS.
        let hd = hooks_dir(tmp.path()).unwrap();
        write_hook_shim(&hd, "pre-commit", false).unwrap();
        let checks = doctor_checks(tmp.path(), &path_env);
        let (status, detail) = find("pre-commit hook", &checks);
        assert_eq!(status, Status::Pass);
        assert!(detail.contains("native scan gate installed"));

        // Empty PATH: binary FAIL.
        let checks = doctor_checks(tmp.path(), "");
        assert_eq!(find("rvl binary", &checks).0, Status::Fail);
    }

    #[cfg(unix)]
    #[test]
    fn doctor_flags_non_executable_hook() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = git_repo();
        let hd = hooks_dir(tmp.path()).unwrap();
        write_hook_shim(&hd, "pre-commit", false).unwrap();
        std::fs::set_permissions(
            hd.join("pre-commit"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let checks = doctor_checks(tmp.path(), "");
        let check = checks
            .iter()
            .find(|c| c.label == "pre-commit hook")
            .unwrap();
        assert_eq!(check.status, Status::Fail);
        assert!(check.detail.contains("not executable"));
    }
}
