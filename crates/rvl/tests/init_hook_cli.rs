//! End-to-end tests for `init` and `hook` (po-av01j.163), driven through
//! the real binary. Only non-interactive paths (`-y`, flags) are
//! exercised; interactive prompts are untested by design.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rvl"))
}

fn git_init(dir: &Path) {
    let out = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .output()
        .expect("run git init");
    assert!(out.status.success(), "git init failed");
}

/// An `init` invocation isolated from the developer's real environment:
/// HOME points at the tempdir (no config file, no harnesses, no skills
/// cache pollution), credentials env vars are cleared (so no network), and
/// the offline kill switch is set (so the plugin step never fetches).
fn init_cmd(dir: &Path) -> Command {
    let mut c = bin();
    c.current_dir(dir)
        .env("HOME", dir)
        .env("RVLSCAN_OFFLINE", "1")
        .env_remove("RVL_API_KEY")
        .env_remove("RVLSCAN_ORG_KEY")
        .env_remove("RVL_API_URL")
        .env_remove("RVLSCAN_API_BASE")
        .env_remove("RVL_ORG_NAME");
    c
}

/// The exact `.revelara.yaml` rvl-cli writes for a repo with no detected
/// components: its comment header plus Go yaml.v3's marshal shape.
fn expected_yaml(name: &str) -> String {
    format!(
        "# Revelara project configuration\n\
         # Used by /rvl:scan and reliability-review skills for consistent service naming\n\
         project: {name}\n\
         components:\n\
         \x20   - name: {name}\n\
         \x20     path: .\n"
    )
}

/// The repo name init detects: no origin remote in these fixtures, so the
/// git-toplevel directory name (canonicalized, as git resolves symlinks).
fn repo_name(dir: &Path) -> String {
    std::fs::canonicalize(dir)
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

// --- init ---

#[test]
fn init_writes_default_yaml_and_memory_seed() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(stdout.contains("Created .revelara.yaml"), "got: {stdout}");
    assert!(
        stdout.contains("=== Revelara Initialization Complete ==="),
        "got: {stdout}"
    );

    let content = std::fs::read_to_string(tmp.path().join(".revelara.yaml")).unwrap();
    assert_eq!(content, expected_yaml(&repo_name(tmp.path())));

    let digest = std::fs::read_to_string(
        tmp.path()
            .join(".revelara")
            .join("memory")
            .join("digest.compact"),
    )
    .unwrap();
    assert!(digest.starts_with("# digest.compact v1"), "got: {digest}");
}

#[test]
fn init_respects_project_flag() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin", "--project", "checkout-svc"])
        .output()
        .expect("run init");
    assert!(out.status.success());
    let content = std::fs::read_to_string(tmp.path().join(".revelara.yaml")).unwrap();
    assert_eq!(content, expected_yaml("checkout-svc"));
}

#[test]
fn init_keeps_existing_config_with_yes() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let original = "project: keepme\ncomponents: []\n";
    std::fs::write(tmp.path().join(".revelara.yaml"), original).unwrap();
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        stdout.contains("Keeping existing .revelara.yaml"),
        "got: {stdout}"
    );
    let content = std::fs::read_to_string(tmp.path().join(".revelara.yaml")).unwrap();
    assert_eq!(
        content, original,
        "-y must not overwrite an existing config"
    );
}

#[test]
fn init_force_overwrites_existing_config() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    std::fs::write(
        tmp.path().join(".revelara.yaml"),
        "project: stale\ncomponents: []\n",
    )
    .unwrap();
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--force", "--skip-plugin"])
        .output()
        .expect("run init");
    assert!(out.status.success());
    let content = std::fs::read_to_string(tmp.path().join(".revelara.yaml")).unwrap();
    assert_eq!(content, expected_yaml(&repo_name(tmp.path())));
}

#[test]
fn init_requires_a_git_repository() {
    let tmp = tempfile::tempdir().unwrap();
    // No git init.
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a git repository"), "got: {stderr}");
    assert!(!tmp.path().join(".revelara.yaml").exists());
}

#[test]
fn init_skip_plugin_skips_the_install_step() {
    // Without --skip-plugin the delegated skills machinery runs (offline,
    // empty HOME: it reports no detected harness). With --skip-plugin it
    // must not run at all.
    let with_plugin = tempfile::tempdir().unwrap();
    git_init(with_plugin.path());
    let out = init_cmd(with_plugin.path())
        .args(["init", "-y"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(
        stdout.contains("No supported coding-agent harness detected"),
        "plugin step should have run: {stdout}"
    );
    assert!(stdout.contains("Skills: Not installed"), "got: {stdout}");

    let skipped = tempfile::tempdir().unwrap();
    git_init(skipped.path());
    let out = init_cmd(skipped.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(
        !stdout.contains("No supported coding-agent harness detected"),
        "--skip-plugin must skip the install step: {stdout}"
    );
}

// --- hook ---

fn hook_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(".git").join("hooks").join(name)
}

#[test]
fn hook_install_writes_the_native_gate_shim() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .expect("run hook install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "install failed:\n{stdout}");
    assert!(
        stdout.contains("Installed pre-commit hook"),
        "got: {stdout}"
    );

    let body = std::fs::read_to_string(hook_path(tmp.path(), "pre-commit")).unwrap();
    assert!(body.starts_with("#!/bin/sh\n"), "got: {body}");
    assert!(
        body.contains("exec rvl scan . --incremental --changed-only --hook pre-commit\n"),
        "shim must invoke the native gate under the post-rename binary name: {body}"
    );
    assert!(
        !body.contains("rvlscan"),
        "shim must say `rvl`, never the pre-rename name, got: {body}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(hook_path(tmp.path(), "pre-commit"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "shim must be executable");
    }
}

#[test]
fn hook_install_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    for _ in 0..2 {
        let out = bin()
            .current_dir(tmp.path())
            .args(["hook", "install"])
            .output()
            .expect("run hook install");
        assert!(out.status.success(), "repeat install must succeed");
    }
    let body = std::fs::read_to_string(hook_path(tmp.path(), "pre-commit")).unwrap();
    assert!(body.contains("--hook pre-commit"));
}

#[test]
fn hook_install_refuses_foreign_hook_then_force_backs_up() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".git/hooks")).unwrap();
    std::fs::write(
        hook_path(tmp.path(), "pre-commit"),
        "#!/bin/sh\necho custom\n",
    )
    .unwrap();

    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .expect("run hook install");
    assert!(!out.status.success(), "foreign hook must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--force"), "got: {stderr}");

    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install", "--force"])
        .output()
        .expect("run hook install --force");
    assert!(out.status.success());
    let backup = std::fs::read_to_string(hook_path(tmp.path(), "pre-commit.pre-rvl")).unwrap();
    assert!(backup.contains("echo custom"), "old hook must be backed up");
    let body = std::fs::read_to_string(hook_path(tmp.path(), "pre-commit")).unwrap();
    assert!(body.contains("--hook pre-commit"));
}

#[test]
fn hook_install_pre_push_variant() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install", "--pre-push"])
        .output()
        .expect("run hook install");
    assert!(out.status.success());
    let body = std::fs::read_to_string(hook_path(tmp.path(), "pre-push")).unwrap();
    assert!(
        body.contains("exec rvl scan . --incremental --changed-only --hook pre-push\n"),
        "got: {body}"
    );
    assert!(
        !hook_path(tmp.path(), "pre-commit").exists(),
        "--pre-push alone must not write pre-commit"
    );
}

#[test]
fn hook_install_prints_lefthook_snippet_instead_of_writing() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    std::fs::write(
        tmp.path().join("lefthook.yml"),
        "pre-commit:\n  commands: {}\n",
    )
    .unwrap();
    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .expect("run hook install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("Lefthook detected"), "got: {stdout}");
    assert!(
        stdout.contains("run: rvl scan . --incremental --changed-only --hook pre-commit"),
        "got: {stdout}"
    );
    assert!(
        !hook_path(tmp.path(), "pre-commit").exists(),
        "with lefthook present, no .git/hooks file may be written"
    );
}

// --- hook doctor (unix-only: fake binaries + executable bits) ---

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A PATH whose only entries are a fake `rvl` (optional) and the real
/// `git`, so doctor's binary check is deterministic regardless of what the
/// developer has installed.
#[cfg(unix)]
fn doctor_path(dir: &Path, with_rvl: bool) -> String {
    let bindir = dir.join("doctor-bin");
    std::fs::create_dir_all(&bindir).unwrap();
    if with_rvl {
        write_executable(&bindir.join("rvl"), "#!/bin/sh\nexit 0\n");
    }
    let real_git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|d| d.join("git"))
        .find(|p| p.is_file())
        .expect("git on PATH");
    std::os::unix::fs::symlink(real_git, bindir.join("git")).unwrap();
    bindir.display().to_string()
}

#[cfg(unix)]
#[test]
fn hook_doctor_healthy() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    assert!(bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .unwrap()
        .status
        .success());
    let out = bin()
        .current_dir(tmp.path())
        .env("PATH", doctor_path(tmp.path(), true))
        .args(["hook", "doctor"])
        .output()
        .expect("run hook doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "healthy doctor must exit 0:\n{stdout}"
    );
    assert!(stdout.contains("PASS  rvl binary"), "got: {stdout}");
    assert!(
        stdout.contains("PASS  pre-commit hook: native scan gate installed"),
        "got: {stdout}"
    );
    assert!(
        stdout.contains("WARN  pre-push hook: not installed"),
        "got: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn hook_doctor_reports_missing_hook_and_binary() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());

    // Hooks missing but binary present: WARN rows only, exit 0.
    let out = bin()
        .current_dir(tmp.path())
        .env("PATH", doctor_path(tmp.path(), true))
        .args(["hook", "doctor"])
        .output()
        .expect("run hook doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "WARNs alone must not fail:\n{stdout}");
    assert!(
        stdout.contains("WARN  pre-commit hook: not installed"),
        "got: {stdout}"
    );

    // Binary missing: FAIL, exit 1.
    let no_rvl = tempfile::tempdir().unwrap();
    git_init(no_rvl.path());
    let out = bin()
        .current_dir(no_rvl.path())
        .env("PATH", doctor_path(no_rvl.path(), false))
        .args(["hook", "doctor"])
        .output()
        .expect("run hook doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(1),
        "missing rvl must FAIL:\n{stdout}"
    );
    assert!(stdout.contains("FAIL  rvl binary"), "got: {stdout}");
}

#[cfg(unix)]
#[test]
fn hook_doctor_flags_non_executable_hook() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    assert!(bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .unwrap()
        .status
        .success());
    std::fs::set_permissions(
        hook_path(tmp.path(), "pre-commit"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let out = bin()
        .current_dir(tmp.path())
        .env("PATH", doctor_path(tmp.path(), true))
        .args(["hook", "doctor"])
        .output()
        .expect("run hook doctor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "non-executable hook must FAIL");
    assert!(
        stdout.contains("FAIL  pre-commit hook") && stdout.contains("not executable"),
        "got: {stdout}"
    );
}
