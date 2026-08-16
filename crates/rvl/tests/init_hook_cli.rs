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
        .env("RVL_OFFLINE", "1")
        .env_remove("RVL_API_KEY")
        .env_remove("RVL_API_URL")
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

// --- the REVELARA MANAGED BLOCK context files (po-av01j.163) ---

const BLOCK_START: &str = "<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->";

/// AGENTS.md is written for EVERY repo, plugin or not: it is how a harness
/// with no slash commands discovers `rvl` at all, which is why it is not
/// gated on the plugin step.
#[test]
fn init_writes_the_agents_md_managed_block_and_never_duplicates_it() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let agents = tmp.path().join("AGENTS.md");

    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(
        stdout.contains("Created AGENTS.md with Revelara managed block"),
        "got: {stdout}"
    );
    assert!(stdout.contains("AGENTS.md: created"), "summary: {stdout}");

    let first = std::fs::read_to_string(&agents).unwrap();
    assert!(first.starts_with(BLOCK_START), "got: {first}");
    assert!(first.contains("rvl risk list --service=<service>"));

    // Re-running REPLACES the block rather than appending a second one.
    for _ in 0..2 {
        let out = init_cmd(tmp.path())
            .args(["init", "-y", "--skip-plugin"])
            .output()
            .expect("run init");
        assert!(out.status.success());
    }
    let after = std::fs::read_to_string(&agents).unwrap();
    assert_eq!(after, first, "re-running init must not change AGENTS.md");
    assert_eq!(after.matches(BLOCK_START).count(), 1);
}

/// The block is APPENDED to a pre-existing AGENTS.md; the user's own content
/// is never rewritten, and a later run replaces only the managed region.
#[test]
fn init_appends_to_an_existing_agents_md_and_preserves_content_outside_the_block() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let agents = tmp.path().join("AGENTS.md");
    std::fs::write(&agents, "# House rules\n\nkeep me\n").unwrap();

    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    assert!(out.status.success());
    let got = std::fs::read_to_string(&agents).unwrap();
    assert!(
        got.starts_with("# House rules\n\nkeep me\n\n"),
        "got: {got}"
    );
    assert!(got.contains(BLOCK_START));

    // A hand edit INSIDE the block does not survive — the markers say DO NOT
    // EDIT and the region is replaced wholesale — while everything outside
    // them does.
    let edited = got.replace(BLOCK_START, &format!("{BLOCK_START}\nHAND EDITED"));
    std::fs::write(&agents, format!("{edited}\n## Trailer\n\nalso keep me\n")).unwrap();
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    assert!(out.status.success());
    let got = std::fs::read_to_string(&agents).unwrap();
    assert!(!got.contains("HAND EDITED"), "got: {got}");
    assert!(
        got.starts_with("# House rules\n\nkeep me\n\n"),
        "got: {got}"
    );
    assert!(got.ends_with("## Trailer\n\nalso keep me\n"), "got: {got}");
    assert_eq!(got.matches(BLOCK_START).count(), 1);
}

/// `--no-context-files` writes neither file. rvl-cli carries the flag on
/// `plugin install`/`update`; it is accepted on `init` too so one flag turns
/// the managed blocks off everywhere they would be written.
#[test]
fn init_no_context_files_writes_neither_agents_md_nor_claude_md() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = init_cmd(tmp.path())
        .args(["init", "-y", "--skip-plugin", "--no-context-files"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(!tmp.path().join("AGENTS.md").exists(), "got: {stdout}");
    assert!(!tmp.path().join("CLAUDE.md").exists(), "got: {stdout}");
    // .revelara.yaml is still written: the flag scopes to context files only.
    assert!(tmp.path().join(".revelara.yaml").exists());
    assert!(
        stdout.contains("Commit .revelara.yaml to your repository"),
        "next steps must not promise files that were not written: {stdout}"
    );
}

/// CLAUDE.md carries Claude-only expert routing on top of the shared body,
/// so rvl-cli writes it only once skills are installed. With nothing
/// installed, only AGENTS.md appears.
#[test]
fn init_without_an_installed_plugin_writes_agents_md_but_not_claude_md() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let out = init_cmd(tmp.path())
        .args(["init", "-y"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(stdout.contains("Skills: Not installed"), "got: {stdout}");
    assert!(tmp.path().join("AGENTS.md").exists());
    assert!(!tmp.path().join("CLAUDE.md").exists());
    assert!(
        stdout.contains("Commit .revelara.yaml and AGENTS.md to your repository"),
        "got: {stdout}"
    );
}

/// Seed the skills cache with an installable tarball so the plugin step
/// succeeds OFFLINE, and give HOME a `.claude` dir so the Claude harness is
/// detected. Returns the env pairs an invocation needs.
///
/// This is what lets the CLAUDE.md step be tested at all: it is gated on the
/// plugin actually installing (rvl-cli parity), and without a cache hit
/// there is no way to reach it without a network.
fn seed_offline_claude_install(home: &Path, cache: &Path) {
    std::fs::create_dir_all(home.join(".claude")).unwrap();
    let stage = cache.join("stage");
    std::fs::create_dir_all(stage.join("skills/rvl-scan")).unwrap();
    std::fs::write(stage.join("skills/rvl-scan/SKILL.md"), "# scan\n").unwrap();
    let tarball = cache.join("plugin.tgz");
    let out = Command::new("tar")
        .arg("-czf")
        .arg(&tarball)
        .arg("-C")
        .arg(&stage)
        .arg(".")
        .output()
        .expect("run tar");
    assert!(out.status.success(), "tar failed");

    let bytes = std::fs::read(&tarball).unwrap();
    let slot = cache.join("claude");
    std::fs::create_dir_all(&slot).unwrap();
    std::fs::write(slot.join("plugin.tar.gz"), &bytes).unwrap();
    // sha256 of the tarball, computed with the same tool the store uses.
    let sha = sha256_hex(&bytes);
    std::fs::write(
        slot.join("meta.json"),
        format!(r#"{{"version":"9.9.9","sha256":"{sha}","fetched_at":"2026-08-15"}}"#),
    )
    .unwrap();
}

/// Minimal sha256 via the `sha256sum` tool, so this test file needs no new
/// dependency to satisfy the store's integrity pin.
fn sha256_hex(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut child = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sha256sum");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(bytes)
        .expect("write to sha256sum");
    let out = child.wait_with_output().expect("sha256sum");
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .expect("sha256sum output")
        .to_string()
}

fn offline_install_cmd(dir: &Path, home: &Path, cache: &Path) -> Command {
    let mut c = bin();
    c.current_dir(dir)
        .env("HOME", home)
        .env("RVL_SKILLS_CACHE_DIR", cache)
        .env("RVL_ALLOW_UNSIGNED", "1")
        .env("RVL_OFFLINE", "1")
        .env("RVL_API_KEY", "pk_test")
        .env("RVL_API_URL", "http://127.0.0.1:9")
        .env_remove("RVL_ORG_NAME");
    c
}

/// With skills installed, init writes BOTH blocks, and the CLAUDE.md one
/// carries the Claude-only expert routing that AGENTS.md must not mention.
#[test]
fn init_writes_both_managed_blocks_once_skills_install() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let cache = tmp.path().join("cache");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    git_init(&repo);
    seed_offline_claude_install(&home, &cache);

    let out = offline_install_cmd(&repo, &home, &cache)
        .args(["init", "-y"])
        .output()
        .expect("run init");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "init failed:\n{stdout}");
    assert!(stdout.contains("Skills: Installed"), "got: {stdout}");
    assert!(stdout.contains("AGENTS.md: created"), "got: {stdout}");
    assert!(stdout.contains("CLAUDE.md: created"), "got: {stdout}");
    assert!(
        stdout.contains("Commit .revelara.yaml, AGENTS.md, and CLAUDE.md to your repository"),
        "got: {stdout}"
    );

    let agents = std::fs::read_to_string(repo.join("AGENTS.md")).unwrap();
    let claude = std::fs::read_to_string(repo.join("CLAUDE.md")).unwrap();
    assert!(agents.starts_with(BLOCK_START));
    assert!(claude.starts_with(BLOCK_START));
    // The Claude-only routing table is in CLAUDE.md and NOT in the
    // agent-neutral AGENTS.md, which must assume nothing beyond a shell.
    assert!(claude.contains("Expert Routing"), "got: {claude}");
    assert!(!agents.contains("Expert Routing"), "got: {agents}");
    // Both carry the shared context-tool body.
    for f in [&agents, &claude] {
        assert!(f.contains("rvl risk list --service=<service>"));
    }

    // Re-running through `plugin update` refreshes rather than duplicates.
    let out = offline_install_cmd(&repo, &home, &cache)
        .args(["plugin", "update", "--all"])
        .output()
        .expect("run plugin update");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "plugin update failed:\n{stdout}");
    assert!(stdout.contains("AGENTS.md: updated"), "got: {stdout}");
    assert!(stdout.contains("CLAUDE.md: updated"), "got: {stdout}");
    assert_eq!(
        std::fs::read_to_string(repo.join("AGENTS.md")).unwrap(),
        agents
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("CLAUDE.md")).unwrap(),
        claude
    );
}

/// `plugin install --no-context-files` says so and writes neither file
/// (rvl-cli parity), and rvl-cli's `--all` spelling reaches the same sweep
/// this binary spells by omitting the harness name (po-av01j.188).
#[test]
fn plugin_install_all_sweeps_and_no_context_files_suppresses_the_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let cache = tmp.path().join("cache");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&cache).unwrap();
    git_init(&repo);
    seed_offline_claude_install(&home, &cache);

    let out = offline_install_cmd(&repo, &home, &cache)
        .args(["plugin", "install", "--all", "--no-context-files"])
        .output()
        .expect("run plugin install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "install failed:\n{stdout}");
    assert!(stdout.contains("installed claude skills"), "got: {stdout}");
    assert!(
        stdout.contains("Skipping AGENTS.md/CLAUDE.md context files (--no-context-files)"),
        "the skip must be announced, not silent: {stdout}"
    );
    assert!(!repo.join("AGENTS.md").exists());
    assert!(!repo.join("CLAUDE.md").exists());

    // Without the flag, the same sweep writes both.
    let out = offline_install_cmd(&repo, &home, &cache)
        .args(["plugin", "install", "--all"])
        .output()
        .expect("run plugin install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "install failed:\n{stdout}");
    assert!(repo.join("AGENTS.md").exists(), "got: {stdout}");
    assert!(repo.join("CLAUDE.md").exists(), "got: {stdout}");
}

/// The served plugin content is AUTHORITATIVE over the embedded fallback, so
/// context wording ships with plugin updates instead of CLI releases.
#[test]
fn a_served_context_template_overrides_the_embedded_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let served = home.join(".revelara/marketplace/plugins/revelara");
    std::fs::create_dir_all(&served).unwrap();
    std::fs::write(served.join("AGENTS.md"), "## Revelara\n\nSERVED WORDING\n").unwrap();
    git_init(&repo);

    let mut c = bin();
    let out = c
        .current_dir(&repo)
        .env("HOME", &home)
        .env("RVL_OFFLINE", "1")
        .env_remove("RVL_API_KEY")
        .env_remove("RVL_API_URL")
        .args(["init", "-y", "--skip-plugin"])
        .output()
        .expect("run init");
    assert!(out.status.success());
    let agents = std::fs::read_to_string(repo.join("AGENTS.md")).unwrap();
    assert!(agents.contains("SERVED WORDING"), "got: {agents}");
    assert!(agents.starts_with(BLOCK_START));
    assert!(
        !agents.contains("rvl risk list --service=<service>"),
        "the served copy replaces the fallback body entirely: {agents}"
    );
}

// --- hook ---

fn hook_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(".git").join("hooks").join(name)
}

/// An rvl-cli v1 shim is OUR OWN PREDECESSOR's gate, and after the cutover we
/// know it is stale, so install REPAIRS it without `--force` (po-av01j.191);
/// the replaced file is still backed up. po-av01j.185 item 10 refused it,
/// reasoning that a v1 shim runs a different (coding-agent) gate — true of a
/// v1 binary, void of this one, where `--agent` is a documented no-op.
///
/// The full repair/doctor/upgrade-path matrix lives in `v1_hook_compat.rs`.
#[test]
fn hook_install_repairs_a_v1_agent_scan_hook_without_force() {
    let tmp = tempfile::tempdir().unwrap();
    git_init(tmp.path());
    let path = hook_path(tmp.path(), "pre-commit");
    let v1 = "#!/bin/sh\n\
              # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
              exec rvl scan --agent --staged --mode enforce\n";
    std::fs::write(&path, v1).unwrap();

    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .expect("run hook install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "got: {stdout}");
    assert!(stdout.contains("Repaired pre-commit hook"), "got: {stdout}");
    assert_eq!(
        std::fs::read_to_string(hook_path(tmp.path(), "pre-commit.pre-rvl")).unwrap(),
        v1,
        "the replaced gate must be recoverable"
    );
    let now = std::fs::read_to_string(&path).unwrap();
    assert!(now.contains("--hook pre-commit"), "got: {now}");
    assert!(!now.contains("--agent"), "got: {now}");

    // Re-installing over OUR OWN gate stays idempotent, no --force needed.
    let out = bin()
        .current_dir(tmp.path())
        .args(["hook", "install"])
        .output()
        .expect("run hook install");
    assert!(out.status.success());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), now);
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
