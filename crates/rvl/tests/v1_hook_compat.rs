//! THE UPGRADE PATH (po-av01j.191), end to end through git.
//!
//! rvl-cli v1's `hook install` wrote two shims into `.git/hooks`. The brew
//! cask keeps the binary name `rvl`, so `brew upgrade` swaps the binary
//! underneath those files without touching them. These tests drive the shims
//! VERBATIM — byte-for-byte what rvl-cli's Go writes — through real `git
//! commit` and `git push`, because the failure this bead is about is not
//! "a flag is rejected", it is "the user's repo cannot accept a commit".
//!
//! The shim bodies here are copied from rvl-cli `internal/commands/hook.go`
//! (`writeHookShim` + `selectedHooks`) rather than shared with the
//! implementation, on purpose: a test that reads its fixture from the code
//! under test cannot notice the code drifting away from what v1 actually
//! wrote.

use std::path::Path;
use std::process::Command;

/// git forwards a hook's stdout to ITS stderr, so a hook's ladder can land on
/// either stream depending on git version; assertions about scan output read
/// both.
fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// rvl-cli v1's pre-commit shim, verbatim.
const V1_PRE_COMMIT: &str = "#!/bin/sh\n\
     # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
     exec rvl scan --agent --staged --mode enforce\n";

/// rvl-cli v1's pre-push shim, verbatim (including its stopgap warning).
const V1_PRE_PUSH: &str = "#!/bin/sh\n\
     # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
     # WARNING: pre-push stopgap. The real stdin ref protocol lands in\n\
     # po-66evv.9 as `rvl scan --agent --pre-push`; swap it in when available.\n\
     exec rvl scan --agent --changed-only\n";

/// A fake AWS key, assembled so no key-shaped literal sits in this source.
/// The content lane blocks on it, which lets these tests exercise the whole
/// hook path with an EMPTY spec file (no signed cache, no network).
fn planted_secret() -> String {
    format!("AWS_KEY = \"{}\"\n", ["AKIA", "ZZ3RVLQ7SG7JBX2Q"].concat())
}

/// Drop CI's OWN base-ref env from a child (po-av01j.194). This suite runs in
/// GitHub Actions, where a `pull_request` event exports `GITHUB_BASE_REF`, and
/// the v1 `--changed-only` alias now READS that chain — inherited, it would
/// change which question these hooks ask between a laptop and CI. Hooks
/// inherit the git process's environment, so it is cleared on both factories.
/// The base-ref mapping itself is exercised deliberately, with the value set.
fn clear_base_ref_env(c: &mut Command) {
    for k in [
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A `bin/` directory whose `rvl` is the binary under test.
///
/// It is a two-line sh wrapper rather than a copy so it can append
/// `--specs-file <empty>`: the deterministic scan needs a verifiable spec
/// cache, which a test has no way to sign, and the DEV override is a flag the
/// verbatim v1 shim obviously cannot carry. The wrapper appends ONLY that —
/// every v1 flag still reaches the real argument parser exactly as v1 wrote
/// it, which is the thing under test.
fn path_with_rvl(dir: &Path) -> (std::ffi::OsString, std::path::PathBuf) {
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let specs = dir.join("specs.json");
    std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
    let wrapper = bin.join("rvl");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec {} \"$@\" --specs-file {}\n",
            env!("CARGO_BIN_EXE_rvl"),
            specs.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = match std::env::var_os("PATH") {
        Some(p) => {
            let mut dirs = vec![bin.clone()];
            dirs.extend(std::env::split_paths(&p));
            std::env::join_paths(dirs).unwrap()
        }
        None => bin.clone().into_os_string(),
    };
    (path, bin)
}

/// A git repo with one clean Python file, plus the env a git hook needs to
/// find an isolated cache/index. Returns the repo root and a `git` command
/// factory that carries that env (hooks inherit it).
struct Fixture {
    dir: tempfile::TempDir,
    root: std::path::PathBuf,
    path: std::ffi::OsString,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"svc\"\n").unwrap();
        std::fs::write(root.join("app.py"), "def hello():\n    return \"hi\"\n").unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "seed"]);
        let (path, _) = path_with_rvl(dir.path());
        Fixture { dir, root, path }
    }

    /// Write a hook file verbatim and make it executable, exactly as rvl-cli
    /// v1 left it on disk.
    fn install_v1_hook(&self, name: &str, body: &str) {
        let hooks = self.root.join(".git").join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let p = hooks.join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// `git` in the repo, with the upgraded binary on PATH and an isolated
    /// HOME/cache/index — the hook inherits all of it.
    fn git(&self) -> Command {
        let mut c = Command::new("git");
        c.arg("-C")
            .arg(&self.root)
            .env("PATH", &self.path)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1");
        clear_base_ref_env(&mut c);
        c
    }

    /// The binary under test, run directly (no wrapper, no hook).
    fn rvl(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
        c.current_dir(&self.root)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1");
        clear_base_ref_env(&mut c);
        c
    }

    fn head(&self) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

/// THE BEAD. A repo whose pre-commit hook was written by rvl-cli v1 must
/// still accept a commit after the binary underneath it is swapped. Before
/// the fix this failed with `error: unexpected argument '--staged'` and no
/// commit was created.
#[test]
fn a_v1_pre_commit_shim_still_commits_after_the_binary_is_swapped() {
    let f = Fixture::new();
    f.install_v1_hook("pre-commit", V1_PRE_COMMIT);
    let before = f.head();

    std::fs::write(f.root.join("added.py"), "def added():\n    return 1\n").unwrap();
    git(&f.root, &["add", "added.py"]);
    let out = f.git().args(["commit", "-m", "clean"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "a v1 shim must not brick the repo:\n{stdout}\n{stderr}"
    );
    assert_ne!(f.head(), before, "the commit must actually exist");

    // The run says what it did with the v1 flags, and names the repair.
    assert!(
        stderr.contains("--incremental --changed-only --hook pre-commit"),
        "must state the command it ran instead: {stderr}"
    );
    assert!(
        stderr.contains("hook install"),
        "must name the repair: {stderr}"
    );
    // `--staged` must map to the STAGED question, not the working tree.
    assert!(
        stderr.contains("staged paths"),
        "must scope to the index: {stderr}"
    );
}

/// The other half: still a GATE. A v1 shim that runs must still stop a commit
/// that introduces a blocking finding, or the compatibility path has quietly
/// disarmed everyone's pre-commit hook.
#[test]
fn a_v1_pre_commit_shim_still_blocks_a_bad_commit() {
    let f = Fixture::new();
    f.install_v1_hook("pre-commit", V1_PRE_COMMIT);
    let before = f.head();

    std::fs::write(f.root.join("prod.env"), planted_secret()).unwrap();
    git(&f.root, &["add", "prod.env"]);
    let out = f.git().args(["commit", "-m", "leak"]).output().unwrap();
    let all = combined(&out);
    assert!(!out.status.success(), "the gate must still fire:\n{all}");
    assert!(
        all.contains("BLOCKING"),
        "the ladder must name the finding: {all}"
    );
    assert_eq!(f.head(), before, "a blocked commit must create nothing");
}

/// v1's pre-push shim carries `--changed-only` with no `--incremental`, which
/// v2 rejected outright (`--changed-only requires --incremental`). It maps to
/// the PRE-PUSH question — `@{upstream}..HEAD`, the committed work the remote
/// does not have — because that is what rvl-cli's `--changed-only` computed
/// (`base...HEAD`). Mapping it to the working tree instead would make a
/// pre-push hook a no-op: a clean tree has an empty changed set.
#[test]
fn a_v1_pre_push_shim_gates_the_pushed_range() {
    let f = Fixture::new();
    let remote = f.dir.path().join("remote.git");
    git(&f.root, &["init", "-q", "--bare"]);
    Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .output()
        .expect("init bare remote");
    git(
        &f.root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&f.root, &["push", "-q", "-u", "origin", "main"]);

    f.install_v1_hook("pre-push", V1_PRE_PUSH);

    // Clean pushed range: the push goes through.
    std::fs::write(f.root.join("added.py"), "def added():\n    return 1\n").unwrap();
    git(&f.root, &["add", "added.py"]);
    git(&f.root, &["commit", "-qm", "clean"]);
    let out = f.git().args(["push", "origin", "main"]).output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "a v1 pre-push shim must run: {stderr}"
    );
    assert!(
        stderr.contains("--hook pre-push"),
        "bare --changed-only must map to the pre-push question: {stderr}"
    );

    // A blocking finding in the pushed range stops the push.
    std::fs::write(f.root.join("prod.env"), planted_secret()).unwrap();
    git(&f.root, &["add", "prod.env"]);
    git(&f.root, &["commit", "-qm", "leak"]);
    let out = f.git().args(["push", "origin", "main"]).output().unwrap();
    assert!(
        !out.status.success(),
        "the pre-push gate must still fire:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// po-av01j.194 REVISITS THE .191 MAPPING. v1's bare `--changed-only`
/// resolved a base ref and diffed `base...HEAD`; .191 could only map it to
/// `--hook pre-push` because v2 had no chain to resolve against. Now it does,
/// so in CI — where the chain IS populated — the same shim asks v1's actual
/// question, against v1's actual base ref.
///
/// Both halves matter: the scope line must name the base range (not the
/// pre-push question), and the gate must still fire.
#[test]
fn a_v1_changed_only_shim_resolves_the_base_ref_chain_when_ci_sets_one() {
    let f = Fixture::new();
    let remote = f.dir.path().join("remote.git");
    Command::new("git")
        .args(["init", "-q", "--bare"])
        .arg(&remote)
        .output()
        .expect("init bare remote");
    git(
        &f.root,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git(&f.root, &["push", "-q", "origin", "main"]);
    git(&f.root, &["checkout", "-q", "-b", "feature"]);

    f.install_v1_hook("pre-push", V1_PRE_PUSH);

    std::fs::write(f.root.join("prod.env"), planted_secret()).unwrap();
    git(&f.root, &["add", "prod.env"]);
    git(&f.root, &["commit", "-qm", "leak"]);

    let out = f
        .git()
        // Exactly what a GitHub `pull_request` event exports.
        .env("GITHUB_BASE_REF", "main")
        .args(["push", "origin", "feature"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        !out.status.success(),
        "the gate must still fire on the PR's committed leak:\n{all}"
    );
    assert!(
        all.contains("main...HEAD"),
        "the v1 alias must resolve v1's question — base...HEAD: {all}"
    );
    assert!(
        all.contains("base-ref chain"),
        "and the compatibility notice must say which scope it ran: {all}"
    );
    assert!(
        !all.contains("--hook pre-push"),
        "with a base ref in play the .191 pre-push mapping must NOT be used: {all}"
    );
}

/// rvl-cli v1's `--mode eval` reported without blocking. A user who
/// deliberately disarmed their gate must not have it re-armed by an upgrade.
#[test]
fn v1_mode_eval_reports_without_blocking() {
    let f = Fixture::new();
    f.install_v1_hook(
        "pre-commit",
        "#!/bin/sh\n\
         # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
         exec rvl scan --agent --staged --mode eval\n",
    );
    let before = f.head();
    std::fs::write(f.root.join("prod.env"), planted_secret()).unwrap();
    git(&f.root, &["add", "prod.env"]);
    let out = f.git().args(["commit", "-m", "leak"]).output().unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "eval mode must not block:\n{all}");
    assert!(
        all.contains("BLOCKING") && all.contains("reports without blocking"),
        "eval mode must still REPORT what it found: {all}"
    );
    assert_ne!(f.head(), before);
}

/// A bare `--changed-only` WITHOUT `--agent` is not a v1 shim — it is a v2
/// user who forgot `--incremental`. They keep the explanatory error rather
/// than silently receiving pre-push scope.
#[test]
fn bare_changed_only_without_the_v1_marker_keeps_its_error() {
    let f = Fixture::new();
    let out = f
        .rvl()
        .args(["scan", ".", "--changed-only"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("--changed-only requires --incremental"),
        "got: {stderr}"
    );
}

// --- install / doctor over a v1 shim ---

/// `hook install` repairs OUR OWN PREDECESSOR's shim without `--force`, and
/// keeps the replaced file. Refusing it (po-av01j.185 item 10) left the user
/// with a repo they could not commit to and no way to fix it that the tool
/// suggested.
#[test]
fn hook_install_repairs_a_v1_shim_without_force() {
    let f = Fixture::new();
    f.install_v1_hook("pre-commit", V1_PRE_COMMIT);
    f.install_v1_hook("pre-push", V1_PRE_PUSH);

    let out = f
        .rvl()
        .args(["hook", "install", "--pre-commit", "--pre-push"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "got: {stdout}");
    assert!(stdout.contains("Repaired pre-commit hook"), "got: {stdout}");
    assert!(stdout.contains("Repaired pre-push hook"), "got: {stdout}");

    let hooks = f.root.join(".git").join("hooks");
    for name in ["pre-commit", "pre-push"] {
        let body = std::fs::read_to_string(hooks.join(name)).unwrap();
        assert!(body.contains(&format!("--hook {name}")), "got: {body}");
        assert!(!body.contains("--agent"), "got: {body}");
        assert_eq!(
            std::fs::read_to_string(hooks.join(format!("{name}.pre-rvl"))).unwrap(),
            if name == "pre-commit" {
                V1_PRE_COMMIT
            } else {
                V1_PRE_PUSH
            },
            "the replaced shim must be recoverable"
        );
    }

    // Idempotent: a second run over our own gate changes nothing and needs no
    // --force.
    let before = std::fs::read_to_string(hooks.join("pre-commit")).unwrap();
    let out = f
        .rvl()
        .args(["hook", "install", "--pre-commit"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(hooks.join("pre-commit")).unwrap(),
        before
    );
}

/// A hook we did not author is still refused without `--force`, and `--force`
/// still backs it up. The v1 carve-out is narrow by construction: it matches
/// the banner rvl-cli's installer wrote, nothing else.
#[test]
fn a_foreign_hook_is_still_refused_without_force() {
    let f = Fixture::new();
    let hooks = f.root.join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).unwrap();
    let foreign = "#!/bin/sh\necho custom gate\n";
    std::fs::write(hooks.join("pre-commit"), foreign).unwrap();

    let out = f.rvl().args(["hook", "install"]).output().unwrap();
    assert!(!out.status.success(), "must refuse a foreign hook");
    assert!(String::from_utf8_lossy(&out.stderr).contains("--force"));
    assert_eq!(
        std::fs::read_to_string(hooks.join("pre-commit")).unwrap(),
        foreign,
        "a refusal must leave the hook untouched"
    );

    // A hand-rolled hook that merely MENTIONS `rvl scan --agent` is also not
    // ours: no v1 installer banner, so it is not ours to rewrite.
    let handrolled = "#!/bin/sh\nexec rvl scan --agent --staged\n";
    std::fs::write(hooks.join("pre-commit"), handrolled).unwrap();
    let out = f.rvl().args(["hook", "install"]).output().unwrap();
    assert!(!out.status.success(), "must refuse a hand-rolled hook");
    assert_eq!(
        std::fs::read_to_string(hooks.join("pre-commit")).unwrap(),
        handrolled
    );

    let out = f
        .rvl()
        .args(["hook", "install", "--force"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(
        std::fs::read_to_string(hooks.join("pre-commit.pre-rvl")).unwrap(),
        handrolled
    );
}

/// `hook doctor` must NAME a v1 shim. Reporting `PASS pre-commit hook: native
/// scan gate installed` over a shim the binary could not even parse is half of
/// what made this bead severe rather than merely broken.
#[test]
fn hook_doctor_names_a_v1_shim_and_passes_a_repaired_one() {
    let f = Fixture::new();
    f.install_v1_hook("pre-commit", V1_PRE_COMMIT);
    f.install_v1_hook("pre-push", V1_PRE_PUSH);

    let out = f.rvl().args(["hook", "doctor"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    for name in ["pre-commit", "pre-push"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(&format!("{name} hook")))
            .unwrap_or_else(|| panic!("no {name} line in:\n{stdout}"));
        assert!(line.starts_with("WARN"), "must not PASS a v1 shim: {line}");
        assert!(line.contains("rvl-cli v1 shim"), "got: {line}");
        assert!(line.contains("hook install"), "must name the fix: {line}");
    }

    assert!(f
        .rvl()
        .args(["hook", "install", "--pre-commit", "--pre-push"])
        .output()
        .unwrap()
        .status
        .success());
    let out = f.rvl().args(["hook", "doctor"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        stdout
            .lines()
            .filter(|l| l.starts_with("PASS") && l.contains("hook:"))
            .count(),
        2,
        "both repaired hooks must pass:\n{stdout}"
    );
}

/// lefthook users pasted v1's `run: rvl scan --agent ...` snippet by hand, so
/// there is no shim file to inspect: the config line is the only place the
/// stale invocation shows up, and doctor must not call it healthy either.
#[test]
fn hook_doctor_names_a_v1_lefthook_run_line() {
    let f = Fixture::new();
    std::fs::write(
        f.root.join("lefthook.yml"),
        "pre-commit:\n  commands:\n    agent-scan:\n      run: rvl scan --agent --staged --mode enforce\n",
    )
    .unwrap();
    let out = f.rvl().args(["hook", "doctor"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = stdout
        .lines()
        .find(|l| l.contains("lefthook"))
        .unwrap_or_else(|| panic!("no lefthook line in:\n{stdout}"));
    assert!(line.starts_with("WARN"), "got: {line}");
    assert!(line.contains("rvl-cli v1"), "got: {line}");
}
