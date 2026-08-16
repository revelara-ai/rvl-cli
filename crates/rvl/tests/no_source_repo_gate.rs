//! THE INSTALLED GATE IN A REPO WITH NO SUPPORTED LANGUAGE (po-av01j.198).
//!
//! `rvl hook install` writes `rvl scan . --incremental --changed-only --hook
//! pre-commit` into `.git/hooks/pre-commit`. The incremental path used to bail
//! with "no supported source files found under ." whenever the candidate set
//! was empty, so in a docs repo, a terraform/YAML repo, a shell repo, or any
//! polyglot repo before its first Go/Py/TS/Rust/C file lands, EVERY commit
//! failed — with a scanner error rather than a finding, which reads as "the
//! tool is broken" rather than "your code has a risk".
//!
//! These tests drive real `git commit` and `git push` through the hook the
//! product actually installs, because the failure is not "a flag is rejected",
//! it is "the user's repo cannot accept a commit". They also pin the other
//! half: absence of source may not become absence of a gate, and a root the
//! walk cannot READ must still fail loudly rather than pass as empty.

use std::path::Path;
use std::process::Command;

/// git forwards a hook's stdout to ITS stderr, so a hook's ladder can land on
/// either stream depending on git version; assertions read both.
fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A fake AWS key, assembled so no key-shaped literal sits in this source.
/// The content lane blocks on it, which lets these tests exercise the whole
/// hook path with an EMPTY spec file (no signed cache, no network).
fn planted_secret() -> String {
    format!("AWS_KEY = \"{}\"\n", ["AKIA", "ZZ3RVL198NOSRC2Q"].concat())
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

/// A `bin/` directory whose `rvl` is the binary under test, wrapped in two
/// lines of sh so it can append `--specs-file <empty>`: the deterministic scan
/// needs a verifiable spec cache, which a test has no way to sign. The hook
/// shim under test is installed by the binary itself and calls plain `rvl`,
/// so this is also what makes the installed shim resolve to it.
fn path_with_rvl(dir: &Path) -> std::ffi::OsString {
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
    match std::env::var_os("PATH") {
        Some(p) => {
            let mut dirs = vec![bin.clone()];
            dirs.extend(std::env::split_paths(&p));
            std::env::join_paths(dirs).unwrap()
        }
        None => bin.into_os_string(),
    }
}

/// A git repo with NO supported source: a README and a YAML config, the shape
/// a docs or infra repository actually has. Plus a bare remote, so `pre-push`
/// has an upstream to resolve its range against.
struct DocsRepo {
    dir: tempfile::TempDir,
    root: std::path::PathBuf,
    path: std::ffi::OsString,
}

impl DocsRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("README.md"), "# Docs\n").unwrap();
        std::fs::write(root.join("config.yml"), "service:\n  name: docs\n").unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "seed"]);

        let remote = dir.path().join("remote.git");
        git(
            &root,
            &["init", "-q", "--bare", "--", remote.to_str().unwrap()],
        );
        git(
            &root,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        // Seed the upstream WITHOUT the gate (it is not installed yet), so the
        // pre-push test has a real `origin/main..HEAD` range to scope to.
        git(&root, &["push", "-q", "-u", "origin", "main"]);

        let path = path_with_rvl(dir.path());
        DocsRepo { dir, root, path }
    }

    /// Install the product's own hook with the binary under test — no fixture
    /// shim. What ships is what runs.
    fn install_hook(&self, which: &str) {
        let out = self
            .rvl()
            .args(["hook", "install", which])
            .output()
            .expect("run hook install");
        assert!(
            out.status.success(),
            "hook install failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `git` in the repo, with the binary on PATH and an isolated
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
        c
    }

    /// The binary under test, run directly (no wrapper, no hook).
    fn rvl(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
        c.current_dir(&self.root)
            .env("PATH", &self.path)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1");
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

/// THE BEAD. A docs-only repo must accept a commit through the hook `rvl hook
/// install` writes. Before the fix this failed with "no supported source files
/// found under ."; exit 1, and no commit was ever created.
#[test]
fn a_docs_only_repo_commits_through_the_installed_pre_commit_hook() {
    let f = DocsRepo::new();
    f.install_hook("--pre-commit");
    let before = f.head();

    std::fs::write(f.root.join("GUIDE.md"), "# Guide\n\nHow to operate it.\n").unwrap();
    git(&f.root, &["add", "GUIDE.md"]);
    let out = f
        .git()
        .args(["commit", "-m", "docs: guide"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        out.status.success(),
        "an installed gate must not brick a docs repo:\n{all}"
    );
    assert_ne!(f.head(), before, "the commit must actually exist");
    // The exact pre-fix bail, verbatim, so a regression cannot hide behind a
    // reworded message: it named `--retrieved` as the way out.
    assert!(
        !all.contains("no supported source files found") && !all.contains("--retrieved"),
        "absence of source is not a scanner error: {all}"
    );

    // A GATE THAT PRINTS NOTHING LOOKS BROKEN TOO. The run must say why the
    // language lane is empty, and still render the report a full scan renders
    // over an empty scope.
    assert!(
        all.contains("no supported source files under") && all.contains("no retriever was needed"),
        "the run must state why nothing was retrieved: {all}"
    );
    assert!(
        all.contains("COVERAGE") && all.contains("commit clean"),
        "an empty scope still gets the full-scan report: {all}"
    );
}

/// The pre-push half of the same shim. Its scoping question differs (a commit
/// range, not the index), so it reaches the same empty candidate set by
/// another road and must land the same way.
#[test]
fn a_docs_only_repo_pushes_through_the_installed_pre_push_hook() {
    let f = DocsRepo::new();
    f.install_hook("--pre-push");

    std::fs::write(f.root.join("RUNBOOK.md"), "# Runbook\n").unwrap();
    git(&f.root, &["add", "RUNBOOK.md"]);
    git(&f.root, &["commit", "-qm", "docs: runbook"]);
    let out = f.git().args(["push", "origin", "main"]).output().unwrap();
    let all = combined(&out);
    assert!(
        out.status.success(),
        "an installed pre-push gate must not brick a docs repo:\n{all}"
    );
    assert!(
        !all.contains("no supported source files found"),
        "absence of source is not a scanner error: {all}"
    );
}

/// THE OTHER HALF. Absence of source must not become absence of a gate: the
/// moment a supported file lands in the same repo, the hook that just let
/// three docs commits through has to stop a bad one. The finding here is a
/// content-lane secret, which needs no signed spec cache to fire.
#[test]
fn the_same_repo_still_gates_once_a_supported_file_lands() {
    let f = DocsRepo::new();
    f.install_hook("--pre-commit");
    let before = f.head();

    std::fs::write(
        f.root.join("app.py"),
        format!("import os\n\n{}", planted_secret()),
    )
    .unwrap();
    git(&f.root, &["add", "app.py"]);
    let out = f
        .git()
        .args(["commit", "-m", "feat: app"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        !out.status.success(),
        "the gate must fire once there is something to gate on:\n{all}"
    );
    assert_eq!(f.head(), before, "no commit may be created");
    assert!(
        all.contains("BLOCKING"),
        "the ladder must name the finding: {all}"
    );
}

/// A repo that DOES have supported source, committing a docs-only change,
/// takes the other road to an empty language scope: the candidate set is
/// non-empty, the changed set is non-empty, and no supported file is in it.
/// It always passed cleanly. The bead's case must read IDENTICALLY — the
/// difference between them is a fact about the repository, not about whether
/// the commit is safe.
#[test]
fn a_docs_change_reads_the_same_with_or_without_source_in_the_repo() {
    let f = DocsRepo::new();
    f.install_hook("--pre-commit");
    std::fs::write(f.root.join("NOTES.md"), "# Notes\n").unwrap();
    git(&f.root, &["add", "NOTES.md"]);
    let no_source = f
        .git()
        .args(["commit", "-m", "docs: notes"])
        .output()
        .unwrap();
    assert!(
        no_source.status.success(),
        "docs commit in a source-free repo: {}",
        combined(&no_source)
    );

    // Now the repo has Python. Commit another docs-only change through the
    // same hook.
    std::fs::write(f.root.join("app.py"), "def hello():\n    return \"hi\"\n").unwrap();
    git(&f.root, &["add", "app.py"]);
    git(&f.root, &["commit", "-qm", "feat: app", "--no-verify"]);
    std::fs::write(f.root.join("MORE.md"), "# More\n").unwrap();
    git(&f.root, &["add", "MORE.md"]);
    let with_source = f
        .git()
        .args(["commit", "-m", "docs: more"])
        .output()
        .unwrap();
    assert!(
        with_source.status.success(),
        "docs commit in a repo that has source: {}",
        combined(&with_source)
    );

    for out in [&no_source, &with_source] {
        assert!(
            combined(out).contains("commit clean"),
            "both must reach the same verdict: {}",
            combined(out)
        );
    }
}

/// THE LINE BETWEEN THE TWO EMPTINESSES. "This repo has no supported
/// language" is benign; "the walk could not look" is not, and turning the
/// first into a pass must not smuggle the second in with it. A root that
/// exists but cannot be opened yields the identical empty candidate set, so
/// this is the case that proves the fix did not trade a false alarm for a
/// silent one.
#[cfg(unix)]
#[test]
fn a_root_the_walk_cannot_read_still_fails_loudly() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("locked");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000)).unwrap();
    // Running as root defeats the permission bit entirely; there is nothing to
    // assert in that environment.
    if std::fs::read_dir(&root).is_ok() {
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
        .args(["scan"])
        .arg(&root)
        .args(["--incremental", "--hook", "pre-commit"])
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .env("RVL_INDEX_DIR", dir.path().join("index"))
        .env("RVL_OFFLINE", "1")
        .output()
        .expect("run rvl");
    // Restore before asserting so a failure cannot leave an unremovable temp.
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();

    let all = combined(&out);
    assert!(
        !out.status.success(),
        "a root that cannot be read must not report a clean scan: {all}"
    );
    assert!(
        !all.contains("commit clean"),
        "and it must not print the clean verdict at all: {all}"
    );
    assert!(
        all.contains("cannot read") || all.contains("cannot scan"),
        "the error must say the tree could not be read: {all}"
    );
}

/// The degenerate form of the same distinction: a target that does not exist
/// walks to the same empty set. Pinned through the INCREMENTAL flags the
/// installed hook uses, because that is the path this bead changed.
#[test]
fn a_target_that_does_not_exist_still_fails_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
        .args(["scan"])
        .arg(dir.path().join("nope"))
        .args(["--incremental", "--hook", "pre-commit"])
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .env("RVL_INDEX_DIR", dir.path().join("index"))
        .env("RVL_OFFLINE", "1")
        .output()
        .expect("run rvl");
    let all = combined(&out);
    assert!(
        !out.status.success(),
        "a missing target must not report a clean scan: {all}"
    );
    assert!(
        !all.contains("commit clean"),
        "and it must not print the clean verdict at all: {all}"
    );
}
