//! THE COMMIT GATE OVER A RETRIEVER THAT CANNOT RUN (po-av01j.199).
//!
//! `rvl hook install` writes `rvl scan . --incremental --changed-only --hook
//! pre-commit` into `.git/hooks/pre-commit`. On a machine with no `python3`,
//! that gate printed a per-language COVERAGE line ("Python: not installed")
//! and then the verdict `0 advisory - commit clean`, exit 0 -- so an unbounded
//! `requests.get` walked straight through. With `python3` present the
//! identical repo blocked. The gate reported success having scanned nothing.
//!
//! The policy was never in doubt: `retrieval_verdict` has always documented
//! fail-OPEN per language, `--strict` fail-closed, and ALL detected languages
//! degraded as fatal at any strictness ("a clean report over nothing scanned is
//! the single outcome that must never be quiet"). The incremental path simply
//! never called it. THE FIX IS THE VERDICT LINE, NOT THE EXIT CODE: our
//! retriever being broken must not block someone's commit.
//!
//! These tests drive a real `git commit` through the hook the product installs,
//! with a PATH that genuinely lacks `python3`, because the defect is not "a
//! flag renders oddly", it is "the gate approved a commit it never read".

use std::path::{Path, PathBuf};
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

/// First match for `name` on the CURRENT process PATH.
fn on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|c| c.is_file())
    })
}

/// An unbounded `requests.get`: the exact shape the bead staged.
const UNBOUNDED_GET: &str = "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n";

/// A fake AWS key, assembled so no key-shaped literal sits in this source. The
/// CONTENT lane blocks on it, which is what lets these tests prove "the gate
/// still blocks" with an empty spec file (no signed cache, no network) -- the
/// call-site lane's own judgment of `requests.get` needs a signed corpus a test
/// cannot produce.
fn planted_secret() -> String {
    format!("AWS_KEY = \"{}\"\n", ["AKIA", "ZZ3RVL199DEGRAD2"].concat())
}

/// A Python repo plus a PATH we control, so `python3` can be present or absent
/// by choice rather than by luck of the test machine.
struct PyRepo {
    dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
}

impl PyRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        // Seed with source so the repo's ONLY language is unambiguously Python.
        std::fs::write(root.join("seed.py"), "def seed():\n    return 1\n").unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "seed"]);

        // A CLOSED PATH, built from nothing. Inheriting the real PATH minus a
        // directory is not an option: `git` and `python3` live in the same
        // /usr/bin on every machine this runs on, so the only way to prove the
        // absence is to enumerate what may be present.
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        for tool in ["git", "sh"] {
            let src = on_path(tool).unwrap_or_else(|| panic!("{tool} must exist to run this test"));
            #[cfg(unix)]
            std::os::unix::fs::symlink(&src, bin.join(tool)).unwrap();
        }
        let specs = dir.path().join("specs.json");
        std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
        // Two lines of sh so the shim can append `--specs-file <empty>`: the
        // deterministic scan needs a verifiable spec cache, which a test has no
        // way to sign. The hook the binary installs calls plain `rvl`, so this
        // is also what makes the installed shim resolve to the binary under
        // test.
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
        PyRepo { dir, root, bin }
    }

    /// Make `python3` resolvable on the sandbox PATH: the CONTROL for the
    /// bead's A/B, and the reason these tests can prove the difference is the
    /// retriever rather than the fixture.
    fn with_python(self) -> Self {
        let src = on_path("python3").expect("this test machine has no python3");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&src, self.bin.join("python3")).unwrap();
        self
    }

    fn path(&self) -> std::ffi::OsString {
        self.bin.clone().into_os_string()
    }

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

    /// `git` in the repo, with ONLY the sandbox bin on PATH and an isolated
    /// HOME/cache/index — the hook inherits all of it.
    fn git(&self) -> Command {
        let mut c = Command::new("git");
        c.arg("-C").arg(&self.root);
        self.envs(&mut c);
        c
    }

    /// The binary under test, run directly (no wrapper, no hook).
    fn rvl(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
        c.current_dir(&self.root);
        self.envs(&mut c);
        c
    }

    fn envs(&self, c: &mut Command) {
        c.env("PATH", self.path())
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1");
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

    fn stage_unbounded_get(&self) {
        std::fs::write(self.root.join("app.py"), UNBOUNDED_GET).unwrap();
        git(&self.root, &["add", "app.py"]);
    }
}

/// Guard: the sandbox PATH must genuinely have no `python3`, or every
/// assertion below passes for the wrong reason.
fn assert_no_python(f: &PyRepo) {
    assert!(
        !f.bin.join("python3").exists() && !f.bin.join("python").exists(),
        "the fixture must not leak an interpreter onto the closed PATH"
    );
}

/// THE BEAD. Python is the repo's only language, its retriever cannot run, so
/// NOTHING was scanned -- and the verdict line said "commit clean".
#[test]
fn a_commit_whose_only_retriever_cannot_run_is_never_called_clean() {
    let f = PyRepo::new();
    assert_no_python(&f);
    f.install_hook("--pre-commit");
    let before = f.head();
    f.stage_unbounded_get();

    let out = f
        .git()
        .args(["commit", "-m", "feat: fetch"])
        .output()
        .unwrap();
    let all = combined(&out);

    // FAIL OPEN (ruled): our retriever being broken is our defect, and it must
    // not stand between a developer and their commit.
    assert!(
        out.status.success(),
        "a broken retriever must not block a commit:\n{all}"
    );
    assert_ne!(f.head(), before, "the commit must actually exist");

    // ...but it must never be sold as a clean one.
    assert!(
        !all.contains("commit clean"),
        "THE BEAD: a scan that read nothing reported a clean commit:\n{all}"
    );
    assert!(
        all.contains("NOT CLEAN") && all.contains("nothing was scanned"),
        "the verdict line must state that nothing was scanned:\n{all}"
    );
    // The incremental path must be at least as loud as the full path, which
    // has rendered this since po-av01j.139.
    assert!(
        all.contains("INCOMPLETE"),
        "the coverage block must say the call-site lane never ran:\n{all}"
    );
    assert!(
        all.contains("python3"),
        "and must name the missing prerequisite:\n{all}"
    );
}

/// The control. The identical repo and the identical file, with `python3`
/// resolvable, reaches a real verdict -- which is what makes the case above a
/// bug rather than a repo with nothing in it. The blocking finding is a
/// content-lane secret (an empty spec file cannot judge `requests.get`), so
/// this pins "the gate still fires" rather than "requests.get is blocking".
#[test]
fn the_same_commit_still_blocks_when_the_retriever_works() {
    let f = PyRepo::new().with_python();
    f.install_hook("--pre-commit");
    let before = f.head();
    std::fs::write(
        f.root.join("app.py"),
        format!("{UNBOUNDED_GET}\n{}", planted_secret()),
    )
    .unwrap();
    git(&f.root, &["add", "app.py"]);

    let out = f
        .git()
        .args(["commit", "-m", "feat: fetch"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        !out.status.success(),
        "the gate must still fire when it can see:\n{all}"
    );
    assert_eq!(f.head(), before, "no commit may be created");
    assert!(all.contains("BLOCKING"), "{all}");
    assert!(
        !all.contains("INCOMPLETE") && !all.contains("NOT CLEAN"),
        "a working retriever is not an incomplete scan:\n{all}"
    );
}

/// A working retriever over a clean file keeps the clean verdict: the fix must
/// not make every scan read as degraded.
#[test]
fn a_working_retriever_over_a_clean_file_still_says_commit_clean() {
    let f = PyRepo::new().with_python();
    f.install_hook("--pre-commit");
    std::fs::write(f.root.join("safe.py"), "def add(a, b):\n    return a + b\n").unwrap();
    git(&f.root, &["add", "safe.py"]);

    let out = f
        .git()
        .args(["commit", "-m", "feat: add"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "{all}");
    assert!(all.contains("commit clean"), "{all}");
    assert!(!all.contains("NOT CLEAN"), "{all}");
}

/// `--strict` is the CI opt-in: a whole answer or none. It was being bypassed
/// by the same gap, so it has to be pinned on the incremental path
/// specifically, not just on the full path where it already worked.
#[test]
fn strict_still_fails_closed_on_the_incremental_path() {
    let f = PyRepo::new();
    assert_no_python(&f);
    f.stage_unbounded_get();

    let out = f
        .rvl()
        .args(["scan", ".", "--incremental", "--changed-only", "--strict"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        !out.status.success(),
        "--strict promises CI a whole answer or none:\n{all}"
    );
    assert!(
        !all.contains("commit clean"),
        "and must not print a verdict at all:\n{all}"
    );
    assert!(
        all.contains("--strict"),
        "the failure must name the flag that caused it:\n{all}"
    );
}

/// po-av01j.198 MUST NOT REGRESS. A repo with no supported source at all is a
/// different fact from a repo whose retriever is broken: there was nothing to
/// scan, so "clean" is the honest word. Same fixture family, same hook, only
/// the presence of source differs -- which is the whole distinction these two
/// beads exist to draw.
#[test]
fn a_repo_with_no_supported_source_still_reads_clean() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("README.md"), "# Docs\n").unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    git(&root, &["config", "user.email", "t@example.com"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-qm", "seed"]);

    // Built the same closed way, WITHOUT python3: a docs repo on a machine
    // with no interpreter is exactly where the two cases could be confused,
    // and it is the one that must stay clean.
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for tool in ["git", "sh"] {
        let src = on_path(tool).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&src, bin.join(tool)).unwrap();
    }
    let specs = dir.path().join("specs.json");
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
    let envs = |c: &mut Command| {
        c.env("PATH", bin.clone().into_os_string())
            .env("HOME", dir.path().join("home"))
            .env("RVL_CACHE_DIR", dir.path().join("cache"))
            .env("RVL_INDEX_DIR", dir.path().join("index"))
            .env("RVL_OFFLINE", "1");
    };
    let mut install = Command::new(env!("CARGO_BIN_EXE_rvl"));
    install
        .current_dir(&root)
        .args(["hook", "install", "--pre-commit"]);
    envs(&mut install);
    assert!(install.output().unwrap().status.success());

    std::fs::write(root.join("GUIDE.md"), "# Guide\n").unwrap();
    git(&root, &["add", "GUIDE.md"]);
    let mut commit = Command::new("git");
    commit.arg("-C").arg(&root).args(["commit", "-m", "docs"]);
    envs(&mut commit);
    let out = commit.output().unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "{all}");
    assert!(
        all.contains("commit clean"),
        "nothing to scan is not the same as could not scan (po-av01j.198):\n{all}"
    );
    assert!(!all.contains("NOT CLEAN"), "{all}");
    assert!(!all.contains("INCOMPLETE"), "{all}");
}
