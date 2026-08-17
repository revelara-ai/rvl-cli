//! THE GATE OVER A RETRIEVER THAT REPORTED SUCCESS AND READ NOTHING
//! (po-av01j.209).
//!
//! Third in the family after po-av01j.198 ("nothing to scan" wrongly blocked)
//! and po-av01j.199 ("could not scan" wrongly read clean), and the only one
//! `--strict` did not catch. `goindex` printed `load failed: ... go command
//! required, not found` to stderr, emitted
//! `{"kind":"","snapshot_id":"","constructions":null}`, and EXITED 0 — so rvl
//! recorded a SUCCESSFUL retrieval of zero sites, `{"state":"scanned",
//! "detail":"0"}`, byte-identical to a genuinely empty repo. Everything .199
//! built keys on a lane that FAILED, so the coverage note, the NOT CLEAN
//! verdict and `--strict` were all satisfied and all stayed silent. A Go
//! service in CI on an image without the Go toolchain had a green reliability
//! gate over code nothing had read, indefinitely.
//!
//! Two independent fixes are pinned here:
//!
//!   1. goindex exits non-zero when it cannot load the package graph, so the
//!      lane becomes `state:"failed"` and .199's machinery does its job.
//!   2. A STRUCTURAL GUARD at the rvl layer: a language whose helper emitted no
//!      packets at all — not even the repo-scoped record it writes on every
//!      successful run — is a failed lane whatever its exit code said. That is
//!      the check that catches the next helper to acquire this bug without
//!      anyone knowing it is broken, and it is tested with a helper stub that
//!      exits 0 precisely so it cannot be passing for reason (1).
//!
//! FAIL OPEN throughout (ruled on .199): our retriever being broken is our
//! defect and must not stand between a developer and their commit. The verdict
//! goes NOT CLEAN, the exit code stays 0 on the hook path, and `--strict` is
//! CI's opt-in to fail closed.

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

/// The goindex FROM THIS TREE, compiled once per test process.
///
/// Deliberately NOT `which goindex`: the machine running these tests very
/// likely has an installed goindex on PATH, and an assertion about a fix that
/// silently exercised yesterday's binary is worth nothing. `cargo test` does
/// not build the Go helper, so the tests build it themselves and skip loudly if
/// there is no Go toolchain to build it with.
fn goindex_binary() -> Option<PathBuf> {
    static BUILT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../helpers/goindex")
                .canonicalize()
                .ok()?;
            let out = PathBuf::from(env!("CARGO_BIN_EXE_rvl"))
                .parent()?
                .join("goindex-under-test");
            let st = Command::new("go")
                .arg("build")
                .arg("-o")
                .arg(&out)
                .arg(".")
                .current_dir(&src)
                .status()
                .ok()?;
            (st.success() && out.is_file()).then_some(out)
        })
        .clone()
}

/// The bead's staged file: one unbounded `http.Get`.
const UNBOUNDED_GET: &str = "package main\n\nimport \"net/http\"\n\n\
     func fetch(url string) (*http.Response, error) {\n\treturn http.Get(url)\n}\n";

/// A fake AWS key, assembled so no key-shaped literal sits in this source. The
/// CONTENT lane blocks on it, which is what lets these tests prove "the gate
/// still blocks" with an empty spec file — the call-site lane's own judgment of
/// `http.Get` needs a signed corpus a test cannot produce.
fn planted_secret() -> String {
    format!(
        "package main\n\nconst AWSKey = \"{}\"\n",
        ["AKIA", "ZZ3RVL209SILENT2"].concat()
    )
}

/// A Go repo plus a PATH we control, so `go` can be present or absent by choice
/// rather than by luck of the test machine.
struct GoRepo {
    dir: tempfile::TempDir,
    root: PathBuf,
    bin: PathBuf,
}

impl GoRepo {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        // A module and a source file, so the repo's ONLY language is
        // unambiguously Go and goindex has a module to load.
        std::fs::write(
            root.join("go.mod"),
            "module example.com/silentzero\n\ngo 1.21\n",
        )
        .unwrap();
        std::fs::write(
            root.join("seed.go"),
            "package main\n\nfunc seed() int { return 1 }\n",
        )
        .unwrap();
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "seed"]);

        // A CLOSED PATH, built from nothing. Inheriting the real PATH minus a
        // directory is not an option: `git` and `go` can live in the same
        // directory, so the only way to prove the absence is to enumerate what
        // may be present.
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
        GoRepo { dir, root, bin }
    }

    /// Make `go` resolvable on the sandbox PATH: the CONTROL for the bead's
    /// A/B, and the reason these tests can prove the difference is the missing
    /// toolchain rather than the fixture.
    fn with_go(self) -> Self {
        let src = on_path("go").expect("this test machine has no `go`");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&src, self.bin.join("go")).unwrap();
        self
    }

    /// Point `RVL_GOINDEX` at an arbitrary script. Used to prove the rvl-layer
    /// guard fires on its own, with a "helper" that cannot possibly be exiting
    /// non-zero.
    fn with_goindex_stub(&self, body: &str) -> PathBuf {
        let stub = self.dir.path().join("goindex-stub");
        std::fs::write(&stub, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        stub
    }

    fn path(&self) -> std::ffi::OsString {
        self.bin.clone().into_os_string()
    }

    /// The empty spec file the direct-invocation tests pass explicitly. The
    /// installed hook gets it from the `rvl` shim on the sandbox PATH; a
    /// Command built here bypasses that shim, so it must say so itself.
    fn specs(&self) -> PathBuf {
        self.dir.path().join("specs.json")
    }

    fn install_hook(&self) {
        let out = self
            .rvl()
            .args(["hook", "install", "--pre-commit"])
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
        // A real goindex is found by env override rather than by PATH, so the
        // ONLY variable these tests change is whether the `go` TOOLCHAIN
        // resolves — not whether the retriever itself does.
        if let Some(g) = goindex_binary() {
            c.env("RVL_GOINDEX", g);
        }
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

    fn stage(&self, name: &str, body: &str) {
        std::fs::write(self.root.join(name), body).unwrap();
        git(&self.root, &["add", name]);
    }
}

/// Guard: the sandbox PATH must genuinely have no `go`, or every assertion
/// below passes for the wrong reason.
fn assert_no_go(f: &GoRepo) {
    assert!(
        !f.bin.join("go").exists(),
        "the fixture must not leak a Go toolchain onto the closed PATH"
    );
}

/// Skip-with-a-reason rather than pass silently: a test that quietly does
/// nothing when goindex is not built is exactly the kind of green-over-nothing
/// this bead is about.
fn require_goindex() -> bool {
    if goindex_binary().is_some() {
        return true;
    }
    eprintln!("SKIP: no goindex binary next to the rvl under test (build it with `make install`)");
    false
}

/// THE BEAD, end to end through the hook the product installs. Go is the
/// repo's only language, the `go` tool is absent so goindex can read nothing,
/// and the commit used to be sold as clean at exit 0.
#[test]
fn a_go_repo_without_the_go_toolchain_is_never_called_clean() {
    if !require_goindex() {
        return;
    }
    let f = GoRepo::new();
    assert_no_go(&f);
    f.install_hook();
    let before = f.head();
    f.stage("app.go", UNBOUNDED_GET);

    let out = f
        .git()
        .args(["commit", "-m", "feat: fetch"])
        .output()
        .unwrap();
    let all = combined(&out);

    // FAIL OPEN (ruled on .199): a broken toolchain is not the developer's
    // fault and must not block their commit.
    assert!(
        out.status.success(),
        "a toolchain we cannot run must not block a commit:\n{all}"
    );
    assert_ne!(f.head(), before, "the commit must actually exist");

    // ...but it must never be sold as a clean one.
    assert!(
        !all.contains("commit clean"),
        "THE BEAD: a scan that read no Go reported a clean commit:\n{all}"
    );
    assert!(
        all.contains("NOT CLEAN") && all.contains("nothing was scanned"),
        "the verdict line must state that nothing was scanned:\n{all}"
    );
    assert!(
        all.contains("INCOMPLETE"),
        "the coverage block must say the call-site lane never ran:\n{all}"
    );
    assert!(
        all.contains("Go"),
        "and must name the language that went unread:\n{all}"
    );
}

/// The control. The identical repo and file, with `go` resolvable, reaches a
/// real verdict — which is what makes the case above a bug rather than a repo
/// with nothing in it. The blocking finding is a content-lane secret (an empty
/// spec file cannot judge `http.Get`), so this pins "the gate still fires".
#[test]
fn the_same_commit_still_blocks_when_the_toolchain_works() {
    if !require_goindex() {
        return;
    }
    let f = GoRepo::new().with_go();
    f.install_hook();
    let before = f.head();
    f.stage("app.go", UNBOUNDED_GET);
    f.stage("keys.go", &planted_secret());

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

/// THE FALSE POSITIVE THE GUARD MUST NOT HAVE. A Go repo that genuinely
/// contains no client call sites is legitimate and common, and the retriever
/// answering "I loaded your code and there is nothing here" is a real answer,
/// not a silence. It must still read clean.
#[test]
fn a_go_repo_with_no_call_sites_at_all_still_reads_clean() {
    if !require_goindex() {
        return;
    }
    let f = GoRepo::new().with_go();
    f.install_hook();
    f.stage(
        "math.go",
        "package main\n\nfunc add(a, b int) int { return a + b }\n",
    );

    let out = f
        .git()
        .args(["commit", "-m", "feat: add"])
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "{all}");
    assert!(
        all.contains("commit clean"),
        "a language with no call sites is scanned, not degraded:\n{all}"
    );
    assert!(!all.contains("NOT CLEAN"), "{all}");
    assert!(!all.contains("INCOMPLETE"), "{all}");
}

/// `--strict` is CI's opt-in: a whole answer or none. It was the one mechanism
/// the bead explicitly reported as ALSO exiting 0, because the lane reported
/// success.
#[test]
fn strict_fails_closed_without_the_go_toolchain() {
    if !require_goindex() {
        return;
    }
    let f = GoRepo::new();
    assert_no_go(&f);
    f.stage("app.go", UNBOUNDED_GET);

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
    assert!(all.contains("--strict"), "{all}");
}

/// THE STRUCTURAL GUARD, ON ITS OWN. This helper EXITS 0 — so it cannot be
/// failing for the goindex fix — and emits nothing. rvl must still refuse to
/// call the lane scanned, because a helper contracted to write a repo-scoped
/// record on every successful run and writing none did not reach its own emit
/// path.
#[test]
fn a_helper_that_exits_zero_with_an_empty_stream_is_a_failed_lane() {
    let f = GoRepo::new();
    let stub = f.with_goindex_stub("#!/bin/sh\nexit 0\n");
    f.stage("app.go", UNBOUNDED_GET);

    let out = f
        .rvl()
        .env("RVL_GOINDEX", &stub)
        .args(["scan", ".", "--incremental", "--changed-only"])
        .arg("--specs-file")
        .arg(f.specs())
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(
        out.status.success(),
        "the guard is fail-open like every other degradation:\n{all}"
    );
    assert!(
        !all.contains("commit clean"),
        "a helper that emitted nothing has not scanned anything:\n{all}"
    );
    assert!(
        all.contains("NOT CLEAN") && all.contains("INCOMPLETE"),
        "{all}"
    );
    assert!(
        all.contains("no packets at all"),
        "the reason must say what the guard actually observed:\n{all}"
    );
}

/// The degenerate record the real bug emitted:
/// `{"kind":"","snapshot_id":"","constructions":null}`. It is a line of JSON,
/// so "did the helper print anything?" is not the question — an EMPTY `kind` is
/// a zero-valued record from a helper that bailed, and must not count as a
/// repo-scoped record.
#[test]
fn a_zero_valued_repo_record_does_not_count_as_having_scanned() {
    let f = GoRepo::new();
    let stub = f.with_goindex_stub(
        "#!/bin/sh\necho '{\"kind\":\"\",\"snapshot_id\":\"\",\"constructions\":null}'\nexit 0\n",
    );
    f.stage("app.go", UNBOUNDED_GET);

    let out = f
        .rvl()
        .env("RVL_GOINDEX", &stub)
        .args(["scan", ".", "--incremental", "--changed-only"])
        .arg("--specs-file")
        .arg(f.specs())
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "{all}");
    assert!(
        !all.contains("commit clean") && all.contains("NOT CLEAN"),
        "the exact record the bead reported must not read as a scan:\n{all}"
    );
}

/// The mirror image, and the second half of the false-positive question: a
/// helper that emitted its repo-scoped record and no sites HAS scanned. Zero
/// sites is a real answer.
#[test]
fn a_repo_record_with_no_sites_is_a_real_scan() {
    let f = GoRepo::new();
    let stub = f.with_goindex_stub(
        "#!/bin/sh\necho '{\"packet_schema\":2,\"kind\":\"repo_config\",\
         \"snapshot_id\":\"t\",\"constructions\":[]}'\nexit 0\n",
    );
    f.stage("app.go", UNBOUNDED_GET);

    let out = f
        .rvl()
        .env("RVL_GOINDEX", &stub)
        .args(["scan", ".", "--incremental", "--changed-only"])
        .arg("--specs-file")
        .arg(f.specs())
        .output()
        .unwrap();
    let all = combined(&out);
    assert!(out.status.success(), "{all}");
    assert!(
        all.contains("commit clean") && !all.contains("NOT CLEAN"),
        "a helper that ran and found nothing must not be called degraded:\n{all}"
    );
}

/// A DEGRADED LANGUAGE MUST NOT POISON THE INDEX. Without this, the fix is
/// hollow one run later: the first pass correctly renders NOT CLEAN, but the
/// changed files were written to the packet index as "scanned, zero packets",
/// so the second pass finds them unchanged, reuses the emptiness, never runs
/// the helper, never degrades, and prints a clean verdict over the same unread
/// code — a permanently green gate, which is the bead's own title.
#[test]
fn a_degraded_language_is_not_recorded_in_the_index_as_scanned() {
    let f = GoRepo::new();
    let stub = f.with_goindex_stub("#!/bin/sh\nexit 0\n");
    f.stage("app.go", UNBOUNDED_GET);

    let run = || {
        let out = f
            .rvl()
            .env("RVL_GOINDEX", &stub)
            .args(["scan", ".", "--incremental", "--changed-only"])
            .arg("--specs-file")
            .arg(f.specs())
            .output()
            .unwrap();
        combined(&out)
    };
    let first = run();
    assert!(first.contains("NOT CLEAN"), "first pass:\n{first}");
    let second = run();
    assert!(
        second.contains("NOT CLEAN") && !second.contains("commit clean"),
        "the SECOND pass over identical content must not go quiet:\n{second}"
    );
}
