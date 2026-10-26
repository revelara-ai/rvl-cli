//! THE PRE-COMMIT GATE RETRIEVES THE COMMIT, NOT THE INDEX'S DRIFT.
//!
//! `rvl scan . --incremental --changed-only --hook pre-commit` resolved its
//! changed set from the git index (the staged files) but RETRIEVED every file
//! whose content hash differed from the packet index, filtering to the staged
//! set only afterwards. In a long-lived checkout whose index was last warmed
//! thousands of files ago, a 3-file commit asked the helpers for all of them,
//! hit the 10 s retrieval cap, and failed open having scanned nothing:
//!
//!   incremental: degraded (fail-open): retrieval capped at 10s: 2424 changed
//!   file(s) not re-scanned; results cover the reused portion only
//!
//! These tests stand up that checkout: thousands of committed Go files and an
//! index that has never seen them, so every one is stale. The Go helper is a
//! stub that records the files it was asked for, and stalls past the cap when
//! asked for more than the commit, the way a real helper does on a large set.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The baseline: committed files the index has never seen.
const BASELINE_FILES: usize = 3000;

/// The commit: three files, as in the report this pins.
const STAGED: [&str; 3] = ["svc/change/a.go", "svc/change/b.go", "svc/change/c.go"];

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

struct Checkout {
    dir: tempfile::TempDir,
    root: PathBuf,
    helper_log: PathBuf,
    stub: PathBuf,
    specs: PathBuf,
}

impl Checkout {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        for i in 0..BASELINE_FILES {
            let pkg = root.join(format!("pkg{:03}", i / 100));
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join(format!("f{i}.go")),
                format!("package pkg\n\nfunc F{i}() int {{ return {i} }}\n"),
            )
            .unwrap();
        }
        std::fs::create_dir_all(root.join("svc/change")).unwrap();
        for f in STAGED {
            std::fs::write(root.join(f), "package change\n").unwrap();
        }
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "baseline"]);

        // The stub Go helper: log the requested files, one per line, then
        // answer with the repo-scoped record every real helper writes. Asked
        // for more than the commit, it stalls past the 10 s cap.
        let helper_log = dir.path().join("helper.log");
        let stub = dir.path().join("goindex-stub");
        rvl_testgate::write_executable(
            &stub,
            &format!(
                "#!/bin/sh\n\
                 files=''\n\
                 while [ $# -gt 0 ]; do\n\
                 \x20 if [ \"$1\" = --files ]; then files=\"$2\"; shift; fi\n\
                 \x20 shift\n\
                 done\n\
                 echo \"$files\" | tr , '\\n' >> {log}\n\
                 n=$(echo \"$files\" | tr , '\\n' | grep -c .)\n\
                 if [ \"$n\" -gt {staged} ]; then sleep 30; fi\n\
                 echo '{{\"packet_schema\":2,\"kind\":\"repo_config\",\"snapshot_id\":\"stub\",\"constructions\":[]}}'\n",
                log = helper_log.display(),
                staged = STAGED.len(),
            ),
        );
        let specs = dir.path().join("specs.json");
        std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
        Checkout {
            dir,
            root,
            helper_log,
            stub,
            specs,
        }
    }

    fn scan(&self, extra: &[&str]) -> (std::process::Output, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
            .current_dir(&self.root)
            .args(["scan", ".", "--incremental"])
            .args(extra)
            .arg("--specs-file")
            .arg(&self.specs)
            .env("RVL_GOINDEX", &self.stub)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1")
            .output()
            .expect("run rvl");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out, all)
    }

    /// Every file the helper was asked to retrieve, sorted.
    fn retrieved(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_to_string(&self.helper_log)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        v.sort();
        v
    }
}

/// THE REPORT. A 3-file commit over a baseline thousands of files stale
/// retrieves exactly the staged files, inside the cap, and says so.
#[test]
fn a_three_file_commit_over_a_stale_index_retrieves_only_the_staged_files() {
    let co = Checkout::new();
    for f in STAGED {
        std::fs::write(co.root.join(f), "package change\n\nfunc Changed() {}\n").unwrap();
        git(&co.root, &["add", f]);
    }
    // Drift the commit does not carry: an unstaged edit to a committed file.
    // It is changed in the working tree and stale in the index, and it is
    // still not what is being committed.
    std::fs::write(co.root.join("pkg000/f0.go"), "package pkg\n\nfunc G() {}\n").unwrap();

    let started = std::time::Instant::now();
    let (out, all) = co.scan(&["--changed-only", "--hook", "pre-commit"]);
    let took = started.elapsed();

    assert!(out.status.success(), "{all}");
    assert_eq!(
        co.retrieved(),
        STAGED.to_vec(),
        "the changed set is the staged files, never the index's drift:\n{all}"
    );
    assert!(
        !all.contains("retrieval capped"),
        "three files must fit the cap:\n{all}"
    );
    assert!(
        !all.contains("nothing was scanned"),
        "the staged files were scanned:\n{all}"
    );
    assert!(all.contains("re-parsed 3 stale"), "{all}");
    assert!(
        all.contains("changed set: 3 file(s)"),
        "the scope line names the staged set:\n{all}"
    );
    assert!(
        took < std::time::Duration::from_secs(10),
        "the scan took {took:?}, past the retrieval cap"
    );
}

/// An unscoped incremental scan still re-parses everything stale: scoping is a
/// property of `--changed-only`, not a new limit on the warm pass. The stub
/// stalls on the large request, so this also pins that fail-open on the cap is
/// unchanged.
#[test]
fn an_unscoped_incremental_scan_still_retrieves_every_stale_file() {
    let co = Checkout::new();
    let (out, all) = co.scan(&[]);
    assert!(out.status.success(), "the cap still fails open:\n{all}");
    // The stalled batch is killed at the cap, so later batches may never be
    // asked for; the baseline showing up at all is the point.
    assert!(
        co.retrieved().iter().any(|f| f.starts_with("pkg")),
        "an unscoped pass asks for the stale baseline:\n{all}"
    );
    // Two clocks enforce the same 10 s cap and either may fire first: the
    // pass's wall budget ("retrieval capped") or the helper's own deadline,
    // which kills the stub and degrades Go. Both fail open on the cap.
    assert!(
        all.contains("retrieval capped at 10s")
            || all.contains("the incremental retrieval budget of 10s ran out"),
        "the cap fails open:\n{all}"
    );
}
