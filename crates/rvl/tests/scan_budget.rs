//! A HUNG HELPER MUST NOT HANG THE SCAN.
//!
//! Helpers used to run through `Command::output()` with no timeout, so one
//! that never exited hung `rvl scan` and the CI job around it. These tests run
//! a stub retriever that starts a grandchild and then sleeps far past the
//! limit, and check the four things the limit promises: the scan ends near
//! the limit, the stub's whole process group is gone, COVERAGE says the
//! language is degraded, and `--strict` turns that into exit 1, the code for
//! "the scanner broke; your code was never judged".
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// Generous on purpose: the limit is what is under test, not how fast a
/// loaded CI machine runs the rest of the scan.
const MARGIN: Duration = Duration::from_secs(15);

struct Repo {
    dir: tempfile::TempDir,
    root: PathBuf,
    stub: PathBuf,
}

impl Repo {
    /// A Go-only repo whose retriever is a stub that records its own pid and
    /// a grandchild's, then waits on the grandchild for a minute.
    fn new() -> Repo {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("main.go"), "package main\n\nfunc main() {}\n").unwrap();
        std::fs::write(dir.path().join("specs.json"), r#"{"apis":[],"configs":[]}"#).unwrap();
        let stub = dir.path().join("goindex-stub");
        rvl_testgate::write_executable(
            &stub,
            &format!(
                "#!/bin/sh\necho $$ > {d}/leader\nsleep 60 &\necho $! > {d}/grandchild\nwait\n",
                d = dir.path().display()
            ),
        );
        Repo { dir, root, stub }
    }

    fn scan(&self, args: &[&str]) -> (Output, Duration) {
        let start = Instant::now();
        let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
            .current_dir(&self.root)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1")
            .env("RVL_GOINDEX", &self.stub)
            .args(["scan", "."])
            .arg("--specs-file")
            .arg(self.dir.path().join("specs.json"))
            .args(args)
            .output()
            .unwrap();
        (out, start.elapsed())
    }

    fn pid(&self, name: &str) -> i32 {
        let path = self.dir.path().join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("the stub never wrote {}: {e}", path.display()))
            .trim()
            .parse()
            .unwrap()
    }

    /// Neither the stub nor the grandchild it started survived the scan.
    fn assert_no_orphan(&self) {
        for name in ["leader", "grandchild"] {
            let pid = self.pid(name);
            assert!(gone(pid), "the stub's {name} (pid {pid}) outlived the scan");
        }
    }
}

/// Is `pid` gone? A killed orphan is a zombie until its new parent reaps it,
/// and a zombie runs nothing, so it counts as gone. Polled briefly: the
/// reparent and reap are not instant.
fn gone(pid: i32) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let ps = Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        let stat = String::from_utf8_lossy(&ps.stdout).trim().to_string();
        if stat.is_empty() || stat.starts_with('Z') {
            return true;
        }
        if Instant::now() > until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_degraded(all: &str, limit: &str) {
    assert!(
        all.contains("timed out") && all.contains(limit) && all.contains("degraded"),
        "COVERAGE must say the language timed out on {limit} and is degraded:\n{all}"
    );
    assert!(
        !all.contains("commit clean"),
        "a scan whose helper timed out read nothing and must not pass as clean:\n{all}"
    );
}

#[test]
fn a_helper_past_the_scan_budget_is_killed_and_the_scan_fails_open() {
    let r = Repo::new();
    let (out, took) = r.scan(&["--scan-budget", "2"]);
    let all = combined(&out);
    assert!(
        took < Duration::from_secs(2) + MARGIN,
        "took {took:?}:\n{all}"
    );
    assert_eq!(out.status.code(), Some(0), "fail-open by default:\n{all}");
    assert_degraded(&all, "--scan-budget");
    r.assert_no_orphan();
}

#[test]
fn strict_turns_a_timed_out_helper_into_exit_1() {
    let r = Repo::new();
    let (out, took) = r.scan(&["--scan-budget", "2", "--strict"]);
    let all = combined(&out);
    assert!(
        took < Duration::from_secs(2) + MARGIN,
        "took {took:?}:\n{all}"
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "--strict refuses a partial answer with the scanner-broke code, never the \
         blocked-findings code 3:\n{all}"
    );
    assert!(all.contains("timed out"), "{all}");
    r.assert_no_orphan();
}

#[test]
fn the_helper_timeout_bounds_one_helper_inside_a_larger_budget() {
    let r = Repo::new();
    let (out, took) = r.scan(&["--scan-budget", "10m", "--helper-timeout", "2s"]);
    let all = combined(&out);
    assert!(
        took < Duration::from_secs(2) + MARGIN,
        "took {took:?}:\n{all}"
    );
    assert_eq!(out.status.code(), Some(0), "{all}");
    assert_degraded(&all, "--helper-timeout");
    r.assert_no_orphan();
}

#[test]
fn the_budget_comes_from_the_repo_config_when_no_flag_is_given() {
    let r = Repo::new();
    std::fs::write(r.root.join(".revelara.yaml"), "scanner:\n  timeout: 2s\n").unwrap();
    let (out, took) = r.scan(&[]);
    let all = combined(&out);
    assert!(
        took < Duration::from_secs(2) + MARGIN,
        "took {took:?}:\n{all}"
    );
    assert_degraded(&all, "scan budget of 2s");
    r.assert_no_orphan();
}

#[test]
fn a_malformed_budget_is_a_usage_error() {
    let r = Repo::new();
    let (out, _) = r.scan(&["--scan-budget", "soon"]);
    assert_eq!(out.status.code(), Some(2), "{}", combined(&out));
    assert!(
        !Path::new(&r.dir.path().join("leader")).exists(),
        "nothing may run"
    );
}
