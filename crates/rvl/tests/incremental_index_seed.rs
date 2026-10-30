//! A FULL SCAN SEEDS THE INCREMENTAL INDEX, AND A COLD ONE BUILDS IT.
//!
//! `rvl scan --incremental --changed-only` is what the installed git hooks
//! run. On a large repository it reported nothing for two reasons. A full
//! scan never wrote the packet index, so the next warm pass found every file
//! stale. And the warm pass capped retrieval at 10 s, which a helper that
//! loads the whole program before filtering to `--files` spends on start-up
//! alone: the cap fired, nothing was indexed, and the next run started cold
//! again.
//!
//! The Go helper here is a stub that logs every invocation (`full`, or the
//! `--files` list) and emits one call site per Go file it was asked about.

use std::path::{Path, PathBuf};
use std::process::Command;

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

struct Repo {
    dir: tempfile::TempDir,
    root: PathBuf,
    log: PathBuf,
    stub: PathBuf,
    specs: PathBuf,
}

impl Repo {
    /// `files` Go files committed as the baseline. A run that asks for more
    /// than one file at once sleeps `stall` seconds first, the way a real
    /// helper spends its program load.
    fn new(files: usize, stall: u32) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(root.join("svc")).unwrap();
        std::fs::write(root.join("go.mod"), "module example.com/svc\n\ngo 1.22\n").unwrap();
        for i in 0..files {
            std::fs::write(
                root.join(format!("svc/f{i}.go")),
                format!("package svc\n\nfunc F{i}() {{}}\n"),
            )
            .unwrap();
        }
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "user.email", "t@example.com"]);
        git(&root, &["config", "user.name", "Test"]);
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "baseline"]);

        let log = dir.path().join("helper.log");
        let stub = dir.path().join("goindex-stub");
        rvl_testgate::write_executable(
            &stub,
            &format!(
                "#!/bin/sh\n\
                 root=. files=''\n\
                 while [ $# -gt 0 ]; do\n\
                 \x20 case \"$1\" in --root) root=\"$2\"; shift;; --files) files=\"$2\"; shift;; esac\n\
                 \x20 shift\n\
                 done\n\
                 cd \"$root\" || exit 1\n\
                 if [ -z \"$files\" ]; then\n\
                 \x20 echo full >> {log}\n\
                 \x20 list=$(find . -name '*.go' | sed 's|^\\./||')\n\
                 else\n\
                 \x20 echo \"$files\" >> {log}\n\
                 \x20 list=$(echo \"$files\" | tr , ' ')\n\
                 fi\n\
                 if [ \"$(echo $list | wc -w)\" -gt 1 ]; then sleep {stall}; fi\n\
                 for f in $list; do\n\
                 \x20 echo \"{{\\\"packet_schema\\\":2,\\\"site_key\\\":\\\"$f:3:net/http:Get\\\",\\\"snapshot_id\\\":\\\"stub\\\",\\\"file_path\\\":\\\"$f\\\",\\\"line_number\\\":3,\\\"func\\\":\\\"Get\\\",\\\"client_type\\\":\\\"net/http\\\",\\\"lang\\\":\\\"go\\\"}}\"\n\
                 done\n\
                 echo '{{\"packet_schema\":2,\"kind\":\"repo_config\",\"snapshot_id\":\"stub\",\"constructions\":[]}}'\n",
                log = log.display(),
            ),
        );
        let specs = dir.path().join("specs.json");
        std::fs::write(&specs, r#"{"apis":[],"configs":[]}"#).unwrap();
        Repo {
            dir,
            root,
            log,
            stub,
            specs,
        }
    }

    fn scan(&self, args: &[&str]) -> (std::process::Output, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
            .current_dir(&self.root)
            .args(["scan", "."])
            .args(args)
            .arg("--specs-file")
            .arg(&self.specs)
            .env("RVL_GOINDEX", &self.stub)
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1")
            .env_remove("RVL_BASE_REF")
            .env_remove("GITHUB_BASE_REF")
            .env_remove("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
            .output()
            .expect("run rvl");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out, all)
    }

    /// The helper invocations since the last call, and forget them.
    fn calls(&self) -> Vec<String> {
        let v = std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect();
        let _ = std::fs::remove_file(&self.log);
        v
    }
}

/// THE REPORT'S SEQUENCE. A full scan, then the hook's command over a range
/// whose files the full scan read: the warm pass reuses the seeded packets,
/// asks the helper for nothing, and reports the changed file's site.
#[test]
fn a_full_scan_seeds_the_index_the_changed_only_scan_reuses() {
    let repo = Repo::new(50, 0);
    std::fs::write(
        repo.root.join("svc/f7.go"),
        "package svc\n\nfunc F7() { _ = 7 }\n",
    )
    .unwrap();
    git(&repo.root, &["commit", "-qam", "change f7"]);

    let (out, all) = repo.scan(&[]);
    assert!(out.status.success(), "{all}");
    assert_eq!(repo.calls(), vec!["full"], "{all}");
    assert!(all.contains("packet index: seeded 50 file(s)"), "{all}");

    let (out, all) = repo.scan(&["--incremental", "--changed-only", "--base", "HEAD~1"]);
    assert!(out.status.success(), "{all}");
    assert!(
        repo.calls().is_empty(),
        "the seeded index answers for the changed file:\n{all}"
    );
    assert!(all.contains("reused 1 files from index"), "{all}");
    assert!(
        all.contains("0/1 API surfaces resolved"),
        "the changed file's site is reported:\n{all}"
    );
    assert!(!all.contains("0 code sites scanned"), "{all}");
}

/// A COLD INDEX IS BUILT, NOT CAPPED. The stub takes 11 s for a whole-tree
/// request, past the 10 s cap this pass used to apply, so the old pass failed
/// open with nothing indexed. Now the first unscoped warm pass reads it all
/// and the second reads nothing.
#[test]
fn a_cold_incremental_scan_builds_the_index_past_the_old_cap() {
    let repo = Repo::new(20, 11);
    let (out, all) = repo.scan(&["--incremental"]);
    assert!(out.status.success(), "{all}");
    assert!(!all.contains("retrieval capped"), "{all}");
    assert!(all.contains("re-parsed 20 stale"), "{all}");
    assert!(all.contains("0/20 API surfaces resolved"), "{all}");
    assert_eq!(repo.calls().len(), 1);

    let (out, all) = repo.scan(&["--incremental"]);
    assert!(out.status.success(), "{all}");
    assert!(
        all.contains("reused 20 files from index, re-parsed 0 stale"),
        "{all}"
    );
    assert!(
        repo.calls().is_empty(),
        "a warm index reads nothing:\n{all}"
    );
}
