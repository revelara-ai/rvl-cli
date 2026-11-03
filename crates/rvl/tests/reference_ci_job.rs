//! THE REFERENCE CI JOB RUNS. docs/examples/rvl-gate.yml is the job users
//! copy, so it is tested as a job, not only read.
//!
//! [`the_reference_job_has_the_on_ramp_steps`] runs on every `cargo test`:
//! the job installs a pinned release archive and checks its .sha256, keeps
//! the spec cache between runs, syncs, then gates.
//!
//! [`the_reference_job_runs_on_a_fixture`] runs the job's `run:` steps in
//! order, the way a runner would, on a git copy of ci/smoke/repo (Go, C and
//! Python, so goindex, cindex and its libclang are all exercised). The
//! rvl-gate workflow runs it; it needs the network, for the release download
//! and for `rvl sync`. What it emulates of a runner:
//!
//!   * `uses:` steps are skipped (checkout is the fixture copy, and the cache
//!     step's path is checked to be where the sync wrote);
//!   * the job's and each step's `env:` apply, and an `${{ }}` value is empty:
//!     no secret, no event payload, so the scan runs on the OSS tier;
//!   * `$GITHUB_PATH` lines prepend to PATH for later steps, as on a runner;
//!   * each step runs as `bash --noprofile --norc -eo pipefail`, the runner's
//!     default shell, in the repository, with HOME and RUNNER_TEMP scratch.
//!
//! [`RVL_DIR_ENV`] names a directory holding a build of rvl and its helpers.
//! When set, the `install` step is skipped and that directory goes on PATH
//! instead: a pull request tests its own build. Unset, the step downloads the
//! release archive. [`VERSION_ENV`] replaces the job's `RVL_VERSION`, so a
//! run after a release installs that release.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A directory with rvl and its helpers, used in place of the install step.
const RVL_DIR_ENV: &str = "RVL_REFERENCE_JOB_RVL_DIR";
/// A release tag that replaces the job's `RVL_VERSION`.
const VERSION_ENV: &str = "RVL_REFERENCE_JOB_VERSION";

/// The step ids the on-ramp needs, in the order it needs them.
const STEP_IDS: &[&str] = &["install", "sync", "gate", "coverage"];

fn workspace_root() -> PathBuf {
    PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into()),
    )
    .join("../..")
}

/// The `rvl-gate` job of docs/examples/rvl-gate.yml.
fn job() -> serde_yaml::Value {
    let path = workspace_root().join("docs/examples/rvl-gate.yml");
    let text = std::fs::read_to_string(&path).expect("docs/examples/rvl-gate.yml must exist");
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("the reference job parses");
    doc["jobs"]["rvl-gate"].clone()
}

fn steps(job: &serde_yaml::Value) -> Vec<serde_yaml::Value> {
    job["steps"]
        .as_sequence()
        .expect("the job has steps")
        .clone()
}

fn step_id(step: &serde_yaml::Value) -> Option<&str> {
    step["id"].as_str()
}

fn run_text(step: &serde_yaml::Value) -> &str {
    step["run"].as_str().unwrap_or_default()
}

/// A mapping of `env:` as strings, an `${{ }}` expression as empty.
fn env_of(v: &serde_yaml::Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in v.as_mapping().into_iter().flatten() {
        let k = k.as_str().unwrap_or_default().to_string();
        let v = match v {
            serde_yaml::Value::String(s) if s.contains("${{") => String::new(),
            serde_yaml::Value::String(s) => s.clone(),
            other => serde_yaml::to_string(other).unwrap().trim().to_string(),
        };
        out.insert(k, v);
    }
    out
}

#[test]
fn the_reference_job_has_the_on_ramp_steps() {
    let job = job();
    let steps = steps(&job);

    let version = env_of(&job["env"])
        .remove("RVL_VERSION")
        .unwrap_or_default();
    let parts: Vec<&str> = version.strip_prefix('v').unwrap_or("").split('.').collect();
    assert!(
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "the job pins one release in its RVL_VERSION, as vX.Y.Z: {version:?}"
    );

    let ids: Vec<&str> = steps.iter().filter_map(step_id).collect();
    let ordered: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| STEP_IDS.contains(id))
        .collect();
    assert_eq!(ordered, STEP_IDS, "the on-ramp steps, in order: {ids:?}");

    let install = steps
        .iter()
        .find(|s| step_id(s) == Some("install"))
        .unwrap();
    let install = run_text(install);
    for needle in [
        "releases/download/$RVL_VERSION",
        "rvl-x86_64-unknown-linux-gnu.tar.xz",
        ".sha256",
        "sha256sum -c",
        "GITHUB_PATH",
    ] {
        assert!(
            install.contains(needle),
            "the install step must use {needle}: {install}"
        );
    }
    let piped_to_shell = install.split('|').skip(1).any(|rest| {
        let cmd = rest.split_whitespace().next().unwrap_or_default();
        matches!(cmd, "sh" | "bash" | "zsh")
    });
    assert!(!piped_to_shell, "no curl-pipe-shell: {install}");

    // The cache step comes before the sync and saves rvl's default cache.
    let at = |pred: &dyn Fn(&serde_yaml::Value) -> bool| steps.iter().position(pred);
    let cache = at(&|s| {
        s["uses"]
            .as_str()
            .is_some_and(|u| u.starts_with("actions/cache@"))
    })
    .expect("the job caches the spec cache");
    let sync = at(&|s| step_id(s) == Some("sync")).unwrap();
    assert!(cache < sync, "the cache is restored before the sync");
    assert_eq!(
        steps[cache]["with"]["path"].as_str(),
        Some("~/.revelara/cache/specs"),
        "the cache step saves the directory rvl syncs into by default"
    );
    assert!(run_text(&steps[sync]).contains("rvl sync"));

    // Untrusted input stays out of shell text: an expression goes through env.
    for s in &steps {
        assert!(
            !run_text(s).contains("${{"),
            "no expression in a run block: {s:?}"
        );
    }
}

fn git(repo: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .args([
            "-c",
            "user.name=rvl",
            "-c",
            "user.email=rvl@example.invalid",
        ])
        .args(args)
        .current_dir(repo)
        .status()
        .expect("running git");
    assert!(ok.success(), "git {args:?}");
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

/// ci/smoke/repo as a pull request: `main` holds the fixture, and the
/// checked-out branch adds one more unbounded Python call on top.
fn fixture_pr(work: &Path) -> PathBuf {
    let repo = work.join("repo");
    copy_dir(&workspace_root().join("ci/smoke/repo"), &repo);
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "base"]);
    git(&repo, &["checkout", "-qb", "change"]);
    let svc = repo.join("svc.py");
    let mut text = std::fs::read_to_string(&svc).unwrap();
    text.push_str("\n\ndef fetch_again(url):\n    return requests.get(url)\n");
    std::fs::write(&svc, text).unwrap();
    git(&repo, &["commit", "-qam", "change"]);
    repo
}

#[test]
#[ignore = "needs the network; the rvl-gate workflow runs it"]
fn the_reference_job_runs_on_a_fixture() {
    let job = job();
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path();
    let repo = fixture_pr(work);
    let home = work.join("home");
    let runner_temp = work.join("runner-temp");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&runner_temp).unwrap();
    let github_path = work.join("github-path");
    std::fs::write(&github_path, "").unwrap();

    let mut job_env = env_of(&job["env"]);
    if let Ok(v) = std::env::var(VERSION_ENV) {
        if !v.trim().is_empty() {
            job_env.insert("RVL_VERSION".into(), v.trim().to_string());
        }
    }
    let local_build = std::env::var_os(RVL_DIR_ENV).filter(|v| !v.is_empty());
    let mut path_dirs: Vec<PathBuf> = Vec::new();
    if let Some(d) = &local_build {
        path_dirs.push(PathBuf::from(d));
    }
    let base_path = std::env::var_os("PATH").unwrap_or_default();

    for step in steps(&job) {
        let label = step["name"]
            .as_str()
            .or(step["uses"].as_str())
            .unwrap_or("step")
            .to_string();
        if step["uses"].is_string() {
            eprintln!("skip (uses:): {label}");
            continue;
        }
        if local_build.is_some() && step_id(&step) == Some("install") {
            eprintln!("skip (the local build is on PATH): {label}");
            continue;
        }
        eprintln!("run: {label}");
        let mut cmd = Command::new("bash");
        cmd.args(["--noprofile", "--norc", "-eo", "pipefail", "-c"])
            .arg(run_text(&step))
            .current_dir(&repo);
        // Nothing from the machine running the test may choose a helper, a
        // cache or a base ref for the job.
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("RVL_") || k.starts_with("GITHUB_") || k == "LIBCLANG_PATH" {
                cmd.env_remove(&k);
            }
        }
        let mut path = std::env::split_paths(&base_path).collect::<Vec<_>>();
        let mut added: Vec<PathBuf> = std::fs::read_to_string(&github_path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(PathBuf::from)
            .collect();
        added.reverse();
        added.extend(path_dirs.iter().cloned());
        path.splice(0..0, added);
        cmd.env("PATH", std::env::join_paths(path).unwrap())
            .env("HOME", &home)
            .env("RUNNER_TEMP", &runner_temp)
            .env("GITHUB_PATH", &github_path)
            .env("GITHUB_BASE_REF", "main")
            .env("CI", "true")
            .envs(&job_env)
            .envs(env_of(&step["env"]));
        let status = cmd.status().expect("running bash");
        assert!(status.success(), "step `{label}` failed: {status}");
    }

    assert!(
        home.join(".revelara/cache/specs/oss/current/specs.json")
            .is_file(),
        "the sync must have installed the OSS tier where the cache step saves"
    );
    // Every helper the scan used sat beside the rvl it ran, so the archive
    // (or the build standing in for it) carries what each lane needs.
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(repo.join("findings.json")).unwrap()).unwrap();
    let retrievers = doc["coverage"]["retrievers"].as_array().unwrap();
    for lang in ["go", "c/c++"] {
        let r = retrievers
            .iter()
            .find(|r| {
                r["lang"]
                    .as_str()
                    .is_some_and(|l| l.eq_ignore_ascii_case(lang))
            })
            .unwrap_or_else(|| panic!("no {lang} retriever row: {retrievers:?}"));
        assert_eq!(r["source"], "bundled", "{lang}: {r}");
    }
}
