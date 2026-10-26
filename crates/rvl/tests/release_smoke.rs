//! EVERY RELEASE ARCHIVE IS RUN BEFORE IT IS PUBLISHED.
//!
//! The release builds each archive on its own runner, and before this nothing
//! ran one: an archive whose `rvl` did not start, or whose goindex or libclang
//! was missing or built for the wrong target, was uploaded all the same. Now
//! `.github/workflows/smoke.yml` unpacks each archive on the runner it was
//! built on and runs `ci/smoke-archive.sh` against it, and `host` waits for it.
//!
//! Nothing here can run a release, so the wiring is held to its contract and
//! the script is run against a fake archive:
//!
//!   * dist-workspace.toml declares the smoke job where `host` waits for it,
//!     and the generated release.yml really does;
//!   * smoke.yml takes its matrix from the plan, so every built target is
//!     smoked on its own runner;
//!   * `ci/smoke-archive.sh` passes an archive whose scan decided every lane
//!     with the archive's own helpers, and fails each way one can fall short.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate directory, read at run time. `cargo test` sets CARGO_MANIFEST_DIR
/// for every test process; a binary reused from a shared CARGO_TARGET_DIR still
/// carries the compile-time path of whichever checkout built it, which may be gone.
fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

fn repo_root() -> PathBuf {
    manifest_dir().join("../..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of `text` that are not YAML/TOML comments, so a key that is only
/// mentioned in a comment does not satisfy a check.
fn live_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// The body of the top-level-in-`jobs` job `name` in a workflow: every line
/// after its `  name:` header up to the next job header.
fn job_body<'a>(workflow: &'a str, name: &str) -> Vec<&'a str> {
    let header = format!("  {name}:");
    let is_job_header =
        |l: &str| l.starts_with("  ") && !l.starts_with("   ") && !l.trim_start().starts_with('#');
    workflow
        .lines()
        .skip_while(|l| l.trim_end() != header)
        .skip(1)
        .take_while(|l| !is_job_header(l))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn dist_config_runs_the_smoke_job_after_the_builds() {
    let toml = read("dist-workspace.toml");
    let live = live_lines(&toml);
    assert!(
        live.contains(&r#"global-artifacts-jobs = ["./smoke"]"#),
        "dist-workspace.toml must run ./smoke as a global-artifacts job"
    );
    assert!(
        live.iter()
            .any(|l| l.starts_with("github-custom-job-permissions")
                && l.contains(r#""smoke" = { contents = "read" }"#)),
        "the smoke job needs contents:read to check out its script and fixture"
    );
}

#[test]
fn generated_release_workflow_holds_the_release_on_the_smoke_job() {
    let release = read(".github/workflows/release.yml");
    let job = job_body(&release, "custom-smoke");
    for line in [
        "uses: ./.github/workflows/smoke.yml",
        "- build-local-artifacts",
        r#""contents": "read""#,
    ] {
        assert!(
            job.contains(&line),
            "release.yml is stale: regenerate it with `dist generate`. Missing {line:?} in {job:?}"
        );
    }

    // `host` runs under always(), so needing the job is not enough: its `if:`
    // must also refuse a failed smoke, or a broken archive is still uploaded.
    let host = job_body(&release, "host");
    assert!(
        host.contains(&"- custom-smoke"),
        "host must need custom-smoke: {host:?}"
    );
    assert!(
        host.iter().any(|l| l.starts_with("if:")
            && l.contains("(needs.custom-smoke.result == 'skipped' || needs.custom-smoke.result == 'success')")),
        "host must not run when the smoke job failed: {host:?}"
    );
}

#[test]
fn smoke_workflow_runs_every_built_target_on_its_own_runner() {
    let workflow = read(".github/workflows/smoke.yml");
    let live = live_lines(&workflow);
    for line in [
        "workflow_call:",
        "matrix: ${{ fromJson(inputs.plan).ci.github.artifacts_matrix }}",
        "runs-on: ${{ matrix.runner }}",
        "fail-fast: false",
        "name: artifacts-build-local-${{ join(matrix.targets, '_') }}",
    ] {
        assert!(live.contains(&line), "smoke.yml must have {line:?}");
    }
    assert!(
        live.iter().any(|l| l.contains("ci/smoke-archive.sh")),
        "smoke.yml must run ci/smoke-archive.sh"
    );
}

const TOP: &str = "rvl-x86_64-unknown-linux-gnu";

/// A stand-in `rvl` for the smoke script. `--version` prints 1.6.0, and `scan`
/// writes an `--out` document of a scan that decided every lane of the
/// fixture with the archive's helpers. Each `FAKE_*` variable breaks one part
/// of that. It also fails if a helper override reached it.
const FAKE_RVL: &str = r#"#!/usr/bin/env bash
here=$(cd "$(dirname "$0")" && pwd)
if [ "$1" = "--version" ]; then echo "rvl 1.6.0"; exit 0; fi
for a in "$@"; do [ "$prev" = "--out" ] && out=$a; prev=$a; done
if [ -n "${RVL_GOINDEX:-}" ]; then echo "RVL_GOINDEX reached the scan" >&2; exit 1; fi
cat > "$out" <<J
{"exit": 3,
 "sites": [
  {"site_id": "main.go:13:net/http.Client:Do", "verdict": "violates"},
  {"site_id": "svc.py:5:requests:get", "verdict": "violates"},
  {"site_id": "src/fetch.c:9:libcurl.CURL:curl_easy_perform", "verdict": "${FAKE_C_VERDICT:-violates}"}],
 "coverage": {
  "degraded": [],
  "lang_status": [
   {"lang": "Go", "state": "scanned", "detail": "1"},
   {"lang": "Python", "state": "${FAKE_PY_STATE:-scanned}", "detail": "1"},
   {"lang": "C/C++", "state": "scanned", "detail": "2"}],
  "retrievers": [
   {"lang": "Go", "path": "${FAKE_GO_PATH:-$here/goindex}", "source": "bundled"},
   {"lang": "Python", "path": "/home/u/.revelara/helpers/1.6.0/pyindex.py", "source": "embedded"},
   {"lang": "C/C++", "path": "$here/cindex", "source": "${FAKE_C_SOURCE:-bundled}"}]}}
J
exit "${FAKE_EXIT:-3}"
"#;

/// A `rvl-<triple>.tar.xz` laid out as dist packs one, holding [`FAKE_RVL`]
/// and, when `runtime`, an `onnxruntime/` bundle.
fn fake_archive(dir: &Path, runtime: bool) -> PathBuf {
    let staged = dir.join(TOP);
    std::fs::create_dir_all(&staged).unwrap();
    if runtime {
        let bundle = staged.join("onnxruntime");
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join("libonnxruntime.so"), "ELF-ish").unwrap();
        std::fs::write(bundle.join("LICENSE"), "MIT License\n").unwrap();
    }
    let rvl = staged.join("rvl");
    std::fs::write(&rvl, FAKE_RVL).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&rvl, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let archive = dir.join(format!("{TOP}.tar.xz"));
    let out = Command::new("tar")
        .arg("-cJf")
        .arg(&archive)
        .arg("-C")
        .arg(dir)
        .arg(TOP)
        .output()
        .expect("run tar");
    assert!(
        out.status.success(),
        "tar: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    archive
}

fn smoke(version: &str, env: &[(&str, &str)]) -> std::process::Output {
    smoke_archive(version, env, true)
}

fn smoke_archive(version: &str, env: &[(&str, &str)], runtime: bool) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let archive = fake_archive(dir.path(), runtime);
    let mut cmd = Command::new("bash");
    cmd.arg(repo_root().join("ci/smoke-archive.sh"))
        .arg(&archive)
        .arg(version)
        .env("TMPDIR", dir.path())
        .env_remove("RUNNER_TEMP")
        // The script must unset it before the scan; the fake fails if it does not.
        .env("RVL_GOINDEX", "/elsewhere/goindex");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run ci/smoke-archive.sh")
}

fn assert_fails(out: &std::process::Output, why: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the smoke must fail: {why}");
    assert!(stderr.contains(why), "stderr must say {why:?}: {stderr}");
}

#[test]
fn smoke_passes_an_archive_that_runs_and_scans_every_lane() {
    let out = smoke("1.6.0", &[]);
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("ok: rvl 1.6.0"));
}

#[test]
fn smoke_passes_a_clean_scan() {
    let out = smoke("1.6.0", &[("FAKE_EXIT", "0")]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn smoke_fails_on_an_archive_without_the_onnx_runtime() {
    assert_fails(
        &smoke_archive("1.6.0", &[], false),
        "does not carry one ONNX Runtime library",
    );
}

#[test]
fn smoke_fails_on_another_version() {
    assert_fails(&smoke("1.7.0", &[]), "expected 'rvl 1.7.0'");
}

#[test]
fn smoke_fails_when_the_scanner_errors() {
    assert_fails(&smoke("1.6.0", &[("FAKE_EXIT", "1")]), "rvl scan exited 1");
}

#[test]
fn smoke_fails_on_a_lane_that_did_not_scan() {
    assert_fails(
        &smoke("1.6.0", &[("FAKE_PY_STATE", "not_installed")]),
        "python: not_installed",
    );
}

#[test]
fn smoke_fails_on_a_helper_from_outside_the_archive() {
    assert_fails(
        &smoke("1.6.0", &[("FAKE_C_SOURCE", "PATH")]),
        "c/c++: helper came from PATH",
    );
    assert_fails(
        &smoke("1.6.0", &[("FAKE_GO_PATH", "/usr/local/bin/goindex")]),
        "go: helper /usr/local/bin/goindex is not the one in the archive",
    );
}

#[test]
fn smoke_fails_on_a_lane_that_decided_nothing() {
    assert_fails(
        &smoke("1.6.0", &[("FAKE_C_VERDICT", "abstain")]),
        "c/c++: no violates site in src/fetch.c",
    );
}
