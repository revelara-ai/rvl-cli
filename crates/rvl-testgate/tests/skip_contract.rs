//! The repository half of the skip rule (po-av01j.99).
//!
//! `rvl_testgate::skip` can only turn a skip into a failure if every skip
//! goes through it, and that failure only means a lane ran if CI both sets
//! the switch and provisions the engine. Each half is held here, because each
//! one alone still reads green: CI once built `cindex` "so the C/C++ lane
//! cannot skip" on runners that had no libclang to load.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest: PathBuf = std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into();
    manifest
        .parent()
        .and_then(Path::parent)
        .expect("crates/rvl-testgate sits two levels under the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under `dir`, leaving out fixture trees and build output.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(
                name.as_ref(),
                "target" | "testdata" | "fixtures" | "node_modules"
            ) {
                rust_sources(&path, out);
            }
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// A test that announces a skip in its own words bypasses the switch. The
/// needles are the spellings the suite has used; they are assembled here so
/// this file does not match itself.
#[test]
fn no_test_prints_its_own_skip_line() {
    let root = workspace_root();
    let needles = [
        format!("{}SKIP", '"'),
        format!("{}skipping:", '"'),
        format!("{}skip:", '"'),
    ];
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    assert!(
        files.len() > 50,
        "the walk found only {} files",
        files.len()
    );

    let mut offenders = Vec::new();
    for file in files {
        if file.starts_with(root.join("crates").join("rvl-testgate")) {
            continue;
        }
        let text = std::fs::read_to_string(&file).unwrap();
        for (i, line) in text.lines().enumerate() {
            if needles.iter().any(|n| line.contains(n.as_str())) {
                offenders.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&root).unwrap().display(),
                    i + 1,
                    line.trim()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these print their own skip line; call rvl_testgate::skip instead, so the skip \
         fails under RVLSCAN_REQUIRE_ENGINES:\n{}",
        offenders.join("\n")
    );
}

fn ci_workflow() -> String {
    std::fs::read_to_string(workspace_root().join(".github/workflows/ci.yml")).unwrap()
}

/// The text of one top-level job of ci.yml: from its `  <id>:` line to the
/// next line at the same indentation.
fn job(workflow: &str, id: &str) -> String {
    let head = format!("  {id}:");
    let mut body = Vec::new();
    let mut inside = false;
    for line in workflow.lines() {
        if line == head {
            inside = true;
            continue;
        }
        let is_job_head = line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#');
        if inside && is_job_head {
            break;
        }
        if inside {
            body.push(line);
        }
    }
    assert!(!body.is_empty(), "ci.yml has no `{id}` job");
    body.join("\n")
}

#[test]
fn ci_exports_the_require_engines_switch_to_every_job() {
    let workflow = ci_workflow();
    let jobs_at = workflow.find("\njobs:").expect("ci.yml has a jobs: key");
    let env_at = workflow
        .find("\nenv:")
        .expect("ci.yml has a workflow-level env:");
    assert!(
        env_at < jobs_at,
        "the env: block must be the workflow-level one"
    );
    assert!(
        workflow[env_at..jobs_at]
            .contains(&format!("  {}: \"1\"", rvl_testgate::REQUIRE_ENGINES_ENV)),
        "ci.yml must export {}=1 at workflow level, so every job's tests fail instead of skipping",
        rvl_testgate::REQUIRE_ENGINES_ENV
    );
}

/// The switch only reports a missing engine. These are the steps that make
/// the engines present in the job that runs `cargo test --workspace`; drop
/// one and the suite fails there, which is the point, but this names the
/// cause before a runner has to.
#[test]
fn the_check_job_provisions_every_engine_before_it_tests() {
    let check = job(&ci_workflow(), "check");
    let test_at = check
        .find("run: cargo test --workspace")
        .expect("the check job runs the workspace tests");
    let before_tests = &check[..test_at];
    for (engine, step) in [
        ("libclang (C/C++)", "ci/fetch-libclang.sh"),
        ("libclang loads", "cindex --engine-check"),
        ("typescript (tsindex)", "npm ci"),
        ("node", "actions/setup-node@"),
        ("the Go toolchain", "actions/setup-go@"),
        ("a JDK", "actions/setup-java@"),
        ("rust-analyzer", "rust-analyzer"),
        (".NET SDK", "actions/setup-dotnet@"),
    ] {
        assert!(
            before_tests.contains(step),
            "the check job must provision {engine} (`{step}`) before `cargo test --workspace`"
        );
    }
}
