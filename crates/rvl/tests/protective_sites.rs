//! PROTECTIVE SITES REACH `--out`.
//!
//! A rate limiter's decision is retrieved by the goindex built from THIS
//! tree and reported in the scan document as `protective_sites`, one row per
//! call, with the function that holds the refusal branch. The rows are
//! retrieval output for the fleet: no finding, no verdict, no eval row. The
//! fixture is goindex's own (`helpers/goindex/testdata/protectivefixture`),
//! with an offline stub of `golang.org/x/time/rate`, so the scan needs no
//! network.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate directory, read at run time (see http_client_whole_call.rs).
fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

/// goindex built from this tree, or `None` (with the reason printed) when
/// there is no usable Go toolchain. A build failure is fatal under CI.
fn goindex_binary(dir: &Path) -> Option<PathBuf> {
    let src = manifest_dir().join("../../helpers/goindex");
    let bin = dir.join("goindex");
    match Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(".")
        .current_dir(&src)
        .output()
    {
        Ok(out) if out.status.success() => Some(bin),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if std::env::var_os("CI").is_some() {
                panic!("goindex failed to build: {stderr}");
            }
            rvl_testgate::skip(
                "goindex_binary",
                format_args!("goindex failed to build (set CI=1 to make this fatal): {stderr}"),
            );
            None
        }
        Err(e) => {
            rvl_testgate::skip("goindex_binary", format_args!("`go` not available: {e}"));
            None
        }
    }
}

/// Copy the fixture out of `testdata/`, so the scan reads it as a repository
/// and not as test material.
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

#[test]
fn scan_out_lists_the_rate_limiter_decision_in_a_handler_as_a_protective_site() {
    let build = tempfile::tempdir().unwrap();
    let Some(goindex) = goindex_binary(build.path()) else {
        return;
    };
    let repo = tempfile::tempdir().unwrap();
    copy_dir(
        &manifest_dir().join("../../helpers/goindex/testdata/protectivefixture"),
        repo.path(),
    );
    let work = tempfile::tempdir().unwrap();
    let specs = work.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[]}"#).unwrap();
    let out_path = work.path().join("scan.json");
    let out = Command::new(env!("CARGO_BIN_EXE_rvl"))
        .arg("scan")
        .arg(repo.path())
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_GOINDEX", &goindex)
        .env("RVL_CACHE_DIR", work.path().join("cache"))
        .env_remove("RVL_BASE_REF")
        .env_remove("GITHUB_BASE_REF")
        .env_remove("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
        .output()
        .expect("failed to run rvl");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out_path.is_file(),
        "scan wrote no --out document: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = doc["protective_sites"]
        .as_array()
        .expect("protective_sites must be a JSON array");

    let handler: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["file"] == "main.go" && r["method"] == "Allow")
        .collect();
    assert_eq!(handler.len(), 1, "one Allow in the handler: {rows:#?}");
    let h = handler[0];
    assert_eq!(h["class"], "golang.org/x/time/rate.Limiter");
    assert_eq!(h["mechanism"], "rate_limit");
    assert_eq!(h["scope"], "runtime");
    let line = h["line"].as_u64().unwrap();
    assert_eq!(
        h["site"],
        format!("main.go:{line}:golang.org/x/time/rate.Limiter:Allow")
    );
    let body = h["enclosing_function"].as_str().unwrap();
    assert!(
        body.starts_with("func handle(") && body.contains("http.StatusTooManyRequests"),
        "the enclosing function is the handler with its refusal: {body}"
    );

    // The test file's call is reported, scoped as test material.
    let test: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| r["file"] == "main_test.go")
        .collect();
    assert_eq!(test.len(), 1, "{rows:#?}");
    assert_eq!(test[0]["scope"], "test_support");

    // Never judged: no eval row is a limiter's.
    let judged = doc["sites"].as_array().unwrap().iter().any(|r| {
        r["class"]
            .as_str()
            .is_some_and(|c| c.contains("rate.Limiter"))
    });
    assert!(
        !judged,
        "a protective site must not be an eval row: {doc:#}"
    );
    // And COVERAGE counts the sites beside the census.
    assert!(
        stdout.contains("go protective sites (rate limiter decisions, not judged): 4"),
        "{stdout}"
    );
}
