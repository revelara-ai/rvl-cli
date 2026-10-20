//! `rvl scan --out` carries `config_sites[]`: one row per config setting the
//! config lane read, with its verdict, control and rule.
//!
//! Pinned end to end, through the binary: the fixture repo under
//! `tests/fixtures/config_sites` (a GitHub Actions workflow, a Kubernetes
//! Deployment and a Dockerfile) is scanned with test-grade specs, and the
//! rows must equal `tests/fixtures/config_sites_golden.json`. Regenerate the
//! golden after an intended change with
//! `UPDATE_GOLDEN=1 cargo test -p rvl --test config_sites` and review the
//! diff. The cap and its overflow count are pinned in `config_lane`'s unit
//! tests, where the cap can be set small.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate directory, read at run time (see `bare_client_config.rs`).
fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

fn fixtures() -> PathBuf {
    manifest_dir().join("tests").join("fixtures")
}

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    for k in [
        "RVL_BASE_REF",
        "GITHUB_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
    ] {
        c.env_remove(k);
    }
    c
}

/// Copy the fixture tree into `to`, so the scan reads a repo of its own and
/// writes nothing into the checkout.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

#[test]
fn config_sites_match_the_golden() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    copy_tree(&fixtures().join("config_sites"), &repo);
    let out_path = dir.path().join("out.json");
    let out = bin()
        .arg("scan")
        .arg(&repo)
        .arg("--specs-file")
        .arg(fixtures().join("config_sites_specs.json"))
        .arg("--out")
        .arg(&out_path)
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .output()
        .expect("failed to run rvl");
    assert!(
        out_path.is_file(),
        "scan wrote no --out document: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
    let rows = doc["config_sites"]
        .as_array()
        .unwrap_or_else(|| panic!("no config_sites array: {doc}"));
    assert_eq!(doc["config_sites_overflow"], 0, "{doc}");

    // Every setting the coverage counts is a row, and the verdicts agree.
    let config = &doc["coverage"]["config"];
    assert_eq!(
        Some(rows.len() as u64),
        config["total"].as_u64(),
        "{config}"
    );
    for k in config["by_key"].as_array().unwrap() {
        for verdict in ["violates", "satisfies", "abstain", "not_applicable"] {
            let n = rows
                .iter()
                .filter(|r| {
                    r["format"] == k["format"] && r["key"] == k["key"] && r["verdict"] == verdict
                })
                .count() as u64;
            assert_eq!(Some(n), k[verdict].as_u64(), "{verdict} of {k}");
        }
    }

    let golden_path = fixtures().join("config_sites_golden.json");
    // One row per line, so a change to one row is a one-line diff.
    let got = format!(
        "[\n{}\n]\n",
        rows.iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join(",\n")
    );
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(&golden_path, &got).unwrap();
    }
    let want = std::fs::read_to_string(&golden_path).expect(
        "the config_sites golden is missing: regenerate it with \
         UPDATE_GOLDEN=1 cargo test -p rvl --test config_sites",
    );
    let want: serde_json::Value = serde_json::from_str(&want).unwrap();
    assert_eq!(
        doc["config_sites"], want,
        "config_sites differ from the golden; got:\n{got}"
    );

    // The rows the fixture exists for, named so a regenerated golden that
    // lost them cannot pass unnoticed.
    let row = |file: &str, key: &str| {
        rows.iter()
            .find(|r| r["file"] == file && r["key"] == key)
            .unwrap_or_else(|| panic!("no {file} {key} row: {got}"))
    };
    let wf = ".github/workflows/ci.yml";
    let lint = rows
        .iter()
        .find(|r| {
            r["file"] == wf && r["key"] == "job.timeout-minutes" && r["resource"] == "job:lint"
        })
        .unwrap_or_else(|| panic!("no lint timeout row: {got}"));
    assert_eq!(lint["verdict"], "violates");
    assert_eq!(lint["control"], "RC-013");
    let replicas = row("k8s/api.yaml", "workload.replicas");
    assert_eq!(replicas["verdict"], "violates");
    assert_eq!(replicas["control"], "RC-001");
    assert_eq!(replicas["value"], "1");
    // The YAML retrievers record no line; 0 says so.
    assert_eq!(replicas["line"], 0);
    assert_eq!(replicas["resource"], "deployment:api");
    let user = row("Dockerfile", "dockerfile.final_stage_user");
    assert_eq!(user["verdict"], "satisfies");
    assert_eq!(user["control"], "RC-044");
    assert_eq!(user["line"], 3, "the USER that decides");
}
