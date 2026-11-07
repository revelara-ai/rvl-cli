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

/// RC-042 is decided end to end: a step pinned to a tag violates, a step
/// pinned to a 40-hex commit SHA satisfies, and the violation is a finding.
/// The specs map the uses-ref keys to RC-042 with the `sha40` pattern, as
/// the published OSS spec cache does (docs/lens-reconciliation.md, row 18a).
#[test]
fn rc042_unpinned_action_ref_is_decided_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let workflows = repo.join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    std::fs::write(
        workflows.join("ci.yml"),
        "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      \
         - uses: actions/checkout@v4\n      \
         - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n",
    )
    .unwrap();
    let specs = dir.path().join("specs.json");
    let key = |key: &str| {
        serde_json::json!({
            "format": "github-actions", "key": key,
            "expect": {"kind": "pattern", "name": "sha40"},
            "confidence": 0.9, "control": "RC-042", "severity": "medium",
            "fix": "pin the action to a full-length commit SHA",
            "rationale": "a tag or branch can be moved to other code",
        })
    };
    let spec_file = serde_json::json!({
        "config_keys": [key("job.uses.ref"), key("step.uses.ref")],
    });
    std::fs::write(&specs, spec_file.to_string()).unwrap();
    let out_path = dir.path().join("out.json");
    let out = bin()
        .arg("scan")
        .arg(&repo)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .env("HOME", dir.path().join("home"))
        .env("RVL_OFFLINE", "1")
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

    let step = |resource: &str| {
        doc["config_sites"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|r| r["key"] == "step.uses.ref" && r["resource"] == resource)
            .unwrap_or_else(|| panic!("no step.uses.ref row for {resource}: {doc}"))
    };
    let tag = step("step:test/0");
    assert_eq!(tag["value"], "v4");
    assert_eq!(tag["verdict"], "violates", "{tag}");
    assert_eq!(tag["control"], "RC-042", "{tag}");
    let sha = step("step:test/1");
    assert_eq!(sha["verdict"], "satisfies", "{sha}");
    assert_eq!(sha["control"], "RC-042", "{sha}");

    let rc042: Vec<&serde_json::Value> = doc["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["control"] == "RC-042")
        .collect();
    assert_eq!(rc042.len(), 1, "one RC-042 finding, the tag step: {doc}");
    assert_eq!(rc042[0]["class"], "github-actions.step.uses.ref");
    assert!(
        rc042[0]["site"].as_str().unwrap().contains("step:test/0"),
        "{}",
        rc042[0]
    );
}

/// RC-079 is decided end to end, one row per release job: a job that
/// publishes with neither an SBOM nor a provenance step violates M1, one that
/// makes both and pins every action to a commit satisfies, one with an action
/// pinned to a tag violates M2b, and a job that does not publish has no row.
#[test]
fn rc079_release_job_supply_chain_is_decided_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let workflows = repo.join(".github/workflows");
    std::fs::create_dir_all(&workflows).unwrap();
    let sha = "11bd71901bbe5b1630ceea73d27597364c9af683";
    std::fs::write(
        workflows.join("release.yml"),
        format!(
            "on: push\njobs:\n  \
             test:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@v4\n      - run: make test\n  \
             npm:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: actions/checkout@{sha}\n      - run: npm publish\n"
        ),
    )
    .unwrap();
    std::fs::write(
        workflows.join("image.yml"),
        format!(
            "on: push\njobs:\n  \
             image:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: docker/build-push-action@{sha}\n        with:\n          \
             push: true\n          sbom: true\n          provenance: true\n  \
             pypi:\n    runs-on: ubuntu-latest\n    steps:\n      \
             - uses: pypa/gh-action-pypi-publish@release/v1\n"
        ),
    )
    .unwrap();
    let specs = dir.path().join("specs.json");
    let spec_file = serde_json::json!({
        "config_keys": [{
            "format": "github-actions", "key": "job.release_supply_chain",
            "expect": {"kind": "pattern", "name": "release_supply_chain"},
            "confidence": 0.9, "control": "RC-079", "severity": "medium",
            "fix": "make an SBOM and a provenance attestation, and pin every action to a commit",
            "rationale": "a release that cannot be traced to its source and builder can be swapped",
        }],
    });
    std::fs::write(&specs, spec_file.to_string()).unwrap();
    let out_path = dir.path().join("out.json");
    let out = bin()
        .arg("scan")
        .arg(&repo)
        .arg("--specs-file")
        .arg(&specs)
        .arg("--out")
        .arg(&out_path)
        .env("RVL_CACHE_DIR", dir.path().join("cache"))
        .env("HOME", dir.path().join("home"))
        .env("RVL_OFFLINE", "1")
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

    let rows: Vec<&serde_json::Value> = doc["config_sites"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["key"] == "job.release_supply_chain")
        .collect();
    let row = |resource: &str| {
        rows.iter()
            .find(|r| r["resource"] == resource)
            .unwrap_or_else(|| panic!("no release row for {resource}: {rows:?}"))
    };
    // `rule` is the class phrase; the value names the rule and the actions.
    for (resource, verdict, value) in [
        (
            "job:npm",
            "violates",
            "M1: no SBOM step and no provenance step",
        ),
        ("job:image", "satisfies", "S1:"),
        (
            "job:pypi",
            "violates",
            "M2b: pypa/gh-action-pypi-publish@release/v1 not pinned to a commit",
        ),
    ] {
        let r = row(resource);
        assert_eq!(r["verdict"], verdict, "{r}");
        assert_eq!(r["control"], "RC-079", "{r}");
        assert!(r["value"].as_str().unwrap().starts_with(value), "{r}");
    }
    assert_eq!(rows.len(), 3, "the test job publishes nothing: {rows:?}");
}
