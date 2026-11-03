//! The reference CI job users copy, docs/examples/rvl-gate.yml, is run by
//! .github/workflows/rvl-gate-reference.yml against a fixture repository. That
//! proves the example only while the workflow runs the example's steps, so
//! this holds them to each other: the workflow's `rvl-gate` steps are the
//! example's, as written, plus steps named `ci-only: ...`, and the install
//! step's one addition is the `if:` that hands a pull request's run to the
//! build of that pull request.

use serde_yaml::Value;
use std::path::Path;

const CI_ONLY: &str = "ci-only: ";
const INSTALL: &str = "Install rvl";
const STAND_IN: &str = "ci-only: install rvl from this pull request";

fn load(rel: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("parsing {rel}: {e}"))
}

fn steps(doc: &Value) -> Vec<Value> {
    doc["jobs"]["rvl-gate"]["steps"]
        .as_sequence()
        .expect("a `rvl-gate` job with steps")
        .clone()
}

fn name(step: &Value) -> &str {
    step["name"].as_str().unwrap_or_default()
}

#[test]
fn the_reference_workflow_runs_the_example_steps_as_written() {
    let example = steps(&load("docs/examples/rvl-gate.yml"));
    let workflow = steps(&load(".github/workflows/rvl-gate-reference.yml"));

    let install = workflow.iter().position(|s| name(s) == INSTALL);
    let stand_in = workflow.iter().position(|s| name(s) == STAND_IN);
    let (Some(install), Some(stand_in)) = (install, stand_in) else {
        panic!("the workflow needs both `{INSTALL}` and `{STAND_IN}`");
    };
    assert_eq!(
        stand_in + 1,
        install,
        "the stand-in runs where the install step does"
    );
    assert_eq!(
        workflow[stand_in]["if"].as_str(),
        Some("github.event_name == 'pull_request'")
    );
    assert_eq!(
        workflow[install]["if"].as_str(),
        Some("github.event_name != 'pull_request'"),
        "every run that is not a pull request uses the real install step"
    );

    let as_written: Vec<Value> = workflow
        .into_iter()
        .filter(|s| !name(s).starts_with(CI_ONLY))
        .map(|mut s| {
            if name(&s) == INSTALL {
                s.as_mapping_mut().unwrap().remove("if");
            }
            s
        })
        .collect();
    assert_eq!(
        as_written, example,
        "the workflow's steps, less its ci-only steps, must be the example's"
    );
}

#[test]
fn the_reference_workflow_runs_on_the_changes_it_proves() {
    let on = &load(".github/workflows/rvl-gate-reference.yml")["on"];
    let paths: Vec<&str> = on["pull_request"]["paths"]
        .as_sequence()
        .expect("pull_request paths")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for want in [
        "docs/examples/rvl-gate.yml",
        ".github/workflows/rvl-gate-reference.yml",
        "ci/gate-fixture.sh",
        "crates/**",
        "helpers/**",
    ] {
        assert!(paths.contains(&want), "pull_request paths lack {want}");
    }
    assert!(on["schedule"].is_sequence(), "a scheduled run");
    assert_eq!(
        on["workflow_run"]["workflows"][0].as_str(),
        Some("Release"),
        "a run after each release"
    );
}

#[test]
fn the_example_installs_a_pinned_checked_archive_and_syncs_before_it_scans() {
    let example = steps(&load("docs/examples/rvl-gate.yml"));
    let at = |n: &str| {
        example
            .iter()
            .position(|s| name(s) == n)
            .unwrap_or_else(|| panic!("the example has no `{n}` step"))
    };
    let install = &example[at(INSTALL)];
    let version = install["env"]["RVL_VERSION"].as_str().unwrap_or_default();
    assert!(
        version.starts_with('v') && version[1..].split('.').count() == 3,
        "pinned to a release tag: {version:?}"
    );
    let run = install["run"].as_str().unwrap();
    for needle in ["sha256sum -c", "tar -xJf", "$GITHUB_PATH"] {
        assert!(run.contains(needle), "the install step lacks {needle}");
    }
    assert!(
        run.find("sha256sum -c") < run.find("tar -xJf"),
        "checked before it is unpacked"
    );
    assert!(at(INSTALL) < at("Restore the spec cache"));
    assert!(at("Restore the spec cache") < at("Sync the spec cache"));
    assert!(at("Sync the spec cache") < at("Gate the change"));
}
