//! Fixture mini-repos per ecosystem: each control's positive / negative /
//! abstain cases, driven through the real walker on tempdir trees.

use rvl_core::Verdict;
use rvl_structure::{
    evaluate, inventory, parse_record, RepoStructure, ScannerClass, StructureFinding,
};
use std::path::Path;

fn write(root: &Path, rel: &str, content: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn finding<'a>(fs: &'a [StructureFinding], control: &str) -> &'a StructureFinding {
    fs.iter()
        .find(|f| f.control == control)
        .unwrap_or_else(|| panic!("no finding for {control}"))
}

fn eval_dir(root: &Path) -> Vec<StructureFinding> {
    evaluate(&inventory(root))
}

/// A Go mini-repo with enough sources to judge and no tests at all.
fn go_repo_without_tests(root: &Path) {
    write(root, "go.mod", "module example.com/svc\n\ngo 1.22\n");
    for i in 0..6 {
        write(
            root,
            &format!("internal/svc/f{i}.go"),
            "package svc\nfunc F() {}\n",
        );
    }
}

// --- RC-033: unit-test presence ---

#[test]
fn rc033_go_repo_without_tests_violates() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let f = &eval_dir(dir.path())[..];
    let f = finding(f, "RC-033");
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);
    assert!(f.reason.contains("go"), "names the ecosystem: {}", f.reason);
}

#[test]
fn rc033_go_repo_with_tests_satisfies_with_ratio() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        "internal/svc/f0_test.go",
        "package svc\nimport \"testing\"\nfunc TestF(t *testing.T) {}\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-033");
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
    assert!(
        f.reason.contains('/'),
        "reports a rough test-to-source ratio: {}",
        f.reason
    );
}

#[test]
fn rc033_too_few_sources_abstains_rather_than_accusing() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "main.go", "package main\nfunc main() {}\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-033");
    assert_eq!(
        f.verdict,
        Verdict::Abstain,
        "2-file repos are not test-coverage verdict material: {}",
        f.reason
    );
}

#[test]
fn rc033_no_source_ecosystems_is_not_applicable() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", "# docs only\n");
    let fs = eval_dir(dir.path());
    assert_eq!(finding(&fs, "RC-033").verdict, Verdict::NotApplicable);
}

#[test]
fn rc033_truncated_walk_never_licenses_reasoning_from_absence() {
    // Evaluator-level: a facts record whose walk did not complete must not
    // turn "no test files seen" into a violation.
    let facts = RepoStructure {
        ecosystems: vec![rvl_structure::EcosystemFacts {
            name: "go".into(),
            source_files: 40,
            test_files: 0,
            integration_markers: vec![],
        }],
        walk_complete: false,
        ..Default::default()
    };
    let fs = evaluate(&facts);
    assert_eq!(
        finding(&fs, "RC-033").verdict,
        Verdict::Abstain,
        "a truncated walk is not evidence of absence"
    );
}

#[test]
fn rc033_js_and_python_test_conventions_are_recognized() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..6 {
        write(dir.path(), &format!("src/m{i}.ts"), "export const x = 1;\n");
        write(dir.path(), &format!("app/p{i}.py"), "x = 1\n");
    }
    write(
        dir.path(),
        "src/__tests__/m0.test.ts",
        "test('x', () => {});\n",
    );
    write(dir.path(), "tests/test_p0.py", "def test_x(): pass\n");
    let facts = inventory(dir.path());
    let js = facts.ecosystems.iter().find(|e| e.name == "js").unwrap();
    let py = facts
        .ecosystems
        .iter()
        .find(|e| e.name == "python")
        .unwrap();
    assert!(js.test_files >= 1, "js test convention: {js:?}");
    assert!(py.test_files >= 1, "python test convention: {py:?}");
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-033").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc033_rust_inline_cfg_test_counts_as_tests() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..6 {
        write(dir.path(), &format!("src/m{i}.rs"), "pub fn f() {}\n");
    }
    write(
        dir.path(),
        "src/lib.rs",
        "pub fn g() {}\n#[cfg(test)]\nmod tests { #[test] fn t() {} }\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-033");
    assert_eq!(
        f.verdict,
        Verdict::Satisfies,
        "inline #[cfg(test)] is the dominant Rust idiom: {}",
        f.reason
    );
}

#[test]
fn vendored_dirs_never_count() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    // A vendored dependency's tests must not satisfy the repo's own RC-033.
    write(
        dir.path(),
        "vendor/dep/dep_test.go",
        "package dep\nfunc TestDep(t *testing.T) {}\n",
    );
    write(
        dir.path(),
        "node_modules/x/x.test.js",
        "test('x', () => {});\n",
    );
    let facts = inventory(dir.path());
    let go = facts.ecosystems.iter().find(|e| e.name == "go").unwrap();
    assert_eq!(go.test_files, 0, "vendor/ leaked into the inventory");
    assert!(
        !facts.ecosystems.iter().any(|e| e.name == "js"),
        "node_modules/ leaked into the inventory"
    );
}

// --- RC-057: coverage configuration ---

#[test]
fn rc057_no_coverage_config_is_a_decidable_negative() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-057");
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);
}

#[test]
fn rc057_codecov_yml_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(dir.path(), "codecov.yml", "coverage:\n  status:\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-057");
    assert_eq!(f.verdict, Verdict::Satisfies);
    assert!(
        f.evidence.iter().any(|e| e == "codecov.yml"),
        "evidence cites the config: {:?}",
        f.evidence
    );
}

#[test]
fn rc057_go_cover_in_ci_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "jobs:\n  test:\n    steps:\n      - run: go test -coverprofile=c.out ./...\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-057").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc057_pyproject_tool_coverage_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..6 {
        write(dir.path(), &format!("app/p{i}.py"), "x = 1\n");
    }
    write(
        dir.path(),
        "pyproject.toml",
        "[project]\nname = \"app\"\n\n[tool.coverage.run]\nbranch = true\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-057").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc057_coverage_delegated_to_a_shell_script_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    // The nats-server shape: the workflow delegates, so the only coverage token
    // in the whole repo lives in the script it calls.
    write(
        dir.path(),
        ".github/workflows/cov.yaml",
        "jobs:\n  cov:\n    steps:\n      - run: ./scripts/cov.sh upload\n",
    );
    write(
        dir.path(),
        "scripts/cov.sh",
        "#!/bin/bash\ngo test -covermode=atomic -coverprofile=./cov/x.out ./...\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-057");
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
}

#[test]
fn rc057_coveralls_uploader_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        ".github/workflows/cov.yaml",
        "jobs:\n  cov:\n    steps:\n      - uses: coverallsapp/github-action@v2\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-057");
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
}

#[test]
fn rc057_absence_claim_names_the_search_that_backs_it() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-057");
    assert_eq!(f.verdict, Verdict::Violates);
    assert!(
        f.reason.contains("build scripts"),
        "a negative may claim only what was actually searched: {}",
        f.reason
    );
}

// --- RC-058: integration/e2e test presence (live catalog: Integration and Smoke Tests) ---

#[test]
fn rc058_integration_dir_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        "tests/integration/api_test.go",
        "package integration\nfunc TestAPI(t *testing.T) {}\n",
    );
    let fs = eval_dir(dir.path());
    assert_eq!(finding(&fs, "RC-058").verdict, Verdict::Satisfies);
}

#[test]
fn rc058_e2e_config_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..6 {
        write(dir.path(), &format!("src/m{i}.ts"), "export const x = 1;\n");
    }
    write(dir.path(), "playwright.config.ts", "export default {};\n");
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-058").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc058_unit_tests_only_abstains() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        "internal/svc/f0_test.go",
        "package svc\nfunc TestF(t *testing.T) {}\n",
    );
    let f = &eval_dir(dir.path())[..];
    let f = finding(f, "RC-058");
    assert_eq!(
        f.verdict,
        Verdict::Abstain,
        "integration tests may not follow a detectable convention: {}",
        f.reason
    );
}

#[test]
fn rc058_no_tests_at_all_violates() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-058").verdict,
        Verdict::Violates
    );
}

// --- RC-034: contract-test frameworks (live catalog: Contract Testing) ---

#[test]
fn rc034_pact_dependency_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"svc","devDependencies":{"@pact-foundation/pact":"^12.0.0"}}"#,
    );
    write(dir.path(), "package-lock.json", "{}");
    for i in 0..6 {
        write(dir.path(), &format!("src/m{i}.ts"), "export const x = 1;\n");
    }
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-034");
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
    assert!(
        f.reason.to_lowercase().contains("pact"),
        "names the framework: {}",
        f.reason
    );
}

#[test]
fn rc034_buf_breaking_config_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(
        dir.path(),
        "buf.yaml",
        "version: v2\nbreaking:\n  use:\n    - FILE\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-034").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc034_absence_abstains_because_applicability_is_a_judgement() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-034");
    assert_eq!(
        f.verdict,
        Verdict::Abstain,
        "a library with no consumers legitimately has no contract tests: {}",
        f.reason
    );
}

// --- RC-070: dep-manifest hygiene ---

#[test]
fn rc070_package_json_without_lockfile_violates() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"svc","dependencies":{"express":"^4.18.0"}}"#,
    );
    for i in 0..6 {
        write(dir.path(), &format!("src/m{i}.ts"), "export const x = 1;\n");
    }
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-070");
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);
    assert!(
        f.evidence.iter().any(|e| e == "package.json"),
        "evidence cites the manifest: {:?}",
        f.evidence
    );
}

#[test]
fn rc070_monorepo_member_is_governed_by_the_root_lockfile() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "package.json",
        r#"{"name":"root","workspaces":["packages/*"]}"#,
    );
    write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: 9\n");
    write(
        dir.path(),
        "packages/a/package.json",
        r#"{"name":"a","dependencies":{"express":"^4.18.0"}}"#,
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc070_go_mod_with_requires_needs_go_sum() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "go.mod",
        "module example.com/svc\n\ngo 1.22\n\nrequire github.com/lib/pq v1.10.9\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Violates
    );
    write(dir.path(), "go.sum", "github.com/lib/pq v1.10.9 h1:x\n");
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc070_stdlib_only_go_mod_needs_no_lock() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "go.mod", "module example.com/svc\n\ngo 1.22\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-070");
    assert_ne!(
        f.verdict,
        Verdict::Violates,
        "a manifest with no deps needs no lockfile: {}",
        f.reason
    );
}

#[test]
fn rc070_cargo_workspace_member_uses_root_lock() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/a\"]\n",
    );
    write(dir.path(), "Cargo.lock", "version = 3\n");
    write(
        dir.path(),
        "crates/a/Cargo.toml",
        "[package]\nname = \"a\"\n\n[dependencies]\nserde = \"1\"\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc070_floating_requirements_violate_pinned_satisfy() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "requirements.txt", "flask\nrequests>=2.0\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-070");
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);

    write(
        dir.path(),
        "requirements.txt",
        "flask==3.0.3\nrequests==2.32.3\n",
    );
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc070_pyproject_without_lock_abstains_library_is_legitimate() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "pyproject.toml",
        "[project]\nname = \"lib\"\ndependencies = [\"requests\"]\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-070");
    assert_eq!(
        f.verdict,
        Verdict::Abstain,
        "a Python library legitimately ships no lockfile: {}",
        f.reason
    );

    write(dir.path(), "uv.lock", "version = 1\n");
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::Satisfies
    );
}

#[test]
fn rc070_no_manifests_is_not_applicable() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "README.md", "# nothing here\n");
    assert_eq!(
        finding(&eval_dir(dir.path()), "RC-070").verdict,
        Verdict::NotApplicable
    );
}

// --- RC-006: runbook-directory presence (weak signal) ---

#[test]
fn rc006_runbook_dir_satisfies_weakly() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(dir.path(), "docs/runbooks/db-failover.md", "# steps\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-006");
    assert_eq!(f.verdict, Verdict::Satisfies);
    assert!(f.weak, "presence-only is a weak signal");
}

#[test]
fn rc006_absence_abstains_runbooks_may_live_elsewhere() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-006");
    assert_eq!(
        f.verdict,
        Verdict::Abstain,
        "a wiki-hosted runbook is invisible to the repo: {}",
        f.reason
    );
    assert!(f.weak);
}

// --- CI scanner inventory (Q21/Q22): a repo-level fact, no verdict ---

const WF_BUILD_ONLY: &str = "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test\n";

#[test]
fn ci_scans_record_known_scanner_actions_across_all_workflows() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".github/workflows/ci.yml", WF_BUILD_ONLY);
    write(
        dir.path(),
        ".github/workflows/deps.yaml",
        "on: [pull_request]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/dependency-review-action@v4\n",
    );
    write(
        dir.path(),
        ".github/workflows/codeql.yml",
        "on: [push]\njobs:\n  analyze:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: github/codeql-action/init@v3\n      - uses: GitHub/CodeQL-Action/analyze@v3\n",
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.workflows_parsed, 3);
    assert_eq!(facts.ci_scans.workflows_unparsed, 0);
    let seen: Vec<(ScannerClass, &str, &str)> = facts
        .ci_scans
        .scanners
        .iter()
        .map(|s| (s.class, s.name.as_str(), s.workflow.as_str()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (
                ScannerClass::DependencyScan,
                "actions/dependency-review-action",
                ".github/workflows/deps.yaml"
            ),
            (
                ScannerClass::Sast,
                "github/codeql-action/analyze",
                ".github/workflows/codeql.yml"
            ),
            (
                ScannerClass::Sast,
                "github/codeql-action/init",
                ".github/workflows/codeql.yml"
            ),
        ]
    );
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), Some(true));
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), Some(true));
}

#[test]
fn ci_scans_absence_is_decidable_when_a_workflow_parsed_and_none_scans() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".github/workflows/ci.yml", WF_BUILD_ONLY);
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.workflows_parsed, 1);
    assert!(facts.ci_scans.scanners.is_empty());
    assert_eq!(
        facts.scanner_seen(ScannerClass::DependencyScan),
        Some(false)
    );
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), Some(false));
}

#[test]
fn ci_scans_absence_is_undecidable_without_ci_config() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    // Another CI system is not read for scanners: it licenses nothing.
    write(dir.path(), ".gitlab-ci.yml", "test:\n  script: make test\n");
    let facts = inventory(dir.path());
    assert!(facts.walk_complete);
    assert_eq!(facts.ci_scans.workflows_parsed, 0);
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), None);
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), None);
}

#[test]
fn ci_scans_one_class_seen_does_not_decide_the_other_as_present() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: golang/govulncheck-action@v1\n",
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), Some(true));
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), Some(false));
}

#[test]
fn ci_scans_a_scanner_run_as_a_command_is_seen() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          cargo install cargo-audit\n          cargo audit\n      - run: semgrep ci\n",
    );
    let facts = inventory(dir.path());
    let names: Vec<&str> = facts
        .ci_scans
        .scanners
        .iter()
        .map(|s| s.name.as_str())
        .collect();
    assert_eq!(names, vec!["cargo audit", "semgrep"]);
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), Some(true));
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), Some(true));
}

#[test]
fn ci_scans_unparsed_workflow_blocks_reasoning_from_absence() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".github/workflows/ci.yml", WF_BUILD_ONLY);
    write(
        dir.path(),
        ".github/workflows/broken.yml",
        "jobs:\n  a: [unclosed\n",
    );
    // Valid YAML that is not a workflow (no jobs) is not a parsed workflow.
    write(dir.path(), ".github/workflows/notes.yml", "just: a note\n");
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.workflows_parsed, 1);
    assert_eq!(facts.ci_scans.workflows_unparsed, 2);
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), None);
}

#[test]
fn ci_scans_opaque_calls_block_reasoning_from_absence() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  shared:\n    uses: org/shared/.github/workflows/security.yml@v2\n  local:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/scan\n",
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.workflows_parsed, 1);
    assert_eq!(facts.ci_scans.opaque_calls, 2);
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), None);
}

#[test]
fn ci_scans_a_local_reusable_workflow_is_walked_not_opaque() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  shared:\n    uses: ./.github/workflows/build.yml\n",
    );
    write(
        dir.path(),
        ".github/workflows/build.yml",
        "on: [workflow_call]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make build\n",
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.workflows_parsed, 2);
    assert_eq!(facts.ci_scans.opaque_calls, 0);
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), Some(false));
}

#[test]
fn ci_scans_a_known_reusable_scanner_workflow_is_seen_not_opaque() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/osv.yml",
        "on: [push]\njobs:\n  osv:\n    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2\n",
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.ci_scans.opaque_calls, 0);
    assert_eq!(facts.ci_scans.scanners[0].name, "google/osv-scanner-action");
    assert_eq!(facts.scanner_seen(ScannerClass::DependencyScan), Some(true));
}

#[test]
fn ci_scans_truncated_walk_never_licenses_absence() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), ".github/workflows/ci.yml", WF_BUILD_ONLY);
    let mut facts = inventory(dir.path());
    facts.walk_complete = false;
    assert_eq!(facts.scanner_seen(ScannerClass::Sast), None);
}

#[test]
fn ci_scans_a_record_without_the_fact_still_parses_and_decides_nothing() {
    let old = r#"{"kind":"repo_structure","snapshot_id":"s","ecosystems":[],"walk_complete":true}"#;
    let parsed = parse_record(old).expect("an older record still parses");
    assert_eq!(parsed.ci_scans.workflows_parsed, 0);
    assert_eq!(parsed.scanner_seen(ScannerClass::Sast), None);
}

#[test]
fn ci_scans_round_trip_through_a_packet_stream() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  scan:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: aquasecurity/trivy-action@0.28.0\n",
    );
    let facts = inventory(dir.path());
    let line = facts.to_jsonl();
    assert!(line.contains(r#""class":"dependency-scan""#), "{line}");
    assert_eq!(parse_record(&line).expect("round trip"), facts);
}

// --- record round-trip through the packet schema ---

#[test]
fn record_round_trips_through_a_packet_stream() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    let facts = inventory(dir.path());
    let stream = format!(
        "{}\n{}\n",
        r#"{"file_path":"a.go","line_number":7,"func":"Query","client_type":"db.Pool"}"#,
        facts.to_jsonl()
    );
    let parsed = parse_record(&stream).expect("record survives the stream");
    assert_eq!(parsed, facts);
}

#[test]
fn evaluate_emits_one_finding_per_control_every_time() {
    let fs = evaluate(&RepoStructure::default());
    let controls: Vec<&str> = fs.iter().map(|f| f.control).collect();
    assert_eq!(
        controls,
        vec!["RC-033", "RC-057", "RC-058", "RC-034", "RC-070", "RC-006"],
        "abstain/satisfies outcomes are part of the record, never dropped"
    );
}
