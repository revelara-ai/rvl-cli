//! Fixture mini-repos per ecosystem: each control's positive / negative /
//! abstain cases, driven through the real walker on tempdir trees.

use rvl_core::Verdict;
use rvl_structure::{
    evaluate, inventory, parse_record, RepoStructure, ScannerClass, StructureFinding,
};
use std::path::Path;

/// The scan date every fixture is judged on.
const TODAY: &str = "2026-11-02";

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
    evaluate(&inventory(root), TODAY)
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
    let fs = evaluate(&facts, TODAY);
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
fn rc006_runbook_dir_without_runbook_files_satisfies_weakly() {
    let dir = tempfile::tempdir().unwrap();
    go_repo_without_tests(dir.path());
    write(dir.path(), "docs/runbooks/README.md", "# index\n");
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

// --- RC-006: runbook currency (front matter, CODEOWNERS, committed rulesets) ---

const RUNBOOK_CURRENT: &str =
    "---\nowner: \"@sre\"\nlast_reviewed: 2026-06-01\n---\n# DB failover\n";

const RULESET_REVIEWED: &str = r#"{
  "name": "main", "target": "branch", "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [{"type": "pull_request", "parameters": {
    "required_approving_review_count": 0, "require_code_owner_review": true,
    "dismiss_stale_reviews_on_push": false, "require_last_push_approval": false,
    "required_review_thread_resolution": false}}]
}"#;

/// A repository whose one runbook is current, owned and review-gated.
fn runbook_repo(root: &Path, runbook: &str) {
    write(root, "docs/runbooks/db-failover.md", runbook);
    write(root, "docs/runbooks/README.md", "# index, not a runbook\n");
    write(
        root,
        ".github/CODEOWNERS",
        "* @org/eng\n/docs/runbooks/ @org/sre\n",
    );
}

#[test]
fn rc006_current_owned_runbook_satisfies_and_scopes_out_forge_settings() {
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(dir.path(), RUNBOOK_CURRENT);
    let facts = inventory(dir.path());
    assert_eq!(
        facts.runbooks.len(),
        1,
        "README indexes, it is not a runbook"
    );
    assert_eq!(facts.codeowners.as_deref(), Some(".github/CODEOWNERS"));
    let f = evaluate(&facts, TODAY)
        .into_iter()
        .find(|f| f.control == "RC-006")
        .unwrap();
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
    assert!(!f.weak, "a judged runbook is not a presence-only signal");
    assert!(
        f.reason.contains("forge settings is out of scope"),
        "{}",
        f.reason
    );
    assert!(!f.reason.contains("advisory"), "{}", f.reason);
}

#[test]
fn rc006_each_owner_and_date_key_is_read() {
    for fm in [
        "owners: [\"@a\", \"@b\"]\nlast_reviewed_on: \"2026-01-02\"",
        "owner_slack: \"#sre-oncall\"\ntested_on: 2026-03-04",
    ] {
        let dir = tempfile::tempdir().unwrap();
        runbook_repo(dir.path(), &format!("---\n{fm}\n---\nsteps\n"));
        let f = eval_dir(dir.path());
        let f = finding(&f, "RC-006");
        assert_eq!(f.verdict, Verdict::Satisfies, "{fm}: {}", f.reason);
    }
}

#[test]
fn rc006_missing_owner_or_date_violates() {
    for (fm, missing) in [
        ("last_reviewed: 2026-06-01", "no owner"),
        ("owner: \"@sre\"", "no last_reviewed"),
        (
            "owner: \"@sre\"\nlast_reviewed: 2026-02-31",
            "no last_reviewed",
        ),
        ("owner: \"\"\nlast_reviewed: 2026-06-01", "no owner"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        runbook_repo(dir.path(), &format!("---\n{fm}\n---\n"));
        let fs = eval_dir(dir.path());
        let f = finding(&fs, "RC-006");
        assert_eq!(f.verdict, Verdict::Violates, "{fm}: {}", f.reason);
        assert!(f.reason.contains(missing), "{fm}: {}", f.reason);
        assert_eq!(f.evidence, vec!["docs/runbooks/db-failover.md".to_string()]);
    }
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(dir.path(), "# no front matter at all\n");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-006");
    assert!(
        f.reason.contains("no owner") && f.reason.contains("no last_reviewed"),
        "{}",
        f.reason
    );
}

#[test]
fn rc006_a_stale_review_is_an_advisory_note_never_a_violation() {
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(
        dir.path(),
        "---\nowner: \"@sre\"\nlast_reviewed: 2025-11-01\n---\n",
    );
    let facts = inventory(dir.path());
    let f = evaluate(&facts, TODAY)
        .into_iter()
        .find(|f| f.control == "RC-006")
        .unwrap();
    assert_eq!(f.verdict, Verdict::Satisfies, "{}", f.reason);
    assert!(
        f.reason.contains("advisory") && f.reason.contains("db-failover.md (2025-11-01)"),
        "366 days before the scan date: {}",
        f.reason
    );
    // Exactly 365 days is not stale.
    let f = evaluate(&facts, "2026-11-01")
        .into_iter()
        .find(|f| f.control == "RC-006")
        .unwrap();
    assert!(!f.reason.contains("advisory"), "{}", f.reason);
}

#[test]
fn rc006_the_last_matching_codeowners_pattern_decides() {
    let cases = [
        // A later pattern with no owners leaves the path unowned.
        ("* @org/eng\n/docs/runbooks/\n", false),
        // A later owned pattern wins over an earlier unowned one.
        ("/docs/\n**/runbooks/*.md @org/sre # inline comment\n", true),
        // An unanchored directory name matches at any depth.
        ("runbooks @org/sre\n", true),
        // A wildcard last segment matches direct entries only.
        ("/docs/* @org/docs\n", false),
        // Paths are case sensitive.
        ("/Docs/runbooks/ @org/sre\n", false),
        // A negation line is unsupported syntax: GitHub skips it.
        ("* @org/eng\n!docs/runbooks/db-failover.md\n", true),
    ];
    for (codeowners, owned) in cases {
        let dir = tempfile::tempdir().unwrap();
        runbook_repo(dir.path(), RUNBOOK_CURRENT);
        write(dir.path(), ".github/CODEOWNERS", codeowners);
        let facts = inventory(dir.path());
        assert_eq!(facts.runbooks[0].code_owned, owned, "{codeowners:?}");
        let f = evaluate(&facts, TODAY)
            .into_iter()
            .find(|f| f.control == "RC-006")
            .unwrap();
        let want = if owned {
            Verdict::Satisfies
        } else {
            Verdict::Violates
        };
        assert_eq!(f.verdict, want, "{codeowners:?}: {}", f.reason);
    }
}

#[test]
fn rc006_codeowners_location_precedence_and_absence() {
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(dir.path(), RUNBOOK_CURRENT);
    std::fs::remove_file(dir.path().join(".github/CODEOWNERS")).unwrap();
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-006");
    assert_eq!(f.verdict, Verdict::Violates);
    assert!(f.reason.contains("no CODEOWNERS file"), "{}", f.reason);

    // The root file is in effect when .github/ has none; docs/ comes last.
    write(dir.path(), "docs/CODEOWNERS", "* @org/docs\n");
    write(dir.path(), "CODEOWNERS", "*.go @org/go\n");
    let facts = inventory(dir.path());
    assert_eq!(facts.codeowners.as_deref(), Some("CODEOWNERS"));
    assert!(!facts.runbooks[0].code_owned);
}

#[test]
fn rc006_a_committed_ruleset_must_require_review_on_the_default_branch() {
    let no_review = RULESET_REVIEWED.replace(
        "\"require_code_owner_review\": true",
        "\"require_code_owner_review\": false",
    );
    let one_approval = no_review.replace(
        "\"required_approving_review_count\": 0",
        "\"required_approving_review_count\": 1",
    );
    let evaluate_only = RULESET_REVIEWED.replace("\"active\"", "\"evaluate\"");
    let other_branch = RULESET_REVIEWED.replace("~DEFAULT_BRANCH", "refs/heads/release");
    let cases = [
        (RULESET_REVIEWED.to_string(), Verdict::Satisfies),
        (one_approval, Verdict::Satisfies),
        (no_review, Verdict::Violates),
        (evaluate_only, Verdict::Violates),
        (other_branch, Verdict::Violates),
    ];
    for (ruleset, want) in cases {
        let dir = tempfile::tempdir().unwrap();
        runbook_repo(dir.path(), RUNBOOK_CURRENT);
        write(dir.path(), ".github/rulesets/main.json", &ruleset);
        let fs = eval_dir(dir.path());
        let f = finding(&fs, "RC-006");
        assert_eq!(f.verdict, want, "{ruleset}: {}", f.reason);
        assert!(
            f.reason.contains("forge settings is out of scope"),
            "{}",
            f.reason
        );
        if want == Verdict::Violates {
            assert!(f
                .evidence
                .contains(&".github/rulesets/main.json".to_string()));
        }
    }

    // A ruleset that does not parse is not read as one that lacks review.
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(dir.path(), RUNBOOK_CURRENT);
    write(dir.path(), ".github/rulesets/broken.json", "{ not json");
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-006");
    assert_eq!(f.verdict, Verdict::Satisfies, "{}", f.reason);
    assert!(f.reason.contains("not read as rulesets"), "{}", f.reason);
}

#[test]
fn rc006_runbook_facts_ride_the_record_and_old_records_still_parse() {
    let dir = tempfile::tempdir().unwrap();
    runbook_repo(dir.path(), RUNBOOK_CURRENT);
    let facts = inventory(dir.path());
    let back = parse_record(&facts.to_jsonl()).unwrap();
    assert_eq!(back, facts);
    let old = parse_record(r#"{"kind":"repo_structure","runbook_dirs":["runbooks"]}"#).unwrap();
    assert!(old.runbooks.is_empty() && old.rulesets.is_empty() && old.codeowners.is_none());
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
    let fs = evaluate(&RepoStructure::default(), TODAY);
    let controls: Vec<&str> = fs.iter().map(|f| f.control).collect();
    assert_eq!(
        controls,
        vec!["RC-033", "RC-057", "RC-058", "RC-034", "RC-070", "RC-006", "RC-027", "RC-040"],
        "abstain/satisfies outcomes are part of the record, never dropped"
    );
}

// --- RC-027: error reporting ---

const GO_SERVER: &str = "package main\n\nimport \"net/http\"\n\nfunc main() {\n\thttp.ListenAndServe(\":8080\", nil)\n}\n";

/// A Go service: a main that listens, and a Dockerfile that ships it.
fn go_service(root: &Path) {
    write(root, "go.mod", "module example.com/api\n\ngo 1.22\n");
    write(root, "cmd/api/main.go", GO_SERVER);
    write(
        root,
        "Dockerfile",
        "FROM scratch\nEXPOSE 8080\nCMD [\"/api\"]\n",
    );
}

#[test]
fn rc027_go_service_without_a_tracker_violates() {
    let dir = tempfile::tempdir().unwrap();
    go_service(dir.path());
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-027");
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);
    assert_eq!(f.evidence, ["cmd/api/main.go"]);
    for searched in [
        "sentry",
        "bugsnag",
        "fluent-bit",
        "promtail",
        "otel-collector",
    ] {
        assert!(
            f.reason.contains(searched),
            "names what was looked for: {}",
            f.reason
        );
    }
}

#[test]
fn rc027_go_service_with_sentry_and_a_prometheus_rule_satisfies() {
    let dir = tempfile::tempdir().unwrap();
    go_service(dir.path());
    write(
        dir.path(),
        "cmd/api/main.go",
        "package main\n\nimport (\n\t\"net/http\"\n\t\"github.com/getsentry/sentry-go\"\n)\n\n\
         func main() {\n\tsentry.Init(sentry.ClientOptions{})\n\thttp.ListenAndServe(\":8080\", nil)\n}\n",
    );
    write(
        dir.path(),
        "deploy/alerts.yaml",
        "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n  name: api\n\
         spec:\n  groups:\n    - name: api\n      rules:\n        - alert: ErrorSpike\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-027");
    assert_eq!(f.verdict, Verdict::Satisfies, "reason: {}", f.reason);
    assert!(f.reason.starts_with("partial"), "{}", f.reason);
    assert_eq!(f.evidence, ["cmd/api/main.go", "deploy/alerts.yaml"]);
}

#[test]
fn rc027_library_with_a_dockerfile_only_under_target_abstains() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "go.mod", "module example.com/lib\n\ngo 1.22\n");
    write(dir.path(), "lib.go", "package lib\n\nfunc Dial() {}\n");
    write(
        dir.path(),
        "target/Dockerfile",
        "FROM scratch\nEXPOSE 8080\n",
    );
    // A test server is not the repository's server.
    write(dir.path(), "server_test.go", GO_SERVER);
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-027");
    assert_eq!(f.verdict, Verdict::Abstain, "reason: {}", f.reason);
}

#[test]
fn rc027_cli_main_without_a_listener_abstains() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "go.mod", "module example.com/tool\n\ngo 1.22\n");
    write(
        dir.path(),
        "main.go",
        "package main\n\nimport \"flag\"\n\nfunc main() { flag.Parse() }\n",
    );
    let fs = eval_dir(dir.path());
    let f = finding(&fs, "RC-027");
    assert_eq!(f.verdict, Verdict::Abstain, "reason: {}", f.reason);
}

#[test]
fn rc027_a_tracker_or_log_shipping_without_alert_rules_abstains() {
    for (path, text) in [
        ("requirements.txt", "flask==3.0.0\nsentry-sdk==2.0.0\n"),
        ("deploy/fluent-bit.conf", "[OUTPUT]\n    Name loki\n"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "app.py",
            "from flask import Flask\napp = Flask(__name__)\napp.run()\n",
        );
        write(dir.path(), path, text);
        let fs = eval_dir(dir.path());
        let f = finding(&fs, "RC-027");
        assert_eq!(f.verdict, Verdict::Abstain, "{path}: {}", f.reason);
        assert!(f.reason.contains(path), "{}", f.reason);
    }
}

#[test]
fn rc027_truncated_walk_never_violates() {
    let mut facts = RepoStructure::default();
    facts.error_reporting.listeners = vec!["main.go".into()];
    let f = finding(&evaluate(&facts, TODAY), "RC-027").clone();
    assert_eq!(f.verdict, Verdict::Abstain, "reason: {}", f.reason);
    facts.walk_complete = true;
    let f = finding(&evaluate(&facts, TODAY), "RC-027").clone();
    assert_eq!(f.verdict, Verdict::Violates, "reason: {}", f.reason);
}

// --- RC-040: SAST on the pull-request path ---

const SERVER_MAIN: &str = "package main\n\nfunc main() { http.ListenAndServe(\":8080\", nil) }\n";

/// A Go service with the given workflows, judged for RC-040.
fn rc040(workflows: &[(&str, &str)]) -> StructureFinding {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "cmd/api/main.go", SERVER_MAIN);
    for (path, text) in workflows {
        write(dir.path(), path, text);
    }
    finding(&eval_dir(dir.path()), "RC-040").clone()
}

fn wf(on: &str, steps: &str) -> String {
    format!("on: {on}\njobs:\n  sast:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n{steps}")
}

const SEMGREP: &str = "      - run: semgrep ci\n";
const CODEQL: &str =
    "      - uses: github/codeql-action/init@v3\n      - uses: github/codeql-action/analyze@v3\n";

#[test]
fn rc040_satisfies_a_gating_sast_step_on_a_pull_request_workflow() {
    for (on, steps) in [
        ("[pull_request]", SEMGREP),
        ("[merge_group]", CODEQL),
        (
            "\n  pull_request:\n    branches: [main]\n  push:",
            "      - uses: securego/gosec@v2\n        with:\n          args: ./...\n",
        ),
        (
            "{pull_request: {}}",
            "      - run: |\n          pip install bandit\n          bandit -r src\n",
        ),
        (
            "[pull_request]",
            "      - uses: snyk/actions/node@master\n        with:\n          command: code test\n",
        ),
    ] {
        let f = rc040(&[(".github/workflows/sast.yml", &wf(on, steps))]);
        assert_eq!(f.verdict, Verdict::Satisfies, "{on} {steps}: {f:?}");
        assert_eq!(f.evidence, vec![".github/workflows/sast.yml"]);
    }
    // A GitLab job in merge request pipelines.
    let f = rc040(&[(
        ".gitlab-ci.yml",
        "semgrep:\n  image: semgrep/semgrep\n  script: semgrep ci\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n",
    )]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
}

#[test]
fn rc040_a_local_reusable_workflow_runs_on_its_callers_triggers() {
    let callee = "on: [workflow_call]\njobs:\n  s:\n    runs-on: ubuntu-latest\n    steps:\n      - run: semgrep ci\n";
    let f = rc040(&[
        (
            ".github/workflows/ci.yml",
            "on: [pull_request]\njobs:\n  sast:\n    uses: ./.github/workflows/semgrep.yml\n",
        ),
        (".github/workflows/semgrep.yml", callee),
    ]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
    assert_eq!(f.evidence, vec![".github/workflows/semgrep.yml"]);
    let f = rc040(&[
        (
            ".github/workflows/nightly.yml",
            "on: [schedule]\njobs:\n  sast:\n    uses: ./.github/workflows/semgrep.yml\n",
        ),
        (".github/workflows/semgrep.yml", callee),
    ]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
    // Called by no local workflow: another repository may call it.
    let f = rc040(&[(".github/workflows/semgrep.yml", callee)]);
    assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
}

#[test]
fn rc040_a_remote_reusable_workflow_named_for_sast_is_a_sast_step() {
    let f = rc040(&[(
        ".github/workflows/ci.yml",
        "on: [pull_request]\njobs:\n  sast:\n    uses: org/security/.github/workflows/sast.yml@v1\n",
    )]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
    assert!(
        f.reason.contains("org/security/.github/workflows/sast.yml"),
        "{f:?}"
    );
}

#[test]
fn rc040_violates_m1_ci_without_any_sast_step() {
    let f = rc040(&[
        (".github/workflows/ci.yml", WF_BUILD_ONLY),
        // Dependency scanning is not SAST.
        (".github/workflows/deps.yml", &wf("[pull_request]", "      - uses: actions/dependency-review-action@v4\n      - uses: snyk/actions/node@master\n")),
    ]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
    assert!(
        f.reason
            .contains("2 CI file(s) read and none runs a SAST step"),
        "{f:?}"
    );
    let f = rc040(&[(".gitlab-ci.yml", "test:\n  script: make test\n")]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
    // A CI system whose steps are not read may run the SAST.
    let f = rc040(&[
        (".github/workflows/ci.yml", WF_BUILD_ONLY),
        (
            "Jenkinsfile",
            "pipeline { stages { stage('sast') { steps { sh 'semgrep ci' } } } }\n",
        ),
    ]);
    assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
    assert!(
        f.reason
            .contains("CI config not read for SAST: Jenkinsfile"),
        "{f:?}"
    );
}

#[test]
fn rc040_violates_m3_sast_only_off_the_pull_request_path() {
    let f = rc040(&[
        (
            ".github/workflows/ci.yml",
            &wf("[pull_request]", "      - run: make test\n"),
        ),
        (
            ".github/workflows/codeql.yml",
            &wf(
                "\n  push:\n    branches: [main]\n  schedule:\n    - cron: '0 0 * * 0'",
                CODEQL,
            ),
        ),
    ]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
    assert!(
        f.reason
            .contains("not triggered by pull_request or merge_group"),
        "{f:?}"
    );
    assert_eq!(f.evidence, vec![".github/workflows/codeql.yml"]);
}

#[test]
fn rc040_violates_m2a_every_pull_request_sast_step_continues_on_error() {
    for steps in [
        "      - run: semgrep ci\n        continue-on-error: true\n",
        "      - run: gosec ./... || true\n",
        "      - run: |\n          bandit -r src \\\n            --exit-zero\n",
    ] {
        let f = rc040(&[(".github/workflows/sast.yml", &wf("[pull_request]", steps))]);
        assert_eq!(f.verdict, Verdict::Violates, "{steps}: {f:?}");
        assert!(f.reason.contains("continues on error"), "{f:?}");
    }
    // A job that continues on error lets its steps' findings pass.
    let f = rc040(&[(
        ".github/workflows/sast.yml",
        "on: [pull_request]\njobs:\n  sast:\n    runs-on: ubuntu-latest\n    continue-on-error: true\n    steps:\n      - run: semgrep ci\n",
    )]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
    let f = rc040(&[(
        ".gitlab-ci.yml",
        "sast:\n  script: [semgrep ci]\n  allow_failure: true\n  only: [merge_requests]\n",
    )]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
}

#[test]
fn rc040_a_line_that_continues_without_running_sast_does_not_excuse_it() {
    let f = rc040(&[(
        ".github/workflows/sast.yml",
        &wf(
            "[pull_request]",
            "      - run: |\n          make lint || true\n          gosec ./...\n",
        ),
    )]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
    // One SAST line that continues does not excuse another that gates.
    let f = rc040(&[(
        ".github/workflows/sast.yml",
        &wf(
            "[pull_request]",
            "      - run: |\n          gosec ./... || true\n          bandit -r src\n",
        ),
    )]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
}

/// The shape of a real security workflow: gosec installed, then run by its
/// GOPATH path; a report-only `semgrep scan` beside it.
#[test]
fn rc040_reads_a_scanner_run_by_its_install_path() {
    let f = rc040(&[(
        ".github/workflows/security.yml",
        &wf(
            "\n  push:\n    branches: [main]\n  pull_request:",
            "      - run: go install github.com/securego/gosec/v2/cmd/gosec@v2.30.0\n      - run: |\n          mkdir -p \"$RUNNER_TEMP/reports\"\n          \"$(go env GOPATH)/bin/gosec\" -exclude-dir=testdata \\\n            -fmt sarif ./...\n      - run: python -m pip install semgrep==1.183.0\n      - run: semgrep scan --config p/default --text\n",
        ),
    )]);
    assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
    assert!(
        f.reason.contains("gosec (.github/workflows/security.yml)"),
        "{f:?}"
    );
    // Installing a scanner is not running one: it keeps no violation from
    // being read.
    let f = rc040(&[(
        ".github/workflows/sast.yml",
        &wf(
            "[pull_request]",
            "      - run: pip install semgrep\n      - run: semgrep ci || true\n",
        ),
    )]);
    assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
}

#[test]
fn rc040_abstains_without_a_server_entry_point_or_ci() {
    // A library: no server entry point outside tests and examples.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "lib.go", "package lib\n");
    write(dir.path(), "examples/server/main.go", SERVER_MAIN);
    write(dir.path(), "server_test.go", SERVER_MAIN);
    write(dir.path(), "vendor/x/main.go", SERVER_MAIN);
    write(dir.path(), ".github/workflows/ci.yml", WF_BUILD_ONLY);
    let facts = inventory(dir.path());
    assert!(
        facts.server_entry_points.is_empty(),
        "{:?}",
        facts.server_entry_points
    );
    let f = finding(&evaluate(&facts, TODAY), "RC-040").clone();
    assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
    assert!(f.reason.contains("no server entry point"), "{f:?}");
    // A service with no CI files at all.
    let f = rc040(&[]);
    assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
    assert!(f.reason.contains("no GitHub Actions workflow"), "{f:?}");
}

/// What the walk cannot see may be the step that gates: no violation.
#[test]
fn rc040_abstains_when_a_gating_step_could_be_out_of_sight() {
    let cases: Vec<(&str, String)> = vec![
        // An opaque call could run SAST.
        (".github/workflows/ci.yml", "on: [pull_request]\njobs:\n  s:\n    uses: org/shared/.github/workflows/security.yml@v2\n".into()),
        // A SAST scanner this rule does not judge.
        (".github/workflows/ci.yml", wf("[pull_request]", "      - uses: SonarSource/sonarcloud-github-action@v2\n")),
        (".github/workflows/ci.yml", wf("[pull_request]", "      - run: semgrep scan --config auto\n")),
        // A path filter, a condition, pull_request_target, an expression.
        (".github/workflows/ci.yml", wf("\n  pull_request:\n    paths: ['src/**']", SEMGREP)),
        (".github/workflows/ci.yml", wf("[pull_request]", "      - run: semgrep ci\n        if: github.event_name == 'push'\n")),
        (".github/workflows/ci.yml", wf("[pull_request_target]", SEMGREP)),
        (".github/workflows/ci.yml", wf("[pull_request]", "      - run: semgrep ci\n        continue-on-error: ${{ inputs.soft }}\n")),
        // A pipe without pipefail, a shell without -e.
        (".github/workflows/ci.yml", wf("[pull_request]", "      - run: semgrep ci | tee semgrep.txt\n")),
        (".github/workflows/ci.yml", wf("[pull_request]", "      - shell: bash {0}\n        run: |\n          gosec ./...\n          echo done\n")),
        // GitLab branch pipelines and includes.
        (".gitlab-ci.yml", "sast:\n  script: semgrep ci\n".into()),
        (".gitlab-ci.yml", "include:\n  - template: Security/SAST.gitlab-ci.yml\ntest:\n  script: make test\n".into()),
        (".gitlab-ci.yml", ".base:\n  script: semgrep ci\nsast:\n  extends: .base\n".into()),
        // An unparsed workflow.
        (".github/workflows/ci.yml", "jobs:\n  a: [unclosed\n".into()),
    ];
    for (path, text) in &cases {
        let files = [(*path, text.as_str())];
        let f = rc040(&files);
        assert_eq!(f.verdict, Verdict::Abstain, "{files:?}: {f:?}");
    }
}

#[test]
fn rc040_facts_round_trip_and_an_older_record_abstains() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "cmd/api/main.go", SERVER_MAIN);
    write(
        dir.path(),
        ".github/workflows/sast.yml",
        &wf("[pull_request]", SEMGREP),
    );
    let facts = inventory(dir.path());
    assert_eq!(facts.server_entry_points, vec!["cmd/api/main.go"]);
    let line = facts.to_jsonl();
    assert!(
        line.contains(r#""pr_path":"yes","on_failure":"fails""#),
        "{line}"
    );
    assert_eq!(parse_record(&line).expect("round trip"), facts);
    let old = r#"{"kind":"repo_structure","snapshot_id":"s","ecosystems":[],"walk_complete":true}"#;
    let f = finding(&evaluate(&parse_record(old).unwrap(), TODAY), "RC-040").clone();
    assert_eq!(f.verdict, Verdict::Abstain);
}

// --- RC-027 answer key (testdata/rc027-key) ---

/// The answer key stays scoreable offline: every row parses with the keys
/// `examples/rc027_key.rs` and `fetch.sh` read, in the order `fetch.sh`
/// reads them, a decided label only on a service, and no repository twice.
#[test]
fn rc027_answer_key_is_well_formed() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/rc027-key/key.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut repos = std::collections::BTreeSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        let o = v.as_object().unwrap();
        let keys: Vec<&str> = o.keys().map(String::as_str).collect();
        assert_eq!(keys, ["commit", "kind", "repo", "truth", "why"], "{line}");
        let s = |k: &str| o[k].as_str().unwrap();
        assert!(line.starts_with(&format!(
            "{{\"repo\": \"{}\", \"commit\": \"{}\"",
            s("repo"),
            s("commit")
        )));
        assert!(repos.insert(s("repo").to_string()), "{} twice", s("repo"));
        assert_eq!(s("commit").len(), 40, "{line}");
        assert!(
            ["service", "library", "cli", "tool"].contains(&s("kind")),
            "{line}"
        );
        assert!(
            ["violates", "satisfies", "abstain"].contains(&s("truth")),
            "{line}"
        );
        assert!(s("truth") == "abstain" || s("kind") == "service", "{line}");
        assert!(!s("why").trim().is_empty(), "{line}");
    }
    assert!(repos.len() >= 100, "{} rows", repos.len());
}
