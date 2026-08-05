//! The walker: observable facts about a repository's shape. RETRIEVAL only —
//! it reports what is present (names, counts, markers), never a verdict.
//! Contents are read locally to detect markers; no source text is stored.

use crate::{EcosystemFacts, ManifestFacts, RepoStructure};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Directories never worth descending into: vendored deps and build output.
/// A vendored dependency's tests must not satisfy the repo's own controls.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".next",
    ".cache",
];

/// Directory names that carry the integration/e2e test convention.
const INTEGRATION_DIRS: &[&str] = &[
    "integration",
    "integrationtest",
    "integrationtests",
    "integration_tests",
    "integration-tests",
    "e2e",
    "acceptance",
    "smoke",
];

/// Directory names that carry the runbook convention (RC-006, weak signal).
const RUNBOOK_DIRS: &[&str] = &["runbooks", "runbook", "playbooks"];

/// Lockfiles that govern an npm manifest (same dir or an ancestor, for
/// workspace/monorepo layouts where one root lock governs every member).
const NPM_LOCKS: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
    "bun.lock",
];

const PYPROJECT_LOCKS: &[&str] = &["poetry.lock", "uv.lock", "pdm.lock", "pylock.toml"];

/// Cap on marker content reads: enough for any config file and for the
/// `#[cfg(test)]` marker in ordinary Rust sources, bounded so a generated
/// megafile cannot turn the inventory walk into a full-content crawl.
const MAX_MARKER_READ: u64 = 256 * 1024;

fn read_capped(path: &Path) -> String {
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = f.take(MAX_MARKER_READ).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Repo-relative, forward-slashed spelling of `file` under `root`.
fn rel(root: &Path, file: &Path) -> String {
    let r = file.strip_prefix(root).unwrap_or(file);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[derive(Default)]
struct EcoAcc {
    sources: u32,
    tests: u32,
    markers: BTreeSet<String>,
}

#[derive(Default)]
struct Acc {
    ecos: BTreeMap<&'static str, EcoAcc>,
    coverage: BTreeSet<String>,
    contract: BTreeSet<String>,
    manifests: Vec<ManifestFacts>,
    runbooks: BTreeSet<String>,
    walk_complete: bool,
}

impl Acc {
    fn eco(&mut self, name: &'static str) -> &mut EcoAcc {
        self.ecos.entry(name).or_default()
    }
}

/// Inventory the repository at `root`. Bounded single walk that skips
/// vendored/build directories.
pub fn inventory(root: &Path) -> RepoStructure {
    let mut acc = Acc {
        walk_complete: true,
        ..Default::default()
    };
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => {
                // An unreadable directory truncates the walk: reasoning from
                // absence is no longer licensed (mirrors Provenance::complete).
                acc.walk_complete = false;
                continue;
            }
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                acc.walk_complete = false;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if ft.is_dir() {
                if SKIP_DIRS.contains(&name.as_str()) {
                    continue;
                }
                if RUNBOOK_DIRS.contains(&name.to_ascii_lowercase().as_str()) {
                    acc.runbooks.insert(rel(root, &entry.path()));
                }
                stack.push(entry.path());
            } else if ft.is_file() {
                classify_file(root, &entry.path(), &name, &mut acc);
            }
        }
    }

    resolve_lockfiles(root, &mut acc.manifests);
    acc.manifests.sort_by(|a, b| a.path.cmp(&b.path));

    RepoStructure {
        kind: crate::RECORD_KIND.to_string(),
        snapshot_id: String::new(),
        ecosystems: acc
            .ecos
            .into_iter()
            .map(|(name, e)| EcosystemFacts {
                name: name.to_string(),
                source_files: e.sources,
                test_files: e.tests,
                integration_markers: e.markers.into_iter().collect(),
            })
            .collect(),
        coverage_configs: acc.coverage.into_iter().collect(),
        contract_frameworks: acc.contract.into_iter().collect(),
        manifests: acc.manifests,
        runbook_dirs: acc.runbooks.into_iter().collect(),
        walk_complete: acc.walk_complete,
    }
}

/// The directory components of a repo-relative path (file name excluded),
/// lowercased for convention matching.
fn dir_components(rel_path: &str) -> Vec<String> {
    let mut comps: Vec<String> = rel_path
        .split('/')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    comps.pop(); // the file name
    comps
}

/// The rel-path prefix up to and including the first component matching one
/// of `names`, if any — the marker DIRECTORY, not the file inside it.
fn dir_prefix_matching(rel_path: &str, names: &[&str]) -> Option<String> {
    let comps: Vec<&str> = rel_path.split('/').collect();
    for i in 0..comps.len().saturating_sub(1) {
        if names.contains(&comps[i].to_ascii_lowercase().as_str()) {
            return Some(comps[..=i].join("/"));
        }
    }
    None
}

fn is_declaration_ts(name: &str) -> bool {
    name.ends_with(".d.ts")
}

fn classify_file(root: &Path, path: &Path, name: &str, acc: &mut Acc) {
    let rp = rel(root, path);
    let dirs = dir_components(&rp);
    let has_dir = |n: &str| dirs.iter().any(|c| c == n);
    let integration_dir = dir_prefix_matching(&rp, INTEGRATION_DIRS);

    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // --- ecosystems + test conventions ---
    match ext.as_str() {
        "go" => {
            let is_test = name.ends_with("_test.go");
            let e = acc.eco("go");
            e.sources += 1;
            if is_test {
                e.tests += 1;
            }
            if name.ends_with("_integration_test.go") {
                e.markers.insert(rp.clone());
            } else if is_test {
                if let Some(d) = &integration_dir {
                    e.markers.insert(d.clone());
                }
            }
        }
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" if !is_declaration_ts(name) => {
            let is_test =
                name.contains(".test.") || name.contains(".spec.") || has_dir("__tests__");
            // Cypress spec convention (`*.cy.ts`) and e2e runner configs are
            // integration markers, not unit tests.
            let e2e_config =
                name.starts_with("playwright.config.") || name.starts_with("cypress.config.");
            let is_cy = name.contains(".cy.");
            let e = acc.eco("js");
            e.sources += 1;
            if is_test {
                e.tests += 1;
            }
            if e2e_config || is_cy {
                e.markers.insert(rp.clone());
            } else if is_test {
                if let Some(d) = &integration_dir {
                    e.markers.insert(d.clone());
                }
            }
        }
        "py" => {
            let is_test = name.starts_with("test_")
                || name.ends_with("_test.py")
                || name == "conftest.py"
                || has_dir("tests")
                || has_dir("test");
            let e = acc.eco("python");
            e.sources += 1;
            if is_test {
                e.tests += 1;
                if let Some(d) = &integration_dir {
                    e.markers.insert(d.clone());
                }
            }
        }
        "rs" => {
            // Inline `#[cfg(test)]` is the dominant Rust idiom; a name-only
            // scan would call an ordinarily-tested Rust repo testless, and a
            // false "no tests" accusation is the error this walker refuses.
            let is_test = has_dir("tests") || read_capped(path).contains("#[cfg(test)]");
            let e = acc.eco("rust");
            e.sources += 1;
            if is_test {
                e.tests += 1;
                if let Some(d) = &integration_dir {
                    e.markers.insert(d.clone());
                }
            }
        }
        "java" => {
            let in_src_test = rp.contains("/src/test/") || rp.starts_with("src/test/");
            let is_test = in_src_test
                || name.ends_with("Test.java")
                || name.ends_with("Tests.java")
                || name.ends_with("IT.java");
            let e = acc.eco("java");
            e.sources += 1;
            if is_test {
                e.tests += 1;
                if name.ends_with("IT.java") {
                    e.markers.insert(rp.clone());
                } else if let Some(d) = &integration_dir {
                    e.markers.insert(d.clone());
                }
            }
        }
        _ => {}
    }

    // --- coverage configuration ---
    const COVERAGE_NAMES: &[&str] = &[
        "codecov.yml",
        ".codecov.yml",
        "codecov.yaml",
        ".codecov.yaml",
        ".coveragerc",
        "tarpaulin.toml",
        ".tarpaulin.toml",
        ".nycrc",
        ".nycrc.json",
        ".nycrc.yml",
    ];
    const COVERAGE_TOKENS: &[&str] = &[
        "-cover",
        "--cov",
        "coverage run",
        "tarpaulin",
        "llvm-cov",
        "go tool cover",
        "covermode",
        "codecov",
        "collectcoverage",
        "coveragethreshold",
    ];
    let is_ci_file = (rp.starts_with(".github/workflows/")
        && (rp.ends_with(".yml") || rp.ends_with(".yaml")))
        || rp == ".gitlab-ci.yml"
        || rp == ".circleci/config.yml"
        || rp == "azure-pipelines.yml"
        || name == "Jenkinsfile";
    let is_makefile = name == "Makefile" || name == "makefile" || name == "GNUmakefile";
    if COVERAGE_NAMES.contains(&name) {
        acc.coverage.insert(rp.clone());
    } else if name.starts_with("jest.config.") || name.starts_with("vitest.config.") {
        if read_capped(path).contains("coverage") {
            acc.coverage.insert(rp.clone());
        }
    } else if name == "pyproject.toml" {
        if read_capped(path).contains("[tool.coverage") {
            acc.coverage.insert(rp.clone());
        }
    } else if name == "setup.cfg" {
        if read_capped(path).contains("[coverage:") {
            acc.coverage.insert(rp.clone());
        }
    } else if is_ci_file || is_makefile {
        let text = read_capped(path).to_ascii_lowercase();
        if COVERAGE_TOKENS.iter().any(|t| text.contains(t)) {
            acc.coverage.insert(rp.clone());
        }
    } else if name == "package.json" {
        let text = read_capped(path);
        if text.contains("collectCoverage") || text.contains("coverageThreshold") {
            acc.coverage.insert(rp.clone());
        }
    }

    // --- contract-test frameworks + dependency manifests ---
    match name {
        "package.json" => {
            let text = read_capped(path);
            if text.contains("@pact-foundation/") {
                acc.contract.insert(format!("pact ({rp})"));
            }
            if text.contains("\"dredd\"") {
                acc.contract.insert(format!("dredd ({rp})"));
            }
            acc.manifests.push(npm_manifest(&rp, &text));
        }
        "go.mod" => {
            let text = read_capped(path);
            if text.contains("pact-go") {
                acc.contract.insert(format!("pact ({rp})"));
            }
            acc.manifests.push(ManifestFacts {
                path: rp.clone(),
                kind: "gomod".into(),
                deps: gomod_deps(&text),
                ..Default::default()
            });
        }
        "Cargo.toml" => {
            let text = read_capped(path);
            if text.contains("pact_consumer") || text.contains("pact_verifier") {
                acc.contract.insert(format!("pact ({rp})"));
            }
            acc.manifests.push(ManifestFacts {
                path: rp.clone(),
                kind: "cargo".into(),
                deps: cargo_deps(&text),
                ..Default::default()
            });
        }
        "pyproject.toml" => {
            let text = read_capped(path);
            python_contract_markers(&text, &rp, acc);
            acc.manifests.push(ManifestFacts {
                path: rp.clone(),
                kind: "pyproject".into(),
                deps: pyproject_deps(&text),
                ..Default::default()
            });
        }
        "Pipfile" => {
            let text = read_capped(path);
            python_contract_markers(&text, &rp, acc);
            acc.manifests.push(ManifestFacts {
                path: rp.clone(),
                kind: "pipfile".into(),
                deps: pipfile_deps(&text),
                ..Default::default()
            });
        }
        "pom.xml" | "build.gradle" | "build.gradle.kts" => {
            if read_capped(path).contains("spring-cloud-contract") {
                acc.contract.insert(format!("spring-cloud-contract ({rp})"));
            }
        }
        "buf.yaml" | "buf.yml" => {
            if read_capped(path).contains("breaking") {
                acc.contract
                    .insert(format!("buf breaking-change gate ({rp})"));
            }
        }
        _ if name.starts_with("requirements") && name.ends_with(".txt") => {
            let text = read_capped(path);
            python_contract_markers(&text, &rp, acc);
            let (deps, pinned) = requirements_pins(&text);
            acc.manifests.push(ManifestFacts {
                path: rp.clone(),
                kind: "requirements".into(),
                deps,
                pinned,
                floating: deps - pinned,
                ..Default::default()
            });
        }
        _ => {}
    }

    // --- runbook conventions carried by loose docs (ops/ with markdown) ---
    if ext == "md" {
        let d = dirs.join("/");
        if d == "ops" || d == "docs/ops" {
            acc.runbooks.insert(d);
        }
    }
}

fn python_contract_markers(text: &str, rp: &str, acc: &mut Acc) {
    if text.contains("pact-python") || text.contains("pactman") {
        acc.contract.insert(format!("pact ({rp})"));
    }
    if text.contains("schemathesis") {
        acc.contract.insert(format!("schemathesis ({rp})"));
    }
}

fn npm_manifest(rp: &str, text: &str) -> ManifestFacts {
    let deps = serde_json::from_str::<serde_json::Value>(text)
        .map(|v| {
            ["dependencies", "devDependencies", "optionalDependencies"]
                .iter()
                .filter_map(|k| v.get(k).and_then(|d| d.as_object()).map(|o| o.len()))
                .sum::<usize>() as u32
        })
        .unwrap_or(0);
    ManifestFacts {
        path: rp.to_string(),
        kind: "npm".into(),
        deps,
        ..Default::default()
    }
}

fn gomod_deps(text: &str) -> u32 {
    let mut deps = 0;
    let mut in_require = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("require (") {
            in_require = true;
            continue;
        }
        if in_require {
            if t == ")" {
                in_require = false;
            } else if !t.is_empty() && !t.starts_with("//") {
                deps += 1;
            }
            continue;
        }
        if t.starts_with("require ") {
            deps += 1;
        }
    }
    deps
}

fn cargo_deps(text: &str) -> u32 {
    let mut deps = 0;
    let mut in_deps = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            let header = t.trim_start_matches('[').trim_end_matches(']');
            if header.contains("dependencies.") {
                // `[dependencies.serde]`-style table: one dep.
                deps += 1;
                in_deps = false;
            } else {
                in_deps = header.ends_with("dependencies");
            }
            continue;
        }
        if in_deps && !t.is_empty() && !t.starts_with('#') && t.contains('=') {
            deps += 1;
        }
    }
    deps
}

fn pyproject_deps(text: &str) -> u32 {
    let mut deps = 0;
    let mut in_array = false;
    let mut in_poetry = false;
    for line in text.lines() {
        let t = line.trim();
        if in_array {
            if t.starts_with(']') {
                in_array = false;
            } else if t.starts_with('"') || t.starts_with('\'') {
                deps += 1;
            }
            continue;
        }
        if in_poetry {
            if t.starts_with('[') {
                in_poetry = false; // fall through to header handling
            } else {
                if !t.is_empty()
                    && !t.starts_with('#')
                    && t.contains('=')
                    && !t.starts_with("python")
                {
                    deps += 1;
                }
                continue;
            }
        }
        if t.starts_with("dependencies") && t.contains('[') {
            // `dependencies = ["requests", ...]` — count inline entries; if
            // the array continues on later lines, keep counting there.
            deps += (t.matches('"').count() / 2) as u32;
            if !t.contains(']') {
                in_array = true;
            }
        } else if t == "[tool.poetry.dependencies]" {
            in_poetry = true;
        }
    }
    deps
}

fn pipfile_deps(text: &str) -> u32 {
    let mut deps = 0;
    let mut in_packages = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_packages = t == "[packages]" || t == "[dev-packages]";
            continue;
        }
        if in_packages && !t.is_empty() && !t.starts_with('#') && t.contains('=') {
            deps += 1;
        }
    }
    deps
}

/// (total, pinned) requirement lines. `-r`/`-c`/flag lines are includes, not
/// dependencies; `-e` editable installs count as floating.
fn requirements_pins(text: &str) -> (u32, u32) {
    let (mut deps, mut pinned) = (0, 0);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("-r") || t.starts_with("-c") {
            continue;
        }
        if t.starts_with("--") {
            continue;
        }
        deps += 1;
        if t.contains("==") {
            pinned += 1;
        }
    }
    (deps, pinned)
}

/// Attach the lockfiles governing each manifest: same directory, or an
/// ancestor up to the repo root for ecosystems whose workspace layouts keep
/// one root lock (npm workspaces, cargo workspaces, uv/poetry monorepos).
/// go.sum is always adjacent to its go.mod.
fn resolve_lockfiles(root: &Path, manifests: &mut [ManifestFacts]) {
    for m in manifests.iter_mut() {
        let (candidates, ancestors): (&[&str], bool) = match m.kind.as_str() {
            "npm" => (NPM_LOCKS, true),
            "gomod" => (&["go.sum"], false),
            "cargo" => (&["Cargo.lock"], true),
            "pyproject" => (PYPROJECT_LOCKS, true),
            "pipfile" => (&["Pipfile.lock"], false),
            _ => (&[], false),
        };
        if candidates.is_empty() {
            continue;
        }
        let abs = root.join(&m.path);
        let mut dir: PathBuf = abs.parent().unwrap_or(root).to_path_buf();
        let mut found = BTreeSet::new();
        loop {
            for c in candidates {
                let cand = dir.join(c);
                if cand.is_file() {
                    found.insert(rel(root, &cand));
                }
            }
            if !ancestors || dir.as_path() == root {
                break;
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => break,
            }
        }
        m.lockfiles = found.into_iter().collect();
    }
}
