//! What the REPOSITORY ITSELF says is build/dev tooling (po-av01j.173).
//!
//! `rvl_core::scope_of` classifies from the path and nothing else, so build
//! tooling parked at the repo root reads as Runtime and the runtime-scoped
//! judgments grade its unbounded call high/blocking. On open-webui that was 3
//! of 6 blocking findings: a commit failed over a hatchling build hook and a
//! contributor-stats script, neither of which is on any request path.
//!
//! EVIDENCE, NOT PATH GUESSING — the same discipline the generated-code lane
//! follows (see `GENERATED_MARKERS` in `main.rs`), and for the same reason. A
//! rule like "any root-level .py is tooling" would exempt a single-module
//! service, and a false dev_only HIDES a real finding, which is strictly worse
//! than the noise it removes. So both rules here rest on something the project
//! declares, or on the demonstrable absence of any wiring at all:
//!
//! 1. DECLARED BUILD HOOK. `[tool.hatch.build.hooks.custom]` in pyproject.toml
//!    names the hook file (`path`, defaulting to `hatch_build.py`). The
//!    project's own manifest says the BUILD executes this file. An UNDECLARED
//!    `hatch_build.py` stays Runtime: without the table hatchling never runs
//!    it, so the name alone is exactly the guess this lane refuses to make.
//! 2. UNREFERENCED ROOT-LEVEL SCRIPT. A `.py` directly at the repo root, in a
//!    repo whose Python lives in packages below it, carrying a `__main__`
//!    guard, that NOTHING else in the repo mentions — not an import, not a
//!    Dockerfile, not a CI job, not a README line. Nothing runs it and nothing
//!    imports it, so it is not on a runtime path. Every clause is required;
//!    dropping any one of them starts demoting service entry points.
//!
//! Both rules are Python-shaped, because that is where the evidence is: the
//! declaration lives in a Python manifest and the layout fact is a Python
//! packaging fact. Other ecosystems need their own evidence sources (a
//! `build.gradle` buildSrc, an npm `scripts` entry, a Makefile recipe), not a
//! widened path rule.

use rvl_core::{ScopeClass, Site};
use std::collections::BTreeSet;
use std::path::Path;

/// Directories that are never repo evidence. Belt and suspenders next to the
/// gitignore-aware walk: `vendor/` and `testdata/` are not always ignored.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
];

/// Hatchling's documented default hook file when the custom-hook table carries
/// no explicit `path`. open-webui declares exactly that shape:
/// `[tool.hatch.build.hooks.custom]` with only a comment under it.
const HATCH_DEFAULT_HOOK: &str = "hatch_build.py";

/// The pyproject table suffix that declares a custom build hook, under either
/// `tool.hatch.build.hooks` or `tool.hatch.build.targets.<target>.hooks`.
const HATCH_CUSTOM_HOOK: &str = "custom";

/// Largest file the reference scan will read. A reference to a script is a
/// line in a manifest, a Dockerfile, a CI job or a README; nothing of this
/// size is that, and reading a 100 MB asset to find out is not free.
const MAX_REFERENCE_BYTES: usize = 1 << 20;

/// Extensions that cannot carry a readable reference. A BLOCKLIST on purpose:
/// an unrecognized file type is READ, so an unforeseen referrer keeps the
/// script Runtime instead of silently demoting it.
const BINARY_EXTS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "bmp", "webp", "tiff", "pdf", "zip", "gz", "tgz", "bz2",
    "xz", "7z", "jar", "war", "class", "so", "dylib", "dll", "exe", "bin", "o", "a", "wasm",
    "woff", "woff2", "ttf", "otf", "eot", "mp3", "mp4", "webm", "mov", "avi", "wav", "db",
    "sqlite", "sqlite3", "pyc", "pack", "idx",
];

/// The repo-relative paths this repository's own evidence puts outside the
/// runtime surface. Built once per scan and applied to every site.
#[derive(Debug, Default, Clone)]
pub struct DevScope {
    dev_only: BTreeSet<String>,
}

impl DevScope {
    /// Gather the evidence under `root`. Never fails: an unreadable manifest
    /// or an unwalkable tree yields LESS evidence, which means more sites stay
    /// Runtime — the safe direction.
    pub fn detect(root: &Path) -> Self {
        let files = walk(root);
        let mut dev_only = BTreeSet::new();
        for rel in files.iter().filter(|f| base_of(f) == "pyproject.toml") {
            let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
                continue;
            };
            let dir = rel.rsplit_once('/').map_or("", |(d, _)| d);
            for hook in declared_hatch_hooks(dir, &text) {
                // The declaration must point at a file that exists; a stale
                // `path` is not evidence about anything in this tree.
                if root.join(&hook).is_file() {
                    dev_only.insert(hook);
                }
            }
        }
        dev_only.extend(unreferenced_root_scripts(root, &files));
        Self { dev_only }
    }

    /// Stamp the evidence onto every site. Assigns unconditionally, including
    /// `None`: sites reused from the incremental index carry whatever the last
    /// run stamped, and a manifest that stopped declaring a hook must take the
    /// exemption away rather than leave a stale one in place.
    pub fn annotate(&self, sites: &mut [Site]) {
        for s in sites.iter_mut() {
            s.scope_override = self
                .dev_only
                .contains(&crate::normalize_rel(&s.file_path))
                .then_some(ScopeClass::DevOnly);
        }
    }

    /// How many files the evidence covers (for reporting, and for tests).
    pub fn len(&self) -> usize {
        self.dev_only.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dev_only.is_empty()
    }
}

fn base_of(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

/// Repo-relative file paths, gitignore-aware. Mirrors the config lane's walk:
/// gitignored output is not repo evidence, `hidden(false)` keeps `.github`
/// in scope, `git_global(false)` keeps the answer independent of whose
/// machine ran it.
fn walk(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .parents(true)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIRS.contains(&name.as_ref())
        })
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        out.push(rel);
    }
    out
}

/// Build-hook files a pyproject.toml DECLARES, as repo-relative paths.
///
/// Reads only the shapes hatchling documents — `[tool.hatch.build.hooks.custom]`
/// and the per-target `[tool.hatch.build.targets.<t>.hooks.custom]` — and takes
/// the table's `path`, or hatchling's `hatch_build.py` default when it names
/// none. Anything else in the manifest is ignored: an unrecognized shape yields
/// no evidence and the file stays Runtime.
fn declared_hatch_hooks(dir: &str, text: &str) -> Vec<String> {
    let Ok(doc) = text.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(build) = doc
        .get("tool")
        .and_then(|t| t.get("hatch"))
        .and_then(|h| h.get("build"))
    else {
        return Vec::new();
    };
    let mut hooks: Vec<&toml::Value> = Vec::new();
    if let Some(h) = build.get("hooks").and_then(|h| h.get(HATCH_CUSTOM_HOOK)) {
        hooks.push(h);
    }
    if let Some(targets) = build.get("targets").and_then(|t| t.as_table()) {
        for (_, target) in targets {
            if let Some(h) = target.get("hooks").and_then(|h| h.get(HATCH_CUSTOM_HOOK)) {
                hooks.push(h);
            }
        }
    }
    hooks
        .into_iter()
        .map(|h| {
            let path = h
                .get("path")
                .and_then(|p| p.as_str())
                .unwrap_or(HATCH_DEFAULT_HOOK);
            join_rel(dir, path)
        })
        .collect()
}

/// Join a manifest's directory with a path it declares, normalized the way
/// site paths are (forward slashes, no leading `./`).
fn join_rel(dir: &str, path: &str) -> String {
    let path = path.trim_start_matches("./").replace('\\', "/");
    if dir.is_empty() {
        path
    } else {
        format!("{dir}/{path}")
    }
}

/// Root-level Python scripts that nothing in the repository references.
///
/// Every clause is load-bearing:
///   - a root `__init__.py` would make the root a package and every file in it
///     an importable module, so the evidence is void;
///   - Python living only at the root means the root IS the project, and its
///     entry point must never be demoted;
///   - a `__main__` guard is the file declaring itself something you RUN, not
///     something you import;
///   - and then: zero mentions anywhere. An entry point is named by a
///     Dockerfile, a compose file, a Procfile, a CI job, a Makefile or a
///     README; a one-off maintenance script is named by nothing. The search is
///     for the bare module stem, so it catches `import x`, `x.py`, `python
///     x.py` and `uvicorn x:app` alike — and any incidental mention keeps the
///     file Runtime, which is the direction to err in.
fn unreferenced_root_scripts(root: &Path, files: &[String]) -> Vec<String> {
    if files.iter().any(|f| f == "__init__.py") {
        return Vec::new();
    }
    if !files.iter().any(|f| f.contains('/') && f.ends_with(".py")) {
        return Vec::new();
    }
    let candidates: Vec<String> = files
        .iter()
        .filter(|f| !f.contains('/') && f.ends_with(".py"))
        .filter(|f| has_main_guard(&root.join(f)))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut unreferenced: BTreeSet<String> = candidates.iter().cloned().collect();
    for f in files {
        if unreferenced.is_empty() {
            break;
        }
        // A script may name itself (a usage string, `__file__` handling); that
        // is not the repo wiring it up.
        if candidates.contains(f) || is_binary_ext(f) {
            continue;
        }
        let Some(text) = read_bounded(&root.join(f)) else {
            continue;
        };
        unreferenced.retain(|c| !text.contains(c.trim_end_matches(".py")));
    }
    unreferenced.into_iter().collect()
}

fn is_binary_ext(rel: &str) -> bool {
    rel.rsplit_once('.')
        .is_some_and(|(_, ext)| BINARY_EXTS.contains(&ext.to_ascii_lowercase().as_str()))
}

/// Read at most [`MAX_REFERENCE_BYTES`], lossily. Bounded because this runs
/// over every file in the tree.
fn read_bounded(path: &Path) -> Option<String> {
    use std::io::Read as _;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    std::io::BufReader::new(f)
        .take(MAX_REFERENCE_BYTES as u64)
        .read_to_end(&mut buf)
        .ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Does this file declare itself directly runnable (`if __name__ == "__main__"`)?
fn has_main_guard(path: &Path) -> bool {
    read_bounded(path).is_some_and(|t| t.contains("__main__"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal Python project: package code under `pkg/`, a declared
    /// hatchling build hook, and an unreferenced maintenance script.
    fn repo(root: &Path, pyproject: &str) {
        let w = |rel: &str, body: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w("pyproject.toml", pyproject);
        w("pkg/app.py", "import subprocess\n\n\ndef go():\n    pass\n");
        // No `__main__` guard, like a real hatchling hook: the DECLARATION is
        // the only thing that can exempt it, which is what these tests probe.
        w(
            "hatch_build.py",
            "import subprocess\n\n\nclass CustomBuildHook:\n    def initialize(self):\n        \
             subprocess.run(['npm', 'build'])\n",
        );
        w(
            "contribution_stats.py",
            "import subprocess\n\n\ndef main():\n    subprocess.check_output(['git', 'log'])\n\n\n\
             if __name__ == '__main__':\n    main()\n",
        );
    }

    const DECLARED: &str = "[project]\nname = \"x\"\n\n[tool.hatch.build.hooks.custom]\n";

    #[test]
    fn a_declared_hatch_hook_is_dev_only() {
        // The manifest names the file; that is the project's own statement
        // that the BUILD runs it, and it is what separates this from a guess.
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "hatch_build.py"), Some(ScopeClass::DevOnly));
    }

    #[test]
    fn an_explicit_hook_path_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        repo(
            dir.path(),
            "[project]\nname = \"x\"\n\n[tool.hatch.build.hooks.custom]\npath = \"build/hook.py\"\n",
        );
        std::fs::create_dir_all(dir.path().join("build")).unwrap();
        std::fs::write(dir.path().join("build/hook.py"), "import subprocess\n").unwrap();
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "build/hook.py"), Some(ScopeClass::DevOnly));
        // The default name is NOT also exempted: the declaration replaced it.
        assert_eq!(scope(&ev, "hatch_build.py"), None);
    }

    #[test]
    fn a_per_target_hook_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        repo(
            dir.path(),
            "[project]\nname = \"x\"\n\n[tool.hatch.build.targets.wheel.hooks.custom]\n",
        );
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "hatch_build.py"), Some(ScopeClass::DevOnly));
    }

    #[test]
    fn an_undeclared_hatch_build_py_stays_runtime() {
        // THE CONSERVATIVE HALF OF THE RULE. Without the table, hatchling
        // never runs this file, so its name proves nothing: it is an ordinary
        // module and its unbounded call keeps blocking.
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), "[project]\nname = \"x\"\n");
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "hatch_build.py"), None);
        assert_eq!(
            rvl_core::scope_of("hatch_build.py"),
            ScopeClass::Runtime,
            "the path lane must not guess from the name either"
        );
    }

    #[test]
    fn an_unreferenced_root_script_is_dev_only() {
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        let ev = DevScope::detect(dir.path());
        assert_eq!(
            scope(&ev, "contribution_stats.py"),
            Some(ScopeClass::DevOnly)
        );
    }

    #[test]
    fn one_mention_anywhere_keeps_a_root_script_runtime() {
        // A README line is enough. The rule is "nothing in the repo wires this
        // up", and any evidence to the contrary wins.
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        std::fs::write(
            dir.path().join("README.md"),
            "Run `python contribution_stats.py` for stats.\n",
        )
        .unwrap();
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "contribution_stats.py"), None);
    }

    #[test]
    fn a_root_entry_point_of_a_single_file_project_stays_runtime() {
        // No Python below the root: the root script IS the service, however
        // little references it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("app.py"),
            "import subprocess\n\n\nif __name__ == '__main__':\n    subprocess.run(['x'])\n",
        )
        .unwrap();
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "app.py"), None);
    }

    #[test]
    fn a_root_package_module_stays_runtime() {
        // `__init__.py` at the root makes every sibling an importable module
        // of the root package, so "nothing references it" proves nothing.
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        std::fs::write(dir.path().join("__init__.py"), "").unwrap();
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "contribution_stats.py"), None);
    }

    #[test]
    fn a_root_module_without_a_main_guard_stays_runtime() {
        // An importable helper module, not a script. Nothing imports it TODAY,
        // which makes it dead code, not tooling — and dead code that gets
        // imported tomorrow must not carry a hidden exemption.
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        std::fs::write(
            dir.path().join("helpers.py"),
            "import subprocess\n\n\ndef go():\n    subprocess.run(['x'])\n",
        )
        .unwrap();
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "helpers.py"), None);
    }

    #[test]
    fn product_code_is_never_touched() {
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        let ev = DevScope::detect(dir.path());
        assert_eq!(scope(&ev, "pkg/app.py"), None);
        assert_eq!(rvl_core::scope_of("pkg/app.py"), ScopeClass::Runtime);
    }

    #[test]
    fn annotate_clears_a_stale_override() {
        // Sites reused from the incremental index carry the last run's stamp.
        // No evidence at all: every site falls back to its path class.
        let ev = DevScope::default();
        let mut sites = vec![Site {
            file_path: "pkg/app.py".into(),
            scope_override: Some(ScopeClass::DevOnly),
            ..Default::default()
        }];
        ev.annotate(&mut sites);
        assert_eq!(sites[0].scope_override, None);
        assert_eq!(sites[0].scope(), ScopeClass::Runtime);
    }

    #[test]
    fn annotate_matches_a_dot_slash_prefixed_site_path() {
        let dir = tempfile::tempdir().unwrap();
        repo(dir.path(), DECLARED);
        let ev = DevScope::detect(dir.path());
        let mut sites = vec![Site {
            file_path: "./hatch_build.py".into(),
            ..Default::default()
        }];
        ev.annotate(&mut sites);
        assert_eq!(sites[0].scope(), ScopeClass::DevOnly);
    }

    /// The evidence's answer for one path, as `Site::scope` would see it.
    fn scope(ev: &DevScope, rel: &str) -> Option<ScopeClass> {
        let mut sites = vec![Site {
            file_path: rel.into(),
            ..Default::default()
        }];
        ev.annotate(&mut sites);
        sites[0].scope_override
    }
}
