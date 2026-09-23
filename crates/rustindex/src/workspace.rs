//! Cargo workspace discovery under a scan root (po-pk3fp.11).
//!
//! rustindex used to assume ONE cargo workspace sitting AT the scan root and
//! ran `cargo metadata` there. On a polyglot monorepo whose Rust lives in a
//! subdirectory that finds nothing: dolthub/dolt, genspark-ai/genoffice and
//! google/osv-scanner all abstained with "could not find Cargo.toml in
//! <repo root>" while carrying real crates one level down. goindex fixed the
//! same shape for nested `go.mod` (po-av01j.131,
//! `helpers/goindex/retrieve.go`); this is that walk for `Cargo.toml`.
//!
//! The charter is unchanged: discovery decides WHERE to look, never whether
//! code is sound. A discovered workspace that fails to load still abstains.

use std::path::{Path, PathBuf};

/// Directory names the walk never descends into: build output, vendored
/// dependency copies, and other languages' dependency trees. A `Cargo.toml`
/// inside any of them belongs to a dependency, not to this repo's code.
const SKIP_DIRS: &[&str] = &["target", "vendor", "node_modules", "dist", "build"];

/// The cargo workspace roots to index under `root`, sorted, each the directory
/// holding a `Cargo.toml`.
///
/// A `Cargo.toml` AT the root means ONE workspace and no descent: a normal
/// Rust repo must not fan out into its own members or a vendored copy.
/// Otherwise the tree is walked for per-directory manifests, and the walk does
/// NOT descend past a manifest it finds -- the crates below it are that
/// workspace's members, which `cargo metadata` already reports.
///
/// An empty result is NOT a scan of zero sites. The caller must turn it into
/// an ABSTENTION, the same charter an unloadable workspace follows: no
/// heuristic tier, decline rather than guess.
pub fn discover_workspaces(root: &Path) -> Vec<PathBuf> {
    if root.join("Cargo.toml").is_file() {
        return vec![root.to_path_buf()];
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    found.sort();
    found
}

/// Depth-first walk collecting manifest directories. Symlinked directories are
/// not followed: a link can point out of the repo or back into it, and either
/// indexes code twice or code that is not here.
fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return; // unreadable directory: degrade coverage, never fail the walk
    };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Dot-directories hold caches and VCS internals (.git, .cargo
        // registry sources), never a workspace this repo is asked about.
        if name.starts_with('.') || SKIP_DIRS.contains(&name.as_ref()) {
            continue;
        }
        let path = entry.path();
        if path.join("Cargo.toml").is_file() {
            found.push(path);
            continue; // members below belong to this workspace, not beside it
        }
        walk(&path, found);
    }
}

/// Rewrite a SCIP index's document paths from workspace-relative to
/// repo-root-relative by prefixing `rel` (empty for a workspace at the root).
///
/// rust-analyzer emits paths relative to the tree it was pointed at, so a
/// nested workspace's documents would otherwise collide with the repo root
/// when derivation reads the source back and when `--files` filters.
pub fn rebase_index(index: &mut scip::types::Index, rel: &str) {
    if rel.is_empty() {
        return;
    }
    let prefix = rel.trim_end_matches('/');
    for doc in index.documents.iter_mut() {
        doc.relative_path = format!("{prefix}/{}", doc.relative_path);
    }
}

/// A workspace that LOADED and is ready to index.
#[derive(Debug)]
pub struct Loaded {
    /// Absolute directory holding the manifest.
    pub dir: PathBuf,
    /// The directory relative to the scan root, `/`-separated; empty at the root.
    pub rel: String,
    pub lock: crate::ra::LockfileProvenance,
}

/// A workspace that FAILED to load and is therefore not indexed.
#[derive(Debug)]
pub struct Declined {
    pub rel: String,
    pub reason: String,
}

/// The outcome of putting every discovered workspace through the build-dep gate.
#[derive(Debug, Default)]
pub struct Load {
    pub loaded: Vec<Loaded>,
    pub declined: Vec<Declined>,
}

/// Run the build-dep gate over every discovered workspace.
///
/// Abstention is PER WORKSPACE (the bead's charter): one unloadable crate in a
/// monorepo must not cost the repo its other crates, and the crate that did
/// not load is recorded rather than dropped, so a consumer can see that its
/// code was declined instead of scanned. The caller still abstains for the
/// whole run when NOTHING loaded -- an empty stream at exit 0 would read as
/// "Rust was scanned and is clean".
pub fn load_workspaces(root: &Path, dirs: &[PathBuf]) -> Load {
    let mut out = Load::default();
    for dir in dirs {
        let rel = relative(root, dir);
        // Sampled BEFORE the gate: cargo metadata writes a lockfile.
        let pre_existing = dir.join("Cargo.lock").is_file();
        match crate::ra::require_workspace_loads(dir) {
            Ok(()) => out.loaded.push(Loaded {
                dir: dir.clone(),
                rel,
                lock: crate::ra::lockfile_provenance(dir, pre_existing),
            }),
            Err(e) => out.declined.push(Declined {
                rel,
                reason: format!("{e:#}"),
            }),
        }
    }
    out
}

/// Whether an incremental run needs this workspace at all.
///
/// `--files` carries repo-relative paths. A workspace whose directory
/// prefixes none of them can contribute neither sites nor evidence, and
/// indexing it means a cold rust-analyzer load for a stream nothing reads --
/// which on a monorepo is the difference between one workspace's load and
/// every workspace's. A full run (`None`) always wants every workspace.
pub fn wanted(rel: &str, only: Option<&[String]>) -> bool {
    let Some(files) = only else { return true };
    if rel.is_empty() {
        return true; // the workspace IS the repo: every path is inside it
    }
    let prefix = format!("{}/", rel.trim_end_matches('/'));
    files.iter().any(|f| f.starts_with(&prefix))
}

/// `dir` relative to `root`, `/`-separated; empty when they are the same.
fn relative(root: &Path, dir: &Path) -> String {
    dir.strip_prefix(root)
        .unwrap_or(dir)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture(dirs: &[&str], files: &[&str]) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "rustindex-ws-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        for d in dirs {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        for f in files {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "[package]\nname = \"x\"\nversion = \"0.1.0\"\n").unwrap();
        }
        root
    }

    fn rel(root: &Path, found: &[PathBuf]) -> Vec<String> {
        found
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// THE REPORTED CASE (dolt, genoffice, osv-scanner): the Rust crates sit
    /// in subdirectories of a repo whose root carries no manifest.
    #[test]
    fn nested_cargo_workspaces_are_all_discovered() {
        let root = fixture(
            &["go/cmd", "integration-tests"],
            &[
                "proto/Cargo.toml",
                "integration-tests/rust-client/Cargo.toml",
                "go/cmd/main.go",
            ],
        );
        let found = discover_workspaces(&root);
        assert_eq!(
            rel(&root, &found),
            vec!["integration-tests/rust-client", "proto"],
            "every nested manifest is a workspace to index, in sorted order"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A manifest at the root is ONE workspace; its members and any vendored
    /// copy are cargo's business, not additional workspaces.
    #[test]
    fn a_root_manifest_is_the_only_workspace_and_the_walk_stops() {
        let root = fixture(
            &[],
            &[
                "Cargo.toml",
                "crates/rustindex/Cargo.toml",
                "vendor/serde/Cargo.toml",
            ],
        );
        let found = discover_workspaces(&root);
        assert_eq!(rel(&root, &found), vec![""], "got {found:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A nested workspace's own members must not be reported separately:
    /// loading the parent already covers them, and loading a member alone
    /// would double-count its sites.
    #[test]
    fn the_walk_does_not_descend_past_a_discovered_manifest() {
        let root = fixture(
            &[],
            &[
                "rust/Cargo.toml",
                "rust/crates/core/Cargo.toml",
                "rust/crates/cli/Cargo.toml",
            ],
        );
        let found = discover_workspaces(&root);
        assert_eq!(rel(&root, &found), vec!["rust"], "got {found:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Build output, vendored crates and other languages' dependency trees
    /// hold manifests that are dependencies, not this repo's code.
    #[test]
    fn build_output_and_vendored_trees_are_not_workspaces() {
        let root = fixture(
            &[],
            &[
                "target/debug/build/foo/Cargo.toml",
                "vendor/serde/Cargo.toml",
                "node_modules/swc/Cargo.toml",
                "dist/x/Cargo.toml",
                ".git/modules/dep/Cargo.toml",
                ".cargo/registry/src/dep/Cargo.toml",
            ],
        );
        assert!(
            discover_workspaces(&root).is_empty(),
            "vendored and generated manifests must not count as workspaces"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// THE CASE THAT MATTERS: no manifest anywhere must reach an ABSTENTION at
    /// the call site, never a silent success. An empty stream with exit 0
    /// reads as "Rust was scanned and is clean" when Rust was never looked at.
    #[test]
    fn a_tree_with_no_manifest_discovers_nothing() {
        let root = fixture(&["src"], &["src/lib.go"]);
        assert!(discover_workspaces(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn crate_at(root: &Path, dir: &str, manifest: &str) {
        let d = root.join(dir);
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("Cargo.toml"), manifest).unwrap();
        std::fs::write(d.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    }

    /// One crate that does not load must not cost the repo the crates that do
    /// -- and the one that declined is RECORDED, not silently dropped.
    #[test]
    fn a_workspace_that_fails_the_gate_is_declined_and_the_rest_still_load() {
        if std::process::Command::new("cargo")
            .arg("--version")
            .output()
            .is_err()
        {
            return; // no cargo on this machine: the gate itself is untestable
        }
        let root = fixture(&[], &[]);
        crate_at(
            &root,
            "good",
            "[package]\nname = \"good\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        crate_at(&root, "broken", "this is not a manifest\n");
        let dirs = discover_workspaces(&root);
        assert_eq!(rel(&root, &dirs), vec!["broken", "good"]);

        let load = load_workspaces(&root, &dirs);
        assert_eq!(
            load.loaded
                .iter()
                .map(|l| l.rel.as_str())
                .collect::<Vec<_>>(),
            vec!["good"]
        );
        assert_eq!(
            load.declined
                .iter()
                .map(|d| d.rel.as_str())
                .collect::<Vec<_>>(),
            vec!["broken"]
        );
        assert!(
            load.declined[0]
                .reason
                .contains("abstains rather than guessing"),
            "the decline carries the charter wording: {}",
            load.declined[0].reason
        );
        assert!(
            !load.loaded[0].lock.pre_existing && !load.loaded[0].lock.sha256.is_empty(),
            "a minted lockfile is still provenance: {:?}",
            load.loaded[0].lock
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_workspace_at_the_root_carries_an_empty_relative_path() {
        let root = fixture(&[], &["Cargo.toml"]);
        assert_eq!(relative(&root, &root), "");
        assert_eq!(relative(&root, &root.join("a/b")), "a/b");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_incremental_run_only_wants_the_workspaces_holding_the_named_files() {
        let files = vec!["rust/app/src/main.rs".to_string()];
        let only = Some(files.as_slice());
        assert!(wanted("rust", only));
        assert!(!wanted("tools/other", only));
        // A sibling whose name merely PREFIXES the wanted one is a different
        // directory: the match is on a path boundary, not on characters.
        assert!(!wanted("rust-client", only));
        // A workspace at the repo root holds every path.
        assert!(wanted("", only));
        // A full run wants everything.
        assert!(wanted("tools/other", None));
    }

    #[test]
    fn rebasing_prefixes_document_paths_with_the_workspace_directory() {
        let mut index = scip::types::Index::new();
        let mut doc = scip::types::Document::new();
        doc.relative_path = "src/main.rs".into();
        index.documents.push(doc);
        rebase_index(&mut index, "integration-tests/rust-client");
        assert_eq!(
            index.documents[0].relative_path,
            "integration-tests/rust-client/src/main.rs"
        );
    }

    #[test]
    fn rebasing_a_root_workspace_changes_nothing() {
        let mut index = scip::types::Index::new();
        let mut doc = scip::types::Document::new();
        doc.relative_path = "src/main.rs".into();
        index.documents.push(doc);
        rebase_index(&mut index, "");
        assert_eq!(index.documents[0].relative_path, "src/main.rs");
    }
}
