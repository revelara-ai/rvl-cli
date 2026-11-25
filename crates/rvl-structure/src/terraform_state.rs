//! RC-016 Terraform state that nothing manages: a repository whose
//! production Terraform root modules keep their state locally, or that
//! commits a state file.
//!
//! RETRIEVAL ([`observe`], then [`Acc::finish`]) reads the `*.tf` files, the
//! committed `*.tfstate` files and, when the `.tf` files leave the backend
//! undecided, the build and documentation files that could supply a backend
//! from outside them. It keeps paths, counts and backend types only.
//! JUDGEMENT ([`evaluate`]) violates on a committed state file with
//! resources, or on production roots of which none names a backend while
//! nothing in the repository names one either. It abstains on sample
//! repositories, on repositories an orchestrator drives, on more roots than
//! one repository plausibly applies by hand, and on mixed backends.
//!
//! A production root is a directory of `.tf` files that no other directory
//! calls as a local module, that no path token marks as test, example or
//! scaffolding, that configures a provider and declares enough resources to
//! be a stack, and that is not a local cluster.
//!
//! The walk stands in for the list of tracked files: the inventory skips
//! vendored and build directories, and this module skips the working
//! directories Terraform and Terragrunt write ([`GENERATED_DIRS`]).

use crate::inventory::read_capped;
use crate::{RepoStructure, StructureFinding};
use rvl_config::non_production;
use rvl_core::Verdict;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};

const CONTROL: &str = "RC-016";
const CONTROL_NAME: &str = "infrastructure as code";

/// The paths kept per list: enough to show, bounded for a large tree.
pub const MAX_PATHS: usize = 5;

/// More production roots than this and the repository is a fleet of stacks
/// whose state a pipeline or a wrapper outside the `.tf` files configures:
/// the rule abstains.
pub const MAX_ROOTS: usize = 20;

/// A production root declares at least this many `resource` and `module`
/// blocks in all: fewer is a stub or a snippet, not a stack.
const MIN_BLOCKS: usize = 3;

/// The prefix of a marker file the backend search reads.
const MARKER_READ: usize = 200_000;

/// The cap on a `.tf` or state file read: past any hand-written module, and
/// bounded so a generated file cannot turn the walk into a crawl.
const TF_READ: u64 = 4 * 1024 * 1024;

/// Tokens of the repository's own name that mark it as sample, teaching,
/// template or personal-config material, beyond the shared
/// [`non_production::SAMPLE_REPOSITORY_TOKENS`]: a repository of reusable
/// modules or providers, a starter or blueprint, a reference or pattern
/// collection, guides, specs, dotfiles and script collections. Its roots
/// are illustrations or building blocks, not an estate anyone applies.
const SAMPLE_REPOSITORY_NAME_TOKENS: &[&str] = &[
    "module",
    "modules",
    "terraform",
    "provider",
    "template",
    "templates",
    "boilerplate",
    "starter",
    "skeleton",
    "patterns",
    "reference",
    "blueprint",
    "blueprints",
    "kickstart",
    "kickstarter",
    "poc",
    "guides",
    "guide",
    "study",
    "specs",
    "dotfiles",
    "nixfiles",
    "scripts",
];

/// File names that mean a tool outside the `.tf` files drives the roots and
/// configures their state: Terragrunt (`terragrunt.hcl`, and the `root.hcl`
/// its newer layout names), Atlantis, and Pulumi beside the Terraform.
const ORCHESTRATOR_FILES: &[&str] = &["terragrunt.hcl", "root.hcl", "atlantis.yaml", "Pulumi.yaml"];

/// Directories Terraform and Terragrunt write while they run: downloaded
/// modules and provider caches, never committed.
const GENERATED_DIRS: &[&str] = &[".terraform", ".terragrunt-cache"];

/// Path tokens that mark a `.tf` directory as no production root, beyond
/// the shared [`non_production::path_token`]: reusable module trees and
/// scaffolding.
const NON_ROOT_PATH_TOKENS: &[&str] = &["module", "modules", "skeleton", "boilerplate"];

/// Path tokens of exercises that apply real infrastructure for a while and
/// tear it down: load and benchmark rigs, hack and hackathon trees, pattern
/// collections, and contributed extras.
const EXERCISE_PATH_TOKENS: &[&str] = &[
    "loadtest",
    "benchmark",
    "bench",
    "hacks",
    "hackathon",
    "patterns",
    "contrib",
];

/// Providers that stand up a cluster on the machine that runs Terraform.
const LOCAL_CLUSTER_PROVIDERS: &[&str] = &["kind", "k3d", "docker"];

/// Providers that touch nothing outside the machine that runs Terraform.
const OTHER_LOCAL_PROVIDERS: &[&str] = &[
    "local", "null", "random", "tls", "time", "external", "archive", "template", "http",
];

/// Providers that talk to a cluster someone else stood up. A root that
/// declares only these may target a real cluster, so they alone do not make
/// a local-cluster root; beside a local provider they do not unmake one.
const IN_CLUSTER_CLIENTS: &[&str] = &["kubernetes", "helm", "kubectl", "flux"];

/// Extensions of the files the backend search reads, with [`MAKEFILES`]:
/// scripts, CI and config files, documentation and wrapper code.
const MARKER_EXTS: &[&str] = &["sh", "yml", "yaml", "md", "hcl", "json", "toml", "py"];

/// The Makefile names the backend search reads.
const MAKEFILES: &[&str] = &["Makefile", "makefile", "GNUmakefile"];

/// Text, lower-cased, that supplies or names a backend from outside the
/// `.tf` files: partial backend configuration passed at init, a remote
/// state reference, Terraform Cloud and workspace variables, a generated
/// backend file, and the orchestrators and hosted runners that own state.
const BACKEND_MARKERS: &[&str] = &[
    "-backend-config",
    "backend-config",
    "tf_backend",
    "remote_state {",
    "tf_cloud_organization",
    "tf_workspace",
    "terraform_remote_state",
    "-backend=",
    "backend.tf",
    "backend.hcl",
    "generate \"backend\"",
    "atlantis",
    "spacelift",
    "terraform cloud",
    "env0",
    "scalr",
    "pulumi",
];

/// Text a state file holds only when it records resources.
const STATE_MARKERS: &[&str] = &["\"resources\": [", "\"type\""];

/// One production root module: its directory and backend type.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerraformRoot {
    /// Repo-relative directory ("" for the repository root).
    pub dir: String,
    /// The type of its `backend` block, `cloud` for a `cloud` block, none
    /// without either.
    #[serde(default)]
    pub backend: Option<String>,
}

/// What the tree shows about Terraform state (RC-016). Paths, counts and
/// backend types only.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TerraformStateFacts {
    /// `*.tf` files in the tree.
    #[serde(default)]
    pub tf_files: u32,
    /// The token of the repository's name that marks it as sample material.
    #[serde(default)]
    pub sample_repository: Option<String>,
    /// The first [`ORCHESTRATOR_FILES`] file, by path.
    #[serde(default)]
    pub orchestrator: Option<String>,
    /// State files with resources outside non-production directories,
    /// sorted, at most [`MAX_PATHS`].
    #[serde(default)]
    pub committed_state: Vec<String>,
    /// Production root modules.
    #[serde(default)]
    pub root_count: u32,
    /// The production roots, sorted by directory, at most one past
    /// [`MAX_ROOTS`].
    #[serde(default)]
    pub roots: Vec<TerraformRoot>,
    /// A `.tf` directory that is no production root has a backend or cloud
    /// block.
    #[serde(default)]
    pub backend_outside_roots: bool,
    /// The first file outside the `.tf` files that names a backend, as
    /// "path (marker)". Searched only when the `.tf` files leave the
    /// backend undecided: some production root, none with a backend other
    /// than `local`, and no backend block elsewhere.
    #[serde(default)]
    pub backend_named: Option<String>,
}

/// What the `.tf` files of one directory declare.
#[derive(Default)]
struct DirAcc {
    providers: BTreeSet<String>,
    blocks: usize,
    backend: Option<String>,
}

/// The Terraform facts, accumulated over the walk.
#[derive(Default)]
pub(crate) struct Acc {
    tf_files: u32,
    dirs: BTreeMap<String, DirAcc>,
    /// Directories some other directory calls as a local module.
    called: BTreeSet<String>,
    orchestrators: BTreeSet<String>,
    state: BTreeSet<String>,
    /// Files the backend search may read: (repo-relative path, path).
    marker_files: Vec<(String, PathBuf)>,
}

/// Record what the file at repo-relative `rp` says about Terraform state.
pub(crate) fn observe(path: &Path, rp: &str, name: &str, ext: &str, acc: &mut Acc) {
    if rp.split('/').any(|seg| GENERATED_DIRS.contains(&seg)) {
        return;
    }
    if ORCHESTRATOR_FILES.contains(&name) {
        acc.orchestrators.insert(rp.to_string());
    }
    let dir = rp.rsplit_once('/').map_or("", |(d, _)| d);
    if ext == "tf" {
        acc.tf_files += 1;
        let text = read_up_to(path, TF_READ);
        let d = acc.dirs.entry(dir.to_string()).or_default();
        for line in text.lines() {
            if let Some(p) = labelled(line, "provider") {
                d.providers.insert(p.to_ascii_lowercase());
            }
            if labelled(line, "resource").is_some() || labelled(line, "module").is_some() {
                d.blocks += 1;
            }
            if d.backend.is_none() {
                d.backend = labelled(line, "backend")
                    .map(str::to_string)
                    .or_else(|| cloud_block(line).then(|| "cloud".to_string()));
            }
            if let Some(target) = local_source(line).and_then(|s| resolve(dir, s)) {
                if target != dir {
                    acc.called.insert(target);
                }
            }
        }
    } else if name.ends_with(".tfstate") || name.ends_with(".tfstate.backup") {
        if non_root_dir(dir).is_none() {
            let text = read_up_to(path, TF_READ);
            if STATE_MARKERS.iter().all(|m| text.contains(m)) {
                acc.state.insert(rp.to_string());
            }
        }
    } else if MAKEFILES.contains(&name)
        || (MARKER_EXTS.contains(&ext) && !name.ends_with(".tfvars.json"))
    {
        acc.marker_files.push((rp.to_string(), path.to_path_buf()));
    }
}

impl Acc {
    pub(crate) fn finish(mut self, root: &Path) -> TerraformStateFacts {
        let mut roots: Vec<TerraformRoot> = Vec::new();
        let mut backend_outside_roots = false;
        for (dir, d) in &self.dirs {
            if production_root(dir, d, &self.called) {
                roots.push(TerraformRoot {
                    dir: dir.clone(),
                    backend: d.backend.clone(),
                });
            } else if d.backend.is_some() {
                backend_outside_roots = true;
            }
        }
        let undecided = !roots.is_empty()
            && roots.len() <= MAX_ROOTS
            && !backend_outside_roots
            && roots.iter().all(|r| !managed(r));
        let backend_named = if undecided {
            self.marker_files.sort();
            self.marker_files.iter().find_map(|(rp, path)| {
                let text: String = read_capped(path)
                    .chars()
                    .take(MARKER_READ)
                    .collect::<String>()
                    .to_lowercase();
                BACKEND_MARKERS
                    .iter()
                    .find(|m| text.contains(*m))
                    .map(|m| format!("{rp} ({m})"))
            })
        } else {
            None
        };
        let root_count = roots.len() as u32;
        roots.truncate(MAX_ROOTS + 1);
        TerraformStateFacts {
            tf_files: self.tf_files,
            sample_repository: sample_repository(root),
            orchestrator: self.orchestrators.into_iter().next(),
            committed_state: self.state.into_iter().take(MAX_PATHS).collect(),
            root_count,
            roots,
            backend_outside_roots,
            backend_named,
        }
    }
}

/// The first `limit` bytes of the file at `path`, lossily decoded.
fn read_up_to(path: &Path, limit: u64) -> String {
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = f.take(limit).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The label of a block that opens `line` with `keyword`:
/// `provider "aws" {` is `aws` for `provider`.
fn labelled<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(keyword)?;
    if !rest.starts_with(|c: char| c.is_whitespace() || c == '"') {
        return None;
    }
    let label = rest.trim_start().strip_prefix('"')?;
    label.split_once('"').map(|(l, _)| l)
}

/// Whether `line` opens a `cloud {` block.
fn cloud_block(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("cloud")
        .is_some_and(|rest| rest.trim_start().starts_with('{'))
}

/// The local path of a `source = "./..."` or `source = "../..."` line.
fn local_source(line: &str) -> Option<&str> {
    let rest = line.trim_start().strip_prefix("source")?;
    let value = rest.trim_start().strip_prefix('=')?.trim_start();
    let value = value.strip_prefix('"')?.split_once('"')?.0;
    (value.starts_with("./") || value.starts_with("../")).then_some(value)
}

/// The repo-relative directory `source` names from `dir`, or `None` when
/// it leaves the repository.
fn resolve(dir: &str, source: &str) -> Option<String> {
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    for seg in source.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// The first whole token of `s`, split on every character that is not a
/// letter or a digit and lower-cased, that `list` holds.
fn token(s: &str, list: &[&'static str]) -> Option<&'static str> {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .find_map(|t| {
            let t = t.to_lowercase();
            list.iter().copied().find(|w| *w == t)
        })
}

/// The token that marks repo-relative directory `dir` as holding no
/// production root: the shared non-production classifier, then
/// [`NON_ROOT_PATH_TOKENS`].
fn non_root_dir(dir: &str) -> Option<&'static str> {
    non_production::path_token(&format!("{dir}/")).or_else(|| token(dir, NON_ROOT_PATH_TOKENS))
}

/// Whether the `.tf` directory `dir` is a production root module.
fn production_root(dir: &str, d: &DirAcc, called: &BTreeSet<String>) -> bool {
    !called.contains(dir)
        && non_root_dir(dir).is_none()
        && !d.providers.is_empty()
        && d.blocks >= MIN_BLOCKS
        && token(dir, EXERCISE_PATH_TOKENS).is_none()
        && !local_cluster(&d.providers)
}

/// Whether `providers` make a local-cluster root: at least one local
/// provider, and every provider local or an in-cluster client.
fn local_cluster(providers: &BTreeSet<String>) -> bool {
    let local =
        |p: &str| LOCAL_CLUSTER_PROVIDERS.contains(&p) || OTHER_LOCAL_PROVIDERS.contains(&p);
    providers.iter().any(|p| local(p))
        && providers
            .iter()
            .all(|p| local(p) || IN_CLUSTER_CLIENTS.contains(&p.as_str()))
}

/// Whether a root keeps its state somewhere other than local disk.
fn managed(root: &TerraformRoot) -> bool {
    root.backend.as_deref().is_some_and(|b| b != "local")
}

/// The token of the scanned root's own name that marks the repository as
/// sample material: the shared list, then [`SAMPLE_REPOSITORY_NAME_TOKENS`].
fn sample_repository(root: &Path) -> Option<String> {
    if let Some(t) = non_production::root_token(root) {
        return Some(t.to_string());
    }
    let name = match root.file_name() {
        Some(name) => name.to_os_string(),
        None => root.canonicalize().ok()?.file_name()?.to_os_string(),
    };
    token(&name.to_string_lossy(), SAMPLE_REPOSITORY_NAME_TOKENS).map(str::to_string)
}

/// RC-016 from the facts. A record without them was not read: abstain.
pub(crate) fn evaluate(facts: &RepoStructure) -> StructureFinding {
    let mk = |verdict, reason: String, evidence: Vec<String>| StructureFinding {
        control: CONTROL,
        control_name: CONTROL_NAME,
        verdict,
        reason,
        evidence,
        fix: "configure a remote backend (s3, gcs, azurerm, Terraform Cloud) in each root \
              module and remove committed state files from the repository"
            .into(),
        severity: "medium",
        weak: false,
    };
    let Some(t) = &facts.terraform_state else {
        return mk(Verdict::Abstain, "Terraform state not read".into(), vec![]);
    };
    if t.tf_files == 0 {
        if !facts.walk_complete {
            return mk(
                Verdict::Abstain,
                "walk truncated: absence of Terraform files is not evidence".into(),
                vec![],
            );
        }
        return mk(Verdict::NotApplicable, "no Terraform files".into(), vec![]);
    }
    if let Some(token) = &t.sample_repository {
        return mk(
            Verdict::Abstain,
            format!("the repository's name marks it as sample material ({token})"),
            vec![],
        );
    }
    if let Some(file) = &t.orchestrator {
        return mk(
            Verdict::Abstain,
            format!("an orchestrator configures the roots' state ({file})"),
            vec![file.clone()],
        );
    }
    if !t.committed_state.is_empty() {
        return mk(
            Verdict::Violates,
            format!("state file committed: {}", t.committed_state.join(", ")),
            t.committed_state.clone(),
        );
    }
    if t.root_count == 0 {
        return mk(
            Verdict::NotApplicable,
            "no production root module: every Terraform directory is a called module, \
             non-production, local-only or too small to be a stack"
                .into(),
            vec![],
        );
    }
    if t.root_count as usize > MAX_ROOTS {
        return mk(
            Verdict::Abstain,
            format!(
                "{} production root modules, over {MAX_ROOTS}: state for that many stacks is \
                 configured outside their .tf files",
                t.root_count
            ),
            vec![],
        );
    }
    let dirs = |roots: &[&TerraformRoot]| -> Vec<String> {
        roots
            .iter()
            .map(|r| {
                if r.dir.is_empty() {
                    ".".into()
                } else {
                    r.dir.clone()
                }
            })
            .collect()
    };
    let all: Vec<&TerraformRoot> = t.roots.iter().collect();
    if all.iter().all(|r| managed(r)) {
        let backends: BTreeSet<&str> = all.iter().filter_map(|r| r.backend.as_deref()).collect();
        return mk(
            Verdict::Satisfies,
            format!(
                "every production root module names a backend ({})",
                backends.into_iter().collect::<Vec<_>>().join(", ")
            ),
            dirs(&all).into_iter().take(MAX_PATHS).collect(),
        );
    }
    if all.iter().any(|r| managed(r)) || t.backend_outside_roots {
        return mk(
            Verdict::Abstain,
            "mixed: some Terraform directories name a backend and some production root \
             modules do not"
                .into(),
            vec![],
        );
    }
    if let Some(named) = &t.backend_named {
        return mk(
            Verdict::Abstain,
            format!("a backend is supplied from outside the .tf files: {named}"),
            vec![],
        );
    }
    if !facts.walk_complete {
        return mk(
            Verdict::Abstain,
            "walk truncated: absence of a backend is not evidence".into(),
            vec![],
        );
    }
    let evidence: Vec<String> = dirs(&all).into_iter().take(MAX_PATHS).collect();
    mk(
        Verdict::Violates,
        format!(
            "{} production root module(s), none with a backend block; no backend named \
             anywhere ({})",
            t.root_count,
            evidence.join(", ")
        ),
        evidence,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root with a cloud provider and three resources, no backend.
    const STACK: &str = "provider \"aws\" {\n  region = \"eu-west-1\"\n}\n\n\
        resource \"aws_s3_bucket\" \"a\" {}\nresource \"aws_s3_bucket\" \"b\" {}\n\
        resource \"aws_sqs_queue\" \"q\" {}\n";

    const S3_BACKEND: &str = "terraform {\n  backend \"s3\" {\n    bucket = \"state\"\n  }\n}\n";

    fn write(root: &Path, rel: &str, content: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    /// A repository root inside a fresh tempdir, named so no token of its
    /// name marks it.
    fn repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("payments-infra");
        std::fs::create_dir(&root).unwrap();
        (dir, root)
    }

    fn judge(root: &Path) -> StructureFinding {
        evaluate(&crate::inventory(root))
    }

    /// The unmanaged stack the twins below start from.
    fn flagged(root: &Path) {
        write(root, "envs/prod/main.tf", STACK);
    }

    #[test]
    fn a_production_root_without_a_backend_violates() {
        let (_d, root) = repo();
        flagged(&root);
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
        assert_eq!(f.evidence, ["envs/prod"]);
        assert!(
            f.reason.contains("none with a backend block"),
            "{}",
            f.reason
        );
    }

    #[test]
    fn a_local_backend_is_no_managed_state() {
        let (_d, root) = repo();
        flagged(&root);
        write(
            &root,
            "envs/prod/backend.tf",
            "terraform {\n  backend \"local\" {}\n}\n",
        );
        assert_eq!(judge(&root).verdict, Verdict::Violates);
    }

    #[test]
    fn no_terraform_is_not_applicable() {
        let (_d, root) = repo();
        write(&root, "README.md", "# infra\n");
        assert_eq!(judge(&root).verdict, Verdict::NotApplicable);
    }

    #[test]
    fn a_sample_repository_name_abstains() {
        for name in [
            "terraform-aws-examples",
            "infra-blueprints",
            "acme-terraform",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join(name);
            flagged(&root);
            let f = judge(&root);
            assert_eq!(f.verdict, Verdict::Abstain, "{name}: {f:?}");
            assert!(f.reason.contains("sample material"), "{}", f.reason);
        }
    }

    #[test]
    fn an_orchestrator_file_abstains() {
        for file in [
            "terragrunt.hcl",
            "live/root.hcl",
            "atlantis.yaml",
            "Pulumi.yaml",
        ] {
            let (_d, root) = repo();
            flagged(&root);
            write(&root, file, "\n");
            let f = judge(&root);
            assert_eq!(f.verdict, Verdict::Abstain, "{file}: {f:?}");
            assert_eq!(f.evidence, [file]);
        }
    }

    #[test]
    fn a_committed_state_file_with_resources_violates() {
        let (_d, root) = repo();
        let state =
            "{\n  \"version\": 4,\n  \"resources\": [\n    {\"type\": \"aws_s3_bucket\"}\n  ]\n}\n";
        write(&root, "envs/prod/main.tf", S3_BACKEND);
        write(&root, "envs/prod/terraform.tfstate", state);
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
        assert_eq!(f.evidence, ["envs/prod/terraform.tfstate"]);

        // Twins: an empty state, and a state under a test tree.
        let (_d, root) = repo();
        write(&root, "envs/prod/main.tf", S3_BACKEND);
        write(
            &root,
            "envs/prod/terraform.tfstate.backup",
            "{\"resources\": []}\n",
        );
        write(&root, "tests/fixtures/terraform.tfstate", state);
        assert_ne!(judge(&root).verdict, Verdict::Violates);
    }

    #[test]
    fn a_locally_called_module_is_no_root() {
        let (_d, root) = repo();
        write(&root, "stacks/net/main.tf", STACK);
        write(
            &root,
            "envs/prod/main.tf",
            "module \"net\" {\n  source = \"../../stacks/net/\"\n}\n",
        );
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::NotApplicable, "{f:?}");
    }

    #[test]
    fn a_non_production_path_is_no_root() {
        for dir in [
            "test/e2e",
            "examples/basic",
            "modules/vpc",
            "envs/dev",
            "skeleton",
        ] {
            let (_d, root) = repo();
            write(&root, &format!("{dir}/main.tf"), STACK);
            let f = judge(&root);
            assert_eq!(f.verdict, Verdict::NotApplicable, "{dir}: {f:?}");
        }
    }

    #[test]
    fn a_root_needs_a_provider_and_three_blocks() {
        let (_d, root) = repo();
        write(
            &root,
            "envs/prod/main.tf",
            "resource \"aws_s3_bucket\" \"a\" {}\nresource \"aws_s3_bucket\" \"b\" {}\n\
             resource \"aws_s3_bucket\" \"c\" {}\n",
        );
        assert_eq!(judge(&root).verdict, Verdict::NotApplicable);
        let (_d, root) = repo();
        write(
            &root,
            "envs/prod/main.tf",
            "provider \"aws\" {}\nresource \"aws_s3_bucket\" \"a\" {}\n# resource \"x\" \"y\" {}\n",
        );
        assert_eq!(judge(&root).verdict, Verdict::NotApplicable);
    }

    #[test]
    fn an_exercise_path_is_no_root() {
        for dir in ["loadtest/cluster", "hackathon", "contrib/aws"] {
            let (_d, root) = repo();
            write(&root, &format!("{dir}/main.tf"), STACK);
            assert_eq!(judge(&root).verdict, Verdict::NotApplicable, "{dir}");
        }
    }

    #[test]
    fn a_local_cluster_root_is_no_root_but_an_in_cluster_client_is() {
        let local =
            "provider \"kind\" {}\nprovider \"helm\" {}\nresource \"kind_cluster\" \"a\" {}\n\
                     resource \"helm_release\" \"b\" {}\nresource \"helm_release\" \"c\" {}\n";
        let (_d, root) = repo();
        write(&root, "cluster/main.tf", local);
        assert_eq!(judge(&root).verdict, Verdict::NotApplicable);

        let remote = "provider \"kubernetes\" {}\nprovider \"helm\" {}\n\
                      resource \"helm_release\" \"a\" {}\nresource \"helm_release\" \"b\" {}\n\
                      resource \"kubernetes_namespace\" \"c\" {}\n";
        let (_d, root) = repo();
        write(&root, "cluster/main.tf", remote);
        assert_eq!(judge(&root).verdict, Verdict::Violates);
    }

    #[test]
    fn more_than_twenty_roots_abstain() {
        let (_d, root) = repo();
        for i in 0..=MAX_ROOTS {
            write(&root, &format!("stacks/s{i}/main.tf"), STACK);
        }
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
        let facts = crate::inventory(&root).terraform_state.unwrap();
        assert_eq!(facts.root_count as usize, MAX_ROOTS + 1);
        assert_eq!(facts.roots.len(), MAX_ROOTS + 1);

        let (_d, root) = repo();
        for i in 0..MAX_ROOTS {
            write(&root, &format!("stacks/s{i}/main.tf"), STACK);
        }
        assert_eq!(judge(&root).verdict, Verdict::Violates);
    }

    #[test]
    fn every_root_with_a_remote_backend_satisfies() {
        let (_d, root) = repo();
        flagged(&root);
        write(&root, "envs/prod/backend.tf", S3_BACKEND);
        write(&root, "envs/stage2/main.tf", STACK);
        write(
            &root,
            "envs/stage2/versions.tf",
            "terraform {\n  cloud {\n    organization = \"o\"\n  }\n}\n",
        );
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Satisfies, "{f:?}");
        assert!(f.reason.contains("cloud, s3"), "{}", f.reason);
    }

    #[test]
    fn mixed_backends_abstain() {
        let (_d, root) = repo();
        flagged(&root);
        write(&root, "envs/prod2/main.tf", STACK);
        write(&root, "envs/prod2/backend.tf", S3_BACKEND);
        assert_eq!(judge(&root).verdict, Verdict::Abstain);

        // A backend block in a directory that is no production root.
        let (_d, root) = repo();
        flagged(&root);
        write(&root, "bootstrap/main.tf", S3_BACKEND);
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Abstain, "{f:?}");
        assert!(f.reason.starts_with("mixed"), "{}", f.reason);
    }

    #[test]
    fn a_backend_named_outside_the_tf_files_abstains() {
        for (file, text) in [
            (
                "Makefile",
                "init:\n\tterraform init -backend-config=prod.hcl\n",
            ),
            (
                ".github/workflows/apply.yml",
                "env:\n  TF_WORKSPACE: prod\n",
            ),
            ("README.md", "State lives in Terraform Cloud.\n"),
        ] {
            let (_d, root) = repo();
            flagged(&root);
            write(&root, file, text);
            let f = judge(&root);
            assert_eq!(f.verdict, Verdict::Abstain, "{file}: {f:?}");
            assert!(f.reason.contains(file), "{}", f.reason);
        }
        // A tfvars file is Terraform input, not a marker.
        let (_d, root) = repo();
        flagged(&root);
        write(&root, "envs/prod/prod.tfvars.json", "{\"backend.tf\": 1}\n");
        assert_eq!(judge(&root).verdict, Verdict::Violates);
    }

    #[test]
    fn generated_terraform_directories_are_skipped() {
        let (_d, root) = repo();
        flagged(&root);
        write(&root, ".terraform/modules/vpc/main.tf", S3_BACKEND);
        write(
            &root,
            ".terraform/terraform.tfstate",
            "{\"resources\": [ {\"type\": 1} ]}",
        );
        let f = judge(&root);
        assert_eq!(f.verdict, Verdict::Violates, "{f:?}");
        assert_eq!(f.evidence, ["envs/prod"]);
    }

    #[test]
    fn a_record_without_terraform_facts_abstains() {
        let f = evaluate(&RepoStructure::default());
        assert_eq!(f.verdict, Verdict::Abstain);
    }

    #[test]
    fn block_labels_and_sources_read_as_written() {
        assert_eq!(labelled("  provider \"aws\" {", "provider"), Some("aws"));
        assert_eq!(labelled("providers = { aws = aws }", "provider"), None);
        assert_eq!(labelled("  backend = \"s3\"", "backend"), None);
        assert!(cloud_block("  cloud {"));
        assert_eq!(local_source("source = \"../net\""), Some("../net"));
        assert_eq!(local_source("source = \"hashicorp/vpc/aws\""), None);
        assert_eq!(
            resolve("envs/prod", "../../stacks/net/"),
            Some("stacks/net".into())
        );
        assert_eq!(resolve("", "../out"), None);
    }
}
