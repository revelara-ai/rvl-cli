//! THE CI BASE-REF CHAIN (po-av01j.194), ported from rvl-cli
//! `internal/scanner/wire.go` (`ResolveBaseRef`, `FormatNoBaseRefDiagnostic`).
//!
//! WHAT WAS BROKEN. `--changed-only` outside a hook asked the working-tree
//! question: "what have you edited since HEAD". That is the right question at
//! a developer's keyboard and the WRONG one in the environment the gate exists
//! for. A CI pull-request checkout has a CLEAN tree with HEAD parked on the PR
//! head, so the working-tree question answers "nothing", the scan finds
//! nothing, and the gate exits 0 having checked no files at all. rvl-cli v1
//! never had that hole because it never asked that question: it resolved a
//! BASE REF from flags, env and repo config, diffed `base...HEAD`, and REFUSED
//! LOUDLY when no base ref was reachable. A loud failure had become a silent
//! pass — the same shape as po-av01j.182's force-next no-op.
//!
//! THE CHAIN, in rvl-cli's actual precedence order (read off wire.go, not
//! inferred from the help text):
//!
//!   1. `--base <ref>`
//!   2. `RVL_BASE_REF`
//!   3. `GITHUB_BASE_REF`                       (GitHub PR events)
//!   4. `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`   (GitLab MRs)
//!   5. `.revelara.yaml` `scanner.base_ref`     — LAST, not first
//!
//! The repo config sits at the BOTTOM: a checked-in `base_ref` is a default
//! for humans, and the CI event's own idea of the base branch outranks it.
//!
//! UNSET IS NOT UNFETCHED. Those are different failures with different fixes,
//! so they are tracked as different states ([`Miss`]) and named separately in
//! the diagnostic:
//!
//!   * UNSET — the source carried no value. Nothing to fetch; the fix is to
//!     set one (or, in a GitHub PR, it is already set and the run is not a PR).
//!   * UNFETCHED — the source named a ref that is not a commit in THIS clone.
//!     CI shallow clones (`actions/checkout` defaults to depth 1) are the
//!     normal cause, and the fix is `fetch-depth: 0`, not a config change.
//!
//! Like rvl-cli, an unreachable value does not end the walk: the chain
//! CONTINUES to the next source, so a stale `--base` still lets
//! `GITHUB_BASE_REF` answer. Only when every source misses is it a refusal.
//! And like rvl-cli, a bare branch name that is not present locally is retried
//! once as `origin/<name>` — the shape a shallow clone actually has, where
//! `main` is absent but `origin/main` is a remote-tracking ref.
//!
//! REFUSAL, NEVER FALLBACK. When a base ref was CONFIGURED and is not
//! reachable, the gate stops with a non-zero exit. Quietly falling back to the
//! working-tree question there would recreate this exact bug: the caller asked
//! for base-relative scope, we could not compute it, and a "clean tree, no
//! findings, exit 0" answer would report success for a check that never ran.

use std::path::Path;

/// Where a candidate base ref came from. The labels are rvl-cli's
/// `BaseRefSource` constants verbatim, so a user who has seen one CLI's
/// diagnostic reads the other's without relearning anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    RvlEnv,
    GitHub,
    GitLab,
    Config,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Flag => "--base flag",
            Source::RvlEnv => "RVL_BASE_REF env var",
            Source::GitHub => "GITHUB_BASE_REF env var (PR events)",
            Source::GitLab => "CI_MERGE_REQUEST_TARGET_BRANCH_NAME env var",
            Source::Config => ".revelara.yaml scanner.base_ref",
        }
    }
}

/// The chain as read from the environment, in precedence order. Values are
/// trimmed; an empty one means the source was not set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Chain {
    entries: Vec<(Source, String)>,
}

impl Chain {
    /// Did ANY source carry a value? This is the question that decides whether
    /// a failure to resolve is a refusal (something was configured and we
    /// could not reach it) or simply "no base ref in play" — and, in
    /// [`crate::compat`], whether a v1 `--changed-only` has a base ref to
    /// resolve against at all.
    ///
    /// Deliberately about CONFIGURATION, not reachability: a configured but
    /// unfetched ref must reach the loud refusal, never slide to a fallback.
    pub fn is_configured(&self) -> bool {
        self.entries.iter().any(|(_, v)| !v.is_empty())
    }
}

/// Build the chain from explicit values. The public entry point for tests and
/// for callers that already hold the environment.
pub fn chain_from(
    flag: Option<&str>,
    rvl_base_ref: &str,
    github_base_ref: &str,
    gitlab_target_branch: &str,
    yaml_base_ref: &str,
) -> Chain {
    let trim = |s: &str| s.trim().to_string();
    Chain {
        entries: vec![
            (Source::Flag, trim(flag.unwrap_or_default())),
            (Source::RvlEnv, trim(rvl_base_ref)),
            (Source::GitHub, trim(github_base_ref)),
            (Source::GitLab, trim(gitlab_target_branch)),
            (Source::Config, trim(yaml_base_ref)),
        ],
    }
}

/// Build the chain from the process environment and `root`'s `.revelara.yaml`.
pub fn chain(flag: Option<&str>, root: &Path) -> Chain {
    let env = |k: &str| std::env::var(k).unwrap_or_default();
    chain_from(
        flag,
        &env("RVL_BASE_REF"),
        &env("GITHUB_BASE_REF"),
        &env("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        &yaml_base_ref(root).unwrap_or_default(),
    )
}

/// Why one source did not produce a usable base ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Miss {
    /// The source carried no value.
    Unset,
    /// The source named a ref that is not a commit in this clone (and neither
    /// is `origin/<name>`). A shallow CI clone is the usual cause.
    Unfetched,
}

/// A base ref that resolved, and which link of the chain produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub git_ref: String,
    pub source: Source,
}

/// Why the chain produced nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unresolved {
    /// `root` is not inside a git work tree. Reported separately so the caller
    /// can leave that (older, more specific) refusal to the changed-set
    /// resolver instead of blaming the base-ref chain for it.
    NotAWorkTree,
    /// Every link missed, with the state of each in chain order.
    NoBaseRef(Vec<(Source, Miss, String)>),
}

/// Walk the chain and return the first REACHABLE base ref.
///
/// Mirrors rvl-cli's `ResolveBaseRef`: unset and unreachable links are both
/// skipped rather than fatal, and only an exhausted chain is an error.
pub fn resolve(root: &Path, chain: &Chain) -> Result<Resolved, Unresolved> {
    if !in_work_tree(root) {
        return Err(Unresolved::NotAWorkTree);
    }
    let mut misses = Vec::new();
    for (source, value) in &chain.entries {
        if value.is_empty() {
            misses.push((*source, Miss::Unset, String::new()));
            continue;
        }
        if ref_reachable(root, value) {
            return Ok(Resolved {
                git_ref: value.clone(),
                source: *source,
            });
        }
        // A bare branch name may need an `origin/` prefix: that is the shape a
        // shallow clone has, where `main` is absent but `origin/main` is a
        // remote-tracking ref. rvl-cli retries exactly once, the same way.
        if !value.starts_with("origin/") {
            let prefixed = format!("origin/{value}");
            if ref_reachable(root, &prefixed) {
                return Ok(Resolved {
                    git_ref: prefixed,
                    source: *source,
                });
            }
        }
        misses.push((*source, Miss::Unfetched, value.clone()));
    }
    Err(Unresolved::NoBaseRef(misses))
}

/// The refusal text: rvl-cli's headline and fix line, with each link's state
/// named so "you set nothing" and "you set something we cannot see" are
/// visibly different problems.
///
/// rvl-cli's own message also advertises `--scan-all-on-missing-base`. That
/// flag is NOT ported, because rvl-cli does not implement it either: the
/// string appears only in its help text and in this diagnostic, and no parser
/// in the binary accepts it (`rvl-cli origin/main`, verified by grep). Telling
/// a blocked user to type a flag that does not exist would be worse than the
/// silence this bead is fixing, so the escape hatch named here is the real one.
pub fn diagnostic(misses: &[(Source, Miss, String)]) -> String {
    let mut s = String::from(
        "--changed-only requires a reachable base ref, but none was found.\n  Tried, in order:\n",
    );
    for (source, miss, value) in misses {
        let state = match miss {
            Miss::Unset => "unset".to_string(),
            Miss::Unfetched => format!(
                "set to {value:?}, but no such commit is in this clone \
                 (nor origin/{value}) — not fetched"
            ),
        };
        s.push_str(&format!("    {:<44}{state}\n", source.label()));
    }
    s.push_str(
        "  Fix (unfetched): deepen the checkout — `fetch-depth: 0` for \
         actions/checkout, `GIT_DEPTH: 0` for GitLab — or `git fetch origin <branch>`.\n  \
         Fix (unset): pass --base <ref>, or set RVL_BASE_REF / scanner.base_ref in \
         .revelara.yaml.\n  \
         Refusing rather than scanning nothing: a CI pull-request checkout has a CLEAN \
         tree, so without a base ref this run would find no changed files and exit 0 — \
         a gate reporting success for a check it never made.\n  \
         Re-run without --changed-only for a full, unscoped scan.\n",
    );
    s
}

/// `scanner.base_ref` from `.revelara.yaml` at `root`.
///
/// A narrow view of the shared file, the convention every other consumer here
/// follows (`waiver.rs` owns `scanner.waivers`, `agent.rs` the consent keys):
/// one consumer can never break another, and an unparseable file yields
/// `None` rather than an error, exactly as rvl-cli's `yaml.Unmarshal` path
/// does. A broken config must not be load-bearing — and because a MISSING base
/// ref is refused rather than defaulted, it cannot silently widen the gate.
pub fn yaml_base_ref(root: &Path) -> Option<String> {
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct File {
        scanner: Scanner,
    }
    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Scanner {
        base_ref: String,
    }
    let dir = git_toplevel(root).unwrap_or_else(|| root.to_path_buf());
    let text = std::fs::read_to_string(dir.join(".revelara.yaml")).ok()?;
    let f = serde_yaml::from_str::<File>(&text).ok()?;
    let v = f.scanner.base_ref.trim().to_string();
    (!v.is_empty()).then_some(v)
}

fn git_toplevel(dir: &Path) -> Option<std::path::PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let root = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (!root.is_empty()).then(|| std::path::PathBuf::from(root))
}

fn in_work_tree(root: &Path) -> bool {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--is-inside-work-tree"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "true")
}

/// Does `git_ref` name a commit in this clone? `^{commit}` so a tag or a tree
/// cannot pass for one, and a leading dash is refused outright rather than
/// handed to git as an option (rvl-cli's po-t8acf argument-injection guard).
fn ref_reachable(root: &Path, git_ref: &str) -> bool {
    if git_ref.starts_with('-') {
        return false;
    }
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--verify", "--quiet"])
        .arg(format!("{git_ref}^{{commit}}"))
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn run(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A repo with `main` plus three extra branches, so precedence can be
    /// tested with every link naming a DIFFERENT reachable ref.
    fn repo(dir: &tempfile::TempDir) -> PathBuf {
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        run(&root, &["init", "-q", "-b", "main"]);
        run(&root, &["config", "user.email", "t@example.com"]);
        run(&root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("a.txt"), "a\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "seed"]);
        for b in [
            "from-flag",
            "from-rvl",
            "from-github",
            "from-gitlab",
            "from-yaml",
        ] {
            run(&root, &["branch", b]);
        }
        root
    }

    /// THE PRECEDENCE ORDER, read off rvl-cli `wire.go` rather than off its
    /// help text: flag, RVL_BASE_REF, GITHUB_BASE_REF, GitLab, and
    /// `.revelara.yaml` LAST. Each step drops the winner and asserts the next
    /// one takes over, so the order is pinned link by link.
    #[test]
    fn the_chain_resolves_in_rvl_cli_order_with_the_yaml_last() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let full = |flag| chain_from(flag, "from-rvl", "from-github", "from-gitlab", "from-yaml");

        let r = resolve(&root, &full(Some("from-flag"))).unwrap();
        assert_eq!((r.git_ref.as_str(), r.source), ("from-flag", Source::Flag));

        let r = resolve(&root, &full(None)).unwrap();
        assert_eq!((r.git_ref.as_str(), r.source), ("from-rvl", Source::RvlEnv));

        let c = chain_from(None, "", "from-github", "from-gitlab", "from-yaml");
        let r = resolve(&root, &c).unwrap();
        assert_eq!(
            (r.git_ref.as_str(), r.source),
            ("from-github", Source::GitHub)
        );

        let c = chain_from(None, "", "", "from-gitlab", "from-yaml");
        let r = resolve(&root, &c).unwrap();
        assert_eq!(
            (r.git_ref.as_str(), r.source),
            ("from-gitlab", Source::GitLab)
        );

        // The repo's own config is the FLOOR, not the ceiling: a CI event's
        // base branch outranks a checked-in default.
        let c = chain_from(None, "", "", "", "from-yaml");
        let r = resolve(&root, &c).unwrap();
        assert_eq!(
            (r.git_ref.as_str(), r.source),
            ("from-yaml", Source::Config)
        );
    }

    /// An unreachable link is SKIPPED, not fatal (rvl-cli continues the walk).
    /// A stale `--base` must still let the CI event answer.
    #[test]
    fn an_unreachable_link_falls_through_to_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let c = chain_from(Some("deleted-long-ago"), "", "from-github", "", "");
        let r = resolve(&root, &c).unwrap();
        assert_eq!(
            (r.git_ref.as_str(), r.source),
            ("from-github", Source::GitHub)
        );
    }

    /// THE SHALLOW-CLONE SHAPE. `GITHUB_BASE_REF` is a bare branch name and a
    /// shallow checkout has no local `main` — only `origin/main`. rvl-cli
    /// retries the prefix once; so do we, and the SOURCE stays the one that
    /// named it.
    #[test]
    fn a_bare_branch_name_is_retried_as_origin_slash_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        // Fabricate a remote-tracking ref with no local branch of that name.
        run(
            &root,
            &["update-ref", "refs/remotes/origin/release", "main"],
        );
        let c = chain_from(None, "", "release", "", "");
        let r = resolve(&root, &c).unwrap();
        assert_eq!(r.git_ref, "origin/release");
        assert_eq!(r.source, Source::GitHub);
    }

    /// UNSET is not UNFETCHED. An empty chain reports every link `Unset` and
    /// is NOT "configured", so the caller keeps its working-tree behaviour
    /// instead of refusing a developer's local scan.
    #[test]
    fn an_empty_chain_reports_every_link_unset_and_is_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let c = chain_from(None, "", "", "", "");
        assert!(!c.is_configured());
        let Err(Unresolved::NoBaseRef(misses)) = resolve(&root, &c) else {
            panic!("an empty chain must not resolve")
        };
        assert_eq!(misses.len(), 5);
        assert!(misses.iter().all(|(_, m, _)| *m == Miss::Unset));
    }

    /// THE CI CASE THIS BEAD IS ABOUT: `GITHUB_BASE_REF` is set (it always is
    /// on a `pull_request` event) but the shallow clone never fetched it. That
    /// is `Unfetched`, the chain IS configured, and the caller must refuse.
    #[test]
    fn a_configured_but_unfetched_ref_is_distinguished_from_an_unset_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let c = chain_from(None, "", "never-fetched", "", "");
        assert!(c.is_configured(), "a set-but-unreachable ref IS configured");
        let Err(Unresolved::NoBaseRef(misses)) = resolve(&root, &c) else {
            panic!("must not resolve")
        };
        let github = misses
            .iter()
            .find(|(s, _, _)| *s == Source::GitHub)
            .unwrap();
        assert_eq!(github.1, Miss::Unfetched);
        assert_eq!(github.2, "never-fetched");
        // And the two states get different advice.
        let text = diagnostic(&misses);
        assert!(text.contains("not fetched"), "{text}");
        assert!(text.contains("fetch-depth: 0"), "{text}");
        assert!(text.contains("--base <ref>"), "{text}");
        // The escape hatch rvl-cli advertises but never implemented must not
        // be repeated here.
        assert!(!text.contains("scan-all-on-missing-base"), "{text}");
    }

    /// Argument injection: a value that begins with a dash is never handed to
    /// git as an option (rvl-cli po-t8acf).
    #[test]
    fn a_leading_dash_is_refused_rather_than_passed_to_git() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let c = chain_from(Some("--upload-pack=touch /tmp/pwned"), "", "", "", "");
        assert!(matches!(resolve(&root, &c), Err(Unresolved::NoBaseRef(_))));
    }

    /// A tag pointing at a tree, or any non-commit, cannot pass for a base ref.
    #[test]
    fn a_ref_that_is_not_a_commit_does_not_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let c = chain_from(Some("refs/heads"), "", "", "", "");
        assert!(matches!(resolve(&root, &c), Err(Unresolved::NoBaseRef(_))));
    }

    /// Outside a git work tree the chain reports THAT, so the caller can leave
    /// the (more specific) "not a git repository" refusal to the changed-set
    /// resolver rather than blaming a base ref for it.
    #[test]
    fn outside_a_work_tree_the_chain_says_so_instead_of_blaming_the_base_ref() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        let c = chain_from(None, "", "main", "", "");
        assert_eq!(resolve(&plain, &c), Err(Unresolved::NotAWorkTree));
    }

    /// `.revelara.yaml` is read from the git TOPLEVEL (a scan of a
    /// subdirectory still sees the repo's config), and only `scanner.base_ref`
    /// is read — every other key belongs to another consumer.
    #[test]
    fn the_yaml_view_reads_scanner_base_ref_from_the_repo_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(
            root.join(".revelara.yaml"),
            "project: svc\nscanner:\n  base_ref: origin/develop\n  waivers:\n    - matcher: x\n",
        )
        .unwrap();
        assert_eq!(yaml_base_ref(&root).as_deref(), Some("origin/develop"));
        std::fs::create_dir_all(root.join("svc")).unwrap();
        assert_eq!(
            yaml_base_ref(&root.join("svc")).as_deref(),
            Some("origin/develop"),
            "a scan of a subdirectory still sees the repo's config"
        );
    }

    /// A missing, empty or malformed config is `None`, never an error: it just
    /// leaves that link of the chain unset.
    #[test]
    fn a_missing_or_broken_yaml_leaves_the_link_unset() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        assert_eq!(yaml_base_ref(&root), None);
        std::fs::write(root.join(".revelara.yaml"), "project: [unclosed\n").unwrap();
        assert_eq!(yaml_base_ref(&root), None);
        std::fs::write(
            root.join(".revelara.yaml"),
            "scanner:\n  base_ref: \"  \"\n",
        )
        .unwrap();
        assert_eq!(yaml_base_ref(&root), None, "whitespace is not a base ref");
    }
}
