//! WHERE THE CHANGED SET COMES FROM (po-sg7jb): git, and only git.
//!
//! `--changed-only` narrows the gate to "what this change touched". Until this
//! module, that set was read off the scanner's own packet index — the files
//! whose content hash differed from the stored one — which made the gate a
//! function of CACHE STATE rather than of the change. One root cause, two
//! failures:
//!
//!   * A COLD index has no stored hash to diff against, so EVERY candidate
//!     file came back "changed" and `--changed-only` gated on the whole
//!     repository's pre-existing debt. That fires on the FIRST commit after
//!     someone installs the hook — the exact moment they decide whether to
//!     keep it — and makes the verdict differ between two runs over identical
//!     code (run 1 populates the index; run 2 reports nothing changed).
//!   * Even warm, the index compares WORKING-TREE bytes, while a pre-commit
//!     gate must judge what is being COMMITTED. With partial staging
//!     (`git add -p`) that flags hunks the author is not committing.
//!
//! So the changed set is a git question. The packet index keeps its real job —
//! deciding which files must be re-parsed — and loses this one. The two are
//! now independent: which files to retrieve (index) vs which files the change
//! touched (git).
//!
//! SCOPE OF THE FIX: this resolves the changed PATH SET from git. The bytes
//! the retrievers read are still the working tree's, so a file that is staged
//! and then further edited is judged in its working-tree form. See
//! `ChangedSet::dirty`, which detects exactly that case and lets the caller
//! say so out loud rather than leaving it silent.

use anyhow::Context as _;
use std::collections::BTreeSet;
use std::path::Path;

/// Which git question answers "what changed" for this invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// `--hook pre-commit`: the staged paths. What is being committed.
    ///
    /// THE INDEX, NOT A BASE REF. This mode is deliberately untouched by the
    /// base-ref chain (po-av01j.194): a pre-commit gate judges the content of
    /// the commit being created, which exists nowhere but the index. Diffing
    /// it against a CI base branch would both miss staged work already on that
    /// branch's tip and drag in every commit made since branching — neither of
    /// which is "what am I about to commit".
    PreCommit,
    /// `--hook pre-push`: the paths touched by the commits being pushed.
    /// `fallback_base` is the resolved base-ref chain, consulted ONLY when the
    /// branch has no upstream — the same position rvl-cli gives it
    /// (`runAgentPrePush`'s `defaultBase`, used when a pushed ref carries no
    /// remote sha).
    PrePush { fallback_base: Option<String> },
    /// `--changed-only` with a base ref in play: `base...HEAD`, the committed
    /// work on this branch since it diverged. rvl-cli's `--changed-only`
    /// question, and the ONLY one that answers correctly in a CI pull-request
    /// checkout, where the tree is clean and HEAD is the PR head
    /// (po-av01j.194).
    BaseRange { base: String, source: String },
    /// `--changed-only` with no hook and no base ref anywhere: the working
    /// tree against HEAD. The honest answer to "what did this change touch" at
    /// a keyboard, where the uncommitted work IS the change.
    WorkingTree,
}

impl Mode {
    /// The mode a `--hook <name>` selects, ignoring the base-ref chain. An
    /// unrecognized hook name falls to the working-tree question rather than
    /// to "everything": a gate must never widen because of a typo.
    pub fn from_hook(hook: Option<&str>) -> Self {
        match hook {
            Some(h) if h.eq_ignore_ascii_case("pre-commit") => Mode::PreCommit,
            Some(h) if h.eq_ignore_ascii_case("pre-push") => Mode::PrePush {
                fallback_base: None,
            },
            _ => Mode::WorkingTree,
        }
    }
}

/// A resolved changed set plus how it was resolved, so the scan can state its
/// own scope instead of leaving the reader to guess.
#[derive(Debug, Clone)]
pub struct ChangedSet {
    /// Paths relative to the scanned root, `/`-separated, sorted, deduped.
    pub files: Vec<String>,
    /// Human-readable provenance, printed with the scan's scope line.
    pub source: String,
    /// Pre-commit only: staged files that ALSO carry unstaged working-tree
    /// edits. The retrievers read the working tree, so for these the content
    /// judged is not exactly the content committed. Reported, never silent.
    pub dirty: Vec<String>,
}

/// The empty set, for callers that need a placeholder.
impl ChangedSet {
    fn new(files: Vec<String>, source: impl Into<String>, dirty: Vec<String>) -> Self {
        Self {
            files: sorted_unique(files),
            source: source.into(),
            dirty: sorted_unique(dirty),
        }
    }
}

fn sorted_unique(v: Vec<String>) -> Vec<String> {
    v.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// Run git in `root` and return stdout. Any non-zero status is an error
/// carrying git's own stderr: a changed set we could not compute must never
/// look like an empty one.
fn git(root: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .with_context(|| format!("running `git {}`", args.join(" ")))?;
    anyhow::ensure!(
        out.status.success(),
        "`git {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Whether a git command succeeds at all, for probing refs.
fn git_ok(root: &Path, args: &[&str]) -> bool {
    git(root, args).is_ok()
}

/// Split git's `-z` output. `-z` (never plain `--name-only`) because git
/// quotes and escapes paths with spaces or non-ASCII bytes otherwise, and a
/// mis-parsed path silently drops a file from the gate's scope.
fn nul_paths(s: &str) -> Vec<String> {
    s.split('\0')
        .filter(|p| !p.is_empty())
        .map(|p| p.replace('\\', "/"))
        .collect()
}

/// Is `root` inside a git work tree? The precondition for every mode.
fn ensure_work_tree(root: &Path) -> anyhow::Result<()> {
    let out = git(root, &["rev-parse", "--is-inside-work-tree"])
        .context("not a git repository (or git is unavailable)")?;
    anyhow::ensure!(
        out.trim() == "true",
        "{} is not inside a git work tree",
        root.display()
    );
    Ok(())
}

/// Does HEAD resolve? False on an unborn branch (a repo with no commit yet).
fn head_exists(root: &Path) -> bool {
    git_ok(root, &["rev-parse", "--verify", "--quiet", "HEAD"])
}

/// The configured upstream of the current branch, if any.
fn upstream(root: &Path) -> Option<String> {
    let r = git(
        root,
        &[
            "rev-parse",
            "--abbrev-ref",
            "--symbolic-full-name",
            "@{upstream}",
        ],
    )
    .ok()?;
    let r = r.trim().to_string();
    (!r.is_empty()).then_some(r)
}

/// Does this repo have any remote-tracking refs? Guards the `--not --remotes`
/// fallback: with no remote refs that revision walk matches ALL of history,
/// which would re-open the "gate on the whole repo" hole from the other side.
fn has_remote_refs(root: &Path) -> bool {
    git(
        root,
        &["for-each-ref", "--format=%(refname)", "refs/remotes"],
    )
    .map(|s| !s.trim().is_empty())
    .unwrap_or(false)
}

/// Paths staged for commit: added, copied, modified, renamed. Deletions are
/// excluded on purpose — a deleted file has no sites to gate on.
fn staged(root: &Path) -> anyhow::Result<Vec<String>> {
    Ok(nul_paths(&git(
        root,
        &[
            "diff",
            "--cached",
            "--name-only",
            "-z",
            "--relative",
            "--diff-filter=ACMR",
        ],
    )?))
}

/// Paths with unstaged working-tree modifications.
fn unstaged(root: &Path) -> anyhow::Result<Vec<String>> {
    Ok(nul_paths(&git(
        root,
        &["diff", "--name-only", "-z", "--relative"],
    )?))
}

/// Untracked, non-ignored files. New code the author has written but not yet
/// added is unmistakably part of "what this change touched" outside a hook.
fn untracked(root: &Path) -> anyhow::Result<Vec<String>> {
    Ok(nul_paths(&git(
        root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
    )?))
}

/// Paths changed on HEAD's side of `base...head`: the three-dot range, i.e.
/// the diff from the MERGE BASE, not from the base tip. Commits landed on the
/// base branch since this one forked are somebody else's change and must never
/// enter this gate's scope. Same range rvl-cli's `RangeChangeSetBetween`
/// computes.
///
/// `--` terminates the revision arguments: placed the other way round git
/// reads the range as a pathspec and the diff comes back SILENTLY EMPTY
/// (rvl-cli po-t8acf). A leading dash is refused rather than handed to git.
fn range_paths(root: &Path, base: &str, head: &str) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        !base.starts_with('-') && !head.starts_with('-'),
        "invalid revision range {base}...{head}: leading dash"
    );
    let range = format!("{base}...{head}");
    Ok(nul_paths(&git(
        root,
        &[
            "diff",
            "--name-only",
            "-z",
            "--relative",
            "--diff-filter=ACMR",
            &range,
            "--",
        ],
    )?))
}

/// Resolve the changed set for `mode`, rooted at `root`.
///
/// `--relative` throughout, so paths come back relative to the scanned root
/// (and files outside it are dropped, which is the same scoping the scan
/// itself applies).
pub fn resolve(root: &Path, mode: Mode) -> anyhow::Result<ChangedSet> {
    ensure_work_tree(root)?;
    match mode {
        Mode::PreCommit => {
            let files = staged(root)?;
            let also_unstaged: BTreeSet<String> = unstaged(root)?.into_iter().collect();
            let dirty: Vec<String> = files
                .iter()
                .filter(|f| also_unstaged.contains(*f))
                .cloned()
                .collect();
            Ok(ChangedSet::new(
                files,
                "git index (staged paths, `git diff --cached`)",
                dirty,
            ))
        }
        Mode::BaseRange { base, source } => {
            let files = range_paths(root, &base, "HEAD")?;
            Ok(ChangedSet::new(
                files,
                format!("git range {base}...HEAD (base ref from {source})"),
                Vec::new(),
            ))
        }
        Mode::PrePush { fallback_base } => {
            if let Some(up) = upstream(root) {
                let range = format!("{up}..HEAD");
                let files = nul_paths(&git(
                    root,
                    &[
                        "diff",
                        "--name-only",
                        "-z",
                        "--relative",
                        "--diff-filter=ACMR",
                        &range,
                    ],
                )?);
                return Ok(ChangedSet::new(
                    files,
                    format!("git range {range} (branch upstream)"),
                    Vec::new(),
                ));
            }
            // No upstream, but a base ref was configured: use it. This is the
            // slot rvl-cli's `defaultBase` occupies — the chain answers only
            // when the push protocol itself could not, so `--base` is honoured
            // here instead of being a flag that silently does nothing.
            if let Some(base) = fallback_base {
                let files = range_paths(root, &base, "HEAD")?;
                return Ok(ChangedSet::new(
                    files,
                    format!("git range {base}...HEAD (base ref; branch has no upstream)"),
                    Vec::new(),
                ));
            }
            // No upstream and no base ref: the commits being pushed are the
            // ones no remote ref contains. Only valid when remote refs EXIST
            // (see `has_remote_refs`).
            anyhow::ensure!(
                has_remote_refs(root),
                "this branch has no upstream and the repository has no remote-tracking \
                 refs, so the commits being pushed cannot be determined; set one with \
                 `git push -u <remote> <branch>`"
            );
            let files = nul_paths(&git(
                root,
                &[
                    "log",
                    "--format=",
                    "--name-only",
                    "-z",
                    "--relative",
                    "--diff-filter=ACMR",
                    "HEAD",
                    "--not",
                    "--remotes",
                ],
            )?);
            Ok(ChangedSet::new(
                files,
                "git commits not present on any remote (no upstream configured)",
                Vec::new(),
            ))
        }
        Mode::WorkingTree => {
            let mut files = if head_exists(root) {
                nul_paths(&git(
                    root,
                    &[
                        "diff",
                        "--name-only",
                        "-z",
                        "--relative",
                        "--diff-filter=ACMR",
                        "HEAD",
                    ],
                )?)
            } else {
                // Unborn branch: there is no HEAD to diff against, so the
                // staged adds are the whole tracked story.
                staged(root)?
            };
            files.extend(untracked(root)?);
            Ok(ChangedSet::new(
                files,
                "git working tree vs HEAD, plus untracked files",
                Vec::new(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // Real git fixtures, never mocks: the whole defect was a changed set that
    // did not come from git, so a fake git proves nothing.

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

    /// A repo with one committed file carrying "pre-existing findings" — i.e.
    /// content the scanner would flag — and a clean tree.
    fn repo(dir: &tempfile::TempDir) -> PathBuf {
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        run(&root, &["init", "-q", "-b", "main"]);
        run(&root, &["config", "user.email", "t@example.com"]);
        run(&root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("legacy.go"), "package main\n// old debt\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "seed"]);
        root
    }

    #[test]
    fn hook_names_map_to_modes_and_an_unknown_name_never_widens() {
        assert_eq!(Mode::from_hook(Some("pre-commit")), Mode::PreCommit);
        assert_eq!(
            Mode::from_hook(Some("pre-push")),
            Mode::PrePush {
                fallback_base: None
            }
        );
        assert_eq!(Mode::from_hook(None), Mode::WorkingTree);
        // A typo must not become "scan everything".
        assert_eq!(Mode::from_hook(Some("precommit")), Mode::WorkingTree);
    }

    /// THE REGRESSION THAT MATTERS MOST. One staged file in a repo whose other
    /// files carry pre-existing findings: the changed set is that ONE file,
    /// and it is identical whether or not any scanner cache exists — because
    /// no cache is consulted at all.
    #[test]
    fn pre_commit_sees_only_the_staged_file_not_the_repos_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(root.join("test.file"), "").unwrap();
        run(&root, &["add", "test.file"]);

        let cs = resolve(&root, Mode::PreCommit).unwrap();
        assert_eq!(
            cs.files,
            vec!["test.file".to_string()],
            "a cold scanner index must not make legacy.go 'changed'"
        );
        assert!(cs.dirty.is_empty());
    }

    /// DETERMINISM. The resolver is a pure function of git state, so running
    /// it twice over identical code yields identical answers — the property
    /// the packet-index version could not hold (run 1 warmed the index and
    /// changed run 2's answer).
    #[test]
    fn pre_commit_is_identical_across_repeated_runs() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(root.join("test.file"), "").unwrap();
        run(&root, &["add", "test.file"]);

        let first = resolve(&root, Mode::PreCommit).unwrap();
        let second = resolve(&root, Mode::PreCommit).unwrap();
        assert_eq!(first.files, second.files);
        assert_eq!(first.files, vec!["test.file".to_string()]);
    }

    /// Unstaged-only edits are NOT being committed, so they are not in the
    /// pre-commit changed set and cannot block.
    #[test]
    fn pre_commit_excludes_a_file_that_is_only_modified_in_the_working_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(
            root.join("legacy.go"),
            "package main\n// edited, not staged\n",
        )
        .unwrap();
        std::fs::write(root.join("staged.go"), "package main\n").unwrap();
        run(&root, &["add", "staged.go"]);

        let cs = resolve(&root, Mode::PreCommit).unwrap();
        assert_eq!(cs.files, vec!["staged.go".to_string()]);
        assert!(
            !cs.files.contains(&"legacy.go".to_string()),
            "an unstaged edit is not part of the commit"
        );
    }

    /// PARTIAL STAGING, and the honest statement of what is still missing.
    /// The file is in the changed set (its staged hunk IS being committed) and
    /// is flagged `dirty`, because the retrievers read working-tree bytes and
    /// so the unstaged hunk is still what gets parsed. Paths are fixed; the
    /// content gap is reported rather than silently carried.
    #[test]
    fn partial_staging_marks_the_file_dirty_so_the_content_gap_is_stated() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        // Stage one version, then edit further without staging.
        std::fs::write(root.join("legacy.go"), "package main\n// staged hunk\n").unwrap();
        run(&root, &["add", "legacy.go"]);
        std::fs::write(
            root.join("legacy.go"),
            "package main\n// staged hunk\n// unstaged hunk\n",
        )
        .unwrap();

        let cs = resolve(&root, Mode::PreCommit).unwrap();
        assert_eq!(cs.files, vec!["legacy.go".to_string()]);
        assert_eq!(
            cs.dirty,
            vec!["legacy.go".to_string()],
            "a partially staged file must be reported, not silently judged on working-tree bytes"
        );
    }

    /// Deletions carry no sites; keeping them out of the set keeps the gate
    /// from reasoning about files that are gone.
    #[test]
    fn pre_commit_drops_deletions_and_keeps_the_rename_destination() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(root.join("gone.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "second"]);
        run(&root, &["rm", "-q", "gone.go"]);

        let cs = resolve(&root, Mode::PreCommit).unwrap();
        assert!(
            cs.files.is_empty(),
            "a pure deletion leaves nothing to gate on: {:?}",
            cs.files
        );
    }

    /// PRE-PUSH picks up the commits in the pushed range, and nothing older.
    #[test]
    fn pre_push_uses_the_pushed_range_via_the_branch_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        // A local "remote" so the branch can have a real upstream.
        let remote = dir.path().join("remote.git");
        run(&root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
        run(
            &root,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        run(&root, &["push", "-q", "-u", "origin", "main"]);

        // Two unpushed commits.
        std::fs::write(root.join("new_a.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "a"]);
        std::fs::write(root.join("new_b.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "b"]);

        let cs = resolve(
            &root,
            Mode::PrePush {
                fallback_base: None,
            },
        )
        .unwrap();
        assert_eq!(
            cs.files,
            vec!["new_a.go".to_string(), "new_b.go".to_string()],
            "pre-push covers every commit in the range, and only those"
        );
        assert!(!cs.files.contains(&"legacy.go".to_string()));
    }

    /// No upstream but remote refs exist: fall back to "commits no remote
    /// has", which is the same question by another route.
    #[test]
    fn pre_push_without_an_upstream_falls_back_to_commits_not_on_any_remote() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let remote = dir.path().join("remote.git");
        run(&root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
        run(
            &root,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        run(&root, &["push", "-q", "origin", "main"]); // no -u: no upstream

        std::fs::write(root.join("unpushed.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "unpushed"]);

        let cs = resolve(
            &root,
            Mode::PrePush {
                fallback_base: None,
            },
        )
        .unwrap();
        assert_eq!(cs.files, vec!["unpushed.go".to_string()]);
        assert!(cs.source.contains("not present on any remote"));
    }

    /// No upstream AND no remote refs: refuse. `HEAD --not --remotes` would
    /// otherwise walk all of history and hand back the entire repository.
    #[test]
    fn pre_push_with_no_remote_at_all_refuses_rather_than_returning_everything() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let err = resolve(
            &root,
            Mode::PrePush {
                fallback_base: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no upstream"), "got: {err}");
    }

    // --- the CI base-ref range (po-av01j.194) ---

    /// The PR-checkout shape, synthesized exactly: a base branch, a feature
    /// branch with committed work, a CLEAN tree, and HEAD parked on the
    /// feature tip. Returns the repo root.
    fn pr_checkout(dir: &tempfile::TempDir) -> PathBuf {
        let root = repo(dir); // main, one commit, legacy.go
        run(&root, &["checkout", "-q", "-b", "feature"]);
        std::fs::write(root.join("added.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "pr commit 1"]);
        std::fs::write(root.join("also_added.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "pr commit 2"]);
        // ... and main moves on underneath, as it does in any real PR.
        run(&root, &["checkout", "-q", "main"]);
        std::fs::write(root.join("someone_elses.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "unrelated work on main"]);
        run(&root, &["checkout", "-q", "feature"]);
        root
    }

    /// THE BUG (po-av01j.194). In the environment the gate exists for — a CI
    /// pull-request checkout — the working-tree question answers "nothing",
    /// because the tree is clean and HEAD is the PR head. Same repo, same
    /// commit, with a base ref: the PR's own files. One of these two answers
    /// makes a gate; the other makes a gate that reports success having read
    /// no files at all.
    #[test]
    fn a_clean_pr_checkout_sees_nothing_without_a_base_ref_and_the_prs_files_with_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = pr_checkout(&dir);

        let without = resolve(&root, Mode::WorkingTree).unwrap();
        assert!(
            without.files.is_empty(),
            "a clean PR checkout has no working-tree changes — this is the silent pass: {:?}",
            without.files
        );

        let with = resolve(
            &root,
            Mode::BaseRange {
                base: "main".into(),
                source: "GITHUB_BASE_REF env var (PR events)".into(),
            },
        )
        .unwrap();
        assert_eq!(
            with.files,
            vec!["added.go".to_string(), "also_added.go".to_string()],
            "the gate must see every file the PR touched"
        );
        assert!(with.source.contains("main...HEAD"), "{}", with.source);
        assert!(
            with.source.contains("GITHUB_BASE_REF"),
            "the scan must name which link of the chain scoped it: {}",
            with.source
        );
    }

    /// THREE DOTS, NOT TWO. `main...HEAD` diffs from the MERGE BASE, so a
    /// commit landed on main after this branch forked is not this PR's change.
    /// Two dots would drag `someone_elses.go` into the author's gate — the
    /// noise `--changed-only` exists to remove.
    #[test]
    fn the_base_range_excludes_commits_that_landed_on_the_base_after_the_fork() {
        let dir = tempfile::tempdir().unwrap();
        let root = pr_checkout(&dir);
        let cs = resolve(
            &root,
            Mode::BaseRange {
                base: "main".into(),
                source: "test".into(),
            },
        )
        .unwrap();
        assert!(
            !cs.files.contains(&"someone_elses.go".to_string()),
            "work that landed on the base branch is not this change: {:?}",
            cs.files
        );
        assert!(
            !cs.files.contains(&"legacy.go".to_string()),
            "and neither is the repo's pre-existing content: {:?}",
            cs.files
        );
    }

    /// A base ref that does not resolve is an ERROR, never an empty set. The
    /// caller turns it into a refusal; silently answering "nothing changed"
    /// is the failure this bead removes.
    #[test]
    fn an_unresolvable_base_ref_errors_rather_than_returning_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        let root = pr_checkout(&dir);
        assert!(resolve(
            &root,
            Mode::BaseRange {
                base: "no-such-branch".into(),
                source: "test".into(),
            },
        )
        .is_err());
    }

    /// Argument injection: a revision that begins with a dash never reaches
    /// git as an option.
    #[test]
    fn a_dash_leading_base_is_refused_before_git_sees_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = pr_checkout(&dir);
        let err = resolve(
            &root,
            Mode::BaseRange {
                base: "--output=/tmp/pwned".into(),
                source: "test".into(),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("leading dash"), "got: {err}");
    }

    /// PRE-PUSH IS UNCHANGED WHEN IT HAS AN UPSTREAM. The pushed range is the
    /// better answer (it is the actual push target), so a configured base ref
    /// does not displace it — the same precedence rvl-cli gives the pushed
    /// ref's remote sha over its `defaultBase`.
    #[test]
    fn pre_push_prefers_its_upstream_over_a_configured_base_ref() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        let remote = dir.path().join("remote.git");
        run(&root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
        run(
            &root,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        run(&root, &["push", "-q", "-u", "origin", "main"]);
        std::fs::write(root.join("unpushed.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);
        run(&root, &["commit", "-qm", "unpushed"]);

        let cs = resolve(
            &root,
            Mode::PrePush {
                fallback_base: Some("main".into()),
            },
        )
        .unwrap();
        assert_eq!(cs.files, vec!["unpushed.go".to_string()]);
        assert!(cs.source.contains("branch upstream"), "{}", cs.source);
    }

    /// ... but with NO upstream, the base ref answers rather than `--base`
    /// being a flag that silently does nothing.
    #[test]
    fn pre_push_without_an_upstream_uses_the_configured_base_ref() {
        let dir = tempfile::tempdir().unwrap();
        let root = pr_checkout(&dir); // `feature`, no upstream, no remote
        let cs = resolve(
            &root,
            Mode::PrePush {
                fallback_base: Some("main".into()),
            },
        )
        .unwrap();
        assert_eq!(
            cs.files,
            vec!["added.go".to_string(), "also_added.go".to_string()]
        );
        assert!(cs.source.contains("no upstream"), "{}", cs.source);
    }

    /// No hook: the working-tree question, which includes unstaged edits and
    /// brand-new untracked files but still excludes untouched repo files.
    #[test]
    fn working_tree_mode_covers_unstaged_and_untracked_but_not_untouched_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(root.join("legacy.go"), "package main\n// edited\n").unwrap();
        std::fs::write(root.join("brand_new.go"), "package main\n").unwrap();
        std::fs::write(root.join("untouched.go"), "package main\n").unwrap();
        run(&root, &["add", "untouched.go"]);
        run(&root, &["commit", "-qm", "third"]);

        let cs = resolve(&root, Mode::WorkingTree).unwrap();
        assert!(cs.files.contains(&"legacy.go".to_string()));
        assert!(cs.files.contains(&"brand_new.go".to_string()));
        assert!(
            !cs.files.contains(&"untouched.go".to_string()),
            "a committed, unmodified file is not part of the change: {:?}",
            cs.files
        );
    }

    /// Ignored files are not part of anyone's change.
    #[test]
    fn working_tree_mode_skips_gitignored_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::write(root.join(".gitignore"), "ignored.go\n").unwrap();
        run(&root, &["add", ".gitignore"]);
        run(&root, &["commit", "-qm", "ignore"]);
        std::fs::write(root.join("ignored.go"), "package main\n").unwrap();

        let cs = resolve(&root, Mode::WorkingTree).unwrap();
        assert!(
            !cs.files.contains(&"ignored.go".to_string()),
            "{:?}",
            cs.files
        );
    }

    /// A scanned SUBDIRECTORY gets paths relative to itself, and files outside
    /// it are dropped — the same scoping the scan applies.
    #[test]
    fn paths_are_relative_to_the_scanned_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = repo(&dir);
        std::fs::create_dir_all(root.join("svc")).unwrap();
        std::fs::write(root.join("svc/inner.go"), "package svc\n").unwrap();
        std::fs::write(root.join("outer.go"), "package main\n").unwrap();
        run(&root, &["add", "-A"]);

        let cs = resolve(&root.join("svc"), Mode::PreCommit).unwrap();
        assert_eq!(cs.files, vec!["inner.go".to_string()]);
    }

    /// Not a git repo: an ERROR, never an empty or a full set. The caller
    /// turns this into a refusal.
    #[test]
    fn a_non_git_directory_is_an_error_not_a_silent_answer() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        std::fs::write(plain.join("a.go"), "package main\n").unwrap();
        for mode in [
            Mode::PreCommit,
            Mode::PrePush {
                fallback_base: None,
            },
            Mode::WorkingTree,
        ] {
            assert!(
                resolve(&plain, mode.clone()).is_err(),
                "{mode:?} must not invent a changed set outside a git work tree"
            );
        }
    }

    /// An unborn branch (repo initialized, nothing committed yet) still
    /// answers, rather than erroring on the missing HEAD.
    #[test]
    fn an_unborn_branch_resolves_from_the_staged_and_untracked_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("fresh");
        std::fs::create_dir_all(&root).unwrap();
        run(&root, &["init", "-q", "-b", "main"]);
        run(&root, &["config", "user.email", "t@example.com"]);
        run(&root, &["config", "user.name", "Test"]);
        std::fs::write(root.join("first.go"), "package main\n").unwrap();
        run(&root, &["add", "first.go"]);

        assert_eq!(
            resolve(&root, Mode::PreCommit).unwrap().files,
            vec!["first.go".to_string()]
        );
        assert_eq!(
            resolve(&root, Mode::WorkingTree).unwrap().files,
            vec!["first.go".to_string()]
        );
    }
}
