//! rvl-cli v1 compatibility for invocations we cannot reach: git hook files
//! ALREADY ON DISK (po-av01j.191).
//!
//! WHY THIS EXISTS, AND WHY IT DOES NOT CONTRADICT DECISION 5.
//!
//! Decision 5 ratified NO transitional alias for the BINARY NAME. That ruling
//! is about the vocabulary a HUMAN types and the identity a package carries:
//! two spellings of one tool split docs, muscle memory and the brand forever,
//! and the cost of the alias is paid by every future reader. There is a person
//! at the keyboard who can be told once, so telling them is cheap and the
//! alias is not worth its permanent cost.
//!
//! A hook shim is the opposite case on every axis. It is machine-written text
//! that no human reads, executed by git with no human in the loop, and WE
//! wrote it — the user never chose those flags. The brew cask keeps the binary
//! name `rvl`, so `brew upgrade` swaps the binary underneath the shim without
//! touching it; the first thing the user learns is that `git commit` failed
//! and no commit was created. They cannot be "told once", because they are not
//! present at execution.
//!
//! So both rulings apply the SAME rule: compatibility is owed where the caller
//! cannot adapt, and refused where it can. A human can retype `rvl`. A file
//! written months ago by a binary that no longer exists cannot rewrite itself.
//!
//! PERMANENT IN CODE, TRANSIENT PER REPO. We can never know when the last v1
//! shim on earth is retired, so the aliases stay. But no run is silent: every
//! v1-shaped invocation prints a notice naming the exact repair, and
//! `rvl hook install` repairs a v1 shim in place WITHOUT `--force`
//! ([`is_v1_shim`]). A repaired repo never takes this path again, so the v1
//! vocabulary decays out of the world instead of becoming a second supported
//! surface. It is documented as a compatibility alias everywhere it appears
//! and is never the recommended spelling.

use rvl_data::BIN;
use std::sync::atomic::{AtomicBool, Ordering};

/// The banner rvl-cli v1's `hook install` wrote verbatim into every shim it
/// created. One commit in rvl-cli's entire history ever wrote a shim
/// (`b34173b`, po-66evv.8), so this literal identifies a v1 hook exactly,
/// with no heuristics and no false positives.
pub const V1_HOOK_BANNER: &str =
    "Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.";

/// v1's agent-scan invocation, as it appears in a shim body or a lefthook
/// `run:` line. Required IN ADDITION to the banner so a v2 shim (whose own
/// banner also starts "Installed by `rvl hook install`") can never match.
pub const V1_AGENT_CALL: &str = "scan --agent";

/// Is this hook file one rvl-cli v1's `hook install` wrote?
///
/// Deliberately narrow: banner AND agent invocation. A hand-rolled hook that
/// merely mentions `rvl scan --agent` is NOT claimed here — it stays a foreign
/// hook that install refuses without `--force`. It still runs, because the
/// flag aliases below accept its flags; what it does not get is us rewriting a
/// file we did not author.
pub fn is_v1_shim(body: &str) -> bool {
    body.contains(V1_HOOK_BANNER) && body.contains(V1_AGENT_CALL)
}

/// Does a lefthook config wire the v1 agent-scan command? v1's
/// `hook install` printed `run: rvl scan --agent ...` snippets for users to
/// paste, so lefthook repos carry the same stale invocation with no shim file
/// to inspect.
pub fn lefthook_has_v1_command(body: &str) -> bool {
    body.contains(V1_AGENT_CALL)
}

/// The v1 scan flags, as parsed off argv.
#[derive(Debug, Clone, Copy, Default)]
pub struct V1Flags<'a> {
    /// `--agent`: present in EVERY invocation v1's `hook install` wrote, and
    /// in no v2 one. This is what marks an argv as v1-shaped.
    pub agent: bool,
    /// `--staged`: v1's pre-commit change set, `git diff --cached` (index vs
    /// HEAD). Verified in rvl-cli `internal/agentscan.StagedChangeSet`.
    pub staged: bool,
    /// `--pre-push`: v1's pre-push entrypoint, printed by its lefthook
    /// snippet. Scans the range behind each pushed ref.
    pub pre_push: bool,
    /// `--mode enforce|eval`: v1's gate mode.
    pub mode: Option<&'a str>,
}

/// v1 flags resolved into this binary's scan scoping.
#[derive(Debug, PartialEq, Eq)]
pub struct Scoping {
    pub incremental: bool,
    pub changed_only: bool,
    pub hook: Option<String>,
    /// stderr notice for a v1-shaped invocation; `None` when no v1 flag was
    /// used and nothing needs saying.
    pub notice: Option<String>,
    /// `--mode eval`: report findings, never block.
    pub never_block: bool,
}

/// Map a v1 invocation onto v2 scan scoping.
///
/// THE MAPPING, derived from rvl-cli's Go rather than from the flag names:
///
/// * `--staged` -> `--incremental --changed-only --hook pre-commit`.
///   rvl-cli's `--staged` computes `StagedChangeSet` = `git diff --cached`,
///   the index against HEAD. [`crate::changed::Mode::PreCommit`] asks git the
///   identical question (`git diff --cached --name-only`), so this is an exact
///   match, not an approximation.
/// * `--pre-push` and bare `--changed-only` ->
///   `--incremental --changed-only --hook pre-push`.
///   rvl-cli's `--changed-only` resolves a base ref and diffs `base...HEAD`:
///   the COMMITTED work on this branch that the remote does not have.
///   [`crate::changed::Mode::PrePush`] asks `@{upstream}..HEAD` — the same
///   question with the base ref read from git instead of from flags/env.
///   Mapping it to the working-tree question instead would be a silent
///   disarming: a pre-push hook runs on a clean tree, so the changed set would
///   be empty and the gate would pass everything.
/// * `--mode enforce` -> nothing. Enforce is v2's only gate mode (a BLOCKING
///   row exits 3), so v1's default is already what happens.
/// * `--mode eval` -> [`Scoping::never_block`]. v1's eval mode reports and
///   exits 0. Honoring it matters: a user who deliberately disarmed their gate
///   must not have it re-armed by an upgrade.
///
/// `--incremental` is forced on because change scoping is implemented only on
/// the incremental path; v1 had no such flag, so there is nothing to lose.
///
/// AMBIGUITY RULE. `--staged` and `--pre-push` do not exist in v2 at all, so
/// their presence is unambiguous and they are honored on their own. A bare
/// `--changed-only` DOES exist in v2 with a different meaning (working tree),
/// so it is reinterpreted only when `--agent` marks the argv as v1's. A v2
/// user who forgets `--incremental` keeps the explanatory error they get today
/// rather than silently receiving pre-push scope.
///
/// An explicit `--hook` always wins: it is a v2 flag, so its presence means
/// the caller said what they meant.
pub fn resolve(
    v1: V1Flags<'_>,
    incremental: bool,
    changed_only: bool,
    hook: Option<&str>,
) -> anyhow::Result<Scoping> {
    anyhow::ensure!(
        !(v1.staged && v1.pre_push),
        "--staged and --pre-push are mutually exclusive"
    );

    let never_block = match v1.mode.map(str::trim) {
        None => false,
        Some(m) if m.eq_ignore_ascii_case("enforce") => false,
        Some(m) if m.eq_ignore_ascii_case("eval") => true,
        Some(m) => anyhow::bail!("invalid --mode {m:?} (expected enforce or eval)"),
    };

    let v1_hook = if v1.staged {
        Some("pre-commit")
    } else if v1.pre_push || (v1.agent && changed_only && !incremental) {
        Some("pre-push")
    } else {
        None
    };

    let Some(v1_hook) = v1_hook else {
        // No scoping alias fired. `--mode` alone still deserves a word, since
        // eval silently changes whether the gate can block.
        let notice = (v1.mode.is_some()).then(|| notice(v1, None, never_block));
        return Ok(Scoping {
            incremental,
            changed_only,
            hook: hook.map(String::from),
            notice,
            never_block,
        });
    };

    let hook = hook.unwrap_or(v1_hook).to_string();
    let notice = Some(notice(v1, Some(&hook), never_block));
    Ok(Scoping {
        incremental: true,
        changed_only: true,
        hook: Some(hook),
        notice,
        never_block,
    })
}

/// The stderr notice: what we saw, what we ran instead, and the one command
/// that retires the alias for this repo. Trailing newline included.
fn notice(v1: V1Flags<'_>, mapped_hook: Option<&str>, never_block: bool) -> String {
    let mut seen: Vec<String> = Vec::new();
    if v1.agent {
        seen.push("--agent".into());
    }
    if v1.staged {
        seen.push("--staged".into());
    }
    if v1.pre_push {
        seen.push("--pre-push".into());
    }
    if let Some(m) = v1.mode {
        seen.push(format!("--mode {m}"));
    }
    let mut s = format!(
        "note: rvl-cli v1 flags accepted for compatibility ({})",
        seen.join(" ")
    );
    match mapped_hook {
        Some(h) => s.push_str(&format!(
            "; running `{BIN} scan . --incremental --changed-only --hook {h}` \
             (the deterministic gate, no model calls)\n"
        )),
        None => s.push('\n'),
    }
    if never_block {
        s.push_str("note: --mode eval: findings are reported but never block (exit 0)\n");
    }
    s.push_str(&format!(
        "note: rvl-cli v1's `hook install` wrote these flags into git hooks. If this came from \
         one, repair it once with `{BIN} hook install` (no --force needed) and this notice stops.\n"
    ));
    s
}

/// `--mode eval`, process-wide.
///
/// A global rather than a threaded parameter because it is exactly that: one
/// process-wide mode, set once from argv before any scan runs, and read at the
/// SINGLE place a blocking verdict becomes a process status
/// (`render_scan_output`). Threading a bool through five signatures to reach
/// one `if` would make the gate harder to read, not safer.
static NEVER_BLOCK: AtomicBool = AtomicBool::new(false);

pub fn set_never_block(v: bool) {
    NEVER_BLOCK.store(v, Ordering::Relaxed);
}

pub fn never_block() -> bool {
    NEVER_BLOCK.load(Ordering::Relaxed)
}

/// Printed in place of the block, so an eval-mode run says out loud that it
/// found something and chose not to stop the commit.
pub const EVAL_MODE_NOTE: &str =
    "BLOCKING findings above; --mode eval (rvl-cli v1) reports without blocking, exit 0.";

/// The two shims rvl-cli v1's `hook install` actually wrote, verbatim
/// (rvl-cli `internal/commands/hook.go`, `writeHookShim` + `selectedHooks`).
#[cfg(test)]
pub(crate) const V1_PRE_COMMIT_SHIM: &str = "#!/bin/sh\n\
     # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
     exec rvl scan --agent --staged --mode enforce\n";
#[cfg(test)]
pub(crate) const V1_PRE_PUSH_SHIM: &str = "#!/bin/sh\n\
     # Installed by `rvl hook install` (po-66evv.8): agent-scan git gate.\n\
     # WARNING: pre-push stopgap. The real stdin ref protocol lands in\n\
     # po-66evv.9 as `rvl scan --agent --pre-push`; swap it in when available.\n\
     exec rvl scan --agent --changed-only\n";

#[cfg(test)]
mod tests {
    use super::*;
    use super::{V1_PRE_COMMIT_SHIM as V1_PRE_COMMIT, V1_PRE_PUSH_SHIM as V1_PRE_PUSH};

    #[test]
    fn detects_both_v1_shims_and_nothing_else() {
        assert!(is_v1_shim(V1_PRE_COMMIT));
        assert!(is_v1_shim(V1_PRE_PUSH));
        // The v2 shim shares the "Installed by `rvl hook install`" prefix and
        // must never be mistaken for its predecessor.
        assert!(!is_v1_shim(
            "#!/bin/sh\n# Installed by `rvl hook install`: Revelara deterministic scan gate.\n\
             exec rvl scan . --incremental --changed-only --hook pre-commit\n"
        ));
        // A hand-rolled agent-scan hook is foreign, not ours.
        assert!(!is_v1_shim("#!/bin/sh\nexec rvl scan --agent --staged\n"));
        assert!(!is_v1_shim("#!/bin/sh\necho custom\n"));
    }

    fn v1(agent: bool, staged: bool, pre_push: bool, mode: Option<&str>) -> V1Flags<'_> {
        V1Flags {
            agent,
            staged,
            pre_push,
            mode,
        }
    }

    #[test]
    fn v1_pre_commit_shim_maps_to_the_pre_commit_gate() {
        // `rvl scan --agent --staged --mode enforce`
        let s = resolve(v1(true, true, false, Some("enforce")), false, false, None).unwrap();
        assert!(s.incremental && s.changed_only);
        assert_eq!(s.hook.as_deref(), Some("pre-commit"));
        assert!(!s.never_block);
        assert!(s.notice.unwrap().contains("--hook pre-commit"));
    }

    #[test]
    fn v1_pre_push_shim_maps_to_the_pre_push_gate() {
        // `rvl scan --agent --changed-only` (the shim) ...
        let s = resolve(v1(true, false, false, None), false, true, None).unwrap();
        assert!(s.incremental && s.changed_only);
        assert_eq!(s.hook.as_deref(), Some("pre-push"));
        // ... and `rvl scan --agent --pre-push` (v1's lefthook snippet).
        let s = resolve(v1(true, false, true, None), false, false, None).unwrap();
        assert_eq!(s.hook.as_deref(), Some("pre-push"));
        assert!(s.incremental && s.changed_only);
    }

    #[test]
    fn bare_changed_only_without_the_v1_marker_is_left_alone() {
        // No `--agent`: a v2 user who forgot `--incremental` keeps today's
        // explanatory error instead of silently getting pre-push scope.
        let s = resolve(v1(false, false, false, None), false, true, None).unwrap();
        assert!(!s.incremental);
        assert_eq!(s.hook, None);
        assert!(s.notice.is_none());
    }

    #[test]
    fn an_explicit_hook_flag_wins_over_the_alias() {
        let s = resolve(v1(true, true, false, None), false, false, Some("pre-push")).unwrap();
        assert_eq!(s.hook.as_deref(), Some("pre-push"));
    }

    #[test]
    fn mode_eval_disarms_the_gate_and_says_so() {
        let s = resolve(v1(true, true, false, Some("eval")), false, false, None).unwrap();
        assert!(s.never_block);
        assert!(s.notice.unwrap().contains("never block"));
        // enforce is v2's only mode, so it changes nothing.
        let s = resolve(v1(true, true, false, Some("ENFORCE")), false, false, None).unwrap();
        assert!(!s.never_block);
    }

    #[test]
    fn rejects_impossible_v1_combinations() {
        assert!(resolve(v1(true, true, true, None), false, false, None).is_err());
        assert!(resolve(v1(true, true, false, Some("nope")), false, false, None).is_err());
    }

    #[test]
    fn a_v2_invocation_passes_through_untouched() {
        let s = resolve(
            v1(false, false, false, None),
            true,
            true,
            Some("pre-commit"),
        )
        .unwrap();
        assert_eq!(
            s,
            Scoping {
                incremental: true,
                changed_only: true,
                hook: Some("pre-commit".into()),
                notice: None,
                never_block: false,
            }
        );
    }
}
