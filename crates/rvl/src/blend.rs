//! `rvl scan --blend`: one command that blends the deterministic scan with
//! the user's own coding agent (po-av01j.205).
//!
//! The shape: deterministic scan -> the sites it could NOT decide go to the
//! agent -> verdicts merge into the report -> one result. The agent here is an
//! ADJUDICATOR for the residue, exactly the po-av01j.15 hook lane's contract,
//! reused rather than re-implemented (`agent.rs` owns the adapter, prompt,
//! verdict parsing and the asymmetric application). The agent as a scanner in
//! its own right (semantic lenses, two-way dedup/precedence/union merge) is
//! NOT part of this module yet; the block says so on every run so the reader
//! never mistakes adjudication for the whole semantic half.
//!
//! Three rules this module exists to keep:
//!
//! * A NEW SPELLING. `--agent` stays the deterministic no-op alias, because
//!   every pre-commit shim rvl-cli v1 wrote runs `rvl scan --agent --staged`
//!   (po-av01j.191). Giving `--agent` its natural meaning back would turn each
//!   inherited hook into a network- and token-dependent gate on every commit.
//!   `--blend` is refused on the hook path; hooks keep the consent lane.
//! * THE FLAG IS THE CONSENT FOR A MANUAL RUN, and the vetoes still win:
//!   `RVL_NO_AGENT=1`, the org `force_deny` kill switch, and an EXPLICIT repo
//!   `scanner.use_agent: deny`. An absent repo key is not a veto here: the
//!   user typed the flag, which is the committed, deliberate act the hook
//!   lane's deny-by-default stands in for.
//! * DEGRADED NEVER READS AS CLEAN (po-av01j.199 at a new seam). No agent,
//!   a veto, a timeout, an error, a malformed reply, or runtime sites the
//!   agent never saw all fail OPEN (the exit code is the deterministic one)
//!   but set [`BlendOutput::incomplete`], which turns the footer's
//!   "commit clean" into "NOT A BLENDED RESULT". Reporting the deterministic
//!   half as the complete answer is the bug this rule prevents.
//!
//! Agent verdicts never mutate deterministic findings, gate metrics or the
//! `--out` eval rows: `apply_verdicts` does not take them as input.

use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::agent::{self, Adapter, Adjudication, Outcome, UndecidedSite};
use crate::render;

/// Most runtime-scoped undecided sites one blend sends. A manual scan of a
/// large repo can hold thousands of abstains; the cap keeps one command
/// bounded, and every site over it makes the result INCOMPLETE, said out loud.
pub const MAX_BLEND_SITES: usize = 50;

/// Total wall-clock budget for all agent chunks of one blend. On top of the
/// deterministic scan, which is finished before the first chunk is sent.
pub const DEFAULT_BLEND_BUDGET: Duration = Duration::from_secs(300);

/// The undecided sites a blend is responsible for.
#[derive(Debug, Default, PartialEq)]
pub struct Selection {
    /// Runtime-scoped undecided sites, at most [`MAX_BLEND_SITES`].
    pub batch: Vec<UndecidedSite>,
    /// Runtime-scoped undecided sites over the cap: never sent.
    pub over_cap: usize,
    /// Undecided sites in test, migration, dev-only or backfill code. Not a
    /// production reliability question, so not the blend's responsibility;
    /// counted so the block can say they were skipped deliberately.
    pub out_of_scope: usize,
}

/// Select the residue: sites the engine did not resolve, restricted to the
/// changed set when `--changed-only` scoped the run, runtime scope only.
pub fn select_undecided(
    findings: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    changed: Option<&[String]>,
) -> Selection {
    let changed: Option<std::collections::HashSet<&str>> =
        changed.map(|c| c.iter().map(String::as_str).collect());
    let mut sel = Selection::default();
    for (f, s) in findings.iter().zip(sites.iter()) {
        if f.verdict.is_resolved() {
            continue;
        }
        if let Some(c) = &changed {
            if !c.contains(s.file_path.as_str()) {
                continue;
            }
        }
        if s.scope() != rvl_core::ScopeClass::Runtime {
            sel.out_of_scope += 1;
            continue;
        }
        if sel.batch.len() == MAX_BLEND_SITES {
            sel.over_cap += 1;
            continue;
        }
        sel.batch.push(UndecidedSite {
            site_key: s.site_key(),
            file_line: format!("{}:{}", s.file_path, s.line_number),
            client_type: s.client_type.clone(),
            method: s.method.clone(),
            reason: f.reason.clone(),
        });
    }
    sel
}

/// The vetoes a typed `--blend` still answers to, strongest first. `None` =
/// the agent may be consulted.
pub fn veto(repo_denied: bool, org_force_deny: bool, env_no_agent: bool) -> Option<&'static str> {
    if env_no_agent {
        Some("RVL_NO_AGENT=1 (env hard-off)")
    } else if org_force_deny {
        Some("org kill switch (org-policy agent: force_deny)")
    } else if repo_denied {
        Some("repo denies it (.revelara.yaml scanner.use_agent: deny)")
    } else {
        None
    }
}

/// Send the batch in chunks of [`agent::MAX_BATCH_SITES`] under one total
/// budget. A breaker: the first chunk that times out, errors or replies
/// malformed stops the run, because the next chunk goes to the same agent and
/// would most likely fail the same way. Returns the merged outcome and how
/// many sites were never sent.
pub fn run_chunks<A: Adapter + Sync + 'static>(
    adapter: Arc<A>,
    batch: &[UndecidedSite],
    budget: Duration,
) -> (Outcome, usize) {
    let start = Instant::now();
    let mut merged = Outcome {
        agent: adapter.name().to_string(),
        verdicts: Vec::new(),
        latency: Duration::ZERO,
        timed_out: false,
        malformed: false,
        error: None,
    };
    let mut sent = 0;
    for chunk in batch.chunks(agent::MAX_BATCH_SITES) {
        let Some(left) = budget.checked_sub(start.elapsed()).filter(|d| !d.is_zero()) else {
            merged.timed_out = true;
            break;
        };
        let out = agent::adjudicate(Arc::clone(&adapter), chunk, left);
        sent += chunk.len();
        merged.verdicts.extend(out.verdicts);
        merged.latency += out.latency;
        merged.timed_out = out.timed_out;
        merged.malformed = out.malformed;
        merged.error = out.error;
        if merged.timed_out || merged.malformed || merged.error.is_some() {
            break;
        }
    }
    (merged, batch.len() - sent)
}

/// The additive `--out` view of a blend: status and counts. Verdict text
/// rides in `block`, provenance-tagged, exactly as rendered.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct BlendSummary {
    /// True when every runtime undecided site in scope got an agent answer
    /// attempt that completed. False = the deterministic half alone.
    pub complete: bool,
    /// Why the blend is incomplete; null when complete.
    pub reason: Option<String>,
    /// The agent consulted; null when none was.
    pub agent: Option<String>,
    /// Runtime undecided sites the blend was responsible for.
    pub in_scope: usize,
    pub sent: usize,
    pub cleared: usize,
    pub warned: usize,
    /// In-scope sites still undecided after the blend (includes unsent ones).
    pub undecided: usize,
    /// Non-runtime undecided sites skipped deliberately.
    pub out_of_scope: usize,
    pub block: String,
}

/// What the scan renderer consumes.
#[derive(Debug, Default)]
pub struct BlendOutput {
    /// Agent `violates` rows for the ladder, ONLY under
    /// `scanner.agent_verdicts: gate` (same rule as the hook lane).
    pub gate_findings: Vec<render::Finding>,
    pub block: String,
    /// Set when the result is NOT a blend; drives the footer.
    pub incomplete: Option<String>,
    pub summary: BlendSummary,
}

/// Why a blend is not complete, or `None`. `unsent` counts runtime sites the
/// agent never saw (over the cap, or cut off by the breaker/budget).
fn incompleteness(outcome: Option<&Outcome>, unsent: usize) -> Option<String> {
    if let Some(o) = outcome {
        if o.timed_out {
            return Some(format!(
                "agent budget exhausted after {:.0}s",
                o.latency.as_secs_f64()
            ));
        }
        if o.malformed {
            return Some("agent reply did not match the verdict contract".to_string());
        }
        if let Some(e) = &o.error {
            return Some(format!("agent invocation failed ({e})"));
        }
    }
    (unsent > 0).then(|| format!("{unsent} undecided runtime site(s) never reached the agent"))
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

fn header(agent_name: &str, gate: bool, color: bool) -> String {
    let mode = if gate {
        "gate mode: agent violations join BLOCKING"
    } else {
        "advisory: agent verdicts never block"
    };
    format!(
        "{} {}\n",
        paint("\u{25a0} BLEND", "35", color),
        paint(
            &format!("(--blend \u{00b7} {agent_name} \u{00b7} {mode})"),
            "2",
            color
        )
    )
}

/// The lines every block ends with: what was skipped on purpose, what the
/// blend does not do yet, and the one-line verdict on the blend itself.
fn footer_lines(sel: &Selection, incomplete: Option<&str>, color: bool) -> String {
    let mut o = String::new();
    if sel.out_of_scope > 0 {
        o.push_str(&format!(
            "  {}\n",
            paint(
                &format!(
                    "{} undecided site(s) in test/migration/dev-only/backfill code not sent (runtime only)",
                    sel.out_of_scope
                ),
                "2",
                color
            )
        ));
    }
    o.push_str(&format!(
        "  {}\n",
        paint(
            "semantic lenses (agent as a scanner in its own right) are not part of --blend yet: adjudication only",
            "2",
            color
        )
    ));
    match incomplete {
        Some(r) => o.push_str(&format!(
            "  {}\n",
            paint(
                &format!("INCOMPLETE \u{2014} {r}; this report is the deterministic half alone"),
                "33",
                color
            )
        )),
        None => o.push_str(&format!(
            "  {}\n",
            paint(
                &format!(
                    "blend complete: {} undecided runtime site(s) sent to the agent",
                    sel.batch.len()
                ),
                "2",
                color
            )
        )),
    }
    o
}

/// The blend when the agent half cannot run at all (a veto or no agent).
/// Nothing was consulted, so every in-scope site stays undecided; with no
/// in-scope site there was nothing to consult and the blend is complete.
pub fn unavailable(sel: &Selection, why: &str, gate: bool, color: bool) -> BlendOutput {
    let in_scope = sel.batch.len() + sel.over_cap;
    let incomplete = (in_scope > 0).then(|| format!("agent half unavailable: {why}"));
    let mut block = header("no agent", gate, color);
    block.push_str(&format!(
        "  {}\n",
        paint(&format!("agent not consulted: {why}"), "2", color)
    ));
    block.push_str(&footer_lines(sel, incomplete.as_deref(), color));
    BlendOutput {
        gate_findings: Vec::new(),
        summary: BlendSummary {
            complete: incomplete.is_none(),
            reason: incomplete.clone(),
            agent: None,
            in_scope,
            sent: 0,
            cleared: 0,
            warned: 0,
            undecided: in_scope,
            out_of_scope: sel.out_of_scope,
            block: block.clone(),
        },
        block,
        incomplete,
    }
}

/// Blend with a resolved agent: chunked adjudication, asymmetric merge, block.
pub fn blend_with<A: Adapter + Sync + 'static>(
    adapter: Arc<A>,
    sel: &Selection,
    budget: Duration,
    gate: bool,
    color: bool,
) -> BlendOutput {
    let name = adapter.name().to_string();
    if sel.batch.is_empty() {
        let incomplete = incompleteness(None, sel.over_cap);
        let mut block = header(&name, gate, color);
        block.push_str(&footer_lines(sel, incomplete.as_deref(), color));
        return BlendOutput {
            summary: BlendSummary {
                complete: incomplete.is_none(),
                reason: incomplete.clone(),
                agent: Some(name),
                in_scope: sel.over_cap,
                undecided: sel.over_cap,
                out_of_scope: sel.out_of_scope,
                block: block.clone(),
                ..Default::default()
            },
            block,
            incomplete,
            gate_findings: Vec::new(),
        };
    }
    let (outcome, unsent) = run_chunks(adapter, &sel.batch, budget);
    let adj: Adjudication = agent::apply_verdicts(&sel.batch, &outcome);
    let not_sent = unsent + sel.over_cap;
    let incomplete = incompleteness(Some(&outcome), not_sent);
    let mut block = header(&name, gate, color);
    block.push_str(&agent::render_verdict_lines(
        &adj, &outcome, not_sent, color,
    ));
    block.push_str(&footer_lines(sel, incomplete.as_deref(), color));
    BlendOutput {
        gate_findings: agent::gate_findings(&adj, &sel.batch, gate),
        summary: BlendSummary {
            complete: incomplete.is_none(),
            reason: incomplete.clone(),
            agent: Some(name),
            in_scope: sel.batch.len() + sel.over_cap,
            sent: sel.batch.len() - unsent,
            cleared: adj.cleared.len(),
            warned: adj.warned.len(),
            undecided: adj.undecided + sel.over_cap,
            out_of_scope: sel.out_of_scope,
            block: block.clone(),
        },
        block,
        incomplete,
    }
}

/// Explicit `scanner.use_agent: deny` in `<repo>/.revelara.yaml`. Absent is
/// not deny for a typed `--blend`; a malformed file is treated as deny, so a
/// broken config never grants what it may have been written to refuse.
fn repo_denies(repo_root: &Path) -> bool {
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct Scanner {
        use_agent: String,
    }
    #[derive(Default, serde::Deserialize)]
    #[serde(default)]
    struct File {
        scanner: Scanner,
    }
    match std::fs::read_to_string(repo_root.join(".revelara.yaml")) {
        Ok(text) => match serde_yaml::from_str::<File>(&text) {
            Ok(f) => f.scanner.use_agent == "deny",
            Err(_) => true,
        },
        Err(_) => false,
    }
}

/// The whole blend for one manual scan. Reads the environment and the user's
/// agent selection; every failure path fails open into an INCOMPLETE block.
pub fn run(
    repo_root: &Path,
    changed: Option<&[String]>,
    findings: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    color: bool,
) -> BlendOutput {
    let sel = select_undecided(findings, sites, changed);
    let gate = agent::RepoAgentConfig::load(repo_root).gate_verdicts;
    let env_no_agent = std::env::var("RVL_NO_AGENT").ok().as_deref() == Some("1");
    if let Some(why) = veto(
        repo_denies(repo_root),
        agent::load_org_force_deny(),
        env_no_agent,
    ) {
        return unavailable(&sel, why, gate, color);
    }
    let env_cmd = std::env::var("RVL_AGENT_CMD").ok();
    let Some(adapter) = agent::resolve_adapter(&agent::user_agent_selection(), env_cmd.as_deref())
    else {
        return unavailable(
            &sel,
            "no approved agent found (claude/copilot on PATH, `agent:` in \
             ~/.revelara/config.yaml, or RVL_AGENT_CMD)",
            gate,
            color,
        );
    };
    blend_with(Arc::new(adapter), &sel, DEFAULT_BLEND_BUDGET, gate, color)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abstain(reason: &str) -> rvl_propagate::Finding {
        rvl_propagate::Finding {
            site_id: "sid".to_string(),
            verdict: rvl_core::Verdict::Abstain,
            reason: reason.to_string(),
        }
    }

    fn resolved() -> rvl_propagate::Finding {
        rvl_propagate::Finding {
            site_id: "sid".to_string(),
            verdict: rvl_core::Verdict::Violates,
            reason: "violates: unbounded".to_string(),
        }
    }

    fn site(path: &str, line: u32) -> rvl_core::Site {
        rvl_core::Site {
            file_path: path.to_string(),
            line_number: line,
            client_type: "x.Client".to_string(),
            method: "Do".to_string(),
            ..Default::default()
        }
    }

    fn batch(n: usize) -> Selection {
        let findings: Vec<_> = (0..n).map(|_| abstain("no spec")).collect();
        let sites: Vec<_> = (0..n).map(|i| site("svc/a.go", i as u32 + 1)).collect();
        select_undecided(&findings, &sites, None)
    }

    struct Fake {
        reply: Result<String, String>,
        delay: Duration,
        calls: std::sync::Mutex<usize>,
    }

    impl Fake {
        fn new(reply: Result<&str, &str>) -> Arc<Self> {
            Arc::new(Fake {
                reply: reply.map(String::from).map_err(String::from),
                delay: Duration::ZERO,
                calls: std::sync::Mutex::new(0),
            })
        }
        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl Adapter for Fake {
        fn name(&self) -> &str {
            "fake"
        }
        fn invoke(&self, prompt: &str) -> anyhow::Result<String> {
            *self.calls.lock().unwrap() += 1;
            std::thread::sleep(self.delay);
            match &self.reply {
                // "ALL" answers every site in the prompt with `violates`.
                Ok(s) if s == "ALL" => {
                    let rows: Vec<String> = prompt
                        .lines()
                        .filter_map(|l| l.split_once(". site: ").map(|(_, k)| k))
                        .map(|k| format!(r#"{{"site":"{k}","verdict":"violates","reason":"r"}}"#))
                        .collect();
                    Ok(format!("[{}]", rows.join(",")))
                }
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        }
    }

    #[test]
    fn selection_takes_runtime_undecided_sites_only() {
        let findings = vec![
            abstain("no spec"),
            resolved(),
            abstain("no spec"),
            abstain("depends"),
        ];
        let sites = vec![
            site("svc/a.go", 1),
            site("svc/a.go", 2),
            site("svc/a_test.go", 3),
            site("migrations/001.go", 4),
        ];
        let sel = select_undecided(&findings, &sites, None);
        assert_eq!(sel.batch.len(), 1, "{sel:?}");
        assert_eq!(sel.batch[0].file_line, "svc/a.go:1");
        assert_eq!(sel.out_of_scope, 2, "test + migration skipped on purpose");
        assert_eq!(sel.over_cap, 0);
    }

    #[test]
    fn selection_honors_the_changed_set() {
        let findings = vec![abstain("no spec"), abstain("no spec")];
        let sites = vec![site("svc/a.go", 1), site("svc/b.go", 2)];
        let changed = vec!["svc/b.go".to_string()];
        let sel = select_undecided(&findings, &sites, Some(&changed));
        assert_eq!(sel.batch.len(), 1);
        assert_eq!(sel.batch[0].file_line, "svc/b.go:2");
    }

    #[test]
    fn selection_counts_sites_over_the_cap() {
        let sel = batch(MAX_BLEND_SITES + 3);
        assert_eq!(sel.batch.len(), MAX_BLEND_SITES);
        assert_eq!(sel.over_cap, 3);
    }

    #[test]
    fn vetoes_in_precedence_order() {
        assert_eq!(veto(false, false, false), None);
        assert!(veto(true, true, true).unwrap().contains("RVL_NO_AGENT"));
        assert!(veto(true, true, false).unwrap().contains("org kill switch"));
        assert!(veto(true, false, false)
            .unwrap()
            .contains("use_agent: deny"));
    }

    #[test]
    fn repo_deny_is_explicit_only() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!repo_denies(dir.path()), "no file is not a deny");
        let f = dir.path().join(".revelara.yaml");
        std::fs::write(&f, "project: x\n").unwrap();
        assert!(!repo_denies(dir.path()), "absent key is not a deny");
        std::fs::write(&f, "scanner:\n  use_agent: deny\n").unwrap();
        assert!(repo_denies(dir.path()));
        std::fs::write(&f, "scanner: [unclosed\n").unwrap();
        assert!(repo_denies(dir.path()), "malformed config never grants");
    }

    #[test]
    fn chunks_cover_the_whole_batch() {
        let sel = batch(agent::MAX_BATCH_SITES * 2 + 1);
        let fake = Fake::new(Ok("ALL"));
        let (out, unsent) = run_chunks(Arc::clone(&fake), &sel.batch, Duration::from_secs(5));
        assert_eq!(fake.calls(), 3);
        assert_eq!(unsent, 0);
        assert_eq!(out.verdicts.len(), sel.batch.len());
    }

    #[test]
    fn breaker_stops_after_the_first_failed_chunk() {
        let sel = batch(agent::MAX_BATCH_SITES * 3);
        let fake = Fake::new(Err("429 rate limited"));
        let (out, unsent) = run_chunks(Arc::clone(&fake), &sel.batch, Duration::from_secs(5));
        assert_eq!(fake.calls(), 1, "the breaker must stop further chunks");
        assert_eq!(unsent, agent::MAX_BATCH_SITES * 2);
        assert!(out.error.unwrap().contains("429"));
    }

    #[test]
    fn a_complete_blend_merges_verdicts_and_says_complete() {
        let sel = batch(2);
        let out = blend_with(
            Fake::new(Ok("ALL")),
            &sel,
            Duration::from_secs(5),
            false,
            false,
        );
        assert_eq!(out.incomplete, None, "{}", out.block);
        assert!(out.summary.complete);
        assert_eq!(out.summary.warned, 2);
        assert_eq!(out.summary.sent, 2);
        assert!(out.gate_findings.is_empty(), "advisory mode never blocks");
        assert!(out.block.contains("BLEND") && out.block.contains("blend complete"));
        assert!(out.block.contains("adjudication only"), "{}", out.block);
    }

    #[test]
    fn gate_mode_turns_violations_into_ladder_rows() {
        let sel = batch(1);
        let out = blend_with(
            Fake::new(Ok("ALL")),
            &sel,
            Duration::from_secs(5),
            true,
            false,
        );
        assert_eq!(out.gate_findings.len(), 1);
        assert!(out.gate_findings[0].class_rule.starts_with("agent."));
    }

    #[test]
    fn a_failed_agent_is_incomplete_not_clean() {
        let sel = batch(2);
        let out = blend_with(
            Fake::new(Err("offline")),
            &sel,
            Duration::from_secs(5),
            false,
            false,
        );
        let why = out
            .incomplete
            .expect("a failed agent must not read as a blend");
        assert!(why.contains("offline"), "{why}");
        assert!(!out.summary.complete);
        assert_eq!(out.summary.undecided, 2);
        assert!(out.block.contains("INCOMPLETE"), "{}", out.block);
    }

    #[test]
    fn a_malformed_reply_is_incomplete() {
        let sel = batch(1);
        let out = blend_with(
            Fake::new(Ok("I think it's fine")),
            &sel,
            Duration::from_secs(5),
            false,
            false,
        );
        assert!(out.incomplete.unwrap().contains("verdict contract"));
    }

    #[test]
    fn a_timed_out_agent_is_incomplete() {
        let sel = batch(1);
        let fake = Arc::new(Fake {
            reply: Ok("ALL".into()),
            delay: Duration::from_millis(300),
            calls: std::sync::Mutex::new(0),
        });
        let out = blend_with(fake, &sel, Duration::from_millis(20), false, false);
        assert!(out.incomplete.unwrap().contains("budget exhausted"));
    }

    #[test]
    fn unknown_verdicts_are_the_agent_answering_not_a_degraded_blend() {
        let sel = batch(1);
        let key = sel.batch[0].site_key.clone();
        let reply = format!(r#"[{{"site":"{key}","verdict":"unknown","reason":"cannot tell"}}]"#);
        let out = blend_with(
            Fake::new(Ok(&reply)),
            &sel,
            Duration::from_secs(5),
            false,
            false,
        );
        assert_eq!(out.incomplete, None);
        assert_eq!(out.summary.undecided, 1);
    }

    #[test]
    fn sites_over_the_cap_make_the_blend_incomplete() {
        let sel = batch(MAX_BLEND_SITES + 1);
        let out = blend_with(
            Fake::new(Ok("ALL")),
            &sel,
            Duration::from_secs(5),
            false,
            false,
        );
        assert!(out
            .incomplete
            .unwrap()
            .contains("1 undecided runtime site(s) never reached"));
    }

    #[test]
    fn an_unavailable_agent_with_work_to_do_is_incomplete() {
        let sel = batch(3);
        let out = unavailable(&sel, "RVL_NO_AGENT=1 (env hard-off)", false, false);
        let why = out.incomplete.expect("no agent must not read as a blend");
        assert!(why.contains("RVL_NO_AGENT"), "{why}");
        assert_eq!(out.summary.undecided, 3);
        assert!(out.block.contains("agent not consulted"));
    }

    #[test]
    fn an_unavailable_agent_with_nothing_to_decide_is_still_complete() {
        // Nothing undecided at runtime: the deterministic answer IS the whole
        // answer, and calling it incomplete would spend the word for nothing.
        let out = unavailable(
            &Selection::default(),
            "no approved agent found",
            false,
            false,
        );
        assert_eq!(out.incomplete, None);
        assert!(out.summary.complete);
    }
}
