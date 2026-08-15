//! Hook-mode agent adjudication (po-av01j.15).
//!
//! Amends the po-ipkfg.20 escape-hatch decision's "manual scans only" clause
//! per its 2026-08-04 forward-amendment note and wayfinder po-ae75b.3 clause 2:
//! a git hook run may delegate its DELTA-SCOPED UNDECIDED sites (median 0 /
//! p95 <=3 per run) to the user's already-approved coding agent, under strict
//! bounds. Everything else from the original decision stays in force:
//!
//! * UNDECIDED-only: deterministic verdicts are untouchable. The agent never
//!   overrides, filters, or re-ranks engine findings.
//! * Approved-agent transport: the hatch shells out to a coding agent the user
//!   already runs on this codebase (Claude Code, Copilot, or a custom command
//!   via `RVL_AGENT_CMD`). rvl introduces zero new data flows,
//!   endpoints, or key handling; the prompt goes to the USER'S OWN agent.
//! * ONE batched headless invocation per hook run, capped at
//!   [`MAX_BATCH_SITES`] sites.
//! * Separate wall-clock budget ON TOP of the deterministic 10s fail-open cap
//!   (defaults: pre-commit 30s, pre-push 120s). Timeout, error, or malformed
//!   agent output all fail OPEN: sites stay undecided, the hook proceeds.
//! * Consent is three independent layers, each OFF by default:
//!   repo `scanner.use_agent: allow` AND per-hook
//!   `scanner.agent_hooks.<hook>.enabled: true`, overridden by the org
//!   force-deny kill switch (`~/.revelara/org-policy.yaml`) and the
//!   `RVL_NO_AGENT=1` env hard-off.
//! * Asymmetric verdicts: `satisfies` CLEARS a site (shown in the agent
//!   block); `violates` becomes an agent-tagged WARNING in the agent block.
//!   Blocking stays deterministic-only unless the repo sets
//!   `scanner.agent_verdicts: gate`, in which case agent violations join the
//!   ladder's BLOCKING section (still agent-tagged, still waivable under the
//!   `agent.<client_type>.<method>` rule).
//! * Agent verdicts NEVER enter gate metrics or eval: the `--out` eval rows
//!   and the shape-only report are built from the deterministic findings
//!   alone; nothing in this module mutates them (see
//!   `verdicts_never_mutate_deterministic_findings`).
//! * Telemetry is identity-only and LOCAL-ONLY today (same posture as the
//!   shape report): hook name, adapter name, `client_type.method` + count for
//!   the adjudicated surfaces, latency, timeout flag. NO verdicts, NO reasons,
//!   NO code, NO paths ever ride in it — see [`AgentTelemetry`].
//!
//! The signed-overlay TRANSPORT for the org kill switch (how
//! `org-policy.yaml` gets synced/signed) is follow-up work; this module owns
//! the local read point and fails CLOSED on a present-but-unreadable policy.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::render;

/// Hard cap on how many undecided sites ride the single batched invocation.
/// Delta scoping keeps the real population tiny (median 0 / p95 <=3); the cap
/// is a guard against a pathological delta, not a tuning knob. Overflow sites
/// simply stay undecided and the block says so.
pub const MAX_BATCH_SITES: usize = 10;

/// Which git hook this scan runs under. The hook identity selects the per-hook
/// consent bit and budget default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    PreCommit,
    PrePush,
}

impl Hook {
    /// Parse the `--hook` argument. Both spellings are accepted because hook
    /// scripts are hand-written; anything else is None (caller warns, skips).
    pub fn parse(s: &str) -> Option<Hook> {
        match s {
            "pre-commit" | "pre_commit" => Some(Hook::PreCommit),
            "pre-push" | "pre_push" => Some(Hook::PrePush),
            _ => None,
        }
    }

    /// Default agent wall-clock budget when the repo config does not set one:
    /// pre-commit 30s, pre-push 120s (a push tolerates more latency than a
    /// commit). Dogfood telemetry (latency + timeout rate) tunes these.
    pub fn default_budget(self) -> Duration {
        match self {
            Hook::PreCommit => Duration::from_secs(30),
            Hook::PrePush => Duration::from_secs(120),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Hook::PreCommit => "pre-commit",
            Hook::PrePush => "pre-push",
        }
    }
}

// --- repo config: the `.revelara.yaml` agent section ---

/// Per-hook opt-in: OFF unless `enabled: true` is committed. `budget_seconds`
/// overrides the hook's default budget when set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct HookOptIn {
    pub enabled: bool,
    pub budget_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AgentHooksSection {
    pre_commit: HookOptIn,
    pre_push: HookOptIn,
}

/// Deserialization view of `.revelara.yaml`: ONLY the agent-consent keys are
/// read here (waiver.rs owns waivers/bounds with its own view; unknown keys
/// are always tolerated so the shared file never breaks a consumer).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RepoFile {
    scanner: ScannerAgentSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ScannerAgentSection {
    /// "allow" | "deny" | absent. Absent is DENY: consent is a committed,
    /// reviewable act, never a default (po-ipkfg.20 clause 6).
    use_agent: String,
    /// "gate" opts agent `violates` verdicts into the BLOCKING section.
    /// Absent/anything else = advisory (blocking stays deterministic-only).
    agent_verdicts: String,
    agent_hooks: AgentHooksSection,
}

/// The resolved repo-level agent policy.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RepoAgentConfig {
    /// `scanner.use_agent: allow` was committed. Deny-absent.
    pub use_agent_allowed: bool,
    /// `scanner.agent_verdicts: gate` was committed.
    pub gate_verdicts: bool,
    pub pre_commit: HookOptIn,
    pub pre_push: HookOptIn,
}

impl RepoAgentConfig {
    pub fn hook(&self, hook: Hook) -> HookOptIn {
        match hook {
            Hook::PreCommit => self.pre_commit,
            Hook::PrePush => self.pre_push,
        }
    }

    /// Parse the agent section out of a `.revelara.yaml` document. Malformed
    /// YAML collapses to the default (everything OFF): a broken config file
    /// must never grant consent.
    pub fn from_yaml_str(text: &str) -> Self {
        let f: RepoFile = serde_yaml::from_str(text).unwrap_or_default();
        RepoAgentConfig {
            use_agent_allowed: f.scanner.use_agent == "allow",
            gate_verdicts: f.scanner.agent_verdicts == "gate",
            pre_commit: f.scanner.agent_hooks.pre_commit,
            pre_push: f.scanner.agent_hooks.pre_push,
        }
    }

    /// Load from `<repo_root>/.revelara.yaml`. Missing file = default (OFF).
    pub fn load(repo_root: &Path) -> Self {
        match std::fs::read_to_string(repo_root.join(".revelara.yaml")) {
            Ok(text) => Self::from_yaml_str(&text),
            Err(_) => Self::default(),
        }
    }
}

// --- org kill switch + user agent selection (~/.revelara) ---

/// Parse the org policy document. `agent: force_deny` is the kill switch.
/// A present-but-unparseable policy is FORCE-DENY: the org clearly tried to
/// set policy, so consent fails closed rather than riding a YAML typo.
pub fn org_force_deny_from_yaml(text: &str) -> bool {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct OrgPolicy {
        agent: String,
    }
    match serde_yaml::from_str::<OrgPolicy>(text) {
        Ok(p) => p.agent == "force_deny",
        Err(_) => true,
    }
}

/// Read `~/.revelara/org-policy.yaml`. A MISSING file is the normal
/// no-org-policy case (not force-deny); a present file goes through the
/// fail-closed parse above. The signed sync that writes this file is
/// follow-up work; this is the read point it will feed.
pub fn load_org_force_deny() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let path = Path::new(&home).join(".revelara").join("org-policy.yaml");
    match std::fs::read_to_string(&path) {
        Ok(text) => org_force_deny_from_yaml(&text),
        Err(_) => false,
    }
}

/// The user's agent selection from `~/.revelara/config.yaml` (`agent:` key):
/// "claude" | "copilot" | "auto" | absent (= auto). Names an INSTALLED agent
/// only — no keys, no endpoints, ever (po-ipkfg.20 clause 6). Read with its
/// own tolerant view so `shared_config`'s api_url/api_key security contract
/// stays untouched.
pub fn user_agent_selection() -> String {
    #[derive(Default, Deserialize)]
    #[serde(default)]
    struct UserView {
        agent: String,
    }
    let Some(home) = std::env::var_os("HOME") else {
        return String::new();
    };
    let path = Path::new(&home).join(".revelara").join("config.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return String::new();
    };
    serde_yaml::from_str::<UserView>(&text)
        .unwrap_or_default()
        .agent
}

// --- consent matrix ---

/// The consent decision for one hook run. Every layer must say yes; the first
/// no wins and names itself, so a disabled lane is diagnosable.
#[derive(Debug, Clone, PartialEq)]
pub enum Consent {
    Enabled { budget: Duration },
    Disabled { reason: &'static str },
}

/// Resolve consent for `hook`. Precedence (strongest first): the
/// `RVL_NO_AGENT=1` env hard-off, the org force-deny kill switch, the
/// repo's committed `use_agent: allow`, the per-hook opt-in. All default OFF.
pub fn consent(
    hook: Hook,
    repo: &RepoAgentConfig,
    org_force_deny: bool,
    env_no_agent: bool,
) -> Consent {
    if env_no_agent {
        return Consent::Disabled {
            reason: "RVL_NO_AGENT=1 (env hard-off)",
        };
    }
    if org_force_deny {
        return Consent::Disabled {
            reason: "org kill switch (org-policy agent: force_deny)",
        };
    }
    if !repo.use_agent_allowed {
        return Consent::Disabled {
            reason: "repo has not consented (.revelara.yaml scanner.use_agent: allow)",
        };
    }
    let opt_in = repo.hook(hook);
    if !opt_in.enabled {
        return Consent::Disabled {
            reason: "hook opt-in is off (.revelara.yaml scanner.agent_hooks.<hook>.enabled)",
        };
    }
    Consent::Enabled {
        budget: opt_in
            .budget_seconds
            .map(Duration::from_secs)
            .unwrap_or_else(|| hook.default_budget()),
    }
}

// --- the approved-agent adapter ---

/// A headless invocation of the user's approved coding agent: one prompt in,
/// raw text out. Implementations must be cheap to construct; the budget wraps
/// `invoke` from outside.
pub trait Adapter: Send {
    fn name(&self) -> &str;
    fn invoke(&self, prompt: &str) -> anyhow::Result<String>;
}

/// Shell-out adapter: runs `argv... <prompt>` headless, captures stdout.
/// The prompt rides as the final argument (batched sites are small by
/// construction — see [`MAX_BATCH_SITES`]); stdin is closed.
pub struct CliAdapter {
    name: String,
    argv: Vec<String>,
}

impl Adapter for CliAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn invoke(&self, prompt: &str) -> anyhow::Result<String> {
        let out = std::process::Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .arg(prompt)
            .stdin(std::process::Stdio::null())
            .output()?;
        anyhow::ensure!(
            out.status.success(),
            "agent '{}' exited {}: {}",
            self.name,
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(200)
                .collect::<String>()
        );
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Resolve the adapter to invoke. `env_cmd` (`RVL_AGENT_CMD`) is the
/// explicit-command seam for custom/local-model agents and tests; otherwise
/// the user's selection picks an installed agent by name, and "auto"/absent
/// tries Claude Code then Copilot on PATH. None = no approved agent found;
/// the caller says so once and the hook proceeds deterministically.
pub fn resolve_adapter(selection: &str, env_cmd: Option<&str>) -> Option<CliAdapter> {
    if let Some(cmd) = env_cmd.filter(|c| !c.trim().is_empty()) {
        let argv: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        return Some(CliAdapter {
            name: "custom".to_string(),
            argv,
        });
    }
    let claude = || {
        crate::find_on_path("claude").map(|p| CliAdapter {
            name: "claude".to_string(),
            argv: vec![p.to_string_lossy().into_owned(), "-p".to_string()],
        })
    };
    let copilot = || {
        crate::find_on_path("copilot").map(|p| CliAdapter {
            name: "copilot".to_string(),
            argv: vec![p.to_string_lossy().into_owned(), "-p".to_string()],
        })
    };
    match selection {
        "claude" => claude(),
        "copilot" => copilot(),
        "auto" | "" => claude().or_else(copilot),
        _ => None,
    }
}

// --- batching, prompt, verdict contract ---

/// One undecided site as handed to the agent. Location and API identity go to
/// the USER'S OWN agent (which already has repo access); nothing here is
/// transmitted to Revelara — telemetry strips down to identity-only.
#[derive(Debug, Clone, PartialEq)]
pub struct UndecidedSite {
    pub site_key: String,
    /// "path:line", for the agent to look at.
    pub file_line: String,
    pub client_type: String,
    pub method: String,
    /// The engine's abstain reason (why it could not decide).
    pub reason: String,
}

/// Select the delta-scoped undecided batch: findings the engine did not
/// resolve, on sites whose file is in this run's CHANGED set, capped at
/// [`MAX_BATCH_SITES`]. Returns the batch plus how many overflowed the cap
/// (they stay undecided; the block reports the truncation).
pub fn delta_undecided(
    findings: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    changed_files: &[String],
) -> (Vec<UndecidedSite>, usize) {
    let changed: std::collections::HashSet<&str> =
        changed_files.iter().map(String::as_str).collect();
    let mut all: Vec<UndecidedSite> = findings
        .iter()
        .zip(sites.iter())
        .filter(|(f, s)| !f.verdict.is_resolved() && changed.contains(s.file_path.as_str()))
        .map(|(f, s)| UndecidedSite {
            site_key: s.site_key(),
            file_line: format!("{}:{}", s.file_path, s.line_number),
            client_type: s.client_type.clone(),
            method: s.method.clone(),
            reason: f.reason.clone(),
        })
        .collect();
    let truncated = all.len().saturating_sub(MAX_BATCH_SITES);
    all.truncate(MAX_BATCH_SITES);
    (all, truncated)
}

/// Compose the ONE batched prompt for the whole undecided set. The contract
/// line ("ONLY a JSON array") is what `parse_verdicts` holds the reply to.
pub fn build_prompt(sites: &[UndecidedSite]) -> String {
    use std::fmt::Write as _;
    let mut p = String::from(
        "You are adjudicating call sites a deterministic reliability scanner could not \
         decide. For EACH site below, judge whether the call is bounded (a timeout, \
         deadline, or equivalent provably covers it) or unbounded, by reading the code \
         at the given location in this repository.\n\
         Respond with ONLY a JSON array, no prose, of the form:\n\
         [{\"site\": \"<site id verbatim>\", \"verdict\": \"satisfies|violates|unknown\", \
         \"reason\": \"<one line>\"}]\n\
         - \"satisfies\": you can point at the bound that covers the call.\n\
         - \"violates\": you verified no bound covers it.\n\
         - \"unknown\": you cannot tell. Never guess.\n\nSites:\n",
    );
    for (i, s) in sites.iter().enumerate() {
        let _ = writeln!(
            p,
            "{n}. site: {key}\n   location: {loc}\n   api: {ct}.{m}\n   scanner reason: {r}",
            n = i + 1,
            key = s.site_key,
            loc = s.file_line,
            ct = s.client_type,
            m = s.method,
            r = s.reason,
        );
    }
    p
}

/// An agent's verdict about one site. `Unknown` (and any unrecognized string)
/// leaves the site undecided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentVerdict {
    Satisfies,
    Violates,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiteVerdict {
    pub site_key: String,
    pub verdict: AgentVerdict,
    pub reason: String,
}

/// Parse the agent's reply against the contract. The JSON array is located by
/// bracket span (agents wrap output in prose despite instructions); entries
/// naming unknown sites are dropped; unrecognized verdict strings map to
/// `Unknown`. `None` = malformed output: the WHOLE reply is discarded and
/// every site stays undecided (fail-open, the caller logs it).
pub fn parse_verdicts(raw: &str, sites: &[UndecidedSite]) -> Option<Vec<SiteVerdict>> {
    #[derive(Deserialize)]
    struct RawVerdict {
        #[serde(default)]
        site: String,
        #[serde(default)]
        verdict: String,
        #[serde(default)]
        reason: String,
    }
    let start = raw.find('[')?;
    let end = raw.rfind(']')?;
    if end < start {
        return None;
    }
    let rows: Vec<RawVerdict> = serde_json::from_str(&raw[start..=end]).ok()?;
    let known: std::collections::HashSet<&str> =
        sites.iter().map(|s| s.site_key.as_str()).collect();
    Some(
        rows.into_iter()
            .filter(|r| known.contains(r.site.as_str()))
            .map(|r| SiteVerdict {
                site_key: r.site,
                verdict: match r.verdict.as_str() {
                    "satisfies" => AgentVerdict::Satisfies,
                    "violates" => AgentVerdict::Violates,
                    _ => AgentVerdict::Unknown,
                },
                reason: r.reason,
            })
            .collect(),
    )
}

// --- budgeted invocation ---

/// What one batched invocation produced. Timeout, error, and malformed output
/// are all recorded (never fatal): the sites simply stay undecided.
#[derive(Debug)]
pub struct Outcome {
    pub agent: String,
    pub verdicts: Vec<SiteVerdict>,
    pub latency: Duration,
    pub timed_out: bool,
    pub malformed: bool,
    pub error: Option<String>,
}

/// Run the ONE batched invocation under the agent budget. The budget is
/// separate from (on top of) the deterministic scan's 10s cap: by the time
/// this runs, the deterministic ladder is already assembled. On timeout the
/// worker thread (and any spawned agent process) is abandoned, same policy as
/// the deterministic `run_with_budget`; the hook process is short-lived.
pub fn adjudicate<A: Adapter + 'static>(
    adapter: A,
    sites: &[UndecidedSite],
    budget: Duration,
) -> Outcome {
    let prompt = build_prompt(sites);
    let name = adapter.name().to_string();
    let start = std::time::Instant::now();
    let outcome = crate::run_with_budget(budget, move || adapter.invoke(&prompt));
    let latency = start.elapsed();
    let mut out = Outcome {
        agent: name,
        verdicts: Vec::new(),
        latency,
        timed_out: false,
        malformed: false,
        error: None,
    };
    match outcome {
        crate::Budgeted::Done(raw) => match parse_verdicts(&raw, sites) {
            Some(v) => out.verdicts = v,
            None => out.malformed = true,
        },
        crate::Budgeted::TimedOut => out.timed_out = true,
        crate::Budgeted::Failed(e) => out.error = Some(e.to_string()),
    }
    out
}

// --- asymmetric verdict application ---

/// The applied adjudication: cleared (satisfies), warned (violates), and how
/// many of the batched sites remain undecided (unknown verdicts, unadjudicated
/// sites, or the whole batch on timeout/malformed output).
#[derive(Debug, Clone, PartialEq)]
pub struct Adjudication {
    pub cleared: Vec<SiteVerdict>,
    pub warned: Vec<SiteVerdict>,
    pub undecided: usize,
}

/// Apply verdicts to the batch. PURE over its inputs: deterministic findings
/// are not an input, so agent verdicts are structurally incapable of touching
/// gate metrics or eval rows.
pub fn apply_verdicts(sites: &[UndecidedSite], outcome: &Outcome) -> Adjudication {
    let mut cleared = Vec::new();
    let mut warned = Vec::new();
    let mut decided_keys = std::collections::HashSet::new();
    for v in &outcome.verdicts {
        match v.verdict {
            AgentVerdict::Satisfies => {
                decided_keys.insert(v.site_key.clone());
                cleared.push(v.clone());
            }
            AgentVerdict::Violates => {
                decided_keys.insert(v.site_key.clone());
                warned.push(v.clone());
            }
            AgentVerdict::Unknown => {}
        }
    }
    let undecided = sites
        .iter()
        .filter(|s| !decided_keys.contains(&s.site_key))
        .count();
    Adjudication {
        cleared,
        warned,
        undecided,
    }
}

/// Ladder rows for agent `violates` verdicts — produced ONLY in gate mode
/// (`scanner.agent_verdicts: gate`). Advisory mode returns nothing: blocking
/// stays deterministic-only, and the warnings live in the agent block. Gate
/// rows are agent-tagged in the description and waivable under the
/// `agent.<client_type>.<method>` rule, a namespace disjoint from every
/// deterministic class key.
pub fn gate_findings(
    adj: &Adjudication,
    sites: &[UndecidedSite],
    gate: bool,
) -> Vec<render::Finding> {
    if !gate {
        return Vec::new();
    }
    adj.warned
        .iter()
        .filter_map(|v| {
            let s = sites.iter().find(|s| s.site_key == v.site_key)?;
            let class_rule = format!("agent.{}.{}", s.client_type, s.method);
            Some(render::Finding {
                id: render::finding_id(&class_rule),
                site: s.file_line.clone(),
                description: format!("agent: {}", v.reason),
                disposition: "surface".to_string(),
                severity: "high".to_string(),
                incident_count: 0,
                critical_count: 0,
                control: String::new(),
                fix: String::new(),
                site_count: 1,
                example_sites: Vec::new(),
                class_rule,
                suppressed: false,
                gate_exempt: false,
            })
        })
        .collect()
}

/// Render the agent block, printed after the ladder. Its own section on
/// purpose: agent output is provenance-tagged and never mixes into the
/// deterministic sections (except gate-mode rows, which stay agent-tagged).
pub fn render_agent_block(
    adj: &Adjudication,
    outcome: &Outcome,
    hook: Hook,
    gate: bool,
    truncated: usize,
    color: bool,
) -> String {
    use std::fmt::Write as _;
    let paint = |s: &str, code: &str| {
        if color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    };
    let mut o = String::new();
    let mode = if gate {
        "gate mode: agent violations join BLOCKING"
    } else {
        "advisory — never blocks, never enters gate metrics"
    };
    let _ = writeln!(
        o,
        "{} {}",
        paint("\u{25a0} AGENT", "35"),
        paint(
            &format!(
                "({} \u{00b7} {} \u{00b7} {})",
                hook.as_str(),
                outcome.agent,
                mode
            ),
            "2"
        )
    );
    if outcome.timed_out {
        let _ = writeln!(
            o,
            "  {}",
            paint(
                &format!(
                    "agent budget of {:.0}s exhausted; sites stay undecided (fail-open)",
                    outcome.latency.as_secs_f64()
                ),
                "2"
            )
        );
    }
    if outcome.malformed {
        let _ = writeln!(
            o,
            "  {}",
            paint(
                "agent reply did not match the verdict contract; sites stay undecided (fail-open)",
                "2"
            )
        );
    }
    if let Some(e) = &outcome.error {
        let _ = writeln!(
            o,
            "  {}",
            paint(
                &format!("agent invocation failed ({e}); sites stay undecided"),
                "2"
            )
        );
    }
    for v in &adj.cleared {
        let _ = writeln!(
            o,
            "  {} {} \u{2014} {}",
            paint("\u{2713} cleared", "32"),
            v.site_key,
            v.reason
        );
    }
    for v in &adj.warned {
        let _ = writeln!(
            o,
            "  {} {} \u{2014} {}",
            paint("\u{26a0} warning", "33"),
            v.site_key,
            v.reason
        );
    }
    if adj.undecided > 0 {
        let _ = writeln!(
            o,
            "  {}",
            paint(&format!("{} site(s) stay undecided", adj.undecided), "2")
        );
    }
    if truncated > 0 {
        let _ = writeln!(
            o,
            "  {}",
            paint(
                &format!("{truncated} additional undecided site(s) over the batch cap; not sent"),
                "2"
            )
        );
    }
    o
}

// --- identity-only telemetry ---

/// One adjudicated surface identity: the public API shape and a count, exactly
/// the `report.rs` contract. STRUCTURALLY INCAPABLE of carrying source, paths,
/// lines, verdicts, or reasons — do not add fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySurface {
    pub client_type: String,
    pub method: String,
    pub site_count: usize,
}

/// The ENTIRE per-run telemetry payload: run identity, adjudicated surface
/// identities, latency, timeout flag. NO verdicts (they never leave the
/// machine), NO reasons, NO code, NO paths. Recording is LOCAL-ONLY today
/// (same posture as the shape report): the async channel consumes this file
/// when it lands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentTelemetry {
    pub scanner_version: String,
    pub hook: String,
    pub agent: String,
    pub surfaces: Vec<TelemetrySurface>,
    pub latency_ms: u64,
    pub timed_out: bool,
}

/// Build the identity-only payload from the batched sites and the outcome.
/// Only `client_type`/`method` cross over from a site; nothing else is read.
pub fn build_telemetry(
    hook: Hook,
    sites: &[UndecidedSite],
    outcome: &Outcome,
    scanner_version: &str,
) -> AgentTelemetry {
    let mut counts: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for s in sites {
        *counts
            .entry((s.client_type.clone(), s.method.clone()))
            .or_insert(0) += 1;
    }
    AgentTelemetry {
        scanner_version: scanner_version.to_string(),
        hook: hook.as_str().to_string(),
        agent: outcome.agent.clone(),
        surfaces: counts
            .into_iter()
            .map(|((client_type, method), site_count)| TelemetrySurface {
                client_type,
                method,
                site_count,
            })
            .collect(),
        latency_ms: outcome.latency.as_millis() as u64,
        timed_out: outcome.timed_out,
    }
}

/// The local telemetry file, a sibling of `last-scan.json` under the cache
/// umbrella (never inside the scanned repo).
pub fn telemetry_path_from_state(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("agent-telemetry.jsonl")
}

/// Best-effort JSONL append. A hook must never fail because telemetry could
/// not be written; degradation is said on stderr.
pub fn record_telemetry(path: &Path, t: &AgentTelemetry) {
    let write = || -> anyhow::Result<()> {
        use std::io::Write as _;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{}", serde_json::to_string(t)?)?;
        Ok(())
    };
    if let Err(e) = write() {
        eprintln!(
            "warning: could not record agent telemetry to {} ({e})",
            path.display()
        );
    }
}

// --- hook-run orchestration ---

/// What the scan renderer consumes: gate-mode ladder rows (empty in advisory
/// mode) and the rendered agent block.
#[derive(Debug, Default)]
pub struct HookOutput {
    pub gate_findings: Vec<render::Finding>,
    pub block: String,
}

/// Run the whole hook adjudication lane for one scan: consent, delta batch,
/// adapter resolution, ONE budgeted invocation, asymmetric application,
/// telemetry. Every failure path is fail-open (returns None or an Output whose
/// block explains): the hook's deterministic result is never at risk.
#[allow(clippy::too_many_arguments)]
pub fn run_hook_adjudication(
    hook_arg: &str,
    repo_root: &Path,
    changed_files: &[String],
    findings: &[rvl_propagate::Finding],
    sites: &[rvl_core::Site],
    telemetry_file: &Path,
    scanner_version: &str,
    color: bool,
) -> Option<HookOutput> {
    let Some(hook) = Hook::parse(hook_arg) else {
        eprintln!("warning: unknown --hook value '{hook_arg}' (expected pre-commit|pre-push); agent adjudication skipped");
        return None;
    };
    let repo = RepoAgentConfig::load(repo_root);
    let env_no_agent = std::env::var("RVL_NO_AGENT").ok().as_deref() == Some("1");
    let budget = match consent(hook, &repo, load_org_force_deny(), env_no_agent) {
        Consent::Enabled { budget } => budget,
        // Consent is OFF by default; a disabled lane stays quiet so hooks
        // never chat on every commit.
        Consent::Disabled { .. } => return None,
    };
    let (batch, truncated) = delta_undecided(findings, sites, changed_files);
    if batch.is_empty() {
        // Median case: nothing undecided in the delta, no invocation at all.
        return None;
    }
    let env_cmd = std::env::var("RVL_AGENT_CMD").ok();
    let Some(adapter) = resolve_adapter(&user_agent_selection(), env_cmd.as_deref()) else {
        eprintln!(
            "note: agent adjudication is enabled for {} but no approved agent was found \
             (claude/copilot on PATH, `agent:` in ~/.revelara/config.yaml, or RVL_AGENT_CMD)",
            hook.as_str()
        );
        return None;
    };
    let outcome = adjudicate(adapter, &batch, budget);
    let adj = apply_verdicts(&batch, &outcome);
    let telemetry = build_telemetry(hook, &batch, &outcome, scanner_version);
    record_telemetry(telemetry_file, &telemetry);
    Some(HookOutput {
        gate_findings: gate_findings(&adj, &batch, repo.gate_verdicts),
        block: render_agent_block(&adj, &outcome, hook, repo.gate_verdicts, truncated, color),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on_repo() -> RepoAgentConfig {
        RepoAgentConfig {
            use_agent_allowed: true,
            gate_verdicts: false,
            pre_commit: HookOptIn {
                enabled: true,
                budget_seconds: None,
            },
            pre_push: HookOptIn {
                enabled: true,
                budget_seconds: None,
            },
        }
    }

    fn site(key: &str, ct: &str, m: &str) -> UndecidedSite {
        UndecidedSite {
            site_key: key.to_string(),
            file_line: format!("internal/secret/{key}.go:42"),
            client_type: ct.to_string(),
            method: m.to_string(),
            reason: "no spec for this API".to_string(),
        }
    }

    // --- consent matrix ---

    #[test]
    fn consent_is_off_by_default() {
        // Absent config at every layer = OFF. This is the load-bearing
        // default: agent adjudication must be a committed, deliberate act.
        let got = consent(Hook::PreCommit, &RepoAgentConfig::default(), false, false);
        assert!(
            matches!(got, Consent::Disabled { .. }),
            "default must be disabled, got {got:?}"
        );
    }

    #[test]
    fn consent_env_kill_switch_overrides_everything() {
        let got = consent(Hook::PreCommit, &all_on_repo(), false, true);
        match got {
            Consent::Disabled { reason } => {
                assert!(reason.contains("RVL_NO_AGENT"), "reason: {reason}")
            }
            other => panic!("env hard-off must win: {other:?}"),
        }
    }

    #[test]
    fn consent_org_force_deny_overrides_everything() {
        let got = consent(Hook::PrePush, &all_on_repo(), true, false);
        match got {
            Consent::Disabled { reason } => {
                assert!(reason.contains("org"), "reason: {reason}")
            }
            other => panic!("org kill switch must win: {other:?}"),
        }
    }

    #[test]
    fn consent_requires_repo_use_agent_allow() {
        // Per-hook opt-in without the committed repo-level allow is not consent.
        let mut repo = all_on_repo();
        repo.use_agent_allowed = false;
        let got = consent(Hook::PreCommit, &repo, false, false);
        match got {
            Consent::Disabled { reason } => {
                assert!(reason.contains("use_agent"), "reason: {reason}")
            }
            other => panic!("deny-absent use_agent must disable: {other:?}"),
        }
    }

    #[test]
    fn consent_requires_the_per_hook_opt_in() {
        // Repo-level allow alone is not enough: each hook opts in separately.
        let mut repo = all_on_repo();
        repo.pre_push.enabled = false;
        let got = consent(Hook::PrePush, &repo, false, false);
        match got {
            Consent::Disabled { reason } => {
                assert!(reason.contains("agent_hooks"), "reason: {reason}")
            }
            other => panic!("hook opt-in off must disable: {other:?}"),
        }
    }

    #[test]
    fn consent_all_on_uses_per_hook_default_budgets() {
        // pre-commit 30s / pre-push 120s when budget_seconds is unset.
        match consent(Hook::PreCommit, &all_on_repo(), false, false) {
            Consent::Enabled { budget } => assert_eq!(budget, Duration::from_secs(30)),
            other => panic!("all-on pre-commit must enable: {other:?}"),
        }
        match consent(Hook::PrePush, &all_on_repo(), false, false) {
            Consent::Enabled { budget } => assert_eq!(budget, Duration::from_secs(120)),
            other => panic!("all-on pre-push must enable: {other:?}"),
        }
    }

    #[test]
    fn consent_honors_a_configured_budget() {
        let mut repo = all_on_repo();
        repo.pre_commit.budget_seconds = Some(5);
        match consent(Hook::PreCommit, &repo, false, false) {
            Consent::Enabled { budget } => assert_eq!(budget, Duration::from_secs(5)),
            other => panic!("configured budget must win: {other:?}"),
        }
    }

    // --- repo config parsing ---

    #[test]
    fn repo_config_parses_the_agent_section() {
        let yaml = "\
scanner:
  use_agent: allow
  agent_verdicts: gate
  agent_hooks:
    pre_commit:
      enabled: true
      budget_seconds: 15
  waivers:
    - matcher: db.Pool.Query
";
        let cfg = RepoAgentConfig::from_yaml_str(yaml);
        assert!(cfg.use_agent_allowed);
        assert!(cfg.gate_verdicts);
        assert!(cfg.pre_commit.enabled);
        assert_eq!(cfg.pre_commit.budget_seconds, Some(15));
        assert!(!cfg.pre_push.enabled, "unset hook stays OFF");
    }

    #[test]
    fn repo_config_absent_keys_mean_deny_and_advisory() {
        let cfg = RepoAgentConfig::from_yaml_str("scanner:\n  waivers: []\n");
        assert!(!cfg.use_agent_allowed, "use_agent absent = deny");
        assert!(!cfg.gate_verdicts, "agent_verdicts absent = advisory");
        assert!(!cfg.pre_commit.enabled && !cfg.pre_push.enabled);
    }

    #[test]
    fn repo_config_malformed_yaml_grants_nothing() {
        let cfg = RepoAgentConfig::from_yaml_str("scanner: [not: a: map");
        assert_eq!(cfg, RepoAgentConfig::default());
    }

    #[test]
    fn repo_config_use_agent_deny_is_deny() {
        let cfg = RepoAgentConfig::from_yaml_str("scanner:\n  use_agent: deny\n");
        assert!(!cfg.use_agent_allowed);
    }

    // --- org policy ---

    #[test]
    fn org_policy_force_deny_parses() {
        assert!(org_force_deny_from_yaml("agent: force_deny\n"));
        assert!(!org_force_deny_from_yaml("agent: allow\n"));
        assert!(!org_force_deny_from_yaml("{}"));
    }

    #[test]
    fn org_policy_malformed_fails_closed() {
        // A present-but-broken org policy means the org TRIED to set policy:
        // consent fails closed rather than riding a YAML typo.
        assert!(org_force_deny_from_yaml("agent: [unterminated"));
    }

    // --- hook identity ---

    #[test]
    fn hook_parses_both_spellings_and_rejects_junk() {
        assert_eq!(Hook::parse("pre-commit"), Some(Hook::PreCommit));
        assert_eq!(Hook::parse("pre_commit"), Some(Hook::PreCommit));
        assert_eq!(Hook::parse("pre-push"), Some(Hook::PrePush));
        assert_eq!(Hook::parse("pre_push"), Some(Hook::PrePush));
        assert_eq!(Hook::parse("post-merge"), None);
    }

    // --- batching + prompt ---

    fn abstain_finding(reason: &str) -> rvl_propagate::Finding {
        rvl_propagate::Finding {
            site_id: "sid".to_string(),
            verdict: rvl_core::Verdict::Abstain,
            reason: reason.to_string(),
        }
    }

    fn core_site(path: &str, line: u32, ct: &str, m: &str) -> rvl_core::Site {
        rvl_core::Site {
            file_path: path.to_string(),
            line_number: line,
            client_type: ct.to_string(),
            method: m.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn delta_scope_takes_undecided_changed_sites_only() {
        let findings = vec![
            abstain_finding("no spec for a.A.Do"),
            rvl_propagate::Finding {
                site_id: "s2".to_string(),
                verdict: rvl_core::Verdict::Violates,
                reason: "violates: unbounded".to_string(),
            },
            abstain_finding("no spec for c.C.Do"),
        ];
        let sites = vec![
            core_site("changed.go", 1, "a.A", "Do"),
            core_site("changed.go", 2, "b.B", "Do"),
            core_site("unchanged.go", 3, "c.C", "Do"),
        ];
        let changed = vec!["changed.go".to_string()];
        let (batch, truncated) = delta_undecided(&findings, &sites, &changed);
        // Only the undecided site in the CHANGED file: the decided site is
        // untouchable and the unchanged file is out of delta scope.
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].client_type, "a.A");
        assert_eq!(truncated, 0);
    }

    #[test]
    fn delta_scope_caps_the_batch_and_reports_overflow() {
        let n = MAX_BATCH_SITES + 3;
        let findings: Vec<_> = (0..n).map(|_| abstain_finding("no spec")).collect();
        let sites: Vec<_> = (0..n)
            .map(|i| core_site("f.go", i as u32, "x.X", "Do"))
            .collect();
        let (batch, truncated) = delta_undecided(&findings, &sites, &["f.go".to_string()]);
        assert_eq!(batch.len(), MAX_BATCH_SITES);
        assert_eq!(truncated, 3);
    }

    #[test]
    fn prompt_batches_every_site_into_one_invocation() {
        let sites = vec![
            site("k1", "db.Pool", "Query"),
            site("k2", "http.Client", "Do"),
        ];
        let p = build_prompt(&sites);
        // ONE prompt carries BOTH sites (the single-batched-invocation
        // contract) plus the strict output contract.
        assert!(p.contains("k1") && p.contains("k2"));
        assert!(p.contains("db.Pool.Query") && p.contains("http.Client.Do"));
        assert!(p.contains("ONLY a JSON array"));
    }

    // --- verdict parsing ---

    #[test]
    fn parse_verdicts_accepts_the_contract_with_surrounding_prose() {
        let sites = vec![site("k1", "a.A", "Do"), site("k2", "b.B", "Do")];
        let raw = "Here are my verdicts:\n[\n {\"site\":\"k1\",\"verdict\":\"satisfies\",\"reason\":\"ctx deadline\"},\n {\"site\":\"k2\",\"verdict\":\"violates\",\"reason\":\"no bound\"}\n]\nDone.";
        let got = parse_verdicts(raw, &sites).expect("valid contract must parse");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].verdict, AgentVerdict::Satisfies);
        assert_eq!(got[1].verdict, AgentVerdict::Violates);
    }

    #[test]
    fn parse_verdicts_malformed_output_is_none() {
        let sites = vec![site("k1", "a.A", "Do")];
        assert!(parse_verdicts("I could not decide anything, sorry!", &sites).is_none());
        assert!(parse_verdicts("[{not json", &sites).is_none());
        assert!(parse_verdicts("", &sites).is_none());
    }

    #[test]
    fn parse_verdicts_drops_unknown_sites_and_maps_junk_verdicts_to_unknown() {
        let sites = vec![site("k1", "a.A", "Do")];
        let raw = r#"[
            {"site":"k1","verdict":"probably-fine","reason":"guess"},
            {"site":"hallucinated","verdict":"violates","reason":"made up"}
        ]"#;
        let got = parse_verdicts(raw, &sites).unwrap();
        assert_eq!(got.len(), 1, "hallucinated site keys are dropped");
        assert_eq!(
            got[0].verdict,
            AgentVerdict::Unknown,
            "an off-contract verdict string leaves the site undecided"
        );
    }

    // --- budgeted invocation ---

    struct FakeAdapter {
        delay: Duration,
        reply: Result<String, String>,
    }

    impl Adapter for FakeAdapter {
        fn name(&self) -> &str {
            "fake"
        }
        fn invoke(&self, _prompt: &str) -> anyhow::Result<String> {
            std::thread::sleep(self.delay);
            match &self.reply {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }
        }
    }

    #[test]
    fn adjudicate_budget_timeout_leaves_all_sites_undecided() {
        let sites = vec![site("k1", "a.A", "Do")];
        let slow = FakeAdapter {
            delay: Duration::from_millis(300),
            reply: Ok(r#"[{"site":"k1","verdict":"satisfies","reason":"late"}]"#.to_string()),
        };
        let out = adjudicate(slow, &sites, Duration::from_millis(20));
        assert!(out.timed_out, "budget exhaustion must be recorded");
        assert!(out.verdicts.is_empty(), "a late verdict never lands");
        let adj = apply_verdicts(&sites, &out);
        assert_eq!(adj.undecided, 1, "timeout -> sites stay undecided");
        assert!(adj.cleared.is_empty() && adj.warned.is_empty());
    }

    #[test]
    fn adjudicate_fast_adapter_returns_verdicts() {
        let sites = vec![site("k1", "a.A", "Do")];
        let fast = FakeAdapter {
            delay: Duration::ZERO,
            reply: Ok(r#"[{"site":"k1","verdict":"satisfies","reason":"bounded"}]"#.to_string()),
        };
        let out = adjudicate(fast, &sites, Duration::from_secs(5));
        assert!(!out.timed_out && !out.malformed);
        assert_eq!(out.verdicts.len(), 1);
    }

    #[test]
    fn adjudicate_malformed_reply_fails_open() {
        let sites = vec![site("k1", "a.A", "Do")];
        let bad = FakeAdapter {
            delay: Duration::ZERO,
            reply: Ok("segfault poetry".to_string()),
        };
        let out = adjudicate(bad, &sites, Duration::from_secs(5));
        assert!(out.malformed, "off-contract output must be recorded");
        assert_eq!(apply_verdicts(&sites, &out).undecided, 1);
    }

    #[test]
    fn adjudicate_adapter_error_fails_open() {
        let sites = vec![site("k1", "a.A", "Do")];
        let err = FakeAdapter {
            delay: Duration::ZERO,
            reply: Err("agent not logged in".to_string()),
        };
        let out = adjudicate(err, &sites, Duration::from_secs(5));
        assert!(out.error.is_some());
        assert_eq!(apply_verdicts(&sites, &out).undecided, 1);
    }

    // --- asymmetric application ---

    fn outcome_with(verdicts: Vec<SiteVerdict>) -> Outcome {
        Outcome {
            agent: "fake".to_string(),
            verdicts,
            latency: Duration::from_millis(7),
            timed_out: false,
            malformed: false,
            error: None,
        }
    }

    #[test]
    fn satisfies_clears_violates_warns_unknown_stays_undecided() {
        let sites = vec![
            site("k1", "a.A", "Do"),
            site("k2", "b.B", "Do"),
            site("k3", "c.C", "Do"),
        ];
        let out = outcome_with(vec![
            SiteVerdict {
                site_key: "k1".into(),
                verdict: AgentVerdict::Satisfies,
                reason: "ctx deadline covers it".into(),
            },
            SiteVerdict {
                site_key: "k2".into(),
                verdict: AgentVerdict::Violates,
                reason: "no bound found".into(),
            },
            SiteVerdict {
                site_key: "k3".into(),
                verdict: AgentVerdict::Unknown,
                reason: "cannot tell".into(),
            },
        ]);
        let adj = apply_verdicts(&sites, &out);
        assert_eq!(adj.cleared.len(), 1);
        assert_eq!(adj.cleared[0].site_key, "k1");
        assert_eq!(adj.warned.len(), 1);
        assert_eq!(adj.warned[0].site_key, "k2");
        assert_eq!(adj.undecided, 1);
    }

    #[test]
    fn advisory_mode_produces_no_ladder_rows() {
        // Blocking stays deterministic-only: without `agent_verdicts: gate`
        // an agent violation NEVER becomes a ladder row (it lives in the
        // agent block alone).
        let sites = vec![site("k1", "a.A", "Do")];
        let out = outcome_with(vec![SiteVerdict {
            site_key: "k1".into(),
            verdict: AgentVerdict::Violates,
            reason: "no bound".into(),
        }]);
        let adj = apply_verdicts(&sites, &out);
        assert!(gate_findings(&adj, &sites, false).is_empty());
    }

    #[test]
    fn gate_mode_rows_are_blocking_agent_tagged_and_waivable() {
        let sites = vec![site("k1", "a.A", "Do")];
        let out = outcome_with(vec![SiteVerdict {
            site_key: "k1".into(),
            verdict: AgentVerdict::Violates,
            reason: "no bound".into(),
        }]);
        let adj = apply_verdicts(&sites, &out);
        let rows = gate_findings(&adj, &sites, true);
        assert_eq!(rows.len(), 1);
        let f = &rows[0];
        assert!(
            f.description.starts_with("agent:"),
            "gate rows stay agent-tagged: {}",
            f.description
        );
        assert_eq!(
            f.class_rule, "agent.a.A.Do",
            "waiver key lives in the disjoint agent.* namespace"
        );
        assert_eq!(
            render::classify(f),
            render::Section::Blocking,
            "gate mode makes the row blocking"
        );
    }

    #[test]
    fn gate_mode_satisfies_never_becomes_a_row() {
        // Asymmetry holds in gate mode too: only violations gate; a satisfies
        // clears in the block, it never turns into a ladder row.
        let sites = vec![site("k1", "a.A", "Do")];
        let out = outcome_with(vec![SiteVerdict {
            site_key: "k1".into(),
            verdict: AgentVerdict::Satisfies,
            reason: "bounded".into(),
        }]);
        let adj = apply_verdicts(&sites, &out);
        assert!(gate_findings(&adj, &sites, true).is_empty());
    }

    #[test]
    fn verdicts_never_mutate_deterministic_findings() {
        // The eval rows (`--out`) and the shape report are built from the
        // deterministic findings. Application is pure over the batch: the
        // findings slice is not even an input to apply_verdicts/gate_findings,
        // and a full application round-trip leaves it bit-identical.
        let findings = vec![abstain_finding("no spec for a.A.Do")];
        let before = findings.clone();
        let sites = vec![core_site("f.go", 1, "a.A", "Do")];
        let (batch, _) = delta_undecided(&findings, &sites, &["f.go".to_string()]);
        let out = outcome_with(vec![SiteVerdict {
            site_key: batch[0].site_key.clone(),
            verdict: AgentVerdict::Satisfies,
            reason: "bounded".into(),
        }]);
        let adj = apply_verdicts(&batch, &out);
        let _rows = gate_findings(&adj, &batch, true);
        assert_eq!(
            findings, before,
            "agent verdicts must never touch eval input"
        );
    }

    // --- telemetry ---

    const SENTINEL_PATH: &str = "internal/secret/customer_module.go";
    const SENTINEL_REASON: &str = "SECRET_BUSINESS_LOGIC_abc123";

    #[test]
    fn telemetry_is_identity_only_no_paths_reasons_or_verdicts() {
        let mut s1 = site("k1", "db.Pool", "Query");
        s1.file_line = format!("{SENTINEL_PATH}:424242");
        s1.reason = SENTINEL_REASON.to_string();
        let mut s2 = site("k2", "db.Pool", "Query");
        s2.file_line = format!("{SENTINEL_PATH}:7");
        let out = outcome_with(vec![SiteVerdict {
            site_key: "k1".into(),
            verdict: AgentVerdict::Violates,
            reason: SENTINEL_REASON.into(),
        }]);
        let t = build_telemetry(Hook::PreCommit, &[s1, s2], &out, "9.9.9");
        let json = serde_json::to_string(&t).unwrap();

        // Identity + instrumentation made it through.
        assert!(json.contains("db.Pool") && json.contains("Query"));
        assert!(json.contains("\"latency_ms\":7"));
        assert!(json.contains("\"timed_out\":false"));
        assert!(json.contains("\"hook\":\"pre-commit\""));
        // Surfaces dedup to identity + count.
        assert_eq!(t.surfaces.len(), 1);
        assert_eq!(t.surfaces[0].site_count, 2);

        // NOTHING code-bearing rode along: no paths, no lines, no verdicts,
        // no agent reasons, no site keys.
        assert!(!json.contains(SENTINEL_PATH), "file path leaked: {json}");
        assert!(!json.contains("424242"), "line number leaked: {json}");
        assert!(
            !json.contains(SENTINEL_REASON),
            "agent reason leaked: {json}"
        );
        assert!(!json.contains("violates"), "verdict leaked: {json}");
        assert!(!json.contains("\"k1\""), "site key leaked: {json}");
    }

    #[test]
    fn telemetry_surface_serializes_exactly_three_identity_keys() {
        let s = TelemetrySurface {
            client_type: "db.Pool".into(),
            method: "Query".into(),
            site_count: 2,
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["client_type", "method", "site_count"]);
    }

    #[test]
    fn telemetry_payload_serializes_exactly_the_instrumentation_keys() {
        let t = build_telemetry(
            Hook::PrePush,
            &[site("k1", "a.A", "Do")],
            &outcome_with(vec![]),
            "1.0.0",
        );
        let v: serde_json::Value = serde_json::to_value(&t).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "agent",
                "hook",
                "latency_ms",
                "scanner_version",
                "surfaces",
                "timed_out"
            ],
            "the payload must carry ONLY run identity + instrumentation"
        );
    }

    #[test]
    fn telemetry_records_append_jsonl() {
        let dir = std::env::temp_dir().join(format!("rvl-agent-test-{}", std::process::id()));
        let path = dir.join("agent-telemetry.jsonl");
        let _ = std::fs::remove_file(&path);
        let t = build_telemetry(
            Hook::PreCommit,
            &[site("k1", "a.A", "Do")],
            &outcome_with(vec![]),
            "1.0.0",
        );
        record_telemetry(&path, &t);
        record_telemetry(&path, &t);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2, "append, never overwrite");
        for line in text.lines() {
            let row: AgentTelemetry = serde_json::from_str(line).unwrap();
            assert_eq!(row.hook, "pre-commit");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- block rendering ---

    #[test]
    fn agent_block_reports_timeout_fail_open() {
        let sites = vec![site("k1", "a.A", "Do")];
        let out = Outcome {
            agent: "claude".to_string(),
            verdicts: Vec::new(),
            latency: Duration::from_secs(30),
            timed_out: true,
            malformed: false,
            error: None,
        };
        let adj = apply_verdicts(&sites, &out);
        let block = render_agent_block(&adj, &out, Hook::PreCommit, false, 0, false);
        assert!(block.contains("AGENT"));
        assert!(block.contains("budget"), "timeout must be said: {block}");
        assert!(
            block.contains("fail-open"),
            "fail-open must be said: {block}"
        );
        assert!(block.contains("1 site(s) stay undecided"));
    }

    #[test]
    fn agent_block_shows_cleared_and_warnings_with_provenance() {
        let sites = vec![site("k1", "a.A", "Do"), site("k2", "b.B", "Do")];
        let out = outcome_with(vec![
            SiteVerdict {
                site_key: "k1".into(),
                verdict: AgentVerdict::Satisfies,
                reason: "bounded".into(),
            },
            SiteVerdict {
                site_key: "k2".into(),
                verdict: AgentVerdict::Violates,
                reason: "no bound".into(),
            },
        ]);
        let adj = apply_verdicts(&sites, &out);
        let block = render_agent_block(&adj, &out, Hook::PrePush, false, 0, false);
        assert!(block.contains("cleared"));
        assert!(block.contains("warning"));
        assert!(
            block.contains("advisory"),
            "advisory mode must self-describe: {block}"
        );
        assert!(block.contains("pre-push"));
    }
}
