//! RC-040, SAST on the pull-request path: which SAST steps a repository's CI
//! runs, whether each runs on the pull-request path, and whether a finding
//! fails its job. Retrieval reads the GitHub Actions workflows the inventory
//! already parsed (a local reusable workflow's steps run on its callers'
//! triggers) and the root `.gitlab-ci.yml`; [`evaluate`] judges a repository
//! with a server entry point and abstains on every other.
//!
//! Built for precision. A step whose path or failure mode hangs on an
//! expression, a filter or a caller this walk cannot see is `unclear`, and a
//! SAST-looking step that is not one of RC-040's SAST steps (a scanner
//! install, a Sonar scan) keeps every violation from being read: a step the
//! rule does not judge may be the one that gates.
//!
//! Privacy: the facts are file paths, scanner names and flags, never the text
//! of a step.

use crate::inventory::{SCANNER_ACTIONS, SCANNER_COMMANDS};
use crate::{RepoStructure, ScannerClass, StructureFinding};
use rvl_core::Verdict;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;

/// Whether a CI step runs on the pull-request path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum PrPath {
    /// A `pull_request` or `merge_group` trigger runs it, unconditioned.
    Yes,
    /// No workflow that runs it is triggered by a pull request.
    No,
    /// A path, branch or type filter, an `if:` condition,
    /// `pull_request_target`, a caller out of sight, or a GitLab job whose
    /// rules do not name merge request pipelines.
    Unclear,
}

impl PrPath {
    /// The path of a step that runs from either of two entries.
    fn or(self, other: PrPath) -> PrPath {
        use PrPath::*;
        match (self, other) {
            (Yes, _) | (_, Yes) => Yes,
            (Unclear, _) | (_, Unclear) => Unclear,
            (No, No) => No,
        }
    }

    /// The path under an `if:` condition this walk does not evaluate.
    fn conditioned(self, condition: bool) -> PrPath {
        if condition && self == PrPath::Yes {
            PrPath::Unclear
        } else {
            self
        }
    }
}

/// Whether a SAST finding fails the step's job.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum OnFailure {
    Fails,
    /// `continue-on-error: true`, `allow_failure: true`, `|| true`, or a
    /// scanner flag that exits zero on findings.
    Continues,
    /// An expression, `set +e`, or a manual GitLab job.
    Unclear,
}

impl OnFailure {
    /// A step and its job: either one continuing lets the job pass.
    fn and(self, other: OnFailure) -> OnFailure {
        use OnFailure::*;
        match (self, other) {
            (Continues, _) | (_, Continues) => Continues,
            (Unclear, _) | (_, Unclear) => Unclear,
            (Fails, Fails) => Fails,
        }
    }
}

/// One RC-040 SAST step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SastStep {
    /// Repo-relative path of the CI file holding the step.
    pub file: String,
    /// "semgrep ci", "github/codeql-action/analyze", a reusable workflow, ...
    pub scanner: String,
    pub pr_path: PrPath,
    pub on_failure: OnFailure,
}

/// The SAST steps across a repository's CI files, with what keeps an absence
/// from being read.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SastFacts {
    /// GitHub Actions workflows and `.gitlab-ci.yml` files that parsed.
    #[serde(default)]
    pub ci_files: u32,
    /// GitLab CI files not read whole: invalid YAML, an `include:`, a job
    /// that `extends:` another, or a `!reference`.
    #[serde(default)]
    pub gitlab_unread: u32,
    /// Config files of CI systems this walk does not read for SAST steps.
    #[serde(default)]
    pub other_ci: Vec<String>,
    /// CI files with a SAST-looking step that is not an RC-040 SAST step.
    #[serde(default)]
    pub unrecognized: Vec<String>,
    /// Sorted.
    #[serde(default)]
    pub steps: Vec<SastStep>,
}

/// RC-040's SAST actions, lowercase, without the ref; an entry matches the
/// action and any path under it. Snyk's actions run `snyk test`, a
/// dependency scan, unless their `command` input is `code test`.
const SAST_ACTIONS: &[&str] = &[
    "github/codeql-action/analyze",
    "pycqa/bandit-action",
    "returntocorp/semgrep-action",
    "securego/gosec",
    "semgrep/semgrep-action",
];

/// What a reusable workflow's file name says when it runs SAST.
const SAST_WORKFLOW_NAMES: &[&str] = &["sast", "codeql", "semgrep"];

/// What, on a scanner's command line or in its inputs, lets a finding pass.
const CONTINUE_MARKERS: &[&str] = &[
    "|| true",
    "||true",
    "|| :",
    "|| exit 0",
    "--exit-zero",
    "-no-fail",
];

/// Root config files of CI systems whose steps are not read here: a SAST step
/// in one of them is out of sight.
pub(crate) const OTHER_CI: &[&str] = &[
    ".buildkite/pipeline.yml",
    ".circleci/config.yml",
    ".drone.yml",
    ".travis.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
];

/// The depth GitHub allows reusable workflows to nest to.
const MAX_CALL_DEPTH: usize = 4;

/// A step's SAST reading.
enum Sast {
    /// One of RC-040's SAST steps, by name.
    Step(String),
    /// A SAST scanner the inventory knows that RC-040 does not judge.
    Other,
}

fn action_of(uses: &str) -> String {
    uses.split('@').next().unwrap_or(uses).to_ascii_lowercase()
}

fn under(action: &str, known: &str) -> bool {
    action
        .strip_prefix(known)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Shell text with backslash-continued lines joined.
fn shell_lines(run: &str) -> Vec<String> {
    run.replace("\\\n", " ")
        .lines()
        .map(str::to_string)
        .collect()
}

/// The words of one shell command, quotes trimmed, with a leading `$(...)`
/// path prefix dropped: `"$(go env GOPATH)/bin/gosec" ./...` runs gosec.
fn command_words(segment: &str) -> Vec<&str> {
    let mut command = segment.trim_start().trim_start_matches('"');
    if let Some(rest) = command.strip_prefix("$(") {
        command = rest.split_once(')').map_or("", |(_, path)| path);
    }
    command
        .split_whitespace()
        .map(|w| w.trim_matches('"'))
        .collect()
}

/// The RC-040 SAST command one shell line runs, if any.
fn sast_command(line: &str) -> Option<&'static str> {
    line.split(['&', '|', ';']).find_map(|segment| {
        let words = command_words(segment);
        let first = words.first()?.rsplit('/').next()?;
        match (first, &words[1..]) {
            ("gosec", _) => Some("gosec"),
            ("bandit", _) => Some("bandit"),
            ("python" | "python3", ["-m", "bandit", ..]) => Some("bandit"),
            ("semgrep", ["ci", ..]) => Some("semgrep ci"),
            ("snyk", ["code", "test", ..]) => Some("snyk code test"),
            _ => None,
        }
    })
}

/// How the shell lines that run a SAST command let a finding through: they
/// continue when every SAST line does. A SAST command piped into another
/// exits with the last command's status unless `pipefail` is set, which
/// GitHub's default `bash -e` does not set.
fn shell_failure(lines: &[String]) -> OnFailure {
    if lines.iter().any(|l| l.contains("set +e")) {
        return OnFailure::Unclear;
    }
    let sast: Vec<&String> = lines.iter().filter(|l| sast_command(l).is_some()).collect();
    if !sast.is_empty()
        && sast
            .iter()
            .all(|l| CONTINUE_MARKERS.iter().any(|m| l.contains(m)))
    {
        OnFailure::Continues
    } else if sast.iter().any(|l| l.replace("||", "").contains('|')) {
        OnFailure::Unclear
    } else {
        OnFailure::Fails
    }
}

/// Whether shell text names a SAST scanner the inventory knows, on a line
/// that does more than install it.
fn mentions_sast(text: &str) -> bool {
    text.to_ascii_lowercase()
        .lines()
        .filter(|l| !l.contains("install"))
        .any(|l| {
            SCANNER_COMMANDS
                .iter()
                .any(|(class, token)| *class == ScannerClass::Sast && l.contains(token))
        })
}

/// `continue-on-error` (GitHub) or `allow_failure` (GitLab).
fn continues(v: Option<&Value>) -> OnFailure {
    match v {
        None | Some(Value::Bool(false)) => OnFailure::Fails,
        Some(Value::Bool(true)) => OnFailure::Continues,
        Some(_) => OnFailure::Unclear,
    }
}

// --- GitHub Actions ---

/// One GitHub Actions step's SAST reading and failure mode.
fn github_step(step: &Value) -> Option<(Sast, OnFailure)> {
    let own = continues(step.get("continue-on-error"));
    if let Some(uses) = step.get("uses").and_then(Value::as_str) {
        let action = action_of(uses);
        let inputs = serde_yaml::to_string(step.get("with").unwrap_or(&Value::Null))
            .unwrap_or_default()
            .to_ascii_lowercase();
        let inputs_continue = if CONTINUE_MARKERS.iter().any(|m| inputs.contains(m)) {
            OnFailure::Continues
        } else {
            OnFailure::Fails
        };
        if under(&action, "snyk/actions") {
            let command = step.get("with").and_then(|w| w.get("command"));
            let code = command
                .and_then(Value::as_str)
                .is_some_and(|c| c.trim() == "code test");
            return code.then(|| {
                (
                    Sast::Step("snyk code test".into()),
                    own.and(inputs_continue),
                )
            });
        }
        if let Some(known) = SAST_ACTIONS.iter().find(|k| under(&action, k)) {
            return Some((Sast::Step(known.to_string()), own.and(inputs_continue)));
        }
        // `init` sets CodeQL up; `analyze` is the step judged.
        let other = SCANNER_ACTIONS.iter().any(|(class, known)| {
            *class == ScannerClass::Sast
                && under(&action, known)
                && *known != "github/codeql-action/init"
        });
        return other.then_some((Sast::Other, own));
    }
    let run = step.get("run").and_then(Value::as_str)?;
    let lines = shell_lines(run);
    if let Some(name) = lines.iter().find_map(|l| sast_command(l)) {
        // A custom shell without `-e` runs on past a failing line.
        let shell = step.get("shell").and_then(Value::as_str).unwrap_or("");
        let shell = if shell.contains("{0}") && !shell.contains("-e") {
            OnFailure::Unclear
        } else {
            OnFailure::Fails
        };
        let failure = own.and(shell).and(shell_failure(&lines));
        return Some((Sast::Step(name.into()), failure));
    }
    mentions_sast(run).then_some((Sast::Other, own))
}

/// A reusable workflow in another repository whose file name says SAST.
fn sast_reusable(uses: &str) -> Option<String> {
    let action = action_of(uses);
    if action.starts_with("./") || !action.contains("/.github/workflows/") {
        return None;
    }
    let name = action.rsplit('/').next()?;
    SAST_WORKFLOW_NAMES
        .iter()
        .any(|n| name.contains(n))
        .then_some(action)
}

/// A `pull_request` trigger's filters: one that may skip a pull request to
/// the default branch leaves the path unclear.
fn pull_request_path(config: &Value) -> PrPath {
    let Some(m) = config.as_mapping() else {
        return PrPath::Yes;
    };
    let words = |key: &str| -> Option<Vec<String>> {
        let v = m.get(key)?;
        Some(match v {
            Value::String(s) => vec![s.clone()],
            Value::Sequence(seq) => seq
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        })
    };
    if m.contains_key("paths") || m.contains_key("branches-ignore") {
        return PrPath::Unclear;
    }
    if words("types").is_some_and(|t| !t.iter().any(|t| t == "synchronize")) {
        return PrPath::Unclear;
    }
    let default_branch = |b: &String| matches!(b.as_str(), "main" | "master" | "*" | "**");
    if words("branches").is_some_and(|b| !b.iter().any(default_branch)) {
        return PrPath::Unclear;
    }
    PrPath::Yes
}

/// A workflow's own pull-request path, and whether it can be called as a
/// reusable workflow.
fn own_triggers(doc: &Value) -> (PrPath, bool) {
    // YAML 1.1 reads a bare `on` key as the boolean true.
    let on = doc
        .get("on")
        .or_else(|| doc.as_mapping().and_then(|m| m.get(Value::Bool(true))));
    let events: Vec<(String, Value)> = match on {
        Some(Value::String(s)) => vec![(s.clone(), Value::Null)],
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|v| v.as_str().map(|s| (s.to_string(), Value::Null)))
            .collect(),
        Some(Value::Mapping(m)) => m
            .iter()
            .filter_map(|(k, v)| k.as_str().map(|k| (k.to_string(), v.clone())))
            .collect(),
        _ => return (PrPath::Unclear, false),
    };
    let mut path = PrPath::No;
    for (event, config) in &events {
        path = path.or(match event.as_str() {
            "pull_request" => pull_request_path(config),
            "merge_group" => PrPath::Yes,
            // Runs on the base branch's code unless it checks the head out.
            "pull_request_target" => PrPath::Unclear,
            _ => PrPath::No,
        });
    }
    (path, events.iter().any(|(e, _)| e == "workflow_call"))
}

/// The pull-request path a step of workflow `file` runs on: its own
/// triggers, and for a reusable workflow its local callers'.
fn workflow_path(workflows: &[(String, Value)], file: &str, depth: usize) -> PrPath {
    let Some((_, doc)) = workflows.iter().find(|(f, _)| f == file) else {
        return PrPath::Unclear;
    };
    let (mut path, callable) = own_triggers(doc);
    if !callable {
        return path;
    }
    let mut called = false;
    for (caller, caller_doc) in workflows {
        let jobs = caller_doc.get("jobs").and_then(Value::as_mapping);
        for job in jobs.into_iter().flat_map(|j| j.values()) {
            let uses = job.get("uses").and_then(Value::as_str).unwrap_or_default();
            if uses.strip_prefix("./") != Some(file) {
                continue;
            }
            called = true;
            let via = if depth < MAX_CALL_DEPTH {
                workflow_path(workflows, caller, depth + 1)
            } else {
                PrPath::Unclear
            };
            path = path.or(via.conditioned(job.get("if").is_some()));
        }
    }
    // A workflow no local file calls may be called from another repository.
    if called {
        path
    } else {
        path.or(PrPath::Unclear)
    }
}

/// The RC-040 SAST steps of the parsed GitHub Actions workflows.
pub(crate) fn github(workflows: &[(String, Value)], out: &mut SastFacts) {
    out.ci_files += workflows.len() as u32;
    for (file, doc) in workflows {
        let jobs = doc.get("jobs").and_then(Value::as_mapping);
        for job in jobs.into_iter().flat_map(|j| j.values()) {
            let job_if = job.get("if").is_some();
            let job_failure = continues(job.get("continue-on-error"));
            let path = || workflow_path(workflows, file, 0);
            if let Some(uses) = job.get("uses").and_then(Value::as_str) {
                if let Some(scanner) = sast_reusable(uses) {
                    out.steps.push(SastStep {
                        file: file.clone(),
                        scanner,
                        pr_path: path().conditioned(job_if),
                        on_failure: job_failure,
                    });
                }
                continue;
            }
            let steps = job.get("steps").and_then(Value::as_sequence);
            for step in steps.into_iter().flatten() {
                match github_step(step) {
                    Some((Sast::Step(scanner), failure)) => out.steps.push(SastStep {
                        file: file.clone(),
                        scanner,
                        pr_path: path().conditioned(job_if || step.get("if").is_some()),
                        on_failure: job_failure.and(failure),
                    }),
                    Some((Sast::Other, _)) => out.unrecognized.push(file.clone()),
                    None => {}
                }
            }
        }
    }
    out.steps.sort();
    out.unrecognized.sort();
    out.unrecognized.dedup();
}

// --- GitLab CI ---

/// Top-level `.gitlab-ci.yml` keys that are not jobs.
const GITLAB_GLOBALS: &[&str] = &[
    "after_script",
    "before_script",
    "cache",
    "default",
    "image",
    "include",
    "services",
    "spec",
    "stages",
    "variables",
    "workflow",
];

/// Whether a `rules:` list runs in merge request pipelines automatically.
fn rules_name_merge_requests(rules: &Value) -> bool {
    rules.as_sequence().into_iter().flatten().any(|rule| {
        let when = rule
            .get("when")
            .and_then(Value::as_str)
            .unwrap_or("on_success");
        rule.get("if")
            .and_then(Value::as_str)
            .is_some_and(|c| c.contains("merge_request_event"))
            && !matches!(when, "never" | "manual")
    })
}

/// A GitLab job's pull-request path. Without rules that name merge request
/// pipelines it runs in branch pipelines, which a project may or may not
/// require for a merge: unclear, never no.
fn gitlab_path(job: &Value) -> PrPath {
    if job.get("when").and_then(Value::as_str) == Some("manual") {
        return PrPath::Unclear;
    }
    let by_rules = job.get("rules").is_some_and(rules_name_merge_requests);
    let by_only = match job.get("only") {
        Some(Value::Sequence(refs)) => refs.iter().any(|r| r.as_str() == Some("merge_requests")),
        Some(only) => only
            .get("refs")
            .and_then(Value::as_sequence)
            .is_some_and(|refs| refs.iter().any(|r| r.as_str() == Some("merge_requests"))),
        None => false,
    };
    if by_rules || by_only {
        PrPath::Yes
    } else {
        PrPath::Unclear
    }
}

/// The RC-040 SAST steps of one `.gitlab-ci.yml`.
pub(crate) fn gitlab(file: &str, text: &str, out: &mut SastFacts) {
    let Some(root) = serde_yaml::from_str::<Value>(text)
        .ok()
        .and_then(|d| d.as_mapping().cloned())
    else {
        out.gitlab_unread += 1;
        return;
    };
    out.ci_files += 1;
    let mut unread = root.contains_key("include");
    // `workflow: rules` that never name merge requests run no MR pipeline.
    let mr_pipelines = root
        .get("workflow")
        .and_then(|w| w.get("rules"))
        .is_none_or(rules_name_merge_requests);
    for (name, job) in &root {
        let Some(name) = name.as_str() else { continue };
        if name.starts_with('.') || GITLAB_GLOBALS.contains(&name) || !job.is_mapping() {
            continue;
        }
        unread |= job.get("extends").is_some();
        let mut lines = Vec::new();
        for key in ["before_script", "script", "after_script"] {
            match job.get(key) {
                Some(Value::String(s)) => lines.extend(shell_lines(s)),
                Some(Value::Sequence(seq)) => {
                    for line in seq {
                        match line.as_str() {
                            Some(s) => lines.extend(shell_lines(s)),
                            None => unread = true,
                        }
                    }
                }
                // A `!reference` or another shape not read here.
                Some(_) => unread = true,
                None => {}
            }
        }
        if let Some(scanner) = lines.iter().find_map(|l| sast_command(l)) {
            let mut pr_path = gitlab_path(job);
            if !mr_pipelines && pr_path == PrPath::Yes {
                pr_path = PrPath::Unclear;
            }
            out.steps.push(SastStep {
                file: file.to_string(),
                scanner: scanner.into(),
                pr_path,
                on_failure: continues(job.get("allow_failure")).and(shell_failure(&lines)),
            });
        } else if lines.iter().any(|l| mentions_sast(l)) {
            out.unrecognized.push(file.to_string());
        }
    }
    if unread {
        out.gitlab_unread += 1;
    }
    out.steps.sort();
    out.unrecognized.sort();
    out.unrecognized.dedup();
}

// --- the verdict ---

fn listed(steps: &[&SastStep]) -> (String, Vec<String>) {
    let text = steps
        .iter()
        .map(|s| format!("{} ({})", s.scanner, s.file))
        .collect::<Vec<_>>()
        .join(", ");
    let mut files: Vec<String> = steps.iter().map(|s| s.file.clone()).collect();
    files.dedup();
    (text, files)
}

/// RC-040: does a SAST step run on the pull-request path and fail its job on
/// a finding? Judged only for a repository with a server entry point.
pub(crate) fn evaluate(facts: &RepoStructure) -> StructureFinding {
    let mk = |verdict, reason: String, evidence| StructureFinding {
        control: "RC-040",
        control_name: "SAST on the pull-request path",
        verdict,
        reason,
        evidence,
        fix: "run a SAST step (semgrep ci, CodeQL analyze, gosec, bandit, snyk code test) in a \
              workflow triggered by pull_request or merge_group, without continue-on-error, so \
              a finding fails the check"
            .into(),
        severity: "medium",
        weak: false,
    };
    if facts.server_entry_points.is_empty() {
        return mk(
            Verdict::Abstain,
            "no server entry point in non-test code: judged only for a deployable service".into(),
            vec![],
        );
    }
    let s = &facts.sast;
    if s.ci_files == 0 {
        return mk(
            Verdict::Abstain,
            "no GitHub Actions workflow or .gitlab-ci.yml parsed".into(),
            vec![],
        );
    }
    let gating: Vec<&SastStep> = s
        .steps
        .iter()
        .filter(|x| x.pr_path == PrPath::Yes && x.on_failure == OnFailure::Fails)
        .collect();
    if !gating.is_empty() {
        let (text, files) = listed(&gating);
        return mk(
            Verdict::Satisfies,
            format!("a SAST step on the pull-request path fails its job on a finding: {text}"),
            files,
        );
    }

    let ci = &facts.ci_scans;
    let mut unseen = Vec::new();
    if !facts.walk_complete {
        unseen.push("walk truncated".to_string());
    }
    if ci.workflows_unparsed > 0 {
        unseen.push(format!(
            "{} workflow file(s) not parsed",
            ci.workflows_unparsed
        ));
    }
    if ci.opaque_calls > 0 {
        unseen.push(format!(
            "{} call(s) to a reusable workflow or composite action not read",
            ci.opaque_calls
        ));
    }
    if s.gitlab_unread > 0 {
        unseen.push(".gitlab-ci.yml includes or extends what is not read".into());
    }
    if !s.other_ci.is_empty() {
        unseen.push(format!(
            "CI config not read for SAST: {}",
            s.other_ci.join(", ")
        ));
    }
    if !s.unrecognized.is_empty() {
        unseen.push(format!(
            "a SAST-looking step this rule does not judge in {}",
            s.unrecognized.join(", ")
        ));
    }
    if !unseen.is_empty() {
        return mk(
            Verdict::Abstain,
            format!(
                "{}: a missing or non-gating SAST step cannot be read",
                unseen.join("; ")
            ),
            vec![],
        );
    }

    if s.steps.is_empty() {
        return mk(
            Verdict::Violates,
            format!(
                "{} CI file(s) read and none runs a SAST step (semgrep, CodeQL analyze, \
                 snyk code test, gosec, bandit)",
                s.ci_files
            ),
            vec![],
        );
    }
    let all: Vec<&SastStep> = s.steps.iter().collect();
    if all.iter().all(|x| x.pr_path == PrPath::No) {
        let (text, files) = listed(&all);
        return mk(
            Verdict::Violates,
            format!(
                "SAST runs only in workflows not triggered by pull_request or merge_group: {text}"
            ),
            files,
        );
    }
    let reachable: Vec<&SastStep> = all
        .into_iter()
        .filter(|x| x.pr_path != PrPath::No)
        .collect();
    if reachable.iter().any(|x| x.pr_path == PrPath::Yes)
        && reachable
            .iter()
            .all(|x| x.on_failure == OnFailure::Continues)
    {
        let (text, files) = listed(&reachable);
        return mk(
            Verdict::Violates,
            format!(
                "every SAST step on the pull-request path continues on error, so a finding \
                 never fails the check: {text}"
            ),
            files,
        );
    }
    let (text, files) = listed(&reachable);
    mk(
        Verdict::Abstain,
        format!(
            "SAST steps whose pull-request path or failure mode hangs on a filter, a condition \
             or a caller not read: {text}"
        ),
        files,
    )
}
