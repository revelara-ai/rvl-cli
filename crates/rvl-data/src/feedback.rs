//! `feedback` / `bugreport`, ported from rvl-cli
//! `internal/commands/feedback.go` (po-nmkeg): users AND coding agents can
//! file feedback or bug reports from the CLI, with a shape-only diagnostic
//! bundle attached.
//!
//! Privacy contract: the bundle NEVER contains file contents, code, or
//! findings — only CLI version, os/arch, the API host, the configured
//! organization, and a summary of the local gate audit trail (event kind
//! + timestamp, nothing else).
//!
//! Both commands share one implementation; only the default `--category`
//! differs (`feedback` vs `bug`), mirroring how rvl-cli's `main.go` wires
//! `CmdFeedback(args, version, "feedback"|"bug")`.

use crate::client::Client;
use crate::config::DataConfig;
use crate::gojson::{compact, pretty, G};
use crate::{CmdResult, Failure, BIN};
use serde::Deserialize;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Shared flags for `feedback` and `bugreport` (same set as rvl-cli).
#[derive(Debug, Default, clap::Args)]
pub struct FeedbackArgs {
    /// The feedback or bug description (required). Pass '--message -' to
    /// read it from stdin.
    #[arg(long)]
    pub message: Option<String>,
    /// Report category (feedback, bug)
    #[arg(long)]
    pub category: Option<String>,
    /// Attach the shape-only diagnostic bundle (default: true)
    #[arg(long, num_args = 0..=1, default_missing_value = "true", require_equals = true, value_name = "BOOL")]
    pub attach_diagnostics: Option<String>,
    /// Skip the confirmation prompt (headless/agent use)
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Output format (text, json)
    #[arg(long)]
    pub format: Option<String>,
}

/// The resolved options, mirroring rvl-cli's `feedbackOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub message: String,
    pub category: String,
    pub attach_diagnostics: bool,
    pub yes: bool,
    pub format: String,
}

/// The shape-only diagnostic bundle (rvl-cli's `feedbackDiagnostics`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Diagnostics {
    pub cli_version: String,
    pub os: String,
    pub arch: String,
    pub api_host: String,
    pub org_id: String,
    pub org_name: String,
    pub gate_event_count: i64,
    pub last_gate_event: Option<AuditEventSummary>,
}

/// Shape-only summary of the newest entry in the per-worktree gate audit
/// log (`rvl-audit.jsonl`): kind + timestamp only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventSummary {
    pub kind: String,
    pub time: String,
}

/// The POST /api/v1/feedback request body (rvl-cli's `feedbackSubmission`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submission {
    pub message: String,
    pub category: String,
    pub cli_version: String,
    pub diagnostics: Option<Diagnostics>,
}

/// Entry point for both commands: `default_category` is "feedback" for
/// `feedback` and "bug" for `bugreport`.
pub fn run(args: FeedbackArgs, default_category: &str, version: &str) -> ExitCode {
    crate::finish(run_inner(args, default_category, version))
}

fn run_inner(args: FeedbackArgs, default_category: &str, version: &str) -> CmdResult {
    let help_cmd = if default_category == "bug" {
        format!("{BIN} bugreport")
    } else {
        format!("{BIN} feedback")
    };

    let mut o =
        resolve_options(args, default_category).map_err(|e| usage_failure(&e, &help_cmd))?;

    let message_from_stdin = o.message == "-";
    if message_from_stdin {
        let mut data = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut data)
            .map_err(|e| Failure::runtime(format!("Error reading message from stdin: {e}")))?;
        o.message = data.trim().to_string();
    }

    validate_options(&o).map_err(|e| usage_failure(&e, &help_cmd))?;

    let (cfg, client) = crate::client::load_and_resolve()?;

    let work_dir = std::env::current_dir().ok();
    let diag = collect_diagnostics(version, &cfg, client.org_id.as_deref(), work_dir.as_deref());
    let sub = build_submission(&o, version, &diag);

    if !o.yes {
        print!("{}", render_preview(&sub));
        if !confirm_send(message_from_stdin)? {
            return Ok("Aborted. Nothing was sent.\n".to_string());
        }
    }

    submit_output(&client, &submission_json(&sub), &o.category, &o.format)
}

/// Usage errors print the error plus a help pointer, then exit 2
/// (rvl-cli prints both lines to stderr before `os.Exit(ExitUsage)`).
fn usage_failure(err: &str, help_cmd: &str) -> Failure {
    Failure::usage(format!("Error: {err}\nRun '{help_cmd} --help' for usage."))
}

/// Resolve clap-parsed flags to options, mirroring `parseFeedbackArgs`:
/// same defaults, same invalid `--attach-diagnostics` error.
pub fn resolve_options(args: FeedbackArgs, default_category: &str) -> Result<Options, String> {
    let attach_diagnostics = match args.attach_diagnostics.as_deref() {
        None | Some("true") => true,
        Some("false") => false,
        Some(v) => {
            return Err(format!(
                "invalid --attach-diagnostics \"{v}\" (valid: true, false)"
            ))
        }
    };
    Ok(Options {
        message: args.message.unwrap_or_default(),
        category: args
            .category
            .unwrap_or_else(|| default_category.to_string()),
        attach_diagnostics,
        yes: args.yes,
        format: args.format.unwrap_or_else(|| "text".to_string()),
    })
}

/// Check the resolved options (after any stdin message read). All
/// violations are usage errors (exit 2), like `validateFeedbackOptions`.
pub fn validate_options(o: &Options) -> Result<(), String> {
    if o.message.trim().is_empty() {
        return Err("--message is required (pass '--message -' to read it from stdin)".to_string());
    }
    if o.category != "feedback" && o.category != "bug" {
        return Err(format!(
            "invalid --category \"{}\" (valid: feedback, bug)",
            o.category
        ));
    }
    if o.format != "text" && o.format != "json" {
        return Err(format!(
            "invalid --format \"{}\" (valid: text, json)",
            o.format
        ));
    }
    Ok(())
}

/// Go `runtime.GOOS` vocabulary: the wire shape matches rvl-cli, so the
/// backend sees one naming scheme.
fn go_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

/// Go `runtime.GOARCH` vocabulary (amd64/arm64/386), same reason.
fn go_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other,
    }
}

/// Assemble the shape-only bundle, mirroring `collectDiagnostics`.
/// Everything here is metadata about the CLI and its configuration;
/// nothing is read from the user's project except the gate audit log
/// summary (kind + time).
pub fn collect_diagnostics(
    version: &str,
    cfg: &DataConfig,
    org_id: Option<&str>,
    work_dir: Option<&Path>,
) -> Diagnostics {
    let mut d = Diagnostics {
        cli_version: version.to_string(),
        os: go_os().to_string(),
        arch: go_arch().to_string(),
        api_host: api_host(&cfg.api_url),
        org_id: org_id.unwrap_or_default().to_string(),
        org_name: cfg.org_name.clone(),
        ..Diagnostics::default()
    };
    if let Some(dir) = work_dir {
        if let Some((last, count)) = last_audit_event(dir) {
            if count > 0 {
                d.gate_event_count = count as i64;
                d.last_gate_event = last;
            }
        }
    }
    d
}

/// Just the host of the configured API URL (no path, no credentials),
/// falling back to the raw string when it does not parse as a URL —
/// matching Go's `url.Parse(...).Host` fallback.
pub fn api_host(raw: &str) -> String {
    let Some((_, rest)) = raw.split_once("://") else {
        return raw.to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.rsplit_once('@') {
        Some((_, h)) => h,
        None => authority,
    };
    if host.is_empty() {
        raw.to_string()
    } else {
        host.to_string()
    }
}

/// Summarize the per-worktree gate audit log (`rvl-audit.jsonl` in the
/// repo's git dir), if the working directory is inside a git repository
/// and the log exists.
fn last_audit_event(dir: &Path) -> Option<(Option<AuditEventSummary>, usize)> {
    let git_dir = git_dir_for(dir)?;
    last_audit_event_from_file(&git_dir.join("rvl-audit.jsonl")).ok()
}

/// Resolve the git dir via `git rev-parse --git-dir` so linked worktrees
/// resolve to their per-worktree dir.
fn git_dir_for(dir: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let git_dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if git_dir.is_empty() {
        return None;
    }
    let p = PathBuf::from(&git_dir);
    Some(if p.is_absolute() { p } else { dir.join(p) })
}

/// Read a JSONL audit log and return the newest event's kind + timestamp
/// and the total event count. Only those two fields are extracted —
/// detail payloads never leave the machine.
pub fn last_audit_event_from_file(
    path: &Path,
) -> std::io::Result<(Option<AuditEventSummary>, usize)> {
    #[derive(Deserialize)]
    struct Ev {
        #[serde(default)]
        time: String,
        #[serde(default)]
        kind: String,
    }
    let text = std::fs::read_to_string(path)?;
    let mut last = None;
    let mut count = 0usize;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(ev) = serde_json::from_str::<Ev>(line) else {
            continue;
        };
        count += 1;
        last = Some(AuditEventSummary {
            kind: ev.kind,
            time: ev.time,
        });
    }
    Ok((last, count))
}

/// Assemble the request body. Diagnostics are only included when
/// `--attach-diagnostics` is true (the default).
pub fn build_submission(o: &Options, version: &str, diag: &Diagnostics) -> Submission {
    Submission {
        message: o.message.clone(),
        category: o.category.clone(),
        cli_version: version.to_string(),
        diagnostics: o.attach_diagnostics.then(|| diag.clone()),
    }
}

/// Go-parity JSON for the POST body: struct field order, `omitempty`
/// semantics identical to rvl-cli's `feedbackSubmission` marshal.
pub fn submission_json(sub: &Submission) -> String {
    let mut fields = vec![
        ("message".to_string(), G::Str(sub.message.clone())),
        ("category".to_string(), G::Str(sub.category.clone())),
    ];
    if !sub.cli_version.is_empty() {
        fields.push(("cli_version".to_string(), G::Str(sub.cli_version.clone())));
    }
    if let Some(d) = &sub.diagnostics {
        fields.push(("diagnostics".to_string(), diagnostics_g(d)));
    }
    compact(&G::Obj(fields))
}

fn diagnostics_g(d: &Diagnostics) -> G {
    let mut fields = vec![
        ("cli_version".to_string(), G::Str(d.cli_version.clone())),
        ("os".to_string(), G::Str(d.os.clone())),
        ("arch".to_string(), G::Str(d.arch.clone())),
    ];
    if !d.api_host.is_empty() {
        fields.push(("api_host".to_string(), G::Str(d.api_host.clone())));
    }
    if !d.org_id.is_empty() {
        fields.push(("org_id".to_string(), G::Str(d.org_id.clone())));
    }
    if !d.org_name.is_empty() {
        fields.push(("org_name".to_string(), G::Str(d.org_name.clone())));
    }
    if d.gate_event_count != 0 {
        fields.push(("gate_event_count".to_string(), G::Int(d.gate_event_count)));
    }
    if let Some(ev) = &d.last_gate_event {
        fields.push((
            "last_gate_event".to_string(),
            G::Obj(vec![
                ("kind".to_string(), G::Str(ev.kind.clone())),
                ("time".to_string(), G::Str(ev.time.clone())),
            ]),
        ));
    }
    G::Obj(fields)
}

/// Show exactly what will be sent, so the user can verify nothing
/// sensitive is included before confirming.
pub fn render_preview(sub: &Submission) -> String {
    let mut b = String::new();
    b.push_str("About to send to Revelara:\n\n");
    let _ = writeln!(b, "Category: {}", sub.category);
    let _ = writeln!(b, "Message:\n  {}", sub.message.replace('\n', "\n  "));
    match &sub.diagnostics {
        Some(d) => {
            b.push_str("Diagnostics (shape-only; no code, file contents, or findings):\n");
            let _ = writeln!(b, "  cli_version: {}", d.cli_version);
            let _ = writeln!(b, "  os/arch:     {}/{}", d.os, d.arch);
            if !d.api_host.is_empty() {
                let _ = writeln!(b, "  api_host:    {}", d.api_host);
            }
            if !d.org_name.is_empty() {
                let _ = writeln!(b, "  org_name:    {}", d.org_name);
            }
            if !d.org_id.is_empty() {
                let _ = writeln!(b, "  org_id:      {}", d.org_id);
            }
            if d.gate_event_count > 0 {
                if let Some(ev) = &d.last_gate_event {
                    let _ = writeln!(
                        b,
                        "  gate_audit:  {} event(s), last \"{}\" at {}",
                        d.gate_event_count, ev.kind, ev.time
                    );
                }
            }
        }
        None => b.push_str("Diagnostics: not attached (--attach-diagnostics=false)\n"),
    }
    b
}

/// Prompt "Send this to Revelara? [y/N]". When the message was read from
/// stdin, the prompt reads from /dev/tty instead; if no terminal is
/// available the command fails loudly and points at --yes.
fn confirm_send(message_from_stdin: bool) -> Result<bool, Failure> {
    if message_from_stdin {
        let tty = std::fs::File::open("/dev/tty").map_err(|_| {
            Failure::runtime(
                "Error: the message was read from stdin, so no terminal is available for \
                 confirmation. Pass --yes to send without confirmation."
                    .to_string(),
            )
        })?;
        prompt_send();
        Ok(read_yes(std::io::BufReader::new(tty)))
    } else {
        prompt_send();
        Ok(read_yes(std::io::stdin().lock()))
    }
}

fn prompt_send() {
    print!("Send this to Revelara? [y/N]: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// Read one line and report whether it is an affirmative answer.
pub fn read_yes(mut r: impl std::io::BufRead) -> bool {
    let mut line = String::new();
    if r.read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    let answer = line.trim().to_lowercase();
    answer == "y" || answer == "yes"
}

pub fn category_noun(category: &str) -> &'static str {
    if category == "bug" {
        "bug report"
    } else {
        "feedback"
    }
}

/// POST the submission and render the returned report id, mirroring the
/// tail of `CmdFeedback` (text and json output shapes, same errors).
pub fn submit_output(client: &Client, body: &str, category: &str, format: &str) -> CmdResult {
    let url = format!("{}/api/v1/feedback", client.api_url);
    let resp = client
        .request("POST", &url, Some(body.as_bytes()))
        .map_err(|e| {
            Failure::runtime(format!("Error submitting {}: {e}", category_noun(category)))
        })?;

    #[derive(Default, Deserialize)]
    struct Resp {
        #[serde(default)]
        id: String,
    }
    let id = serde_json::from_slice::<Resp>(&resp)
        .map(|r| r.id)
        .unwrap_or_default();
    if id.is_empty() {
        return Err(Failure::runtime(format!(
            "Error: unexpected response from server: {}",
            String::from_utf8_lossy(&resp)
        )));
    }

    if format == "json" {
        // Go marshals map[string]string with MarshalIndent: sorted keys.
        return Ok(format!(
            "{}\n",
            pretty(&G::Obj(vec![
                ("category".to_string(), G::Str(category.to_string())),
                ("id".to_string(), G::Str(id)),
                ("status".to_string(), G::Str("submitted".to_string())),
            ]))
        ));
    }
    Ok(format!(
        "Thanks! Your {} was sent to Revelara.\nReport id: {id}\n",
        category_noun(category)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Test-only wrapper so the Go arg-parsing tests can drive the same
    /// clap surface `rvl feedback` exposes.
    #[derive(Parser)]
    #[command(name = "test")]
    struct Wrap {
        #[command(flatten)]
        args: FeedbackArgs,
    }

    fn parse(argv: &[&str], default_category: &str) -> Result<Options, String> {
        let mut full = vec!["test"];
        full.extend_from_slice(argv);
        let w = Wrap::try_parse_from(full).map_err(|e| e.to_string())?;
        resolve_options(w.args, default_category)
    }

    #[test]
    fn parse_defaults() {
        let o = parse(&["--message", "hello"], "feedback").unwrap();
        assert_eq!(o.message, "hello");
        assert_eq!(o.category, "feedback");
        assert!(o.attach_diagnostics, "attach-diagnostics defaults to true");
        assert!(!o.yes, "--yes defaults to false");
        assert_eq!(o.format, "text");
    }

    #[test]
    fn parse_bugreport_default_category() {
        // `bugreport` passes "bug" as the default category.
        let o = parse(&["--message=broken"], "bug").unwrap();
        assert_eq!(o.category, "bug");
    }

    #[test]
    fn parse_all_flags() {
        let o = parse(
            &[
                "--message=scan did not submit",
                "--category=bug",
                "--attach-diagnostics=false",
                "--yes",
                "--format=json",
            ],
            "feedback",
        )
        .unwrap();
        assert_eq!(o.category, "bug");
        assert!(
            !o.attach_diagnostics,
            "attach-diagnostics=false not honored"
        );
        assert!(o.yes, "--yes not honored");
        assert_eq!(o.format, "json");
    }

    #[test]
    fn parse_bare_attach_diagnostics_flag_means_true() {
        let o = parse(&["--message=m", "--attach-diagnostics"], "feedback").unwrap();
        assert!(o.attach_diagnostics);
    }

    #[test]
    fn parse_short_yes_flag() {
        let o = parse(&["--message=m", "-y"], "feedback").unwrap();
        assert!(o.yes);
    }

    #[test]
    fn parse_unknown_flag_is_an_error() {
        assert!(parse(&["--bogus"], "feedback").is_err());
    }

    #[test]
    fn parse_bad_attach_value_is_an_error() {
        let err = parse(&["--message=m", "--attach-diagnostics=maybe"], "feedback").unwrap_err();
        assert_eq!(
            err,
            "invalid --attach-diagnostics \"maybe\" (valid: true, false)"
        );
    }

    #[test]
    fn validate_options_table() {
        let mk = |message: &str, category: &str, format: &str| Options {
            message: message.to_string(),
            category: category.to_string(),
            attach_diagnostics: true,
            yes: false,
            format: format.to_string(),
        };
        // (name, options, ok)
        let tests = [
            ("valid feedback", mk("m", "feedback", "text"), true),
            ("valid bug json", mk("m", "bug", "json"), true),
            ("empty message", mk("  ", "feedback", "text"), false),
            ("bad category", mk("m", "rant", "text"), false),
            ("bad format", mk("m", "bug", "yaml"), false),
        ];
        for (name, o, ok) in tests {
            assert_eq!(validate_options(&o).is_ok(), ok, "{name}");
        }
    }

    #[test]
    fn build_submission_omits_diagnostics() {
        let o = Options {
            message: "m".into(),
            category: "bug".into(),
            attach_diagnostics: false,
            yes: false,
            format: "text".into(),
        };
        let diag = Diagnostics {
            cli_version: "1.2.3".into(),
            os: "linux".into(),
            arch: "amd64".into(),
            ..Diagnostics::default()
        };
        let sub = build_submission(&o, "1.2.3", &diag);
        assert!(
            sub.diagnostics.is_none(),
            "diagnostics must be None when --attach-diagnostics=false"
        );
        let raw = submission_json(&sub);
        assert!(
            !raw.contains("diagnostics"),
            "payload must omit diagnostics key entirely: {raw}"
        );
        assert!(
            raw.contains(r#""cli_version":"1.2.3""#),
            "payload missing cli_version: {raw}"
        );
    }

    #[test]
    fn build_submission_attaches_diagnostics() {
        let o = Options {
            message: "m".into(),
            category: "feedback".into(),
            attach_diagnostics: true,
            yes: false,
            format: "text".into(),
        };
        let diag = Diagnostics {
            cli_version: "1.2.3".into(),
            os: "linux".into(),
            arch: "amd64".into(),
            api_host: "api.revelara.ai".into(),
            ..Diagnostics::default()
        };
        let sub = build_submission(&o, "1.2.3", &diag);
        let d = sub
            .diagnostics
            .as_ref()
            .expect("diagnostics attached by default");
        assert_eq!(d.api_host, "api.revelara.ai");
    }

    #[test]
    fn submission_json_matches_go_struct_marshal() {
        // Field order + omitempty semantics of Go's feedbackSubmission /
        // feedbackDiagnostics structs, including Go's SetEscapeHTML
        // default (& -> &).
        let sub = Submission {
            message: "m & n".into(),
            category: "bug".into(),
            cli_version: "1.2.3".into(),
            diagnostics: Some(Diagnostics {
                cli_version: "1.2.3".into(),
                os: "linux".into(),
                arch: "amd64".into(),
                api_host: "api.revelara.ai".into(),
                org_id: String::new(),
                org_name: "acme".into(),
                gate_event_count: 2,
                last_gate_event: Some(AuditEventSummary {
                    kind: "fail-open".into(),
                    time: "2026-08-02T00:00:00Z".into(),
                }),
            }),
        };
        assert_eq!(
            submission_json(&sub),
            r#"{"message":"m \u0026 n","category":"bug","cli_version":"1.2.3","diagnostics":{"cli_version":"1.2.3","os":"linux","arch":"amd64","api_host":"api.revelara.ai","org_name":"acme","gate_event_count":2,"last_gate_event":{"kind":"fail-open","time":"2026-08-02T00:00:00Z"}}}"#
        );
    }

    #[test]
    fn api_host_cases() {
        let tests = [
            ("https://api.revelara.ai", "api.revelara.ai"),
            ("http://localhost:8080", "localhost:8080"),
            ("not a url", "not a url"),
        ];
        for (input, want) in tests {
            assert_eq!(api_host(input), want, "api_host({input:?})");
        }
    }

    #[test]
    fn last_audit_event_from_file_reads_newest_and_count() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rvl-audit.jsonl");
        let lines = concat!(
            r#"{"time":"2026-08-01T00:00:00Z","kind":"force-through","detail":{"mechanism":"env"}}"#,
            "\n",
            r#"{"time":"2026-08-02T00:00:00Z","kind":"fail-open","detail":{"lens_errors":"2"}}"#,
            "\n",
        );
        std::fs::write(&path, lines).unwrap();
        let (last, count) = last_audit_event_from_file(&path).unwrap();
        assert_eq!(count, 2);
        let last = last.expect("last event present");
        assert_eq!(last.kind, "fail-open");
        assert_eq!(last.time, "2026-08-02T00:00:00Z");
    }

    #[test]
    fn last_audit_event_from_file_missing_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(last_audit_event_from_file(&dir.path().join("nope.jsonl")).is_err());
    }

    #[test]
    fn preview_lists_everything_sent() {
        let sub = Submission {
            message: "the scan did not submit data".into(),
            category: "bug".into(),
            cli_version: "1.2.3".into(),
            diagnostics: Some(Diagnostics {
                cli_version: "1.2.3".into(),
                os: "linux".into(),
                arch: "amd64".into(),
                api_host: "api.revelara.ai".into(),
                org_id: "11111111-2222-3333-4444-555555555555".into(),
                ..Diagnostics::default()
            }),
        };
        let out = render_preview(&sub);
        for want in [
            "the scan did not submit data",
            "bug",
            "1.2.3",
            "linux",
            "amd64",
            "api.revelara.ai",
        ] {
            assert!(out.contains(want), "preview missing {want:?}:\n{out}");
        }
        // Product name policy: internal codename must never appear in
        // user-facing CLI output. (Built from parts so the repo-wide
        // codename grep gate stays clean.)
        let codename = ["Pol", "aris"].concat();
        assert!(
            !out.contains(&codename),
            "preview must not contain the internal codename:\n{out}"
        );
    }

    #[test]
    fn preview_states_when_diagnostics_not_attached() {
        let sub = Submission {
            message: "m".into(),
            category: "feedback".into(),
            cli_version: String::new(),
            diagnostics: None,
        };
        let out = render_preview(&sub);
        assert!(
            out.contains("not attached"),
            "preview should state diagnostics are not attached:\n{out}"
        );
    }

    #[test]
    fn read_yes_table() {
        let tests: [(&str, bool); 6] = [
            ("y\n", true),
            ("Y\n", true),
            ("yes\n", true),
            ("n\n", false),
            ("\n", false),
            ("", false),
        ];
        for (input, want) in tests {
            assert_eq!(read_yes(input.as_bytes()), want, "read_yes({input:?})");
        }
    }

    #[test]
    fn category_nouns() {
        assert_eq!(category_noun("bug"), "bug report");
        assert_eq!(category_noun("feedback"), "feedback");
    }
}
