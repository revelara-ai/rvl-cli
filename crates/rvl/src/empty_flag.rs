//! WHAT AN EMPTY FLAG VALUE MEANS, PER FLAG (po-av01j.192).
//!
//! rvl-cli parses flags by hand. `--flag=` and (where the space form is
//! accepted at all) `--flag ''` both hand the consumer an empty string, and
//! then EACH CONSUMER decides what that means:
//!
//! * a string filter guards `if v != ""` — the empty value means the flag was
//!   never given (`Empty::Absent`);
//! * a numeric flag runs `strconv.Atoi("")`, which fails, and exits 2
//!   (`Empty::Error`);
//! * a handful of flags carry the empty string all the way to the wire —
//!   `risk resolve --reason=` POSTs `{"reason":""}` (`Empty::Value`);
//! * an unknown flag exits 2 whatever its spelling, so a TYPO written with a
//!   trailing `=` (`--serivce=`) is still a usage error.
//!
//! po-av01j.185 tried to satisfy the first bullet for everyone at once by
//! stripping any `--x=` token from argv before clap saw it. That is the wrong
//! layer: argv only knows the SHAPE of a token, so the strip also swallowed
//! the numeric errors, the typos, and the values that were supposed to reach
//! the wire. This module is the replacement: the decision moves back to the
//! consumer, and the table below is the audit of what each consumer decides,
//! checked against rvl-cli's parsers flag by flag.
//!
//! The table is not documentation, it is a TEST FIXTURE:
//! [`audit_against`] walks the real clap command tree and fails if any
//! value-taking long flag is missing from it, so a flag added later cannot
//! silently inherit somebody else's empty-value semantics — the author has to
//! read rvl-cli and write the row down.

/// What rvl-cli does when this flag is given an empty value.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Empty {
    /// The consumer guards `if v != ""`: empty behaves exactly as omitted.
    /// In this binary the flag is normalized with
    /// `rvl_core::flag::EmptyFlag::empty_is_absent` at its dispatch site.
    Absent,
    /// Empty is a usage error (exit 2): a numeric parse, an enum validation
    /// that is NOT guarded by `!= ""`, or a required-value check. Typed clap
    /// arguments (`u32`, `usize`) produce this for free; string-typed ones
    /// must reject the empty value explicitly.
    Error,
    /// The empty string is a real value and is used/transmitted as one.
    Value,
}

/// Every value-taking long flag in this binary, with the empty-value
/// semantics rvl-cli gives it. `path` is the subcommand path as the user
/// types it (`""` for the root).
///
/// Rows marked "rvl-native" have no rvl-cli counterpart; they follow the
/// convention of their family, which is stated on the row.
/// Compiled only under `cfg(test)`: this is a FIXTURE, not runtime data —
/// the behaviour it describes lives in the consumers. Keeping it out of the
/// shipped binary means a stale row can only ever fail a test, never change
/// what the binary does.
#[cfg(test)]
pub const SEMANTICS: &[(&str, &str, Empty)] = &[
    // ---------------- rvl-native scanner surface ----------------
    // No rvl-cli counterpart. The PATH flags are Empty::Error because clap's
    // PathBuf parser refuses an empty path in BOTH spellings ("a value is
    // required", exit 2) — identical spellings, and an empty path is not a
    // file anybody meant to name. The rendering hints are strings the
    // scanner treats as optional, so empty == not given, the convention
    // rvl-cli follows for every guarded string flag (scan.go:520,
    // scan_agent.go:195-211).
    ("scan", "retrieved", Empty::Error),
    ("scan", "specs-file", Empty::Error),
    ("scan", "judgments", Empty::Error),
    ("scan", "out", Empty::Error),
    // Added when po-av01j.185 and .191 merged in alongside .192; this table is
    // what caught them. Each read off rvl-cli origin/main, not inferred:
    //
    // scan.go:667 `if csFile != ""` guards the read, so empty == not given.
    ("scan", "cs-file", Empty::Absent),
    // scan_agent.go:189 `if a.mode != ""` guards the override, leaving
    // scan_agent.go:114 Mode: GateModeEnforce. So empty == not given, NOT a
    // request for an empty mode.
    ("scan", "mode", Empty::Absent),
    // report.go:75 lowercases/trims then validates unguarded:
    // `if set != "starter" && set != "full"` -> exit 2. Empty is rejected.
    ("compliance report", "set", Empty::Error),
    // report.go:44 defaults "soc2" but nothing guards the override, and the
    // value is interpolated straight into the URL path, so `--framework=`
    // really does request /api/v1/compliance//readiness. Faithful, if odd.
    ("compliance report", "framework", Empty::Value),
    // report.go:46 defaults to "" and only ever asks `if format == "json"`
    // (report.go:91), so empty IS the default and means table output.
    ("compliance report", "format", Empty::Absent),
    ("scan", "color", Empty::Absent),
    ("scan", "hook", Empty::Absent),
    // po-av01j.194's `--base`. rvl-cli parses it two ways and BOTH end at
    // `ResolveBaseRef`, whose first act is `strings.TrimSpace(cfg.FlagBaseRef)`
    // and whose chain treats `""` as "this link is unset" and walks on to
    // RVL_BASE_REF (wire.go:148/155-158). So `--base=` is not a request to
    // diff against the ref named "" — it is the flag not being given, and the
    // env/config links still get their turn. (The SPACE form with no value at
    // all is a different thing: scan.go:468 exits 2 with "--base requires a
    // value", which clap produces for free.)
    ("scan", "base", Empty::Absent),
    // rvl-cli submission-mode flags. scan.go:520 (`--target`),
    // scan_agent.go:230, scan.go:557/1022 all guard with `!= ""`.
    ("scan", "service", Empty::Absent),
    ("scan", "team", Empty::Absent),
    ("scan", "target", Empty::Absent),
    ("scan", "file", Empty::Absent),
    ("scan", "scan-dir", Empty::Absent),
    ("scan", "timeout", Empty::Absent),
    // scan_agent.go:96 guards ValidateFormat with `!= ""`.
    ("scan", "format", Empty::Absent),
    ("report", "retrieved", Empty::Error),
    ("report", "specs-file", Empty::Error),
    ("report", "out", Empty::Error),
    ("explain", "retrieved", Empty::Error),
    ("explain", "specs-file", Empty::Error),
    ("explain", "judgments", Empty::Error),
    ("explain", "color", Empty::Absent),
    ("suppress", "retrieved", Empty::Error),
    ("suppress", "specs-file", Empty::Error),
    ("suppress", "judgments", Empty::Error),
    // A waiver reason is audit text written to `.revelara.yaml`; an empty
    // one is no reason at all, which is exactly what omitting it records.
    ("suppress", "reason", Empty::Absent),
    // Documented on the flag as "Empty is open-ended", and
    // `waiver::expiry_active` reads an empty `expires` as never-expiring —
    // so Absent IS open-ended, and stays that way.
    ("suppress", "expires", Empty::Absent),
    ("cache import", "sig", Empty::Error),
    ("index init", "retrieved", Empty::Error),
    ("index reindex", "retrieved", Empty::Error),
    ("index reindex", "files", Empty::Absent),
    // init.go:88/353: an empty --project falls back to the detected name.
    ("init", "project", Empty::Absent),
    ("doctor", "format", Empty::Absent),
    // rvl-cli's `parseAgentsListFlags` (plugin/manager.go:473) TrimPrefixes
    // --editor with NO `!= ""` guard, so `--editor=` really does resolve the
    // harness named "" and report that failure. Kept: silently substituting
    // the "claude" default would answer a question about one harness with
    // another harness's lenses. (manager.go:463 accepts "" for --format.)
    ("plugin agents", "editor", Empty::Value),
    ("plugin agents", "format", Empty::Absent),
    // ---------------- risk (internal/commands/risk.go) ----------------
    ("risk list", "status", Empty::Absent),    // risk.go:417
    ("risk list", "category", Empty::Absent),  // risk.go:420
    ("risk list", "service", Empty::Absent),   // risk.go:423
    ("risk list", "format", Empty::Absent),    // risk.go:440, no validator
    ("risk list", "limit", Empty::Error),      // risk.go:351 Atoi("")
    ("risk ready", "category", Empty::Absent), // risk.go:532
    ("risk ready", "service", Empty::Absent),  // risk.go:535
    ("risk ready", "format", Empty::Absent),   // risk.go:574
    ("risk ready", "limit", Empty::Error),     // risk.go:498/506
    ("risk show", "format", Empty::Absent),    // risk.go:751
    ("risk context", "format", Empty::Absent), // risk.go:920
    // risk.go:1097/1152: `--reason=` OVERRIDES the "Resolved" default and is
    // POSTed as {"reason":""}. Substituting the default would write a
    // sentence into the risk register that the operator never typed.
    ("risk resolve", "reason", Empty::Value),
    ("risk resolve", "format", Empty::Absent), // risk.go:1159
    ("risk accept", "reason", Empty::Value),   // risk.go:1205
    // ---------------- control (internal/commands/control.go) ----------------
    ("control list", "category", Empty::Absent), // control.go:176
    ("control list", "limit", Empty::Error),     // control.go:128/138
    // control.go:163 wraps ValidateFormat in `if format != ""`, so `--format=`
    // renders the table while `--format=xyz` still exits 2.
    ("control list", "format", Empty::Absent),
    ("control show", "format", Empty::Absent), // control.go:251, same guard
    // rvl-native scope filters; they follow the filter rule.
    ("control show", "team", Empty::Absent),
    ("control show", "service", Empty::Absent),
    // ---------------- incident (internal/commands/incident.go) ----------------
    ("incident search", "limit", Empty::Error), // incident.go:152
    // incident.go:163 calls ValidateFormat UNGUARDED — the one --format in
    // the port that rejects an empty value.
    ("incident search", "format", Empty::Error),
    // ---------------- knowledge (internal/commands/knowledge.go) ----------------
    // knowledge.go:372 switches on the raw value; "" hits `default`.
    ("knowledge search", "min-class", Empty::Error),
    ("knowledge search", "limit", Empty::Error), // knowledge.go:382
    ("knowledge search", "offset", Empty::Error), // knowledge.go:391
    ("knowledge search", "format", Empty::Absent), // knowledge.go:413
    ("knowledge facts", "vertical", Empty::Absent), // knowledge.go:559
    ("knowledge facts", "technology", Empty::Absent), // knowledge.go:562
    ("knowledge facts", "status", Empty::Absent), // knowledge.go:565
    ("knowledge facts", "limit", Empty::Error),  // knowledge.go:517
    ("knowledge facts", "offset", Empty::Error), // knowledge.go:526
    ("knowledge facts", "format", Empty::Absent), // knowledge.go:545
    ("knowledge procedures", "vertical", Empty::Absent), // knowledge.go:677
    ("knowledge procedures", "technology", Empty::Absent), // knowledge.go:680
    ("knowledge procedures", "type", Empty::Absent), // knowledge.go:683
    ("knowledge procedures", "control", Empty::Absent), // knowledge.go:687
    ("knowledge procedures", "limit", Empty::Error), // knowledge.go:635
    ("knowledge procedures", "offset", Empty::Error), // knowledge.go:645
    ("knowledge procedures", "format", Empty::Absent), // knowledge.go:663
    ("knowledge patterns", "vertical", Empty::Absent), // knowledge.go:852
    ("knowledge patterns", "type", Empty::Absent), // knowledge.go:855
    ("knowledge patterns", "min-occurrences", Empty::Error), // knowledge.go:800
    ("knowledge patterns", "limit", Empty::Error), // knowledge.go:810
    ("knowledge patterns", "offset", Empty::Error), // knowledge.go:820
    ("knowledge patterns", "format", Empty::Absent), // knowledge.go:838
    // knowledge.go:959 stores --format and only compares it to "json".
    ("knowledge relationships", "format", Empty::Absent),
    ("knowledge graph", "depth", Empty::Error), // knowledge.go:1037
    // knowledge.go:1045: a bare TrimPrefix, no parse, no guard — `min_strength=`
    // really is what goes on the wire (foresight validates the same flag;
    // graph does not, and that inconsistency is rvl-cli's, not ours).
    ("knowledge graph", "min-strength", Empty::Value),
    ("knowledge graph", "type", Empty::Absent), // knowledge.go:1057
    ("knowledge foresight", "entity-type", Empty::Error), // knowledge.go:1142
    ("knowledge foresight", "entity-id", Empty::Error), // knowledge.go:1142
    ("knowledge foresight", "depth", Empty::Error), // knowledge.go:1117
    ("knowledge foresight", "min-strength", Empty::Error), // knowledge.go:1125
    ("knowledge foresight", "relation-types", Empty::Absent), // knowledge.go:1158
    ("knowledge foresight", "format", Empty::Absent), // knowledge.go:1175
    ("knowledge graph-search", "limit", Empty::Error), // knowledge.go:1258
    ("knowledge graph-search", "depth", Empty::Error), // knowledge.go:1266
    ("knowledge graph-search", "types", Empty::Absent), // knowledge.go:1296
    // knowledge.go:1354/1360/1409: `--vertical=` wipes the "fault-tolerance"
    // default and is interpolated into the patterns/procedures URLs unguarded.
    ("knowledge enrich", "vertical", Empty::Value),
    ("knowledge enrich", "control", Empty::Absent), // knowledge.go:1427
    ("knowledge enrich", "technology", Empty::Absent), // knowledge.go:1460
    ("knowledge enrich", "query", Empty::Absent),   // knowledge.go:1482
    ("knowledge enrich", "limit", Empty::Error),    // knowledge.go:1369
    ("knowledge health", "format", Empty::Absent),
    // ---------------- evidence (internal/commands/evidence.go) ----------------
    ("evidence submit", "control", Empty::Error), // evidence.go:142 required
    ("evidence submit", "type", Empty::Error),    // evidence.go:146 required
    ("evidence submit", "name", Empty::Error),    // evidence.go:150 required
    // evidence.go:197/198: both keys are ALWAYS in the POST body, so an
    // empty value is transmitted rather than dropped.
    ("evidence submit", "url", Empty::Value),
    ("evidence submit", "description", Empty::Value),
    // evidence.go:136: an empty --git-hash re-runs `git rev-parse HEAD`,
    // exactly as omitting it does.
    ("evidence submit", "git-hash", Empty::Absent),
    ("evidence submit", "format", Empty::Absent), // evidence.go:129 guarded
    ("evidence submit", "team", Empty::Absent),   // rvl-native scope
    ("evidence submit", "service", Empty::Absent), // rvl-native scope
    ("evidence list", "control", Empty::Absent),  // evidence.go:304
    ("evidence list", "type", Empty::Absent),     // evidence.go:298
    // evidence.go:283 guards the enum check AND the query param.
    ("evidence list", "status", Empty::Absent),
    ("evidence list", "team", Empty::Absent), // rvl-native filter
    ("evidence list", "service", Empty::Absent), // rvl-native filter
    ("evidence list", "scope-state", Empty::Absent), // rvl-native filter
    ("evidence list", "limit", Empty::Error), // evidence.go:258
    ("evidence list", "format", Empty::Absent), // evidence.go:276
    ("evidence verify", "format", Empty::Absent), // evidence.go:381
    // ---------------- feedback / bugreport (feedback.go) ----------------
    // feedback.go:195 requires a non-blank message; :198 rejects a category
    // outside {feedback,bug}; :201 validates --format UNGUARDED; :174 rejects
    // any --attach-diagnostics value that is not true/false.
    ("feedback", "message", Empty::Error),
    ("feedback", "category", Empty::Error),
    ("feedback", "format", Empty::Error),
    ("feedback", "attach-diagnostics", Empty::Error),
    ("bugreport", "message", Empty::Error),
    ("bugreport", "category", Empty::Error),
    ("bugreport", "format", Empty::Error),
    ("bugreport", "attach-diagnostics", Empty::Error),
    // ---------------- stpa (internal/commands/stpa.go) ----------------
    ("stpa submit", "file", Empty::Error), // stpa.go:152 required
    // stpa.go:194: an empty --service prints the same "[skip]" notice as
    // omitting it.
    ("stpa submit", "service", Empty::Absent),
    // list-ucas, un-retired by po-av01j.202. All three string filters are
    // guarded before they reach the query or the client-side filter, so an
    // empty value is the flag not being given:
    //   stpa.go:540 `if source != ""`
    //   stpa.go:543 `if ucaType != ""`
    //   stpa.go:562 `if controlCode != ""`
    ("stpa list-ucas", "source", Empty::Absent),
    ("stpa list-ucas", "uca-type", Empty::Absent),
    ("stpa list-ucas", "control-code", Empty::Absent),
    // stpa.go:524-530 Atoi("") fails and exits 2 BEFORE any network call
    // (po-cj4s7), which clap's typed range parse reproduces.
    ("stpa list-ucas", "limit", Empty::Error),
];

/// Normalize THIS binary's own commands (the ones whose flags are consumed in
/// `main.rs` rather than in `rvl-data`). The ported rvl-cli commands are
/// normalized at their own dispatch sites, where the Go line that decides the
/// rule can be quoted next to the field.
///
/// Only [`Empty::Absent`] rows appear here: `Empty::Error` is produced by
/// clap's typed parse or by a validator that must SEE the empty string, and
/// `Empty::Value` means leaving it alone is the whole point.
pub fn normalize(cmd: &mut crate::Cmd) {
    use crate::{Cmd, IndexCmd, PluginCmd};
    match cmd {
        Cmd::Scan {
            retrieved,
            specs_file,
            judgments,
            out,
            color,
            hook,
            base,
            service,
            team,
            target,
            file,
            scan_dir,
            timeout,
            format,
            ..
        } => {
            // Only the three rvl-cli-parity paths can be empty at all (they
            // use `path_allowing_empty`); the rest are rejected by clap.
            let _ = (&retrieved, &specs_file, &judgments, &out);
            for p in [target, file, scan_dir] {
                absent_path(p);
            }
            for s in [color, hook, base, service, team, timeout, format] {
                absent_str(s);
            }
        }
        Cmd::Explain { color, .. } => absent_str(color),
        Cmd::Suppress {
            reason, expires, ..
        } => {
            // `--expires=` MUST stay open-ended: absent is how a waiver with
            // no expiry is written, and `waiver::expiry_active` reads it as
            // never-expiring.
            for s in [reason, expires] {
                absent_str(s);
            }
        }
        Cmd::Index {
            cmd: IndexCmd::Reindex { files, .. },
        } => absent_str(files),
        // `plugin agents --editor=` is Empty::Value and is deliberately NOT
        // normalized; only --format is.
        Cmd::Plugin {
            cmd: PluginCmd::Agents { format, .. },
        } => absent_str(format),
        Cmd::Init { project, .. } => absent_str(project),
        Cmd::Doctor { format, .. } => absent_str(format),
        _ => {}
    }
}

/// clap's built-in `PathBuf` parser rejects an EMPTY value outright ("a
/// value is required ... but none was supplied", exit 2) in both spellings.
/// That is fine for this binary's own path flags, but rvl-cli's
/// `scan --target=` / `--scan-dir=` are plain `TrimPrefix` reads guarded with
/// `!= ""` (scan.go:462/464, :520/:557), i.e. an empty value means "not
/// given". This parser accepts the empty path so those three flags can be
/// normalized to absent like every other guarded rvl-cli string flag.
pub fn path_allowing_empty(s: &str) -> Result<std::path::PathBuf, std::convert::Infallible> {
    Ok(std::path::PathBuf::from(s))
}

fn absent_str(v: &mut Option<String>) {
    if v.as_deref() == Some("") {
        *v = None;
    }
}

fn absent_path(v: &mut Option<std::path::PathBuf>) {
    if v.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
        *v = None;
    }
}

/// Flags whose row is keyed by a DIFFERENT path than clap reports, because
/// the same `Args` struct is shared by several subcommands. None today; the
/// walker keeps working if that changes.
#[cfg(test)]
fn lookup(path: &str, flag: &str) -> Option<Empty> {
    SEMANTICS
        .iter()
        .find(|(p, f, _)| *p == path && *f == flag)
        .map(|(_, _, e)| *e)
}

/// Every (path, flag) pair clap knows about that takes a value.
#[cfg(test)]
pub fn value_flags(root: &clap::Command) -> Vec<(String, String)> {
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
fn walk(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
    for a in cmd.get_arguments() {
        let Some(long) = a.get_long() else { continue };
        if long == "help" || long == "version" {
            continue;
        }
        if !a.get_action().takes_values() {
            continue;
        }
        out.push((path.to_string(), long.to_string()));
    }
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        let child = if path.is_empty() {
            sub.get_name().to_string()
        } else {
            format!("{path} {}", sub.get_name())
        };
        walk(sub, &child, out);
    }
}

/// Fails with the list of flags that have no declared empty-value semantics.
/// Wired into a test so a new flag cannot silently inherit the wrong
/// behaviour: adding `--foo` to any subcommand fails the suite until its row
/// is written down here.
#[cfg(test)]
pub fn audit_against(root: &clap::Command) -> Result<(), Vec<String>> {
    let mut missing = Vec::new();
    for (path, flag) in value_flags(root) {
        if lookup(&path, &flag).is_none() {
            missing.push(format!("{path} --{flag}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

/// The reverse check: a row for a flag clap no longer has is a stale claim
/// about parity, so it fails too.
#[cfg(test)]
pub fn stale_rows(root: &clap::Command) -> Vec<String> {
    let live = value_flags(root);
    SEMANTICS
        .iter()
        .filter(|(p, f, _)| !live.iter().any(|(lp, lf)| lp == p && lf.as_str() == *f))
        .map(|(p, f, _)| format!("{p} --{f}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Cmd};
    use clap::{CommandFactory, Parser};

    /// THE GUARD AGAINST THIS CLASS COMING BACK (po-av01j.192): every
    /// value-taking long flag in the whole command tree must have a declared
    /// empty-value rule. Adding `--foo` to any subcommand fails this test
    /// until its author reads the matching rvl-cli parser and writes the row
    /// down — a new flag can no longer inherit somebody else's semantics by
    /// accident, which is exactly how the argv-level strip over-applied.
    #[test]
    fn every_value_flag_declares_what_an_empty_value_means() {
        if let Err(missing) = audit_against(&Cli::command()) {
            panic!(
                "{} flag(s) have no empty-value semantics declared in \
                 empty_flag::SEMANTICS. For each one, read the rvl-cli parser \
                 (internal/commands/*.go) and add a row: Absent if the Go code \
                 guards `if v != \"\"`, Error if it Atoi/validates the raw \
                 value, Value if it puts the value on the wire unguarded.\n  {}",
                missing.len(),
                missing.join("\n  ")
            );
        }
    }

    /// The other direction: a row for a flag that no longer exists is a stale
    /// parity claim, so it fails too.
    #[test]
    fn no_semantics_row_describes_a_flag_that_is_gone() {
        assert_eq!(stale_rows(&Cli::command()), Vec::<String>::new());
    }

    /// The two empty spellings must agree AT PARSE TIME for every flag clap
    /// accepts in both forms. rvl-cli's `FlagValue` returns "" for `--x=` and
    /// for `--x ''` alike, so any disagreement here is a divergence by
    /// construction. `require_equals` flags are excluded because they refuse
    /// the space form outright, in both CLIs (rvl-cli's
    /// `--attach-diagnostics ''` leaves the `''` orphaned and exits 2 as an
    /// unknown flag; clap rejects it as an unexpected argument — same code,
    /// same class).
    #[test]
    fn the_two_empty_spellings_agree_for_every_declared_flag() {
        let root = Cli::command();
        for (path, flag, _) in SEMANTICS {
            if requires_equals(&root, path, flag) {
                continue;
            }
            let mut argv: Vec<String> = std::iter::once("rvl".to_string())
                .chain(path.split(' ').map(String::from))
                .chain(sample_positionals(&root, path))
                .collect();
            argv.push(format!("--{flag}="));
            let equals = Cli::try_parse_from(&argv).is_err();
            argv.pop();
            argv.push(format!("--{flag}"));
            argv.push(String::new());
            let space = Cli::try_parse_from(&argv).is_err();
            assert_eq!(
                equals, space,
                "{path} --{flag}: `--{flag}=` and `--{flag} \'\'` disagree at parse time"
            );
        }
    }

    /// Every flag declared `Empty::Error` must actually reject an empty
    /// value — either in clap's typed parse (numeric flags, empty paths) or
    /// in a validator downstream. The parse-time half is asserted here; the
    /// validator-backed half is asserted end-to-end, against the real binary
    /// and a stub server, in `tests/empty_flag_parity.rs`.
    #[test]
    fn every_typed_error_flag_is_rejected_at_parse_time() {
        let root = Cli::command();
        for (path, flag, kind) in SEMANTICS {
            if *kind != Empty::Error || !typed_at_parse_time(&root, path, flag) {
                continue;
            }
            let mut argv: Vec<String> = std::iter::once("rvl".to_string())
                .chain(path.split(' ').map(String::from))
                .chain(sample_positionals(&root, path))
                .collect();
            argv.push(format!("--{flag}="));
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{path} --{flag}= must be a usage error (rvl-cli exits 2)"
            );
        }
    }

    /// The other half, and the half whose absence let a wrong row survive
    /// three audits: an `Absent`/`Value` row CLAIMS the parser accepts an
    /// empty value, and until now nothing checked that claim.
    ///
    /// `("scan", "cs-file", Empty::Absent)` was wrong for exactly this
    /// reason — clap's stock `PathBuf` parser rejected an empty path, so both
    /// spellings exited 2 while the table said the flag was absent. The row
    /// was read off the right Go guard (scan.go:667) and was still wrong
    /// about our own binary, which is what a fixture can drift into when it
    /// is only ever checked in one direction.
    ///
    /// Both spellings, because they diverged: rvl-cli's hand-rolled parsers
    /// accept `--flag=` and `--flag ''` down different code paths.
    #[test]
    fn every_non_error_flag_accepts_an_empty_value() {
        let root = Cli::command();
        for (path, flag, kind) in SEMANTICS {
            if *kind == Empty::Error {
                continue;
            }
            let base: Vec<String> = std::iter::once("rvl".to_string())
                .chain(path.split(' ').map(String::from))
                .chain(sample_positionals(&root, path))
                .collect();

            let mut equals = base.clone();
            equals.push(format!("--{flag}="));
            assert!(
                Cli::try_parse_from(&equals).is_ok(),
                "{path} --{flag}= is declared {kind:?}, so the parser must ACCEPT it \
                 and leave the decision to the consumer — it was rejected instead"
            );

            let mut spaced = base;
            spaced.push(format!("--{flag}"));
            spaced.push(String::new());
            assert!(
                Cli::try_parse_from(&spaced).is_ok(),
                "{path} --{flag} '' is declared {kind:?}, so the parser must ACCEPT it \
                 — it was rejected instead (the two spellings must not diverge)"
            );
        }
    }

    /// Flags whose EMPTY rejection comes from clap itself: anything that is
    /// not parsed as a plain string (numbers, paths).
    fn typed_at_parse_time(root: &clap::Command, path: &str, flag: &str) -> bool {
        arg(root, path, flag).is_some_and(|a| {
            let vn = a.get_value_names().map(|n| n.first().map(|v| v.as_str()));
            !matches!(vn, Some(Some("BOOL")))
                && a.get_value_parser().type_id() != std::any::TypeId::of::<String>()
        })
    }

    fn requires_equals(root: &clap::Command, path: &str, flag: &str) -> bool {
        arg(root, path, flag).is_some_and(clap::Arg::is_require_equals_set)
    }

    /// Walk a space-separated subcommand path to its `clap::Command`.
    fn resolve<'a>(root: &'a clap::Command, path: &str) -> Option<&'a clap::Command> {
        let mut cmd = root;
        for seg in path.split(' ').filter(|s| !s.is_empty()) {
            cmd = cmd.get_subcommands().find(|c| c.get_name() == seg)?;
        }
        Some(cmd)
    }

    fn arg<'a>(root: &'a clap::Command, path: &str, flag: &str) -> Option<&'a clap::Arg> {
        resolve(root, path)?
            .get_arguments()
            .find(|a| a.get_long() == Some(flag))
    }

    /// `risk list --limit=` must NOT quietly become the default (regression
    /// (a) of po-av01j.192): rvl-cli exits 2 on Atoi("").
    #[test]
    fn empty_limit_is_rejected_rather_than_defaulted() {
        assert!(Cli::try_parse_from(["rvl", "risk", "list", "--limit="]).is_err());
        assert!(Cli::try_parse_from(["rvl", "risk", "list", "--limit", ""]).is_err());
        // A real value still parses, and the default still applies when the
        // flag is absent.
        assert!(Cli::try_parse_from(["rvl", "risk", "list", "--limit=5"]).is_ok());
        assert!(Cli::try_parse_from(["rvl", "risk", "list"]).is_ok());
    }

    /// A MISSPELLED flag written with a trailing `=` must still be a usage
    /// error (regression (b)): the argv strip disabled unknown-flag detection
    /// for the entire `--x=` shape, so `risk list --serivce=` exited 0.
    #[test]
    fn a_typo_with_a_trailing_equals_is_still_an_unknown_flag() {
        for argv in [
            vec!["rvl", "risk", "list", "--serivce="],
            vec!["rvl", "risk", "list", "--serivce", ""],
            vec!["rvl", "evidence", "list", "--contorl="],
            vec!["rvl", "knowledge", "facts", "--verticl="],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_err(),
                "{argv:?} must be a usage error"
            );
        }
    }

    /// `--reason=` carries the empty string (regression (c)): rvl-cli POSTs
    /// {"reason":""}, so the parsed value must stay `Some("")` and never be
    /// replaced by the "Resolved" default.
    #[test]
    fn an_empty_reason_survives_parsing_as_an_empty_value() {
        for argv in [
            vec!["rvl", "risk", "resolve", "R-1", "--reason="],
            vec!["rvl", "risk", "resolve", "R-1", "--reason", ""],
        ] {
            let cli = Cli::try_parse_from(&argv).expect("parses");
            let Some(Cmd::Risk {
                cmd: rvl_data::risk::RiskCmd::Resolve { reason, .. },
            }) = cli.cmd
            else {
                panic!("{argv:?} did not parse as risk resolve")
            };
            assert_eq!(reason.as_deref(), Some(""), "{argv:?}");
        }
    }

    /// `suppress --expires=` stays OPEN-ENDED: normalized to absent, which is
    /// how a waiver with no expiry is written and what `waiver::expiry_active`
    /// reads as never-expiring. A real date is untouched.
    #[test]
    fn an_empty_expires_is_open_ended_and_a_real_one_is_kept() {
        for argv in [
            vec!["rvl", "suppress", "2ben", "--expires="],
            vec!["rvl", "suppress", "2ben", "--expires", ""],
        ] {
            let mut cmd = Cli::try_parse_from(&argv).expect("parses").cmd.unwrap();
            normalize(&mut cmd);
            let Cmd::Suppress { expires, .. } = cmd else {
                panic!("not suppress")
            };
            assert_eq!(expires, None, "{argv:?} must be open-ended");
        }
        let mut cmd = Cli::try_parse_from(["rvl", "suppress", "2ben", "--expires=2027-01-01"])
            .expect("parses")
            .cmd
            .unwrap();
        normalize(&mut cmd);
        let Cmd::Suppress { expires, .. } = cmd else {
            panic!("not suppress")
        };
        assert_eq!(expires.as_deref(), Some("2027-01-01"));
    }

    /// The two spellings must be indistinguishable AFTER normalization, for
    /// every flag this binary normalizes itself. `--flag=` and `--flag ''`
    /// are the same thing to rvl-cli's FlagValue, so any difference here is a
    /// divergence by construction.
    #[test]
    fn the_two_empty_spellings_normalize_to_the_same_thing() {
        let root = Cli::command();
        for (path, flag, _) in SEMANTICS.iter().filter(|(p, _, _)| {
            // The rvl-native commands normalized by `normalize`.
            matches!(
                *p,
                "scan" | "report" | "explain" | "suppress" | "init" | "doctor"
            )
        }) {
            let base: Vec<String> = std::iter::once("rvl".to_string())
                .chain(path.split(' ').map(String::from))
                .chain(sample_positionals(&root, path))
                .collect();
            let mut eq = base.clone();
            eq.push(format!("--{flag}="));
            let mut sp = base.clone();
            sp.push(format!("--{flag}"));
            sp.push(String::new());
            let (a, b) = (Cli::try_parse_from(&eq), Cli::try_parse_from(&sp));
            let (Ok(a), Ok(b)) = (a, b) else {
                // Rejected in both spellings (an empty path) — already
                // identical, and asserted by the parse-agreement test above.
                assert!(
                    Cli::try_parse_from(&eq).is_err() && Cli::try_parse_from(&sp).is_err(),
                    "{path} --{flag}: one spelling failed to parse"
                );
                continue;
            };
            let (mut a, mut b) = (a.cmd.unwrap(), b.cmd.unwrap());
            normalize(&mut a);
            normalize(&mut b);
            assert_eq!(
                render(&a),
                render(&b),
                "{path} --{flag}: `--{flag}=` and `--{flag} ''` differ"
            );
        }
    }

    /// Placeholder values for a subcommand's REQUIRED positionals, derived
    /// from the clap tree rather than hardcoded.
    ///
    /// This used to be a two-entry `match` covering `explain` and `suppress`,
    /// which quietly weakened every test that used it: a command with an
    /// unsatisfied positional fails to parse for that reason, so
    /// `every_typed_error_flag_is_rejected_at_parse_time` could pass on a
    /// `MissingRequiredArgument` without the empty value ever being judged.
    /// Deriving them means a new subcommand with a positional is handled the
    /// day it lands instead of silently hollowing out the assertions.
    fn sample_positionals(root: &clap::Command, path: &str) -> Vec<String> {
        let Some(cmd) = resolve(root, path) else {
            return Vec::new();
        };
        cmd.get_positionals()
            .filter(|p| p.is_required_set())
            .map(|p| {
                // Values that satisfy the typed parsers we actually use for
                // positionals; anything else takes a harmless string.
                match p
                    .get_value_names()
                    .and_then(|n| n.first())
                    .map(|v| v.as_str())
                {
                    Some("ENTITY_TYPE") => "fact".to_string(),
                    _ => "x".to_string(),
                }
            })
            .collect()
    }

    /// Debug rendering is enough to compare two parses of the same command.
    fn render(cmd: &Cmd) -> String {
        match cmd {
            Cmd::Scan {
                retrieved,
                specs_file,
                judgments,
                out,
                color,
                hook,
                base,
                service,
                team,
                target,
                file,
                scan_dir,
                timeout,
                format,
                ..
            } => format!(
                "{retrieved:?}{specs_file:?}{judgments:?}{out:?}{color:?}{hook:?}{base:?}\
                 {service:?}{team:?}{target:?}{file:?}{scan_dir:?}{timeout:?}{format:?}"
            ),
            Cmd::Report {
                retrieved,
                specs_file,
                out,
                ..
            } => format!("{retrieved:?}{specs_file:?}{out:?}"),
            Cmd::Explain {
                retrieved,
                specs_file,
                judgments,
                color,
                ..
            } => format!("{retrieved:?}{specs_file:?}{judgments:?}{color:?}"),
            Cmd::Suppress {
                retrieved,
                specs_file,
                judgments,
                reason,
                expires,
                ..
            } => format!("{retrieved:?}{specs_file:?}{judgments:?}{reason:?}{expires:?}"),
            Cmd::Init { project, .. } => format!("{project:?}"),
            Cmd::Doctor { format, .. } => format!("{format:?}"),
            _ => String::new(),
        }
    }
}
