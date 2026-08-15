//! `rvl doctor [--fix]` — diagnose (and where it is safe, repair) this
//! machine's ability to scan THIS repository (po-av01j.169).
//!
//! po-aml3h removed most first-run friction: the scripted retrievers ride
//! inside the binary, cindex/rustindex/goindex ride the release archive, and a
//! hand-built helper is found at the canonical dir with no env var. Two manual
//! steps survive BY DESIGN, and both are exactly what a doctor should own:
//!
//!   * csindex needs a .NET 8 SDK and one `dotnet build` — we deliberately do
//!     not bundle ~9 MB of Roslyn for every target.
//!   * tsindex needs a COMPATIBLE `typescript`. npm's `typescript` now
//!     resolves to 7.x, the native port with no `ts.sys` and no
//!     `createProgram`, which crashes mid-run. The pin is `^5.9.3` and the pin
//!     is load-bearing, not incidental.
//!
//! Two properties this file exists to keep:
//!
//! REPO-AWARE. The languages reported are the ones [`detect_languages`]
//! finds — the SAME function the scan uses, not a second detector that would
//! drift. A Go shop is never told about .NET.
//!
//! THE SAME HONESTY DISCIPLINE AS THE SCAN ROLL-CALL. Per lane it names which
//! helper resolved and FROM WHICH SLOT (`env:` / `bundled` / `embedded` /
//! `installed` / `PATH`), plus whether the runtime that helper drives exists.
//! A stale helper shadowing the shipped one via PATH is undiagnosable from any
//! other output this binary produces, and it is diagnosable here.
//!
//! `--fix` performs only repairs that are safe, idempotent, and local:
//! extracting the embedded helpers, npm-installing the PINNED typescript into
//! the helper dir, building csindex when a .NET SDK and the project source are
//! both already present, and refreshing the spec cache when credentials are
//! already configured. Anything needing a system package manager or sudo is
//! PRINTED, never run. Every action is announced before it runs, and a second
//! `--fix` on a healthy machine performs none of them.

use crate::embedded_helpers;
use crate::hook;
use crate::hook::Status;
use crate::{
    detect_languages, detect_unsupported, embedded_for, find_on_path, language_is_incidental,
    missing_helper_hint, node_path_for, resolve_helper, Config, HelperKind, Lang,
};
use rvl_data::BIN;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// `doctor` found a gap this repository's scan would trip over.
///
/// Reuses the binary's existing contract rather than inventing a code: `1` is
/// already "the scan could not complete" (see the EXIT-CODE CONTRACT in
/// `main.rs`), and an unresolvable retriever for a language this repo contains
/// is precisely that condition, reported one step earlier. `2` stays the usage
/// error (an unknown `--format`), and `0` means everything THIS repo needs is
/// satisfied. WARN never changes the code: a warning is a thing worth knowing,
/// not a thing that stops a scan.
const EXIT_GAP: u8 = 1;

/// The `typescript` requirement tsindex enforces, read out of the helper this
/// binary CARRIES rather than restated here.
///
/// The pin lives in `helpers/tsindex/tsindex.js` as `const TS_REQUIREMENT`,
/// and a second copy in Rust would be a second thing to update: the day the
/// helper moves to `^6` and this file does not, `--fix` installs a compiler
/// the helper then rejects, which is worse than not fixing at all. Parsing it
/// out is three lines and cannot drift.
fn ts_requirement() -> String {
    parse_ts_requirement(embedded_helpers::TSINDEX.contents).unwrap_or_else(|| "^5.9.3".to_string())
}

fn parse_ts_requirement(src: &str) -> Option<String> {
    let rest = src.split("TS_REQUIREMENT").nth(1)?;
    let rest = rest.split_once('\'')?.1;
    let (req, _) = rest.split_once('\'')?;
    (!req.is_empty()).then(|| req.to_string())
}

/// One reported line, plus the command that would close it.
struct Check {
    section: &'static str,
    status: Status,
    label: String,
    detail: String,
    /// The exact command a reader should run. `None` when nothing is wrong or
    /// nothing can be done from here.
    remedy: Option<String>,
    /// Whether `--fix` is allowed to run [`Check::remedy`] itself. False for
    /// anything needing a package manager, sudo, or a decision.
    fixable: bool,
}

impl Check {
    fn new(section: &'static str, status: Status, label: impl Into<String>) -> Self {
        Check {
            section,
            status,
            label: label.into(),
            detail: String::new(),
            remedy: None,
            fixable: false,
        }
    }
    fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }
    fn remedy(mut self, r: impl Into<String>) -> Self {
        self.remedy = Some(r.into());
        self
    }
    fn fixable(mut self) -> Self {
        self.fixable = true;
        self
    }
}

pub struct DoctorArgs {
    pub path: Option<PathBuf>,
    pub fix: bool,
    pub format: Option<String>,
}

pub fn run(args: DoctorArgs) -> ExitCode {
    let json = match args.format.as_deref() {
        None | Some("text") => false,
        Some("json") => true,
        Some(other) => {
            eprintln!("error: unknown --format {other:?} (expected text or json)");
            return ExitCode::from(2);
        }
    };
    let root = args.path.unwrap_or_else(|| PathBuf::from("."));

    // --fix runs FIRST and announces itself, so the report that follows
    // describes the machine as it now is rather than as it was. A doctor that
    // printed a gap it had just closed would teach the reader to distrust it.
    if args.fix {
        if json {
            eprintln!("note: --fix narrates its actions on stderr; stdout stays JSON");
        }
        apply_fixes(&root);
        eprintln!();
    }

    let checks = collect(&root);
    let worst = checks
        .iter()
        .map(|c| c.status)
        .max()
        .unwrap_or(Status::Pass);
    if json {
        print!("{}", render_json(&root, &checks, worst));
    } else {
        print!("{}", render_text(&root, &checks, worst, args.fix));
    }
    if worst == Status::Fail {
        ExitCode::from(EXIT_GAP)
    } else {
        ExitCode::SUCCESS
    }
}

// --- the checks ---

fn collect(root: &Path) -> Vec<Check> {
    let mut out = Vec::new();
    let langs = detect_languages(root);
    out.extend(repo_checks(root, &langs));
    out.extend(retriever_checks(root, &langs));
    out.extend(config_checks());
    out.extend(spec_cache_checks());
    out.extend(hook_checks(root));
    out
}

fn repo_checks(root: &Path, langs: &[Lang]) -> Vec<Check> {
    let mut out = Vec::new();
    if langs.is_empty() {
        // Not an error, and the scan agrees: a pure-infrastructure repo has no
        // source any retriever reads, and the config/secret/structure lanes
        // read the tree directly (po-av01j.148).
        out.push(Check::new("repo", Status::Pass, "languages").detail(
            "none detected; the config, secret and structure lanes read the tree directly",
        ));
    } else {
        let names: Vec<String> = langs.iter().map(|l| l.to_string()).collect();
        out.push(Check::new("repo", Status::Pass, "languages").detail(names.join(", ")));
    }
    let unsupported = detect_unsupported(root);
    if !unsupported.is_empty() {
        // Reported, and deliberately only a WARN with no remedy: nothing the
        // reader can install makes these readable today. Staying silent about
        // them is the failure mode (po-av01j.128) — silence is
        // indistinguishable from "scanned and clean".
        let list: Vec<String> = unsupported
            .iter()
            .map(|(n, c)| format!("{n} ({c} files)"))
            .collect();
        out.push(
            Check::new("repo", Status::Warn, "no retriever exists").detail(format!(
                "{} — these lanes cannot be read by any version of {BIN} yet",
                list.join(", ")
            )),
        );
    }
    out
}

/// The interpreter a resolved helper is driven by, when it needs one. A native
/// helper (goindex, cindex, rustindex) needs nothing.
fn runtime_for(kind: HelperKind) -> Option<&'static str> {
    match kind {
        HelperKind::Executable => None,
        HelperKind::PyScript => Some("python3"),
        HelperKind::NodeScript => Some("node"),
        HelperKind::DotnetAssembly => Some("dotnet"),
        HelperKind::JavaSource => Some("java"),
    }
}

fn retriever_checks(root: &Path, langs: &[Lang]) -> Vec<Check> {
    let mut out = Vec::new();
    for &lang in langs {
        // A language present only as a fixture or testdata must not be
        // reported as a hard gap: the scan itself degrades that lane rather
        // than failing (po-hjte8), so the doctor must agree or it would send
        // someone to install a .NET SDK for one vendored sample.
        let incidental = language_is_incidental(root, lang);
        let gap = if incidental {
            Status::Warn
        } else {
            Status::Fail
        };
        let label = format!("{lang} ({})", lang.helper_base());
        match resolve_helper(lang) {
            Err(e) => {
                // The resolver's error ENDS in the install hint, and the hint
                // is about to be printed on its own `fix:` line. Printing it
                // twice in one row is how a reader learns to skim past the
                // line that mattered, so it is stripped from the detail and
                // whatever else the error said (an extraction failure, say)
                // is kept.
                let hint = missing_helper_hint(lang);
                let why = format!("{e:#}")
                    .replace(&hint, "")
                    .trim_end_matches([':', ' '])
                    .to_string();
                let mut c = Check::new("retrievers", gap, label)
                    .detail(if incidental {
                        format!("{why}; this repo carries {lang} only as non-production material, so the scan degrades this lane instead of failing")
                    } else {
                        why
                    })
                    .remedy(hint);
                if lang == Lang::CSharp && find_on_path("dotnet").is_some() {
                    if let Some(proj) = csindex_project_dir() {
                        c = c.remedy(csindex_build_command(&proj)).fixable();
                    }
                }
                out.push(c);
            }
            Ok(h) => {
                // THE SLOT IS THE POINT. "goindex resolved" is not a useful
                // sentence; "goindex resolved from PATH when a bundled one
                // exists" is the whole diagnosis.
                let where_from = format!("{} ({})", h.path.display(), h.source);
                match runtime_for(h.kind) {
                    None => out.push(
                        Check::new("retrievers", Status::Pass, label)
                            .detail(format!("{where_from}, native — no runtime prereq")),
                    ),
                    Some(rt) if find_on_path(rt).is_none() => out.push(
                        Check::new("retrievers", gap, label)
                            .detail(format!(
                                "{where_from}, but `{rt}` is not installed, so this lane cannot run"
                            ))
                            .remedy(format!(
                                "install {rt} with your system package manager, then re-run `{BIN} doctor`"
                            )),
                    ),
                    Some(rt) => {
                        out.push(
                            Check::new("retrievers", Status::Pass, label)
                                .detail(format!("{where_from}, runs under `{rt}`")),
                        );
                        if lang == Lang::TypeScript {
                            out.push(typescript_compiler_check(root, gap));
                        }
                    }
                }
            }
        }
    }
    out
}

/// tsindex drives the real TypeScript compiler API, so `node` being present is
/// only half the prerequisite. Probed by CAPABILITY, exactly as the helper
/// itself probes it: npm's `typescript` now resolves to the 7.x native port,
/// which has neither `ts.sys` nor `createProgram` and whose version string
/// gives no reliable signal.
fn typescript_compiler_check(root: &Path, gap: Status) -> Check {
    let label = "TypeScript compiler (typescript)";
    let Some(helper_dir) = embedded_helpers::cache_root() else {
        return Check::new("retrievers", Status::Warn, label)
            .detail("no writable helper dir, so the compiler could not be probed");
    };
    let req = ts_requirement();
    let install = format!(
        "npm install --no-audit --no-fund --prefix {} \"typescript@{req}\"",
        helper_dir.display()
    );
    let probe = Command::new("node")
        .arg("-e")
        .arg(TS_PROBE)
        .current_dir(&helper_dir)
        .env("NODE_PATH", node_path_for(root))
        .output();
    match probe {
        Err(_) => Check::new("retrievers", gap, label)
            .detail("`node` could not be run to probe the compiler")
            .remedy("install node with your system package manager"),
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match o.status.code() {
                Some(0) => Check::new("retrievers", Status::Pass, label).detail(stdout),
                Some(4) => Check::new("retrievers", gap, label)
                    .detail(format!(
                        "found {stdout}, which does NOT expose the compiler API tsindex drives \
                         (npm's `typescript` now resolves to the native port)"
                    ))
                    .remedy(install)
                    .fixable(),
                _ => Check::new("retrievers", gap, label)
                    .detail(format!("not installed where node can find it (pin: {req})"))
                    .remedy(install)
                    .fixable(),
            }
        }
    }
}

/// The compiler probe, run with cwd at the helper dir and NODE_PATH pointed at
/// the scanned repo — the same resolution tsindex itself gets. Exit 4 mirrors
/// the helper's own HELPER_EXIT_PREREQ_MISSING for "present but wrong".
const TS_PROBE: &str =
    "let ts; try { ts = require('typescript'); } catch (e) { process.exit(3); }\n\
     if (!ts || typeof ts.createProgram !== 'function' || !ts.sys) {\n\
       console.log('typescript ' + ((ts && ts.version) || 'unknown'));\n\
       process.exit(4);\n\
     }\n\
     console.log('typescript ' + ts.version + ' at ' + require.resolve('typescript'));";

/// Config and credentials, read through `rvl-data` so this stays a VIEW of
/// what `status` reports rather than a second opinion about it. Network-free
/// on purpose: a doctor that hangs on a captive-portal DNS lookup is a doctor
/// nobody runs.
fn config_checks() -> Vec<Check> {
    let mut out = Vec::new();
    match rvl_data::config::load() {
        Err(e) => out.push(
            Check::new("config", Status::Fail, "config file")
                .detail(format!("could not be read: {e}"))
                .remedy(format!("run `{BIN} login`")),
        ),
        Ok(None) => out.push(
            Check::new("config", Status::Warn, "credentials")
                .detail("not configured; deterministic scans still run against the spec cache")
                .remedy(format!(
                    "run `{BIN} login`, or set RVL_API_KEY for headless/CI use"
                )),
        ),
        Ok(Some(cfg)) => {
            // The exact lines `status` prints, from `status`'s own formatter.
            for line in rvl_data::auth::status_header(&cfg, env!("CARGO_PKG_VERSION"))
                .lines()
                .skip(1)
            {
                let (label, detail) = line.split_once(": ").unwrap_or((line, ""));
                out.push(
                    Check::new("config", Status::Pass, label.to_string())
                        .detail(detail.to_string()),
                );
            }
            out.push(
                Check::new("config", Status::Pass, "connection")
                    .detail(format!("not probed here; run `{BIN} status` to check it")),
            );
        }
    }
    out
}

fn spec_cache_checks() -> Vec<Check> {
    let cfg = Config::from_env();
    let mut out = Vec::new();
    let store = match rvl_cache::CacheStore::open(&cfg.cache_dir) {
        Ok(s) => s,
        Err(e) => {
            return vec![Check::new("spec cache", Status::Fail, "store")
                .detail(format!("{}: {e}", cfg.cache_dir.display()))];
        }
    };
    let keyset = match rvl_cache::Keyset::from_hex(rvl_cache::DEV_KEYSET_HEX) {
        Ok(k) => k,
        Err(e) => {
            return vec![Check::new("spec cache", Status::Fail, "keyset").detail(format!("{e}"))];
        }
    };
    match store.load(&keyset, &rvl_cache::today_utc()) {
        Ok(loaded) => {
            out.push(
                Check::new("spec cache", Status::Pass, "installed").detail(format!(
                    "{} (schema {}, {:?})",
                    loaded.envelope.content_version, loaded.envelope.schema, loaded.source
                )),
            );
            if let Some(note) = loaded.staleness_note {
                out.push(
                    Check::new("spec cache", Status::Warn, "freshness")
                        .detail(note)
                        .remedy(format!("run `{BIN} sync`")),
                );
            }
        }
        Err(_) => out.push(
            // FAIL, not WARN: without a verifiable cache the deterministic
            // scan exits 1 rather than degrading. That is a gap in exactly the
            // sense this command's exit code reports.
            Check::new("spec cache", Status::Fail, "installed")
                .detail("no verifiable spec cache; a deterministic scan cannot run")
                .remedy(format!(
                    "run `{BIN} sync` (or `{BIN} cache import` for an air-gapped install)"
                )),
        ),
    }
    out
}

/// Delegated wholesale to `hook doctor` (po-av01j.163), which already answers
/// this question. Folding it in rather than reimplementing it is the point:
/// the day the hook shim's marker changes, one file changes.
fn hook_checks(root: &Path) -> Vec<Check> {
    let git_root = match hook::git_toplevel(root) {
        Ok(r) => r,
        Err(_) => {
            return vec![Check::new("hooks", Status::Warn, "git repository")
                .detail("not inside one, so there is nowhere to install a scan gate")];
        }
    };
    let path_env = std::env::var("PATH").unwrap_or_default();
    hook::doctor_checks(&git_root, &path_env)
        .into_iter()
        .map(|c| {
            // `hook doctor`'s details already END in the command to run
            // ("run `rvl hook install --pre-commit`"). Appending a generic
            // remedy under those would print the same instruction twice, so
            // one is added only where the detail carries none.
            let has_command = c.detail.contains("run `") || c.detail.contains("run rvl");
            let mut out = Check::new("hooks", c.status, c.label).detail(c.detail);
            if c.status != Status::Pass && !has_command {
                out = out.remedy(format!("run `{BIN} hook install` to wire the scan gate"));
            }
            out
        })
        .collect()
}

// --- --fix ---

/// Announce, then act. Never the other way round: a command that installs
/// software must say what it is about to install while the user can still
/// stop it.
fn announce(what: &str) {
    eprintln!("doctor --fix: {what}");
}

fn apply_fixes(root: &Path) {
    let langs = detect_languages(root);
    let cfg = Config::from_env();
    let mut acted = false;
    // RVLSCAN_OFFLINE is the binary's kill switch for reaching the network,
    // and it binds here too: an npm install and a spec-cache sync are both
    // fetches. An operator who set it meant it, so those two repairs are
    // PRINTED instead. Extraction and the csindex build are purely local and
    // still run.
    if cfg.offline {
        eprintln!("doctor --fix: RVLSCAN_OFFLINE=1, so no repair will reach the network");
    }

    // (1) Materialize the scripted retrievers this binary carries. `ensure` is
    // content-addressed, so this is a no-op on a healthy machine and a repair
    // on a truncated or hand-edited one.
    for &lang in &langs {
        let Some(emb) = embedded_for(lang) else {
            continue;
        };
        let already = embedded_helpers::cache_root()
            .map(|r| r.join(emb.file_name).is_file())
            .unwrap_or(false);
        match embedded_helpers::ensure(emb) {
            Ok(p) if !already => {
                announce(&format!("extracted {} to {}", emb.file_name, p.display()));
                acted = true;
            }
            Ok(_) => {}
            Err(e) => eprintln!("doctor --fix: could not extract {}: {e:#}", emb.file_name),
        }
    }

    // (2) The PINNED typescript, into the helper dir where tsindex looks. Only
    // when the lane is actually broken: re-running --fix must not reinstall a
    // working compiler.
    if langs.contains(&Lang::TypeScript) {
        let c = typescript_compiler_check(root, Status::Fail);
        if c.status != Status::Pass && c.fixable {
            if let Some(cmd) = &c.remedy {
                if cfg.offline {
                    eprintln!("doctor --fix: offline, so run this yourself when online:\n  {cmd}");
                } else if find_on_path("npm").is_some() {
                    announce(&format!("installing the pinned TypeScript compiler: {cmd}"));
                    run_shellless(cmd);
                    acted = true;
                } else {
                    eprintln!(
                        "doctor --fix: `npm` is not installed, so this must be run by hand:\n  {cmd}"
                    );
                }
            }
        }
    }

    // (3) csindex, but only when BOTH the SDK and the project source are
    // already here. We refuse to clone a repository or install an SDK on
    // someone's behalf; that is the "printed, never run" half of the contract.
    if langs.contains(&Lang::CSharp) && resolve_helper(Lang::CSharp).is_err() {
        match (find_on_path("dotnet"), csindex_project_dir()) {
            (Some(_), Some(proj)) => {
                let cmd = csindex_build_command(&proj);
                announce(&format!("building csindex (this takes a minute): {cmd}"));
                run_shellless(&cmd);
                acted = true;
            }
            (None, _) => eprintln!(
                "doctor --fix: no .NET SDK on PATH. Install .NET 8, then:\n  {}",
                missing_helper_hint(Lang::CSharp)
            ),
            (Some(_), None) => eprintln!(
                "doctor --fix: a .NET SDK is present but the csindex project is not on this \
                 machine, so the build cannot be run from here:\n  {}",
                missing_helper_hint(Lang::CSharp)
            ),
        }
    }

    // (4) The spec cache, ONLY when credentials are already configured. A
    // fetch is idempotent and needs no privileges, but inventing credentials
    // is not something a repair can do.
    if !cfg.offline && !cfg.org_key.is_empty() && !spec_cache_is_installed(&cfg) {
        announce("refreshing the spec cache from the Revelara API");
        let fetcher = rvl_cache::HttpFetcher {
            base_url: cfg.base_url.clone(),
            org_key: cfg.org_key.clone(),
        };
        if let (Ok(store), Ok(keyset)) = (
            rvl_cache::CacheStore::open(&cfg.cache_dir),
            rvl_cache::Keyset::from_hex(rvl_cache::DEV_KEYSET_HEX),
        ) {
            let outcome = rvl_cache::sync(&store, &fetcher, &keyset, cfg.offline);
            eprintln!("doctor --fix: spec cache: {outcome:?}");
        }
        acted = true;
    }

    if !acted {
        eprintln!("doctor --fix: nothing to repair.");
    }
}

fn spec_cache_is_installed(cfg: &Config) -> bool {
    let Ok(store) = rvl_cache::CacheStore::open(&cfg.cache_dir) else {
        return false;
    };
    let Ok(keyset) = rvl_cache::Keyset::from_hex(rvl_cache::DEV_KEYSET_HEX) else {
        return false;
    };
    store.load(&keyset, &rvl_cache::today_utc()).is_ok()
}

/// Run a remedy command WITHOUT a shell.
///
/// The commands here are ours and contain no shell syntax, and going through
/// `sh -c` would turn a path with a space in it — a home directory on macOS,
/// routinely — into a word-splitting bug. Quotes in the printed form are for
/// the human copying it; they are stripped here.
fn run_shellless(cmd: &str) {
    let parts: Vec<String> = cmd
        .split_whitespace()
        .map(|w| w.trim_matches('"').to_string())
        .collect();
    let Some((program, args)) = parts.split_first() else {
        return;
    };
    match Command::new(program).args(args).status() {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("doctor --fix: `{program}` exited {s}; the gap above remains"),
        Err(e) => eprintln!("doctor --fix: could not run `{program}`: {e}"),
    }
}

fn csindex_build_command(project: &Path) -> String {
    format!(
        "dotnet build {} -c Release -o {}",
        project.display(),
        csindex_install_dir().display()
    )
}

/// Where a built csindex must land: the canonical per-helper dir resolution
/// already searches, so the build IS the install (po-aml3h).
fn csindex_install_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(".revelara").join("helpers").join("csindex")
}

/// The csindex project on THIS machine, if it is here at all: a clone of the
/// rvl repository (running the doctor from inside one, or a source build
/// whose binary sits under the same tree). Returns `None` for the ordinary
/// `brew install` case, where the honest answer is to print the clone command.
fn csindex_project_dir() -> Option<PathBuf> {
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("RVLSCAN_SRC") {
        starts.push(PathBuf::from(dir));
    }
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(d) = exe.parent() {
            starts.push(d.to_path_buf());
        }
    }
    for start in starts {
        let mut dir = Some(start.as_path());
        while let Some(d) = dir {
            let proj = d.join("helpers").join("csindex");
            if proj.join("csindex.csproj").is_file() {
                return Some(proj);
            }
            dir = d.parent();
        }
    }
    None
}

// --- rendering ---

fn render_text(root: &Path, checks: &[Check], worst: Status, fixed: bool) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let shown = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let _ = writeln!(o, "{BIN} doctor — {}", shown.display());
    let mut section = "";
    for c in checks {
        if c.section != section {
            section = c.section;
            let _ = writeln!(o, "\n{}", section.to_uppercase());
        }
        if c.detail.is_empty() {
            let _ = writeln!(o, "  {:<5} {}", c.status.as_str(), c.label);
        } else {
            let _ = writeln!(o, "  {:<5} {}: {}", c.status.as_str(), c.label, c.detail);
        }
        if c.status != Status::Pass {
            if let Some(r) = &c.remedy {
                let _ = writeln!(o, "        fix: {r}");
            }
        }
    }
    let gaps = checks.iter().filter(|c| c.status == Status::Fail).count();
    let auto = checks
        .iter()
        .filter(|c| c.status != Status::Pass && c.fixable)
        .count();
    let _ = writeln!(o);
    if worst == Status::Fail {
        let _ = write!(
            o,
            "{gaps} gap(s) remain; this repo cannot be scanned honestly yet"
        );
        if auto > 0 && !fixed {
            let _ = write!(o, " — `{BIN} doctor --fix` can close {auto} of them");
        }
        let _ = writeln!(o, ".");
    } else {
        let _ = writeln!(
            o,
            "everything this repo needs is in place; run `{BIN} scan`."
        );
    }
    o
}

fn render_json(root: &Path, checks: &[Check], worst: Status) -> String {
    let shown = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let rows: Vec<serde_json::Value> = checks
        .iter()
        .map(|c| {
            serde_json::json!({
                "section": c.section,
                "status": c.status.as_str(),
                "label": c.label,
                "detail": c.detail,
                "remedy": c.remedy,
                "fixable": c.fixable,
            })
        })
        .collect();
    let doc = serde_json::json!({
        "path": shown.display().to_string(),
        "status": worst.as_str(),
        "checks": rows,
    });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&doc).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_typescript_pin_is_read_from_the_helper_not_restated() {
        // If this ever falls back to the literal, `--fix` and tsindex can
        // disagree about which compiler is acceptable, which is the one thing
        // this indirection exists to prevent.
        let parsed = parse_ts_requirement(embedded_helpers::TSINDEX.contents)
            .expect("tsindex.js must declare TS_REQUIREMENT for the doctor to read");
        assert!(
            parsed.starts_with('^') || parsed.starts_with('~') || parsed.starts_with('>'),
            "the pin must be a semver range, got {parsed:?}"
        );
        assert_eq!(ts_requirement(), parsed);
    }

    #[test]
    fn parse_ts_requirement_ignores_a_file_without_the_pin() {
        assert_eq!(parse_ts_requirement("const x = 1;\n"), None);
        assert_eq!(
            parse_ts_requirement("const TS_REQUIREMENT = '^9.0.0';"),
            Some("^9.0.0".to_string())
        );
    }

    #[test]
    fn native_helpers_report_no_runtime_prereq() {
        // The roll-call must not invent an interpreter for goindex/cindex/
        // rustindex, or a Go shop would be told to install node.
        assert_eq!(runtime_for(HelperKind::Executable), None);
        assert_eq!(runtime_for(HelperKind::PyScript), Some("python3"));
        assert_eq!(runtime_for(HelperKind::NodeScript), Some("node"));
        assert_eq!(runtime_for(HelperKind::DotnetAssembly), Some("dotnet"));
        assert_eq!(runtime_for(HelperKind::JavaSource), Some("java"));
    }

    #[test]
    fn an_infrastructure_only_repo_is_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("main.tf"), "resource \"x\" \"y\" {}\n").unwrap();
        let checks = repo_checks(dir.path(), &[]);
        assert!(
            checks.iter().all(|c| c.status == Status::Pass),
            "a repo with no scannable source needs no helper, so it must not read as broken"
        );
    }

    #[test]
    fn a_language_with_no_retriever_anywhere_is_reported_but_not_a_gap() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.rb"), "puts 1\n").unwrap();
        let checks = repo_checks(dir.path(), &[]);
        let row = checks
            .iter()
            .find(|c| c.label == "no retriever exists")
            .expect("Ruby must be named, not silently dropped");
        assert_eq!(
            row.status,
            Status::Warn,
            "nothing the reader installs makes it readable, so it must not fail the exit code"
        );
        assert!(row.detail.contains("Ruby"), "{}", row.detail);
        assert!(
            row.remedy.is_none(),
            "a remedy that does not exist must not be printed"
        );
    }

    #[test]
    fn the_csindex_build_lands_where_resolution_already_looks() {
        // The whole point of po-aml3h's fourth slot: the build IS the install,
        // so the command must target the canonical dir and never end in "now
        // export RVLSCAN_CSINDEX=...".
        let cmd = csindex_build_command(Path::new("/src/helpers/csindex"));
        assert!(cmd.contains(".revelara/helpers/csindex"), "{cmd}");
        assert!(!cmd.contains("RVLSCAN_CSINDEX"), "{cmd}");
    }

    #[test]
    fn json_render_is_machine_readable_and_carries_every_row() {
        let checks = vec![
            Check::new("repo", Status::Pass, "languages").detail("Go"),
            Check::new("retrievers", Status::Fail, "C# (csindex)")
                .detail("not resolved")
                .remedy("dotnet build ...")
                .fixable(),
        ];
        let doc: serde_json::Value =
            serde_json::from_str(&render_json(Path::new("."), &checks, Status::Fail)).unwrap();
        assert_eq!(doc["status"], "FAIL");
        assert_eq!(doc["checks"].as_array().unwrap().len(), 2);
        assert_eq!(doc["checks"][1]["fixable"], true);
        assert_eq!(doc["checks"][1]["remedy"], "dotnet build ...");
    }

    #[test]
    fn the_text_report_names_a_command_for_every_non_passing_row() {
        let checks = vec![Check::new("spec cache", Status::Fail, "installed")
            .detail("no verifiable spec cache")
            .remedy("run `rvl sync`")];
        let text = render_text(Path::new("."), &checks, Status::Fail, false);
        assert!(text.contains("fix: run `rvl sync`"), "{text}");
        assert!(text.contains("gap(s) remain"), "{text}");
    }
}
