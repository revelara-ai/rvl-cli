use std::io::IsTerminal;
mod config_lane;
mod render;
mod report;
mod shared_config;
mod waiver;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use rvl_cache::{offline_from_env, CacheStore, HttpFetcher, Keyset, SyncOutcome};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "rvlscan", version, about = "Revelara reliability scanner")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a repo against the signed spec cache: spec matching, propagation,
    /// triage. Deterministic, no model calls. With no `--retrieved`, rvlscan
    /// detects the languages under PATH and runs the matching retriever helper
    /// itself; `--retrieved` is an escape hatch for a prebuilt packet stream.
    Scan {
        /// Repo/dir to scan (default: current directory). Ignored when
        /// `--retrieved` is given.
        path: Option<PathBuf>,
        /// Escape hatch: a prebuilt retriever packet stream (JSONL). When
        /// present, helper orchestration is skipped entirely.
        #[arg(long)]
        retrieved: Option<PathBuf>,
        /// DEV ONLY: bypass the signed cache and load specs from a file.
        /// Loudly announced; never silent.
        #[arg(long)]
        specs_file: Option<PathBuf>,
        /// Class judgments (JSON array) for triage; unjudged classes still
        /// surface, they are never dropped.
        #[arg(long)]
        judgments: Option<PathBuf>,
        /// Write findings JSON here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Color output: auto (default), always, or never. NO_COLOR is honored.
        #[arg(long)]
        color: Option<String>,
        /// Warm re-scan: reuse the persistent packet index and re-retrieve only
        /// files whose content hash changed. Ignored when `--retrieved` is given.
        #[arg(long)]
        incremental: bool,
        /// Fail CLOSED when the incremental wall budget is exhausted or a
        /// retriever errors (CI). Default is fail-open: degrade to the reused
        /// portion so a scan never blocks.
        #[arg(long)]
        strict: bool,
    },
    /// Show EXACTLY what a scan would report to the Revelara spec factory about
    /// unknown API surfaces: shape only — `client_type.method` and a site count,
    /// NEVER source, file paths, or line numbers. This visibility IS the privacy
    /// feature; you can audit precisely what would ever leave this machine.
    /// Reporting is LOCAL-ONLY today: this command shows/writes the payload, it
    /// does not transmit it. Mirrors `scan`'s inputs.
    Report {
        /// Repo/dir to scan (default: current directory). Ignored when
        /// `--retrieved` is given.
        path: Option<PathBuf>,
        /// Escape hatch: a prebuilt retriever packet stream (JSONL).
        #[arg(long)]
        retrieved: Option<PathBuf>,
        /// DEV ONLY: bypass the signed cache and load specs from a file.
        #[arg(long)]
        specs_file: Option<PathBuf>,
        /// Warm re-scan: reuse the persistent packet index. Ignored when
        /// `--retrieved` is given.
        #[arg(long)]
        incremental: bool,
        /// Print the exact `Report` JSON payload (what the wire would carry)
        /// instead of the human-readable table.
        #[arg(long)]
        json: bool,
        /// Write the exact `Report` JSON payload to this file.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Explain one finding as an evidence block: the sites it covers, the
    /// control, and the fix. Takes the same inputs as `scan` plus the finding
    /// id shown in the ladder (e.g. `rvlscan explain 2ben path/to/repo`).
    Explain {
        /// The finding id from the ladder's `explain:` hint.
        id: String,
        /// Repo/dir to scan (default: current directory). Ignored when
        /// `--retrieved` is given.
        path: Option<PathBuf>,
        /// Escape hatch: a prebuilt retriever packet stream (JSONL).
        #[arg(long)]
        retrieved: Option<PathBuf>,
        #[arg(long)]
        specs_file: Option<PathBuf>,
        #[arg(long)]
        judgments: Option<PathBuf>,
        /// Color output: auto (default), always, or never. NO_COLOR is honored.
        #[arg(long)]
        color: Option<String>,
    },
    /// Waive a finding: append a rule waiver to `./.revelara.yaml` (under
    /// `scanner.waivers`, the same list rvl-cli reads) so it no longer surfaces
    /// as blocking/advisory. Takes the same inputs as `explain` plus the finding
    /// id; the waived rule is the finding's class key `client_type.method`.
    Suppress {
        /// The finding id from the ladder's `explain:`/`suppress:` hint.
        id: String,
        /// Repo/dir to scan and where `.revelara.yaml` is written (default: cwd).
        path: Option<PathBuf>,
        /// Optional audit reason recorded on the waiver.
        #[arg(long)]
        reason: Option<String>,
        /// Optional `YYYY-MM-DD` expiry; after it the waiver is inert. Empty is
        /// open-ended.
        #[arg(long)]
        expires: Option<String>,
        /// Escape hatch: a prebuilt retriever packet stream (JSONL).
        #[arg(long)]
        retrieved: Option<PathBuf>,
        #[arg(long)]
        specs_file: Option<PathBuf>,
        #[arg(long)]
        judgments: Option<PathBuf>,
    },
    /// Refresh the spec cache from the Revelara API (async-safe, never
    /// blocks a scan; RVLSCAN_OFFLINE=1 disables all fetches).
    Sync,
    /// Spec-cache maintenance.
    Cache {
        #[command(subcommand)]
        cmd: CacheCmd,
    },
    /// Incremental-scan packet index (content-hash keyed).
    Index {
        #[command(subcommand)]
        cmd: IndexCmd,
    },
    /// Install the Revelara workflow skills and lenses (the /rvl:scan lens
    /// set, CAST/STPA interrogatory workflows, assessment skills) into your
    /// coding-agent harness. Download-only: content is fetched from the
    /// Revelara API, verified, and cached; nothing leaves this machine.
    Skills {
        #[command(subcommand)]
        cmd: SkillsCmd,
    },
}

#[derive(Subcommand)]
enum SkillsCmd {
    /// Install skills into a harness. With no name, installs into every
    /// detected harness (Claude Code first).
    Install {
        /// Harness name: claude, codex, gemini, cursor, copilot, windsurf.
        harness: Option<String>,
        /// Stage files but do not run the harness's plugin registration
        /// commands (Claude Code); they are printed for manual use instead.
        #[arg(long)]
        no_register: bool,
    },
    /// Update installed skills to the served version. With no name, updates
    /// every harness recorded by a previous install.
    Update {
        /// Harness name; defaults to everything previously installed.
        harness: Option<String>,
        /// Stage files but do not run registration commands (Claude Code).
        #[arg(long)]
        no_register: bool,
    },
    /// Show installed, cached, and served skill versions (drift report).
    Status,
}

#[derive(Subcommand)]
enum IndexCmd {
    /// Build the index. Explicit and off the hook path: a cold full load is
    /// never paid during a commit. With --retrieved, loads a prebuilt packet
    /// stream; without, runs the language helpers over the repo itself.
    Init {
        /// Repository root to index (defaults to the current directory).
        path: Option<PathBuf>,
        #[arg(long)]
        retrieved: Option<PathBuf>,
    },
    /// Re-index. What a post-commit hook invokes: live mode (no --retrieved)
    /// hash-gates the sources and re-retrieves only what changed.
    Reindex {
        /// Repository root to re-index (defaults to the current directory).
        path: Option<PathBuf>,
        #[arg(long)]
        retrieved: Option<PathBuf>,
        /// Comma-separated repo-relative files to consider (defaults to every
        /// supported source file under the root).
        #[arg(long)]
        files: Option<String>,
        /// Spawn the reindex detached and return immediately, so a commit
        /// hook never waits on the warm.
        #[arg(long)]
        detach: bool,
    },
    /// Show how many files are indexed.
    Status,
}

#[derive(Subcommand)]
enum CacheCmd {
    /// Air-gapped import of a signed spec-cache artifact (same verification
    /// as sync; there is no bypass).
    Import {
        /// The artifact file (signed envelope JSON).
        artifact: PathBuf,
        /// Detached signature; defaults to <artifact>.sig.
        #[arg(long)]
        sig: Option<PathBuf>,
    },
    /// Show installed cache versions and staleness.
    Status,
}

/// All runtime configuration, resolved once. `base_url` and `org_key` layer
/// three sources (rvlscan-specific env / shared rvl-cli env / shared config
/// file) over a default; that merge happens in this constructor and nowhere
/// else. The signing keyset is deliberately NOT here: pinned keys are compiled
/// in, and a configurable keyset would be the verification bypass the
/// distribution contract forbids. `shared_config` reads ONLY api_url/api_key.
struct Config {
    cache_dir: PathBuf,
    index_dir: PathBuf,
    offline: bool,
    base_url: String,
    org_key: String,
}

/// The production default API endpoint, matching rvl-cli's `DefaultAPIURL`.
const DEFAULT_API_URL: &str = "https://api.revelara.ai";

impl Config {
    fn from_env() -> Self {
        let cache_dir = std::env::var_os("RVLSCAN_CACHE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default();
                home.join(".revelara").join("cache").join("specs")
            });
        let index_dir = std::env::var_os("RVLSCAN_INDEX_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default();
                home.join(".revelara").join("cache").join("index")
            });

        // Read the shared rvl-cli config file once (missing/malformed → empty).
        let shared = shared_config::load_shared_config();

        // Precedence (highest first), for BOTH values:
        //   base_url: RVLSCAN_API_BASE  > RVL_API_URL > file api_url > default
        //   org_key:  RVLSCAN_ORG_KEY   > RVL_API_KEY > file api_key > (empty)
        // Empty strings are skipped so an exported-but-empty env var never
        // shadows a real value from a lower-precedence source.
        let base_url = shared_config::first_nonempty(&[
            std::env::var("RVLSCAN_API_BASE").ok(),
            std::env::var("RVL_API_URL").ok(),
            shared.api_url.clone(),
            Some(DEFAULT_API_URL.to_string()),
        ])
        .unwrap_or_else(|| DEFAULT_API_URL.to_string());

        let org_key = shared_config::first_nonempty(&[
            std::env::var("RVLSCAN_ORG_KEY").ok(),
            std::env::var("RVL_API_KEY").ok(),
            shared.api_key.clone(),
        ])
        .unwrap_or_default();

        Self {
            cache_dir,
            index_dir,
            offline: offline_from_env(std::env::var("RVLSCAN_OFFLINE").ok().as_deref()),
            base_url,
            org_key,
        }
    }
}

/// CLI-only exit mapping: an EXPLICIT `rvlscan sync` exits nonzero when the
/// refresh didn't happen, because the user asked for it and scripts need the
/// signal. Scan-path sync must consume `SyncOutcome` directly and never call
/// this — "sync never fails a scan" is the library's contract, not this one.
fn report(outcome: &SyncOutcome) -> ExitCode {
    match outcome {
        SyncOutcome::Offline => {
            println!("offline (RVLSCAN_OFFLINE=1): no fetch attempted");
            ExitCode::SUCCESS
        }
        SyncOutcome::UpToDate => {
            println!("spec cache is up to date");
            ExitCode::SUCCESS
        }
        SyncOutcome::Installed { content_version } => {
            println!("installed spec cache {content_version}");
            ExitCode::SUCCESS
        }
        SyncOutcome::SchemaTooNew { hint } => {
            println!("{hint}");
            ExitCode::SUCCESS
        }
        SyncOutcome::Rejected { reason } => {
            eprintln!("rejected: {reason} (artifact quarantined; continuing on last-good)");
            ExitCode::FAILURE
        }
        SyncOutcome::FetchFailed { reason } => {
            eprintln!("fetch failed: {reason} (continuing on the installed cache)");
            ExitCode::FAILURE
        }
        SyncOutcome::InstallFailed { reason } => {
            eprintln!(
                "install failed: {reason} (a verified cache survives in current or \
                 last-good; run 'rvlscan cache status' to see which)"
            );
            ExitCode::FAILURE
        }
    }
}

/// One finding row. Mirrors the rvl-eval `run` emitter so the eval harness
/// can score a scan output without a conversion step.
#[derive(serde::Serialize)]
struct FindingOut {
    site_id: String,
    snapshot_id: String,
    verdict: String,
    reason: String,
    class: String,
}

/// Map triaged items to renderable findings. Incident-linkage fields
/// (counts, control) are not yet populated — they arrive from the corpus/
/// judgment layer — so they default to empty and the ladder degrades to
/// severity + coverage until that data flows.
fn triage_to_findings(items: &[rvl_triage::TriagedItem]) -> Vec<render::Finding> {
    items
        .iter()
        .map(|it| {
            let ck = &it.class;
            // The id must be unique per rendered class. ClassKey distinguishes
            // by reason too (e.g. "no bound anywhere" vs "only phase bounds"),
            // so the reason belongs in the id key or distinct classes collide.
            let key = format!(
                "{}.{}:{}:{}",
                ck.client_type, ck.method, ck.scope, ck.reason
            );
            let short = ck.client_type.rsplit('/').next().unwrap_or(&ck.client_type);
            render::Finding {
                id: render::finding_id(&key),
                site: it
                    .example_sites
                    .first()
                    .cloned()
                    .unwrap_or_else(|| format!("{} sites", it.site_count)),
                description: format!("{}.{} \u{2014} {}", short, ck.method, ck.reason),
                disposition: it.disposition.clone(),
                severity: it.severity.clone(),
                incident_count: 0,
                critical_count: 0,
                control: it.control.clone(),
                fix: it.fix.clone(),
                site_count: it.site_count,
                example_sites: it.example_sites.clone(),
                // The waiver key: the readable class key `client_type.method`.
                // Matched against `.revelara.yaml` waivers; written by suppress.
                class_rule: format!("{}.{}", ck.client_type, ck.method),
                suppressed: false,
            }
        })
        .collect()
}

// --- G7 repo-structure lane (po-av01j.7) ---

/// Map repo-structure control verdicts into ladder findings. Only violations
/// surface (satisfies/abstain outcomes stay in the facts record); every one
/// renders ADVISORY — a structural shape never blocks a commit. The waiver
/// key is `repo_structure.RC-XXX`, so `rvlscan suppress` and `.revelara.yaml`
/// waivers work on these like any other finding.
fn structure_to_findings(findings: &[rvl_structure::StructureFinding]) -> Vec<render::Finding> {
    findings
        .iter()
        .filter(|f| f.verdict == rvl_core::Verdict::Violates)
        .map(|f| {
            let class_rule = format!("repo_structure.{}", f.control);
            render::Finding {
                id: render::finding_id(&class_rule),
                site: f.evidence.first().cloned().unwrap_or_else(|| "repo".into()),
                description: format!("{} \u{2014} {}", f.control_name, f.reason),
                // "surface" + medium/low severity + zero incident counts is
                // exactly the Advisory cell of render::classify. Structure
                // verdicts are judged by the evaluator itself, so they are
                // not "unjudged" (which would print "severity unrated").
                disposition: "surface".into(),
                severity: f.severity.to_string(),
                incident_count: 0,
                critical_count: 0,
                control: f.control.to_string(),
                fix: f.fix.clone(),
                site_count: f.evidence.len().max(1),
                example_sites: f.evidence.clone(),
                class_rule,
                suppressed: false,
            }
        })
        .collect()
}

/// The ladder findings for this scan's repo-structure lane. Live scans
/// inventory the tree directly; a `--retrieved` scan has no tree, so the
/// facts come from the `repo_structure` record riding the prebuilt stream
/// (absent record = no facts = no findings, honestly).
fn resolve_structure_findings(
    retrieved: Option<&Path>,
    stream: &str,
    path: &Path,
) -> Vec<render::Finding> {
    let facts = if retrieved.is_some() {
        rvl_structure::parse_record(stream)
    } else {
        Some(rvl_structure::retrieve(path, &snapshot_name(path)))
    };
    facts
        .map(|f| structure_to_findings(&rvl_structure::evaluate(&f)))
        .unwrap_or_default()
}

// --- single-command scan: language detection + helper orchestration (po-3t3oj.25) ---
//
// Today a scan can be handed a prebuilt packet stream with `--retrieved`. When
// it is omitted, rvlscan discovers and runs the language retriever helper over
// the target itself and feeds the packets into the same pipeline. Helper
// PACKAGING for release (bundling goindex/pyindex with the shipped binary) is
// intentionally out of scope: discovery falls back to env override, a helper
// adjacent to the rvlscan binary, then PATH.

/// A source language rvlscan knows how to retrieve packets for. `Ord` (variant
/// order Go < Python < TypeScript) makes it a stable `BTreeMap` key, so a
/// multi-language incremental retrieval runs helpers in the same deterministic
/// order the single-command path documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Lang {
    Go,
    Python,
    TypeScript,
}

impl Lang {
    /// The retriever helper's base name.
    fn helper_base(self) -> &'static str {
        match self {
            Lang::Go => "goindex",
            Lang::Python => "pyindex",
            Lang::TypeScript => "tsindex",
        }
    }
    /// The env var that overrides helper discovery for this language.
    fn env_override(self) -> &'static str {
        match self {
            Lang::Go => "RVLSCAN_GOINDEX",
            Lang::Python => "RVLSCAN_PYINDEX",
            Lang::TypeScript => "RVLSCAN_TSINDEX",
        }
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Lang::Go => "Go",
            Lang::Python => "Python",
            Lang::TypeScript => "TypeScript",
        })
    }
}

/// How a resolved helper is invoked. A Go helper (or a pyindex/tsindex
/// executable on PATH) runs directly; a pyindex `.py` script runs under
/// `python3`, and a tsindex `.js` script runs under `node`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperKind {
    Executable,
    PyScript,
    NodeScript,
}

/// A helper located on disk, ready to be turned into a command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedHelper {
    path: PathBuf,
    kind: HelperKind,
}

/// Directory names never worth descending into during language detection.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", "__pycache__"];

/// A TypeScript declaration file (`*.d.ts`) is types-only, not scannable source.
/// Its extension is still `ts`, so it must be filtered by name, not extension.
fn is_declaration_ts(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".d.ts"))
}

/// Detect which supported languages have source under `root`. Pure and
/// bounded: marker files (`go.mod`, `pyproject.toml`, `setup.py`,
/// `tsconfig.json`) short-circuit, otherwise a walk that skips vendored/build
/// dirs looks for `*.go` / `*.py` / `*.ts`|`*.tsx` (never `*.d.ts`). Order is
/// stable (Go, Python, TypeScript) so a multi-language repo runs its helpers in
/// a deterministic order.
fn detect_languages(root: &Path) -> Vec<Lang> {
    let mut go = root.join("go.mod").is_file();
    let mut py = root.join("pyproject.toml").is_file() || root.join("setup.py").is_file();
    let mut ts = root.join("tsconfig.json").is_file();
    if !(go && py && ts) {
        walk_for_sources(root, &mut go, &mut py, &mut ts);
    }
    let mut out = Vec::new();
    if go {
        out.push(Lang::Go);
    }
    if py {
        out.push(Lang::Python);
    }
    if ts {
        out.push(Lang::TypeScript);
    }
    out
}

/// Bounded directory walk: sets `go`/`py`/`ts` when a `.go`/`.py`/`.ts`|`.tsx`
/// (non-`.d.ts`) file is seen, and stops early once all three are found. Skips
/// `.git`, `node_modules`, `target`, `vendor`, `__pycache__` so a big checkout
/// does not turn detection into a full-tree crawl.
fn walk_for_sources(root: &Path, go: &mut bool, py: &mut bool, ts: &mut bool) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if *go && *py && *ts {
            return;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(entry.path());
                }
            } else if ft.is_file() {
                let path = entry.path();
                match path.extension().and_then(|e| e.to_str()) {
                    Some("go") => *go = true,
                    Some("py") => *py = true,
                    Some("ts" | "tsx") if !is_declaration_ts(&path) => *ts = true,
                    _ => {}
                }
            }
        }
    }
}

/// Classify a resolved helper path into how it must be invoked. Go helpers are
/// always executables; a Python helper is a `python3` script when it ends in
/// `.py`, a TypeScript helper is a `node` script when it ends in `.js`,
/// otherwise an executable on PATH.
fn classify_helper(lang: Lang, path: &Path) -> ResolvedHelper {
    let ext = path.extension().and_then(|e| e.to_str());
    let kind = match lang {
        Lang::Go => HelperKind::Executable,
        Lang::Python if ext == Some("py") => HelperKind::PyScript,
        Lang::Python => HelperKind::Executable,
        Lang::TypeScript if ext == Some("js") => HelperKind::NodeScript,
        Lang::TypeScript => HelperKind::Executable,
    };
    ResolvedHelper {
        path: path.to_path_buf(),
        kind,
    }
}

/// First matching file named `name` on `PATH`.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|cand| cand.is_file())
}

/// Locate the retriever helper for `lang`, failing closed with actionable
/// guidance when none is found (never silently skip a detected language, that
/// would under-report). Precedence:
///   1. env override (`RVLSCAN_GOINDEX` / `RVLSCAN_PYINDEX`),
///   2. a helper next to the current exe,
///   3. a helper on `PATH` (for Python, `pyindex` or `pyindex.py`).
fn resolve_helper(lang: Lang) -> anyhow::Result<ResolvedHelper> {
    // (1) explicit env override wins.
    if let Some(p) = std::env::var_os(lang.env_override()) {
        let p = PathBuf::from(p);
        anyhow::ensure!(
            p.exists(),
            "{} points at {} which does not exist",
            lang.env_override(),
            p.display()
        );
        return Ok(classify_helper(lang, &p));
    }
    let base = lang.helper_base();
    // The scripted-helper filename to also look for, for a language whose helper
    // ships as a script rather than a native binary (pyindex.py, tsindex.js).
    let script_name = match lang {
        Lang::Python => Some(format!("{base}.py")),
        Lang::TypeScript => Some(format!("{base}.js")),
        Lang::Go => None,
    };
    // (2) adjacent to the rvlscan binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(base);
            if cand.is_file() {
                return Ok(classify_helper(lang, &cand));
            }
            if let Some(script) = &script_name {
                let cand_script = dir.join(script);
                if cand_script.is_file() {
                    return Ok(classify_helper(lang, &cand_script));
                }
            }
        }
    }
    // (3) on PATH.
    if let Some(found) = find_on_path(base) {
        return Ok(classify_helper(lang, &found));
    }
    if let Some(script) = &script_name {
        if let Some(found) = find_on_path(script) {
            return Ok(classify_helper(lang, &found));
        }
    }
    anyhow::bail!(
        "no {base} helper found for detected {lang} sources: set {env} to the helper path, \
         place {base} next to the rvlscan binary, or put it on PATH",
        env = lang.env_override(),
    )
}

/// Build the full argv (program first) for invoking a resolved helper against
/// `root`, tagging the snapshot `name`. When `files` is non-empty, append
/// `--files a,b,c` (repo-relative paths) so the helper emits packets ONLY for
/// those files, the incremental reload path both goindex and pyindex support.
/// Pure, so command construction is unit-testable without spawning a process.
fn helper_argv(helper: &ResolvedHelper, root: &Path, name: &str, files: &[String]) -> Vec<String> {
    let root = root.display().to_string();
    let helper_path = helper.path.display().to_string();
    let mut tail = vec![
        "--retrieve".to_string(),
        "--root".to_string(),
        root,
        "--name".to_string(),
        name.to_string(),
    ];
    if !files.is_empty() {
        tail.push("--files".to_string());
        tail.push(files.join(","));
    }
    match helper.kind {
        HelperKind::Executable => std::iter::once(helper_path).chain(tail).collect(),
        HelperKind::PyScript => std::iter::once("python3".to_string())
            .chain(std::iter::once(helper_path))
            .chain(tail)
            .collect(),
        HelperKind::NodeScript => std::iter::once("node".to_string())
            .chain(std::iter::once(helper_path))
            .chain(tail)
            .collect(),
    }
}

/// Run a resolved helper over `root` and return its stdout (the JSONL packet
/// stream). When `files` is non-empty the helper emits only those files'
/// packets. A non-zero exit surfaces the helper's stderr in the error.
fn run_helper(
    helper: &ResolvedHelper,
    root: &Path,
    name: &str,
    files: &[String],
) -> anyhow::Result<String> {
    let argv = helper_argv(helper, root, name, files);
    let (program, args) = argv.split_first().expect("argv always has a program");
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running retriever helper `{program}`"))?;
    anyhow::ensure!(
        output.status.success(),
        "retriever helper `{}` exited {}: {}",
        program,
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Derive the snapshot tag for a scan target: the canonical base name of
/// `path`, falling back to "repo" when that is unavailable (e.g. `.` at `/`).
fn snapshot_name(path: &Path) -> String {
    std::fs::canonicalize(path)
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "repo".to_string())
}

/// Collect the candidate source files (`*.go` / `*.py`) under `root` for the
/// incremental hash-gate, using the same bounded, vendored-dir-skipping walk
/// `detect_languages` relies on. Paths are `root`-prefixed so they hash
/// directly and strip cleanly back to the repo-relative form the helpers emit.
fn walk_source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(entry.path());
                }
            } else if ft.is_file() {
                let path = entry.path();
                match path.extension().and_then(|e| e.to_str()) {
                    Some("go" | "py") => out.push(path),
                    Some("ts" | "tsx") if !is_declaration_ts(&path) => out.push(path),
                    _ => {}
                }
            }
        }
    }
    out.sort();
    out
}

/// The repo-relative, forward-slashed spelling of `file` under `root`. Matches
/// the `file_path` the helpers emit (`filepath.Rel` + `ToSlash` on the Go side,
/// `os.path.relpath` + `/` on the Python side), so a candidate path lines up
/// with the sites retrieved from it.
fn repo_relative(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The language whose helper retrieves a given source file, by extension. A
/// TypeScript declaration file (`*.d.ts`) is types-only and maps to no helper.
fn lang_of_path(path: &Path) -> Option<Lang> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("go") => Some(Lang::Go),
        Some("py") => Some(Lang::Python),
        Some("ts") | Some("tsx") if !is_declaration_ts(path) => Some(Lang::TypeScript),
        _ => None,
    }
}

/// Resolve the packet-stream TEXT feeding the pipeline. With `--retrieved`,
/// that file is read verbatim (the escape hatch). Otherwise rvlscan detects the
/// languages under `path`, runs each matching helper, and concatenates their
/// stdout.
fn resolve_packet_stream(retrieved: Option<&Path>, path: &Path) -> anyhow::Result<String> {
    if let Some(p) = retrieved {
        return std::fs::read_to_string(p)
            .with_context(|| format!("reading --retrieved {}", p.display()));
    }
    let langs = detect_languages(path);
    anyhow::ensure!(
        !langs.is_empty(),
        "no supported source files found under {}; pass --retrieved to scan a prebuilt packet stream",
        path.display()
    );
    let name = snapshot_name(path);
    let mut combined = String::new();
    for lang in langs {
        let helper = resolve_helper(lang)?;
        let out = run_helper(&helper, path, &name, &[])?;
        if !combined.is_empty() && !combined.ends_with('\n') {
            combined.push('\n');
        }
        combined.push_str(&out);
    }
    Ok(combined)
}

/// The scan: packets + verified specs -> propagation -> triage.
/// Deterministic, no model calls. Undecided outcomes are reported in the
/// coverage section, never promoted to a violation.
/// The deterministic core shared by `scan` and `explain`: load verified specs,
/// parse packets, propagate, triage. Returns the raw findings (for --out and
/// coverage) alongside the triaged items and a `verbose` cache-status line.
/// `verbose` gates the one-line "sites | specs" summary so `explain` stays quiet.
/// Takes the already-resolved packet-stream text (see `resolve_packet_stream`).
/// What the resolve pipeline hands back: propagation findings, triaged
/// items, the sites both index against (1:1), and the loaded spec cache so
/// callers can run the G6 config lane against the same specs.
type ResolvedScan = (
    Vec<rvl_propagate::Finding>,
    Vec<rvl_triage::TriagedItem>,
    Vec<rvl_core::Site>,
    rvl_spec::SpecCache,
);

#[allow(clippy::too_many_arguments)]
fn resolve_findings(
    store: &CacheStore,
    keyset: &Keyset,
    stream: &str,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    policy_root: Option<&std::path::Path>,
    verbose: bool,
) -> anyhow::Result<ResolvedScan> {
    let (sites, repo_cfg, skipped) = rvl_core::parse_stream(stream);
    findings_from_sites(
        store,
        keyset,
        sites,
        &repo_cfg,
        skipped,
        specs_file,
        judgments,
        policy_root,
        verbose,
    )
}

/// The pipeline shared by the packet-stream path and the incremental path:
/// verified specs + already-assembled sites -> propagation -> triage. The
/// incremental caller hands its merged (reused + freshly retrieved) sites here
/// directly, skipping `parse_stream`.
/// Also returns the loaded [`rvl_spec::SpecCache`] so callers can run the G6
/// config lane against the SAME specs the code lane used (one signed artifact
/// carries both; loading twice would double the verification and the
/// staleness chatter).
#[allow(clippy::too_many_arguments)]
fn findings_from_sites(
    store: &CacheStore,
    keyset: &Keyset,
    sites: Vec<rvl_core::Site>,
    repo_cfg: &rvl_core::RepoConfig,
    skipped: usize,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    policy_root: Option<&std::path::Path>,
    verbose: bool,
) -> anyhow::Result<ResolvedScan> {
    let specs_text = match specs_file {
        Some(p) => {
            // Dev override. Announced on stderr every time: an unverified
            // spec cache must never load quietly.
            eprintln!(
                "WARNING: loading UNVERIFIED specs from {} (--specs-file is a dev override; \
                 production scans use the signed cache)",
                p.display()
            );
            std::fs::read_to_string(p)?
        }
        None => {
            let loaded = store.load(keyset, &rvl_cache::today_utc())?;
            if let Some(hint) = &loaded.upgrade_hint {
                eprintln!("{hint}");
            }
            if let Some(note) = &loaded.staleness_note {
                eprintln!("{note}");
            }
            // Gated by `verbose` (like the sites|specs line below) so quiet
            // callers such as `explain` and `report --json` keep stdout clean
            // for their own payload. Staleness/upgrade hints stay on stderr.
            if verbose {
                println!(
                    "spec cache {} (schema {}, {:?})",
                    loaded.envelope.content_version, loaded.envelope.schema, loaded.source
                );
            }
            serde_json::to_string(&loaded.envelope.specs)?
        }
    };

    anyhow::ensure!(
        !sites.is_empty(),
        "no parseable sites in the retrieved packet stream"
    );
    let mut cache = rvl_spec::SpecCache::load(&specs_text)?;
    // Out-of-code bound declarations (po-3t3oj.30): repo policy in
    // `.revelara.yaml` asserting a bound no retrieval can see (a prod
    // statement_timeout, an infra deadline). Merged as exact-type
    // whole-call this-client ConfigSpecs with the policy provenance; the
    // declaration is committed to the repo, so the audit trail is git.
    if let Some(root) = policy_root {
        let declared =
            waiver::load_declared_bounds(&root.join(".revelara.yaml"), &rvl_cache::today_utc());
        if !declared.is_empty() {
            eprintln!(
                "applying {} declared bound(s) from .revelara.yaml",
                declared.len()
            );
            let overlay = rvl_spec::SpecFile {
                apis: vec![],
                scopes: vec![],
                config_keys: vec![],
                configs: declared
                    .into_iter()
                    .map(|d| rvl_spec::ConfigSpec {
                        type_name: d.client_type,
                        bounds: rvl_spec::Bounds::WholeCall,
                        scope: rvl_spec::Scope::ThisClient,
                        confidence: 1.0,
                        rationale: format!("declared in .revelara.yaml: {}", d.reason),
                        declared: true,
                    })
                    .collect(),
            };
            cache.merge(rvl_spec::SpecCache::from_file(overlay));
        }
    }
    let served = cache.served_bound(repo_cfg);
    let client = cache.client_bound_by_family(repo_cfg);
    let findings = rvl_propagate::propagate_all(&sites, &cache, &served, &client);

    if verbose {
        println!(
            "sites {} | specs {} | unparseable lines {skipped}",
            sites.len(),
            cache.len()
        );
    }

    // Triage: collapse violations into reader-facing classes. Unjudged classes
    // still surface; they are never dropped.
    let judgments: Vec<rvl_triage::ClassJudgment> = match judgments {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => Vec::new(),
    };
    // Key each verdict on the site's UNIQUE site_key (not the finding's
    // file:line site_id, which collides on chained calls), so triage rematches
    // it to the right call and labels the finding correctly (po-3t3oj.35).
    // findings are index-aligned with sites (propagate_all maps 1:1).
    let verdict_rows: Vec<(String, rvl_core::Verdict, String)> = findings
        .iter()
        .zip(sites.iter())
        .map(|(f, s)| (s.site_key(), f.verdict, f.reason.clone()))
        .collect();
    let items = rvl_triage::triage(&sites, &verdict_rows, &judgments);
    Ok((findings, items, sites, cache))
}

// --- G5 content lane: language-agnostic secret scanning, RC-043 (po-av01j.6) ---
//
// A pure-Rust in-process lane (crates/rvl-content), not an external helper:
// content-pattern scanning needs no language toolchain, so the helper model's
// per-target packaging cost buys nothing here. Content findings ride the same
// packet schema (`client_type` "secret", `method` = rule id, snippet = masked
// preview ONLY) and the same triage/waiver/render machinery, but they are kept
// OUT of the spec-lane plumbing on purpose: never in coverage totals (they are
// not API surfaces), never in `--out` eval rows (the eval harness scores spec
// verdicts), and never in the shape-only report (their sites carry file paths,
// which the report contract forbids).

/// The control every content-lane secret finding maps to: RC-043, centralized
/// secret management. The judgment layer owns control mapping; the content
/// lane's judgments are built in, so its findings are born mapped.
const SECRETS_CONTROL: &str = "RC-043";

/// Fix guidance, from RC-043's remediation: an exposed secret is compromised
/// the moment it is committed, so rotation is part of the fix, not an option.
const SECRETS_FIX: &str = "remove the secret from source, rotate it immediately, and load it \
     from a centralized secret manager (RC-043)";

/// Built-in class judgments for content findings, one per rule x scope class.
/// Token shapes are high severity (blocking) everywhere except test support,
/// where a planted fixture credential is the common case; the generic entropy
/// rule stays medium (advisory) everywhere because shape alone is weak
/// evidence. `verdict` is always `surface`: a matched secret is never spam.
fn content_judgments(findings: &[rvl_content::ContentFinding]) -> Vec<rvl_triage::ClassJudgment> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for f in findings {
        if !seen.insert((f.rule_id.clone(), f.severity.clone())) {
            continue;
        }
        for scope in [
            "runtime",
            "migration",
            "test_support",
            "dev_only",
            "backfill",
        ] {
            let severity = if scope == "test_support" || f.severity != "high" {
                "medium"
            } else {
                "high"
            };
            out.push(rvl_triage::ClassJudgment {
                api: format!("secret.{}", f.rule_id),
                scope: scope.to_string(),
                verdict: "surface".to_string(),
                severity: severity.to_string(),
                fix: SECRETS_FIX.to_string(),
                control: SECRETS_CONTROL.to_string(),
            });
        }
    }
    out
}

/// Run the content lane over `path` and triage its findings into ladder items.
/// Verdicts are pre-decided (`Violates`): a content-pattern match IS the
/// evidence, there is no spec question to propagate. The waiver key downstream
/// is the class rule `secret.<rule_id>`, so `rvlscan suppress` and hand-written
/// `.revelara.yaml` waivers work unchanged (po-3t3oj.27).
fn content_items(path: &Path) -> Vec<rvl_triage::TriagedItem> {
    let findings = rvl_content::scan_root(path);
    if findings.is_empty() {
        return Vec::new();
    }
    let sites = rvl_content::to_sites(&findings, &snapshot_name(path));
    let rows: Vec<(String, rvl_core::Verdict, String)> = sites
        .iter()
        .zip(findings.iter())
        .map(|(s, f)| {
            (
                s.site_key(),
                rvl_core::Verdict::Violates,
                f.description.clone(),
            )
        })
        .collect();
    rvl_triage::triage(&sites, &rows, &content_judgments(&findings))
}

/// Resolve the color decision, honoring `--color` then NO_COLOR and a non-tty
/// stdout. An unrecognized `--color` value falls back to auto.
fn stdout_color(mode: Option<&str>) -> bool {
    let mode = match mode {
        Some("always") => render::ColorMode::Always,
        Some("never") => render::ColorMode::Never,
        _ => render::ColorMode::Auto,
    };
    mode.resolve(
        std::env::var_os("NO_COLOR").is_some(),
        std::io::stdout().is_terminal(),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_scan(
    store: &CacheStore,
    keyset: &Keyset,
    state_path: &std::path::Path,
    path: &std::path::Path,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
    color: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let start = std::time::Instant::now();
    // Content lane first: it is language-agnostic, so it must not depend on
    // the language pipeline having anything to do. With `--retrieved` the scan
    // is an escape-hatch replay of a prebuilt stream, possibly from another
    // tree entirely, so scanning PATH's content would mix two repos: skip.
    let citems = if retrieved.is_none() {
        content_items(path)
    } else {
        Vec::new()
    };
    // A repo with no supported languages but WITH content findings (an
    // .env/terraform tree) still gets a scan: the ladder is the content lane
    // alone and coverage reports zero API surfaces. Without content findings
    // the original fail-closed guidance stands.
    if retrieved.is_none() && !citems.is_empty() && detect_languages(path).is_empty() {
        // Content-only repo: no packet stream exists, so the structure lane
        // inventories the live tree directly (same as the incremental path).
        // The config lane is skipped on this early path (no spec cache gets
        // resolved before the return) -- follow-up tracked on the epic.
        let structure = resolve_structure_findings(None, "", path);
        return render_scan_output(
            state_path,
            path,
            &[],
            &citems,
            &[],
            &structure,
            None,
            out,
            color,
            start,
        );
    }
    let stream = resolve_packet_stream(retrieved, path)?;
    let (findings, mut items, sites, specs) = resolve_findings(
        store,
        keyset,
        &stream,
        specs_file,
        judgments,
        Some(path),
        true,
    )?;
    items.extend(citems);
    let structure = resolve_structure_findings(retrieved, &stream, path);
    // The G6 config lane: same repo, same specs, per-format retrievers.
    let lane = config_lane::run(path, &specs, &snapshot_name(path));
    render_scan_output(
        state_path,
        path,
        &findings,
        &items,
        &sites,
        &structure,
        Some(&lane),
        out,
        color,
        start,
    )
}

/// What `scan` persists for `explain`/`suppress` to resolve finding ids from.
/// The ladder prints `explain: rvlscan explain <id>` as a copy-pasteable hint;
/// without this state the hint silently re-scans the CURRENT directory with
/// DEFAULT inputs, which is a different scan (po-3t3oj.38: a scan run with
/// --retrieved/--specs-file printed ids that bare `explain` could never find).
#[derive(serde::Serialize, serde::Deserialize)]
struct LastScan {
    /// Canonical root of the scanned repo; `suppress` writes its waiver here
    /// when no path is given.
    root: String,
    findings: Vec<render::Finding>,
}

/// The last-scan state file: a sibling of the spec-cache dir, so it lives
/// under the same RVLSCAN_CACHE_DIR umbrella and never touches the scanned
/// repo.
fn last_scan_path(cache_dir: &std::path::Path) -> PathBuf {
    cache_dir
        .parent()
        .unwrap_or(cache_dir)
        .join("last-scan.json")
}

/// Best-effort persist: a scan must never fail because its state file could
/// not be written, but the degradation is said out loud because it breaks the
/// verbatim `explain` hint.
fn save_last_scan(state: &std::path::Path, root: &std::path::Path, findings: &[render::Finding]) {
    let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let ls = LastScan {
        root: canonical.to_string_lossy().into_owned(),
        findings: findings.to_vec(),
    };
    let write = || -> anyhow::Result<()> {
        if let Some(dir) = state.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(state, serde_json::to_string(&ls)?)?;
        Ok(())
    };
    if let Err(e) = write() {
        eprintln!(
            "warning: could not save scan state to {} ({e}); `rvlscan explain <id>` \
             will need the same path/flags this scan used",
            state.display()
        );
    }
}

/// Missing or unreadable state is simply "no last scan" (first run, cleared
/// cache, or a corrupt file) -- callers fall back to a live re-scan.
fn load_last_scan(state: &std::path::Path) -> Option<LastScan> {
    serde_json::from_str(&std::fs::read_to_string(state).ok()?).ok()
}

/// Render the ladder + optional `--out` JSON for a completed scan. Shared by
/// the packet-stream path and the incremental path so both report identically.
#[allow(clippy::too_many_arguments)]
fn render_scan_output(
    state_path: &std::path::Path,
    path: &std::path::Path,
    findings: &[rvl_propagate::Finding],
    items: &[rvl_triage::TriagedItem],
    sites: &[rvl_core::Site],
    structure: &[render::Finding],
    config: Option<&config_lane::LaneOutput>,
    out: Option<&std::path::Path>,
    color: Option<&str>,
    start: std::time::Instant,
) -> anyhow::Result<ExitCode> {
    // Resolved = the scanner reached a conclusion (bounded/unbounded blocking,
    // or non-blocking). The rest abstain; bucket them by the lever that closes
    // each: no spec -> mint, truncated search -> retrieval depth, "depends" ->
    // per-site judge. Reason strings are the propagation layer's output contract.
    let resolved = findings.iter().filter(|f| f.verdict.is_resolved()).count();
    let mut coverage = render::Coverage {
        resolved,
        total: sites.len(),
        abstain_no_spec: 0,
        abstain_bounds: 0,
        abstain_judge: 0,
        abstain_other: 0,
    };
    for f in findings.iter().filter(|f| !f.verdict.is_resolved()) {
        if f.reason.starts_with("no spec") {
            coverage.abstain_no_spec += 1;
        } else if f.reason.contains("truncated") {
            coverage.abstain_bounds += 1;
        } else if f.reason.contains("depends") || f.reason.contains("per-site") {
            coverage.abstain_judge += 1;
        } else {
            coverage.abstain_other += 1;
        }
    }
    let mut ladder_findings = triage_to_findings(items);
    // Repo-structure lane findings join the ladder (always Advisory) and the
    // persisted last-scan state, so explain/suppress resolve their ids too.
    ladder_findings.extend(structure.iter().cloned());
    // Config-lane findings join the ladder as ordinary rows BEFORE waivers,
    // so a `.revelara.yaml` waiver on `<format>.<key>` suppresses them the
    // same way it suppresses a code class.
    if let Some(lane) = config {
        ladder_findings.extend(lane.findings.iter().cloned());
    }

    // Apply `.revelara.yaml` waivers (PATH-relative, the same base the retriever
    // used). A waived finding is folded into the Suppressed section: reported in
    // the footer count, kept out of BLOCKING/ADVISORY. Missing config = no-op.
    let waivers = waiver::load_waivers(&path.join(".revelara.yaml"));
    if !waivers.is_empty() {
        let today = rvl_cache::today_utc();
        for f in &mut ladder_findings {
            if waiver::is_waived(&f.class_rule, &f.site, &waivers, &today) {
                f.suppressed = true;
            }
        }
    }

    // Persist the ladder so the printed `explain:`/`suppress:` hints resolve
    // verbatim, from any directory, without re-running this scan's inputs.
    save_last_scan(state_path, path, &ladder_findings);

    let elapsed = format!("scan complete in {:.2}s", start.elapsed().as_secs_f64());
    print!(
        "{}",
        render::render_ladder(
            &ladder_findings,
            coverage,
            config.map(|lane| &lane.coverage),
            &elapsed,
            stdout_color(color)
        )
    );

    if let Some(p) = out {
        let rows: Vec<FindingOut> = findings
            .iter()
            .zip(sites.iter())
            .map(|(f, s)| FindingOut {
                site_id: f.site_id.clone(),
                snapshot_id: s.snapshot_id.clone(),
                verdict: f.verdict.as_str().to_string(),
                reason: f.reason.clone(),
                class: rvl_triage::class_key_string(s),
            })
            .collect();
        std::fs::write(p, serde_json::to_string_pretty(&rows)?)?;
        println!("\nwrote {}", p.display());
    }
    Ok(ExitCode::SUCCESS)
}

// --- incremental scan: warm re-scan via the persistent packet index (po-3t3oj.14) ---
//
// A warm re-scan hashes the candidate source files, reuses indexed packets for
// the ones whose content is unchanged, and re-retrieves ONLY the changed files
// through the language helpers (`--files a,b,c`). Reused + freshly retrieved
// sites are merged and fed into the same pipeline a full scan uses; the changed
// files are re-indexed so the next run treats them as unchanged.
//
// Two invariants, inherited from rvl-index:
//   * Reuse and merge key on the full `site_key` (path:line:client_type:method),
//     never file:line: one location can resolve to several sites with different
//     verdicts, and a file:line key silently drops one of a colliding pair.
//   * The retrieval wall budget fails OPEN: when it is exhausted the scan
//     degrades to the reused portion rather than blocking. `--strict` inverts
//     that for CI, where a partial answer is worse than a failed job.

/// Default wall-clock cap on the CHANGED-file retrieval, mirroring
/// `rvl_index::Budget::hook()`. A warm scan sits on a pre-commit hook; it must
/// never hang a commit, so it degrades to what it has once this elapses.
const INCREMENTAL_WALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// A real `rvl_index::Retriever`: shells out to the language helpers for a
/// specific CHANGED-file list. Files are grouped by extension -> language and
/// each language's helper runs once over just that language's changed files.
struct HelperRetriever {
    root: PathBuf,
    name: String,
}

impl HelperRetriever {
    /// Retrieve packets for `changed` (absolute paths), returning the sites and
    /// the repo-scoped construction facts (carried by whichever helper ran).
    /// Sites keep the repo-relative `file_path` the helpers emit.
    fn retrieve_full(
        &self,
        changed: &[PathBuf],
    ) -> anyhow::Result<(Vec<rvl_core::Site>, rvl_core::RepoConfig)> {
        // Group changed files by language, as repo-relative paths for `--files`.
        let mut by_lang: std::collections::BTreeMap<Lang, Vec<String>> =
            std::collections::BTreeMap::new();
        for p in changed {
            if let Some(lang) = lang_of_path(p) {
                by_lang
                    .entry(lang)
                    .or_default()
                    .push(repo_relative(&self.root, p));
            }
        }
        let mut sites = Vec::new();
        let mut repo_cfg = rvl_core::RepoConfig::default();
        for (lang, files) in by_lang {
            let helper = resolve_helper(lang)?;
            let stream = run_helper(&helper, &self.root, &self.name, &files)?;
            let (mut got, cfg, _skipped) = rvl_core::parse_stream(&stream);
            sites.append(&mut got);
            // The last non-empty construction record wins; helpers emit
            // whole-repo constructions regardless of `--files`.
            if !cfg.constructions.is_empty() {
                repo_cfg = cfg;
            }
        }
        Ok((sites, repo_cfg))
    }
}

impl rvl_index::Retriever for HelperRetriever {
    fn retrieve(&self, paths: &[PathBuf]) -> anyhow::Result<Vec<rvl_core::Site>> {
        Ok(self.retrieve_full(paths)?.0)
    }
}

/// What a budgeted retrieval produced: the fresh sites, the repo config, and a
/// degradation note when the wall budget was hit or the retriever errored under
/// fail-open. `degraded` gates re-indexing: files we did not actually retrieve
/// must NOT be recorded as scanned, or the next run skips them.
#[derive(Debug)]
struct RetrieveResult {
    sites: Vec<rvl_core::Site>,
    repo_cfg: rvl_core::RepoConfig,
    degraded_note: Option<String>,
}

/// The outcome of running a closure under a wall-clock cap.
enum Budgeted<T> {
    Done(T),
    TimedOut,
    Failed(anyhow::Error),
}

/// Run `f` on a worker thread and wait at most `cap`. On timeout the worker is
/// left to finish and exit on its own (the process is short-lived); we never
/// block past the cap. Sync by design: no async runtime, like the rest of the
/// binary.
fn run_with_budget<T, F>(cap: std::time::Duration, f: F) -> Budgeted<T>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(cap) {
        Ok(Ok(v)) => Budgeted::Done(v),
        Ok(Err(e)) => Budgeted::Failed(e),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Budgeted::TimedOut,
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Budgeted::Failed(anyhow::anyhow!("retrieval worker exited without a result"))
        }
    }
}

/// Turn a budget outcome into a `RetrieveResult`, applying the fail-open /
/// `--strict` policy. Pure and thread-free so the policy is unit-testable.
fn resolve_budgeted(
    outcome: Budgeted<(Vec<rvl_core::Site>, rvl_core::RepoConfig)>,
    strict: bool,
    changed_len: usize,
    cap: std::time::Duration,
) -> anyhow::Result<RetrieveResult> {
    match outcome {
        Budgeted::Done((sites, repo_cfg)) => Ok(RetrieveResult {
            sites,
            repo_cfg,
            degraded_note: None,
        }),
        Budgeted::TimedOut => {
            if strict {
                anyhow::bail!(
                    "wall budget of {:?} exhausted retrieving {changed_len} changed file(s); \
                     --strict refuses a partial answer",
                    cap
                );
            }
            Ok(RetrieveResult {
                sites: Vec::new(),
                repo_cfg: rvl_core::RepoConfig::default(),
                degraded_note: Some(format!(
                    "retrieval capped at {cap:?}: {changed_len} changed file(s) not re-scanned; \
                     results cover the reused portion only"
                )),
            })
        }
        Budgeted::Failed(e) => {
            if strict {
                return Err(e);
            }
            Ok(RetrieveResult {
                sites: Vec::new(),
                repo_cfg: rvl_core::RepoConfig::default(),
                degraded_note: Some(format!(
                    "retrieval failed ({e}); results cover the reused portion only"
                )),
            })
        }
    }
}

/// Merge reused and freshly-retrieved sites, de-duplicating on the full
/// `site_key`. Reused and fresh come from disjoint file sets, so this normally
/// drops nothing; keying on `site_key` (never file:line) guarantees a location
/// that resolves to two sites with different client types keeps both.
fn merge_on_site_key(
    reused: Vec<rvl_core::Site>,
    fresh: Vec<rvl_core::Site>,
) -> Vec<rvl_core::Site> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(reused.len() + fresh.len());
    for s in reused.into_iter().chain(fresh) {
        if seen.insert(rvl_index::site_key(&s)) {
            out.push(s);
        }
    }
    out
}

/// The assembled result of a warm pass.
struct IncrementalScan {
    sites: Vec<rvl_core::Site>,
    repo_cfg: rvl_core::RepoConfig,
    reused_files: usize,
    retrieved_files: usize,
    degraded_note: Option<String>,
}

/// Core of the warm path, retriever-agnostic so a fake can drive it in tests:
/// hash-gate `candidates`, reuse indexed packets for the unchanged, retrieve the
/// changed via `retrieve`, re-index what came back (unless degraded), and merge.
fn incremental_sites<F>(
    index: &rvl_index::PacketIndex,
    root: &Path,
    candidates: &[PathBuf],
    retrieve: F,
) -> anyhow::Result<IncrementalScan>
where
    F: FnOnce(&[PathBuf]) -> anyhow::Result<RetrieveResult>,
{
    let plan = index.plan_reload(candidates);

    // Reuse indexed packets for the unchanged files.
    let mut reused = Vec::new();
    for f in &plan.unchanged {
        let h = rvl_index::hash_file(f)?;
        if let Some(cached) = index.get(f, &h)? {
            reused.extend(cached);
        }
    }
    let reused_files = plan.unchanged.len();

    // Retrieve the changed files (skip the helper entirely when nothing changed).
    let rr = if plan.changed.is_empty() {
        RetrieveResult {
            sites: Vec::new(),
            repo_cfg: rvl_core::RepoConfig::default(),
            degraded_note: None,
        }
    } else {
        retrieve(&plan.changed)?
    };

    // Re-index the freshly retrieved files so the next pass reuses them. Only
    // when NOT degraded: recording a file we did not actually retrieve would
    // make the next run skip it.
    let degraded = rr.degraded_note.is_some();
    if !degraded {
        for f in &plan.changed {
            let rel = repo_relative(root, f);
            let for_file: Vec<rvl_core::Site> = rr
                .sites
                .iter()
                .filter(|s| s.file_path == rel)
                .cloned()
                .collect();
            let h = rvl_index::hash_file(f)?;
            index.put(f, &h, &for_file)?;
        }
    }
    let retrieved_files = if degraded { 0 } else { plan.changed.len() };

    let sites = merge_on_site_key(reused, rr.sites);
    Ok(IncrementalScan {
        sites,
        repo_cfg: rr.repo_cfg,
        reused_files,
        retrieved_files,
        degraded_note: rr.degraded_note,
    })
}

/// Run one warm incremental pass: hash-gate the candidate sources, reuse indexed
/// packets, and budget-retrieve the changed files. Shared by `scan --incremental`
/// and `report --incremental` so both assemble sites the same way.
fn incremental_scan_pass(
    index_dir: &std::path::Path,
    path: &std::path::Path,
    strict: bool,
) -> anyhow::Result<IncrementalScan> {
    let candidates = walk_source_files(path);
    anyhow::ensure!(
        !candidates.is_empty(),
        "no supported source files found under {}; pass --retrieved to scan a prebuilt packet stream",
        path.display()
    );

    let index = rvl_index::PacketIndex::open(&index_dir.join("packets.redb"))?;
    let name = snapshot_name(path);
    let root = path.to_path_buf();

    incremental_sites(&index, path, &candidates, |changed| {
        // Budget only the potentially-slow helper retrieval.
        let retriever = HelperRetriever {
            root: root.clone(),
            name: name.clone(),
        };
        let changed_owned = changed.to_vec();
        let changed_len = changed_owned.len();
        let outcome = run_with_budget(INCREMENTAL_WALL_BUDGET, move || {
            retriever.retrieve_full(&changed_owned)
        });
        resolve_budgeted(outcome, strict, changed_len, INCREMENTAL_WALL_BUDGET)
    })
}

/// The argv a detached reindex child re-runs: everything except `--detach`
/// itself, or the respawn would fork forever.
fn strip_detach_args<I: IntoIterator<Item = String>>(args: I) -> Vec<String> {
    args.into_iter().filter(|a| a != "--detach").collect()
}

/// Where a detached reindex child writes its output. One well-known path, so
/// "the background warm did nothing" is always answerable.
fn detached_log_path(cache_dir: &std::path::Path) -> PathBuf {
    cache_dir.join("reindex.log")
}

/// How long a background warm waits for a busy index. Generous on purpose:
/// it runs behind a commit with nobody watching, so waiting out a concurrent
/// scan costs nothing while giving up loses the entire reindex.
const INDEX_WARM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// `index init` / `index reindex`, both packet-stream and live modes.
///
/// Live mode (no --retrieved) is the background warm a post-commit hook
/// triggers: hash-gate the sources, re-retrieve ONLY the changed files
/// through the language helpers, store the fresh packets. Deliberately NOT
/// under the incremental wall budget — the budget protects the commit path,
/// and this runs behind it (with --detach, literally in the background).
fn run_index_build(
    cfg: &Config,
    path: Option<PathBuf>,
    retrieved: Option<PathBuf>,
    files: Option<String>,
    detach: bool,
) -> anyhow::Result<ExitCode> {
    if detach {
        // Respawn ourselves without --detach and (on unix) in a new process
        // group, so the hook's shell never waits and a terminal signal to the
        // commit never kills the warm.
        //
        // The child's output goes to a log file, never to /dev/null. Nobody
        // is watching a detached warm, so discarding its stderr means a
        // failed reindex looks exactly like a successful one: the parent has
        // already printed "detached ..." and exited 0 (po-l3jo5).
        let log_path = detached_log_path(&cfg.cache_dir);
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("opening detached reindex log at {}", log_path.display()))?;
        let log_err = log.try_clone()?;
        let exe = std::env::current_exe()?;
        let args = strip_detach_args(std::env::args().skip(1));
        let mut cmd = std::process::Command::new(exe);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log))
            .stderr(std::process::Stdio::from(log_err));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }
        let child = cmd.spawn()?;
        println!(
            "detached (pid {}): reindex continues in the background, logging to {}",
            child.id(),
            log_path.display()
        );
        return Ok(ExitCode::SUCCESS);
    }

    // The warm waits a long time for a busy index. It is a background batch
    // job; losing the whole reindex because a status check held the lock for
    // a few milliseconds is the bug this timeout exists to prevent.
    let idx = rvl_index::PacketIndex::open_with_timeout(
        &cfg.index_dir.join("packets.redb"),
        INDEX_WARM_TIMEOUT,
    )?;

    if let Some(retrieved) = retrieved {
        let stream = std::fs::read_to_string(&retrieved)?;
        let (sites, _, skipped) = rvl_core::parse_stream(&stream);
        // Group by originating file so each entry is keyed by that
        // file's current content hash.
        let mut by_file: std::collections::BTreeMap<String, Vec<rvl_core::Site>> =
            std::collections::BTreeMap::new();
        for s in sites {
            by_file.entry(s.file_path.clone()).or_default().push(s);
        }
        let (mut indexed, mut missing) = (0usize, 0usize);
        for (file, packets) in by_file {
            let path = PathBuf::from(&file);
            match rvl_index::hash_file(&path) {
                Ok(h) => {
                    idx.put(&path, &h, &packets)?;
                    indexed += 1;
                }
                // The stream can name files this checkout does not
                // have (foreign corpus); count them, never fail.
                Err(_) => missing += 1,
            }
        }
        println!("indexed {indexed} file(s) | unreadable {missing} | unparseable lines {skipped}");
        return Ok(ExitCode::SUCCESS);
    }

    // Live mode: run the helpers ourselves over the changed files.
    let root = path
        .unwrap_or_else(|| PathBuf::from("."))
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve repository root: {e}"))?;
    let candidates: Vec<PathBuf> = match files {
        Some(list) => list
            .split(',')
            .filter(|f| !f.trim().is_empty())
            .map(|f| root.join(f.trim()))
            .collect(),
        None => walk_source_files(&root),
    };
    anyhow::ensure!(
        !candidates.is_empty(),
        "no supported source files under {}; nothing to index",
        root.display()
    );

    let name = snapshot_name(&root);
    let retriever = HelperRetriever {
        root: root.clone(),
        name,
    };
    let scan = incremental_sites(&idx, &root, &candidates, |changed| {
        let (sites, repo_cfg) = retriever.retrieve_full(changed)?;
        Ok(RetrieveResult {
            sites,
            repo_cfg,
            degraded_note: None,
        })
    })?;
    println!(
        "reindexed: reused {} unchanged, retrieved {} changed",
        scan.reused_files, scan.retrieved_files
    );
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn run_scan_incremental(
    store: &CacheStore,
    keyset: &Keyset,
    index_dir: &std::path::Path,
    state_path: &std::path::Path,
    path: &std::path::Path,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
    color: Option<&str>,
    strict: bool,
) -> anyhow::Result<ExitCode> {
    let start = std::time::Instant::now();
    let scan = incremental_scan_pass(index_dir, path, strict)?;

    // One-line reuse summary to stderr; the ladder itself goes to stdout.
    eprintln!(
        "incremental: reused {} files from index, retrieved {} changed",
        scan.reused_files, scan.retrieved_files
    );
    if let Some(note) = &scan.degraded_note {
        eprintln!("incremental: degraded (fail-open): {note}");
    }

    let (findings, mut items, sites, specs) = findings_from_sites(
        store,
        keyset,
        scan.sites,
        &scan.repo_cfg,
        0,
        specs_file,
        judgments,
        Some(path),
        true,
    )?;
    // The content lane is cheap (one regex pass over the tree) and its rules
    // change with the binary, not the sources, so it runs FULL on every warm
    // scan rather than riding the packet index.
    items.extend(content_items(path));
    // Incremental scans own the live tree, so the structure lane inventories
    // it directly (one bounded walk; there is no packet stream to ride).
    let structure = resolve_structure_findings(None, "", path);
    // Config files are not content-hash indexed (parsing them is cheap): the
    // lane simply re-runs on every warm scan, so it can never be stale.
    let lane = config_lane::run(path, &specs, &snapshot_name(path));
    render_scan_output(
        state_path,
        path,
        &findings,
        &items,
        &sites,
        &structure,
        Some(&lane),
        out,
        color,
        start,
    )
}

/// Resolve a finding id the way the ladder's hint promises: from the LAST
/// SCAN's persisted state. Only when no dev override flags are given -- an
/// explicit --retrieved/--specs-file/--judgments asks for a live re-scan of
/// exactly those inputs, and gets one.
fn finding_from_last_scan(
    state_path: &std::path::Path,
    id: &str,
    overridden: bool,
) -> Option<(render::Finding, String)> {
    if overridden {
        return None;
    }
    let ls = load_last_scan(state_path)?;
    let f = ls.findings.iter().find(|f| f.id == id)?.clone();
    Some((f, ls.root))
}

#[allow(clippy::too_many_arguments)]
fn run_explain(
    store: &CacheStore,
    keyset: &Keyset,
    state_path: &std::path::Path,
    id: &str,
    path: &std::path::Path,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    color: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let overridden = retrieved.is_some() || specs_file.is_some() || judgments.is_some();
    // The id came from a ladder; the last scan's state is where it resolves.
    if let Some((f, root)) = finding_from_last_scan(state_path, id, overridden) {
        eprintln!("finding {id} from the last scan (of {root})");
        let incidents: Vec<(String, bool, String)> = Vec::new();
        print!(
            "{}",
            render::render_explain(&f, &incidents, stdout_color(color))
        );
        return Ok(ExitCode::SUCCESS);
    }
    let stream = resolve_packet_stream(retrieved, path)?;
    let (_findings, mut items, _sites, specs) = resolve_findings(
        store,
        keyset,
        &stream,
        specs_file,
        judgments,
        Some(path),
        false,
    )?;
    // Mirror the scan's content lane so a `secret.*` finding id resolves in
    // the live fallback too (skipped for --retrieved, same as scan).
    if retrieved.is_none() {
        items.extend(content_items(path));
    }
    let mut ladder_findings = triage_to_findings(&items);
    ladder_findings.extend(resolve_structure_findings(retrieved, &stream, path));
    // Config-lane ids resolve here too: the fresh scan mirrors what the
    // ladder printed, config rows included.
    ladder_findings.extend(config_lane::run(path, &specs, &snapshot_name(path)).findings);
    let Some(f) = ladder_findings.iter().find(|f| f.id == id) else {
        eprintln!(
            "no finding with id '{id}' in the last scan or in a fresh scan of {}; \
             ids come from `rvlscan scan` -- re-run it and use an id it prints",
            path.display()
        );
        return Ok(ExitCode::FAILURE);
    };
    // Named incident citations arrive from the corpus/judgment layer, which is
    // not yet wired; until then explain shows the structural evidence it has.
    let incidents: Vec<(String, bool, String)> = Vec::new();
    print!(
        "{}",
        render::render_explain(f, &incidents, stdout_color(color))
    );
    Ok(ExitCode::SUCCESS)
}

#[allow(clippy::too_many_arguments)]
fn run_suppress(
    store: &CacheStore,
    keyset: &Keyset,
    state_path: &std::path::Path,
    id: &str,
    path: Option<&std::path::Path>,
    reason: Option<&str>,
    expires: Option<&str>,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
) -> anyhow::Result<ExitCode> {
    let overridden = retrieved.is_some() || specs_file.is_some() || judgments.is_some();
    let cwd = PathBuf::from(".");
    // Resolve the id from the last scan first (the hint's contract), falling
    // back to the live resolve -> triage pipeline explain uses. The waiver file
    // goes to an explicitly given path, else the recorded scan root, else cwd.
    let (found, target): (render::Finding, PathBuf) =
        match finding_from_last_scan(state_path, id, overridden) {
            Some((f, root)) => {
                let target = path.map(Path::to_path_buf).unwrap_or(PathBuf::from(root));
                (f, target)
            }
            None => {
                let scan_path = path.unwrap_or(&cwd);
                let stream = resolve_packet_stream(retrieved, scan_path)?;
                let (_findings, mut items, _sites, specs) = resolve_findings(
                    store,
                    keyset,
                    &stream,
                    specs_file,
                    judgments,
                    Some(scan_path),
                    false,
                )?;
                // Same content-lane mirror as explain's live fallback.
                if retrieved.is_none() {
                    items.extend(content_items(scan_path));
                }
                let mut ladder_findings = triage_to_findings(&items);
                ladder_findings.extend(resolve_structure_findings(retrieved, &stream, scan_path));
                ladder_findings.extend(
                    config_lane::run(scan_path, &specs, &snapshot_name(scan_path)).findings,
                );
                let Some(f) = ladder_findings.iter().find(|f| f.id == id) else {
                    eprintln!(
                        "no finding with id '{id}' in the last scan or in a fresh scan of {}; \
                         ids come from `rvlscan scan` -- re-run it and use an id it prints",
                        scan_path.display()
                    );
                    return Ok(ExitCode::FAILURE);
                };
                (f.clone(), scan_path.to_path_buf())
            }
        };
    let f = &found;

    let w = waiver::Waiver {
        rule: f.class_rule.clone(),
        paths: vec![],
        expires: expires.unwrap_or("").trim().to_string(),
        reason: reason.unwrap_or("").trim().to_string(),
    };
    let file = target.join(".revelara.yaml");
    waiver::append_waiver(&file, &w)?;

    println!("waived rule `{}` (finding {})", f.class_rule, f.id);
    if !w.expires.is_empty() {
        println!("expires {}", w.expires);
    }
    println!("wrote {}", file.display());
    println!("this waiver is a local file; commit .revelara.yaml so your team shares it via git");
    Ok(ExitCode::SUCCESS)
}

/// The shape-only privacy report. Runs the SAME resolve->scan pipeline `scan`
/// uses to get findings + sites, then reduces to shape-only surfaces. Prints the
/// human-readable audit view by default, the exact JSON payload with `--json`,
/// and writes the JSON with `--out`. NEVER transmits: this shows/writes exactly
/// what a future upload would carry, nothing more.
#[allow(clippy::too_many_arguments)]
fn run_report(
    store: &CacheStore,
    keyset: &Keyset,
    index_dir: &std::path::Path,
    path: &std::path::Path,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    incremental: bool,
    json: bool,
    out: Option<&std::path::Path>,
) -> anyhow::Result<ExitCode> {
    // Reporting is local-only today: this command shows/writes the payload; it
    // does not transmit it.
    eprintln!(
        "note: reporting is local-only; this shows exactly what a scan WOULD send \
         to the spec factory (shape + counts only), it does not transmit anything"
    );

    // Same resolve->scan pipeline scan uses, via the shared building blocks.
    let (findings, sites) = if incremental && retrieved.is_none() {
        // report is read-only and never blocks a workflow: fail-open (strict=false).
        let scan = incremental_scan_pass(index_dir, path, false)?;
        eprintln!(
            "incremental: reused {} files from index, retrieved {} changed",
            scan.reused_files, scan.retrieved_files
        );
        if let Some(note) = &scan.degraded_note {
            eprintln!("incremental: degraded (fail-open): {note}");
        }
        let (findings, _items, sites, _specs) = findings_from_sites(
            store,
            keyset,
            scan.sites,
            &scan.repo_cfg,
            0,
            specs_file,
            None,
            Some(path),
            false,
        )?;
        (findings, sites)
    } else {
        let stream = resolve_packet_stream(retrieved, path)?;
        let (findings, _items, sites, _specs) =
            resolve_findings(store, keyset, &stream, specs_file, None, Some(path), false)?;
        (findings, sites)
    };

    let report = report::build_report(&sites, &findings, env!("CARGO_PKG_VERSION"));
    let payload = serde_json::to_string_pretty(&report)?;

    if let Some(p) = out {
        std::fs::write(p, &payload)
            .with_context(|| format!("writing report JSON to {}", p.display()))?;
        eprintln!("wrote report payload to {}", p.display());
    }

    if json {
        // The exact payload the wire would carry: shape + counts, nothing else.
        println!("{payload}");
    } else {
        print!("{}", render_report_human(&report));
    }
    Ok(ExitCode::SUCCESS)
}

/// The human-readable report: an explicit header stating precisely what would
/// leave and that it carries no source/paths, the `site_count  client_type.method`
/// table, and a total-surface footer. This visibility IS the privacy feature.
fn render_report_human(report: &report::Report) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str(
        "This is EXACTLY what a scan would send to the Revelara spec factory.\n\
         It contains ONLY API shape (client_type.method) and a per-surface count.\n\
         No source code, no file paths, no line numbers, nothing repo-identifying \
         ever leaves this machine.\n\n",
    );

    if report.surfaces.is_empty() {
        s.push_str("No unknown API surfaces: nothing would be reported.\n");
        return s;
    }

    // Width the count column to the widest count for a clean right-aligned table.
    let w = report
        .surfaces
        .iter()
        .map(|r| r.site_count.to_string().len())
        .max()
        .unwrap_or(1)
        .max("sites".len());
    let _ = writeln!(s, "  {:>w$}  surface", "sites", w = w);
    let _ = writeln!(s, "  {:>w$}  -------", "-".repeat(w), w = w);
    for r in &report.surfaces {
        let _ = writeln!(
            s,
            "  {:>w$}  {}.{}",
            r.site_count,
            r.client_type,
            r.method,
            w = w
        );
    }
    let _ = writeln!(
        s,
        "\n{} unknown API surface(s) would be reported.",
        report.surfaces.len()
    );
    s
}

// --- skills distribution: install workflow skills/lenses into harnesses (po-av01j.14) ---

/// Is `binary` a file on PATH? Used only to decide between running the
/// Claude Code registration commands and printing them for manual use.
fn binary_on_path(binary: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|d| d.join(binary).is_file())
}

/// Print a registration's commands in copy-pasteable form.
fn print_registration_commands(reg: &rvl_skills::harness::Registration) {
    for argv in &reg.commands {
        println!("  {} {}", reg.binary, argv.join(" "));
    }
}

/// Run the harness registration commands (e.g. `claude plugin marketplace
/// add`). The first command is cleanup and may fail harmlessly; any later
/// failure falls back to printing the remaining commands for manual use.
fn run_registration(reg: &rvl_skills::harness::Registration) {
    for (i, argv) in reg.commands.iter().enumerate() {
        let result = std::process::Command::new(reg.binary).args(argv).output();
        let ok = match &result {
            Ok(out) => out.status.success(),
            Err(_) => false,
        };
        if ok || i == 0 {
            continue; // cleanup (i == 0) is best-effort: nothing to remove is fine
        }
        let detail = match result {
            Ok(out) => String::from_utf8_lossy(&out.stderr).trim().to_string(),
            Err(e) => e.to_string(),
        };
        eprintln!(
            "registration step '{} {}' failed: {detail}",
            reg.binary,
            argv.join(" ")
        );
        eprintln!("finish registration manually:");
        for argv in &reg.commands[i..] {
            eprintln!("  {} {}", reg.binary, argv.join(" "));
        }
        return;
    }
    println!("registered with {}", reg.binary);
}

/// Print one install's outcome and handle its registration step.
fn render_install_report(report: &rvl_skills::flow::InstallReport, no_register: bool) {
    let source = if report.from_cache {
        " (from cache)"
    } else {
        ""
    };
    println!(
        "installed {} skills {}{source}: {} file(s) at {}",
        report.harness,
        report.version,
        report.receipt.files_written,
        report.receipt.location.display()
    );
    for w in &report.warnings {
        eprintln!("  warning: {w}");
    }
    if let Some(reg) = &report.receipt.register {
        if no_register {
            println!("skipping registration (--no-register); to register manually:");
            print_registration_commands(reg);
        } else if binary_on_path(reg.binary) {
            run_registration(reg);
        } else {
            println!(
                "'{}' not found on PATH; to register once it is:",
                reg.binary
            );
            print_registration_commands(reg);
        }
    }
    println!("  {}", report.receipt.note);
}

/// Install or update the named harness, or every relevant one when omitted
/// (install: detected harnesses; update: previously installed harnesses,
/// falling back to detection). Mirrors `rvl plugin install/update`.
fn run_skills_install(
    env: &rvl_skills::flow::Env,
    harness: Option<String>,
    no_register: bool,
    update: bool,
) -> anyhow::Result<ExitCode> {
    let supported = || rvl_skills::harness::supported_names().join(", ");
    let targets: Vec<String> = match harness {
        Some(name) => {
            anyhow::ensure!(
                rvl_skills::harness::by_name(&name).is_some(),
                "unsupported harness: {name} (supported: {})",
                supported()
            );
            vec![name]
        }
        None => {
            let mut names: Vec<String> = if update {
                env.store.read_installed().keys().cloned().collect()
            } else {
                Vec::new()
            };
            if names.is_empty() {
                names = rvl_skills::harness::detect_installed(env.home);
            }
            if names.is_empty() {
                println!(
                    "No supported coding-agent harness detected (supported: {}).",
                    supported()
                );
                println!("Install one, or name it explicitly: rvlscan skills install <harness>");
                return Ok(ExitCode::SUCCESS);
            }
            names
        }
    };

    let mut failed = 0usize;
    for name in &targets {
        // by_name is total over `targets` by construction; skip defensively.
        let Some(h) = rvl_skills::harness::by_name(name) else {
            continue;
        };
        match rvl_skills::flow::install_one(env, h.as_ref()) {
            Ok(report) => render_install_report(&report, no_register),
            Err(e) => {
                eprintln!("{name}: {e}");
                failed += 1;
            }
        }
    }
    Ok(if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Render the drift report, mirroring `rvl plugin list`'s UX.
fn render_skills_status(report: &rvl_skills::flow::StatusReport) {
    match (&report.served_version, &report.server_note) {
        (Some(v), _) => println!("Served plugin version: {v}"),
        (None, Some(note)) => println!("Served plugin version: unknown ({note})"),
        (None, None) => println!("Served plugin version: unknown"),
    }

    if report.harnesses.is_empty() {
        println!("\nNo skills installed. Run 'rvlscan skills install'.");
    } else {
        println!("\nInstalled:");
        let mut drift = false;
        for h in &report.harnesses {
            let state = match &h.update_available {
                Some(v) => {
                    drift = true;
                    format!("update available: {v}")
                }
                None if report.served_version.is_some() => "up to date".to_string(),
                None => "server version unknown".to_string(),
            };
            println!(
                "  {:<10} {:<10} ({state})  {}",
                h.harness, h.installed_version, h.location
            );
        }
        if drift {
            println!("\nRun 'rvlscan skills update' to upgrade.");
        }
    }

    if !report.cached.is_empty() {
        println!("\nCached:");
        for c in &report.cached {
            println!(
                "  {:<10} {:<10} (fetched {})",
                c.editor, c.version, c.fetched_at
            );
        }
    }
}

/// `rvlscan skills`: resolve env/config once, then dispatch. Uses the same
/// base URL/org key resolution as `sync` (rvlscan env > rvl-cli env >
/// shared config file) and the spec cache's offline kill switch.
fn run_skills(cfg: &Config, cmd: SkillsCmd) -> anyhow::Result<ExitCode> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("HOME is not set; cannot locate harness directories"))?;
    let skills_cache_dir = std::env::var_os("RVLSCAN_SKILLS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".revelara").join("cache").join("skills"));
    let store = rvl_skills::store::SkillsStore::open(&skills_cache_dir)?;
    let fetcher = rvl_skills::fetch::HttpFetcher {
        base_url: cfg.base_url.clone(),
        org_key: cfg.org_key.clone(),
    };
    let env = rvl_skills::flow::Env {
        store: &store,
        fetcher: &fetcher,
        home: &home,
        offline: cfg.offline,
        allow_unsigned: std::env::var("RVLSCAN_ALLOW_UNSIGNED").ok().as_deref() == Some("1"),
        allow_missing_checksum: std::env::var("RVLSCAN_ALLOW_MISSING_CHECKSUM")
            .ok()
            .as_deref()
            == Some("1"),
    };
    let require_key = || {
        anyhow::ensure!(
            cfg.offline || !cfg.org_key.is_empty(),
            "no API key found: set RVLSCAN_ORG_KEY or RVL_API_KEY, or add \
             `api_key` to ~/.revelara/config.yaml (or set RVLSCAN_OFFLINE=1 \
             to install from the local cache)"
        );
        Ok(())
    };
    match cmd {
        SkillsCmd::Install {
            harness,
            no_register,
        } => {
            require_key()?;
            run_skills_install(&env, harness, no_register, false)
        }
        SkillsCmd::Update {
            harness,
            no_register,
        } => {
            require_key()?;
            run_skills_install(&env, harness, no_register, true)
        }
        SkillsCmd::Status => {
            render_skills_status(&rvl_skills::flow::status(&env));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let Some(cmd) = cli.cmd else {
        // Bootstrap behavior preserved: bare invocation prints help, exits 0.
        use clap::CommandFactory;
        Cli::command().print_help()?;
        return Ok(ExitCode::SUCCESS);
    };
    let cfg = Config::from_env();
    let store = CacheStore::open(&cfg.cache_dir)?;
    let keyset = Keyset::from_hex(rvl_cache::DEV_KEYSET_HEX)?;
    let state_path = last_scan_path(&cfg.cache_dir);
    match cmd {
        Cmd::Scan {
            path,
            retrieved,
            specs_file,
            judgments,
            out,
            color,
            incremental,
            strict,
        } => {
            let path = path.unwrap_or_else(|| PathBuf::from("."));
            // `--incremental` only applies when we own retrieval; `--retrieved`
            // is a prebuilt stream with no per-file hash gate to reuse.
            if incremental && retrieved.is_none() {
                run_scan_incremental(
                    &store,
                    &keyset,
                    &cfg.index_dir,
                    &state_path,
                    &path,
                    specs_file.as_deref(),
                    judgments.as_deref(),
                    out.as_deref(),
                    color.as_deref(),
                    strict,
                )
            } else {
                run_scan(
                    &store,
                    &keyset,
                    &state_path,
                    &path,
                    retrieved.as_deref(),
                    specs_file.as_deref(),
                    judgments.as_deref(),
                    out.as_deref(),
                    color.as_deref(),
                )
            }
        }
        Cmd::Report {
            path,
            retrieved,
            specs_file,
            incremental,
            json,
            out,
        } => run_report(
            &store,
            &keyset,
            &cfg.index_dir,
            &path.unwrap_or_else(|| PathBuf::from(".")),
            retrieved.as_deref(),
            specs_file.as_deref(),
            incremental,
            json,
            out.as_deref(),
        ),
        Cmd::Explain {
            id,
            path,
            retrieved,
            specs_file,
            judgments,
            color,
        } => run_explain(
            &store,
            &keyset,
            &state_path,
            &id,
            &path.unwrap_or_else(|| PathBuf::from(".")),
            retrieved.as_deref(),
            specs_file.as_deref(),
            judgments.as_deref(),
            color.as_deref(),
        ),
        Cmd::Suppress {
            id,
            path,
            reason,
            expires,
            retrieved,
            specs_file,
            judgments,
        } => run_suppress(
            &store,
            &keyset,
            &state_path,
            &id,
            path.as_deref(),
            reason.as_deref(),
            expires.as_deref(),
            retrieved.as_deref(),
            specs_file.as_deref(),
            judgments.as_deref(),
        ),
        Cmd::Sync => {
            if !cfg.offline && cfg.org_key.is_empty() {
                anyhow::bail!(
                    "no API key found: set RVLSCAN_ORG_KEY or RVL_API_KEY, or add \
                     `api_key` to ~/.revelara/config.yaml (or set RVLSCAN_OFFLINE=1)"
                );
            }
            let fetcher = HttpFetcher {
                base_url: cfg.base_url,
                org_key: cfg.org_key,
            };
            Ok(report(&rvl_cache::sync(
                &store,
                &fetcher,
                &keyset,
                cfg.offline,
            )))
        }
        Cmd::Index { cmd } => match cmd {
            IndexCmd::Init { path, retrieved } => {
                run_index_build(&cfg, path, retrieved, None, false)
            }
            IndexCmd::Reindex {
                path,
                retrieved,
                files,
                detach,
            } => run_index_build(&cfg, path, retrieved, files, detach),
            IndexCmd::Status => {
                match rvl_index::PacketIndex::open(&cfg.index_dir.join("packets.redb")) {
                    Ok(idx) => {
                        println!(
                            "{} file(s) indexed at {}",
                            idx.len()?,
                            cfg.index_dir.display()
                        );
                        Ok(ExitCode::SUCCESS)
                    }
                    // A busy index is a normal transient state, not a broken
                    // one. Say so plainly instead of reporting it as a
                    // failure to open the database.
                    Err(e) if e.downcast_ref::<rvl_index::IndexBusy>().is_some() => {
                        eprintln!("{e}");
                        Ok(ExitCode::FAILURE)
                    }
                    Err(e) => Err(e),
                }
            }
        },
        Cmd::Cache { cmd } => match cmd {
            CacheCmd::Import { artifact, sig } => {
                let sig = sig.unwrap_or_else(|| {
                    let mut p = artifact.clone().into_os_string();
                    p.push(".sig");
                    PathBuf::from(p)
                });
                Ok(report(&store.import(&artifact, &sig, &keyset)?))
            }
            CacheCmd::Status => {
                match store.load(&keyset, &rvl_cache::today_utc()) {
                    Ok(loaded) => {
                        println!(
                            "spec cache {} (schema {}, {:?})",
                            loaded.envelope.content_version, loaded.envelope.schema, loaded.source
                        );
                        println!("artifact sha256 {}", loaded.artifact_sha256);
                        if let Some(hint) = loaded.upgrade_hint {
                            println!("{hint}");
                        }
                        if let Some(note) = loaded.staleness_note {
                            println!("{note}");
                        }
                    }
                    Err(_) => {
                        println!(
                            "no spec cache installed; run 'rvlscan sync' or 'rvlscan cache import'"
                        )
                    }
                }
                Ok(ExitCode::SUCCESS)
            }
        },
        Cmd::Skills { cmd } => run_skills(&cfg, cmd),
    }
}

/// Rust sets SIGPIPE to SIG_IGN before main, so writing to a closed pipe
/// returns EPIPE and `println!` panics. A scanner is piped into `head`,
/// `less`, and `grep -q` constantly; restore the default disposition so the
/// process dies quietly the way every other unix tool does.
#[cfg(unix)]
fn restore_default_sigpipe() {
    // SAFETY: setting a signal disposition to the OS default before any
    // output happens; no handler state to race with.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn restore_default_sigpipe() {}

fn main() -> ExitCode {
    restore_default_sigpipe();
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes tests that mutate process-global env so they don't race.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn strip_detach_removes_only_the_detach_flag() {
        let args = vec![
            "index".to_string(),
            "reindex".to_string(),
            "--detach".to_string(),
            "/some/repo".to_string(),
            "--files".to_string(),
            "a.go,b.go".to_string(),
        ];
        assert_eq!(
            strip_detach_args(args),
            vec!["index", "reindex", "/some/repo", "--files", "a.go,b.go"],
            "everything except --detach must survive, or the child re-forks forever"
        );
    }

    fn touch(path: &Path) {
        std::fs::write(path, "").unwrap();
    }

    #[test]
    fn structure_violations_render_advisory_never_blocking() {
        let violate = rvl_structure::StructureFinding {
            control: "RC-033",
            control_name: "unit test coverage",
            verdict: rvl_core::Verdict::Violates,
            reason: "no test files: go (40 source files)".into(),
            evidence: vec![],
            fix: "add unit tests".into(),
            severity: "medium",
            weak: false,
        };
        let satisfies = rvl_structure::StructureFinding {
            control: "RC-006",
            control_name: "incident runbooks",
            verdict: rvl_core::Verdict::Satisfies,
            reason: "runbook directory present".into(),
            evidence: vec!["docs/runbooks".into()],
            fix: String::new(),
            severity: "",
            weak: true,
        };
        let fs = structure_to_findings(&[violate, satisfies]);
        assert_eq!(fs.len(), 1, "only violations surface in the ladder");
        let f = &fs[0];
        assert_eq!(f.control, "RC-033", "control code rides into the ladder");
        assert_eq!(
            f.class_rule, "repo_structure.RC-033",
            "waiver key lets suppress/.revelara.yaml target it"
        );
        assert_eq!(
            render::classify(f),
            render::Section::Advisory,
            "a structural shape must never block a commit"
        );
    }

    #[test]
    fn live_scan_structure_findings_inventory_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("go.mod"), "module example.com/x\n").unwrap();
        for i in 0..6 {
            std::fs::write(
                dir.path().join(format!("f{i}.go")),
                "package x\nfunc F() {}\n",
            )
            .unwrap();
        }
        let fs = resolve_structure_findings(None, "", dir.path());
        assert!(
            fs.iter().any(|f| f.control == "RC-033"),
            "an untested live tree must surface RC-033: {fs:?}"
        );
    }

    #[test]
    fn retrieved_stream_without_a_record_yields_no_structure_findings() {
        // A prebuilt stream may predate the G7 retriever; no facts means no
        // findings — never a fabricated inventory of the CURRENT directory,
        // which is a different repo than the stream describes.
        let fs = resolve_structure_findings(
            Some(Path::new("prebuilt.jsonl")),
            r#"{"file_path":"a.go","line_number":1,"func":"Do","client_type":"c"}"#,
            Path::new("."),
        );
        assert!(fs.is_empty(), "no record, no findings: {fs:?}");
    }

    #[test]
    fn detect_go_only() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("main.go"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::Go]);
    }

    #[test]
    fn detect_python_only() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("app.py"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::Python]);
    }

    #[test]
    fn detect_both_is_go_then_python() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("main.go"));
        touch(&dir.path().join("app.py"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::Go, Lang::Python]);
    }

    #[test]
    fn detect_typescript_only() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("app.ts"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::TypeScript]);
    }

    #[test]
    fn detect_typescript_via_tsconfig() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("tsconfig.json"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::TypeScript]);
    }

    #[test]
    fn detect_tsx_counts_but_dts_does_not() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("component.tsx"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::TypeScript]);

        // A directory whose only TS file is a `.d.ts` is types-only: no helper.
        let dts_only = tempfile::tempdir().unwrap();
        touch(&dts_only.path().join("types.d.ts"));
        assert!(detect_languages(dts_only.path()).is_empty());
    }

    #[test]
    fn detect_neither_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("README.md"));
        assert!(detect_languages(dir.path()).is_empty());
    }

    #[test]
    fn detect_via_marker_files() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("go.mod"));
        touch(&dir.path().join("pyproject.toml"));
        assert_eq!(detect_languages(dir.path()), vec![Lang::Go, Lang::Python]);
    }

    #[test]
    fn detect_skips_vendored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&nested).unwrap();
        touch(&nested.join("bundled.go"));
        // The only .go file is under node_modules, which is skipped.
        assert!(detect_languages(dir.path()).is_empty());
    }

    #[test]
    fn go_helper_argv_is_direct_invocation() {
        let helper = ResolvedHelper {
            path: PathBuf::from("/opt/goindex"),
            kind: HelperKind::Executable,
        };
        let argv = helper_argv(&helper, Path::new("/repo"), "repo", &[]);
        assert_eq!(
            argv,
            vec![
                "/opt/goindex",
                "--retrieve",
                "--root",
                "/repo",
                "--name",
                "repo"
            ]
        );
    }

    #[test]
    fn python_script_argv_runs_under_python3() {
        let helper = ResolvedHelper {
            path: PathBuf::from("/opt/pyindex.py"),
            kind: HelperKind::PyScript,
        };
        let argv = helper_argv(&helper, Path::new("/repo"), "repo", &[]);
        assert_eq!(
            argv,
            vec![
                "python3",
                "/opt/pyindex.py",
                "--retrieve",
                "--root",
                "/repo",
                "--name",
                "repo"
            ]
        );
    }

    #[test]
    fn ts_node_script_argv_runs_under_node() {
        let helper = ResolvedHelper {
            path: PathBuf::from("/opt/tsindex.js"),
            kind: HelperKind::NodeScript,
        };
        let argv = helper_argv(&helper, Path::new("/repo"), "repo", &[]);
        assert_eq!(
            argv,
            vec![
                "node",
                "/opt/tsindex.js",
                "--retrieve",
                "--root",
                "/repo",
                "--name",
                "repo"
            ]
        );
    }

    #[test]
    fn classify_typescript_js_is_a_script_but_bin_is_executable() {
        assert_eq!(
            classify_helper(Lang::TypeScript, Path::new("/x/tsindex.js")).kind,
            HelperKind::NodeScript
        );
        assert_eq!(
            classify_helper(Lang::TypeScript, Path::new("/x/tsindex")).kind,
            HelperKind::Executable
        );
    }

    #[test]
    fn lang_of_path_maps_ts_but_not_dts() {
        assert_eq!(
            lang_of_path(Path::new("svc/app.ts")),
            Some(Lang::TypeScript)
        );
        assert_eq!(
            lang_of_path(Path::new("svc/view.tsx")),
            Some(Lang::TypeScript)
        );
        assert_eq!(lang_of_path(Path::new("svc/types.d.ts")), None);
    }

    #[test]
    fn helper_argv_appends_files_for_changed_only() {
        let helper = ResolvedHelper {
            path: PathBuf::from("/opt/goindex"),
            kind: HelperKind::Executable,
        };
        let changed = vec!["svc/db.go".to_string(), "svc/http.go".to_string()];
        let argv = helper_argv(&helper, Path::new("/repo"), "repo", &changed);
        assert_eq!(
            argv,
            vec![
                "/opt/goindex",
                "--retrieve",
                "--root",
                "/repo",
                "--name",
                "repo",
                "--files",
                "svc/db.go,svc/http.go",
            ],
            "the incremental path passes only the changed files via --files"
        );
        // The full path (no --files) is unchanged.
        assert!(
            !helper_argv(&helper, Path::new("/repo"), "repo", &[]).contains(&"--files".to_string())
        );
    }

    #[test]
    fn repo_relative_is_forward_slashed_under_root() {
        let root = Path::new("/repo");
        assert_eq!(
            repo_relative(root, Path::new("/repo/svc/db.go")),
            "svc/db.go"
        );
        assert_eq!(repo_relative(root, Path::new("/repo/main.go")), "main.go");
    }

    fn site_at(path: &str, line: u32, client: &str, method: &str) -> rvl_core::Site {
        rvl_core::Site {
            file_path: path.into(),
            line_number: line,
            client_type: client.into(),
            method: method.into(),
            ..Default::default()
        }
    }

    #[test]
    fn merge_keeps_two_sites_sharing_a_location() {
        // po-3t3oj.15: one file:line resolves to two sites with different client
        // types. A file:line-keyed merge would drop one; site_key keeps both.
        let a = site_at("svc/x.go", 306, "drive.Service", "Do");
        let b = site_at("svc/x.go", 306, "http.Client", "Do");
        let merged = merge_on_site_key(vec![a.clone()], vec![b.clone()]);
        assert_eq!(merged.len(), 2, "colliding location must not drop a site");
        // A genuine duplicate (same site_key) IS collapsed.
        let dup = merge_on_site_key(vec![a.clone()], vec![a]);
        assert_eq!(dup.len(), 1);
    }

    #[test]
    fn site_key_collision_round_trips_through_index_and_reload() {
        // Two sites at the SAME file:line, different client_type, must survive
        // put -> get -> plan_reload without collision.
        let dir = tempfile::tempdir().unwrap();
        let idx = rvl_index::PacketIndex::open(&dir.path().join("packets.redb")).unwrap();
        let f = dir.path().join("x.go");
        std::fs::write(&f, "package x\n").unwrap();
        let h = rvl_index::hash_file(&f).unwrap();
        let both = vec![
            site_at("x.go", 306, "drive.Service", "Do"),
            site_at("x.go", 306, "http.Client", "Do"),
        ];
        idx.put(&f, &h, &both).unwrap();

        let got = idx.get(&f, &h).unwrap().expect("hash matches");
        assert_eq!(got.len(), 2, "both colliding sites stored and returned");
        let keys: std::collections::HashSet<_> = got.iter().map(rvl_index::site_key).collect();
        assert_eq!(keys.len(), 2, "the two sites keep distinct site_keys");

        // The unchanged file reloads from the index (reuse), not re-retrieval.
        let plan = idx.plan_reload(std::slice::from_ref(&f));
        assert_eq!(plan.unchanged, vec![f]);
        assert!(plan.changed.is_empty());
    }

    #[test]
    fn incremental_reuses_unchanged_and_retrieves_only_changed() {
        use std::cell::Cell;
        let dir = tempfile::tempdir().unwrap();
        let idx = rvl_index::PacketIndex::open(&dir.path().join("packets.redb")).unwrap();
        let warm = dir.path().join("warm.go");
        let cold = dir.path().join("cold.go");
        std::fs::write(&warm, "package warm\n").unwrap();
        std::fs::write(&cold, "package cold\n").unwrap();
        // Pre-index warm.go so it is reused.
        idx.put(
            &warm,
            &rvl_index::hash_file(&warm).unwrap(),
            &[site_at("warm.go", 9, "p.C", "Warm")],
        )
        .unwrap();

        let calls = Cell::new(0usize);
        // Fake retriever: echoes one site per changed file, repo-relative pathed.
        let fake = |changed: &[PathBuf]| {
            calls.set(calls.get() + 1);
            let sites = changed
                .iter()
                .map(|c| site_at(&repo_relative(dir.path(), c), 1, "p.C", "Do"))
                .collect();
            Ok(RetrieveResult {
                sites,
                repo_cfg: rvl_core::RepoConfig::default(),
                degraded_note: None,
            })
        };
        let candidates = walk_source_files(dir.path());
        let scan = incremental_sites(&idx, dir.path(), &candidates, fake).unwrap();
        assert_eq!(scan.reused_files, 1);
        assert_eq!(scan.retrieved_files, 1);
        assert_eq!(scan.sites.len(), 2, "1 reused + 1 retrieved");
        assert_eq!(
            calls.get(),
            1,
            "retriever invoked once, for the changed file"
        );

        // Second pass: nothing changed, the retriever is not invoked at all.
        let calls2 = Cell::new(0usize);
        let fake2 = |changed: &[PathBuf]| {
            calls2.set(calls2.get() + 1);
            Ok(RetrieveResult {
                sites: changed
                    .iter()
                    .map(|c| site_at(&repo_relative(dir.path(), c), 1, "p.C", "Do"))
                    .collect(),
                repo_cfg: rvl_core::RepoConfig::default(),
                degraded_note: None,
            })
        };
        let scan2 = incremental_sites(&idx, dir.path(), &candidates, fake2).unwrap();
        assert_eq!(scan2.reused_files, 2, "both files now reused");
        assert_eq!(scan2.retrieved_files, 0);
        assert_eq!(calls2.get(), 0, "no helper run when nothing changed");
    }

    #[test]
    fn budget_timeout_fails_open_but_strict_fails_closed() {
        let cap = std::time::Duration::from_millis(10);
        // Fail-open: a timeout degrades to the reused portion with a note.
        let open = resolve_budgeted(Budgeted::TimedOut, false, 3, cap).unwrap();
        assert!(open.sites.is_empty());
        assert!(
            open.degraded_note.is_some(),
            "degradation must be explained"
        );
        // --strict: a timeout is an error naming the budget.
        let err = resolve_budgeted(Budgeted::TimedOut, true, 3, cap).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("budget"));
    }

    #[test]
    fn budget_retriever_error_fails_open_but_strict_propagates() {
        let cap = std::time::Duration::from_secs(10);
        let mk = || Budgeted::Failed(anyhow::anyhow!("helper missing"));
        // Fail-open: an error degrades, keeping the scan alive.
        let open = resolve_budgeted(mk(), false, 1, cap).unwrap();
        assert!(open.sites.is_empty());
        assert!(open.degraded_note.unwrap().contains("helper missing"));
        // --strict: the error propagates.
        let err = resolve_budgeted(mk(), true, 1, cap).unwrap_err();
        assert!(err.to_string().contains("helper missing"));
    }

    #[test]
    fn run_with_budget_returns_done_and_times_out() {
        // Fast closure completes.
        match run_with_budget(std::time::Duration::from_secs(5), || Ok(7u32)) {
            Budgeted::Done(v) => assert_eq!(v, 7),
            _ => panic!("a fast closure must complete within the cap"),
        }
        // Slow closure trips the (tiny, injected) cap.
        let slow = run_with_budget(std::time::Duration::from_millis(10), || {
            std::thread::sleep(std::time::Duration::from_millis(300));
            Ok(0u32)
        });
        assert!(matches!(slow, Budgeted::TimedOut), "the wall cap must fire");
    }

    #[test]
    fn classify_python_py_is_a_script_but_bin_is_executable() {
        assert_eq!(
            classify_helper(Lang::Python, Path::new("/x/pyindex.py")).kind,
            HelperKind::PyScript
        );
        assert_eq!(
            classify_helper(Lang::Python, Path::new("/x/pyindex")).kind,
            HelperKind::Executable
        );
        assert_eq!(
            classify_helper(Lang::Go, Path::new("/x/goindex")).kind,
            HelperKind::Executable
        );
    }

    #[test]
    fn resolve_helper_env_override_wins() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("my-goindex");
        touch(&fake);
        std::env::set_var("RVLSCAN_GOINDEX", &fake);
        let resolved = resolve_helper(Lang::Go);
        std::env::remove_var("RVLSCAN_GOINDEX");
        let resolved = resolved.expect("env override must resolve");
        assert_eq!(resolved.path, fake);
        assert_eq!(resolved.kind, HelperKind::Executable);
    }

    #[test]
    fn resolve_helper_env_override_missing_file_errors() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("RVLSCAN_GOINDEX", "/definitely/not/here/goindex");
        let resolved = resolve_helper(Lang::Go);
        std::env::remove_var("RVLSCAN_GOINDEX");
        assert!(resolved.is_err(), "a missing override path must error");
    }

    fn ladder_finding(id: &str) -> render::Finding {
        render::Finding {
            id: id.to_string(),
            site: "src/a.ts:12".into(),
            description: "no bound anywhere".into(),
            disposition: "unjudged".into(),
            severity: String::new(),
            incident_count: 0,
            critical_count: 0,
            control: String::new(),
            fix: String::new(),
            site_count: 3,
            example_sites: vec!["src/a.ts:12".into()],
            class_rule: "kysely.SelectQueryBuilder.execute".into(),
            suppressed: false,
        }
    }

    #[test]
    fn explain_hint_resolves_from_the_persisted_last_scan() {
        // Regression (po-3t3oj.38): the ladder prints `rvlscan explain <id>`;
        // that verbatim command must find the id WITHOUT re-running the scan's
        // inputs. Persist a ladder, then resolve the id from the state file.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("last-scan.json");
        save_last_scan(&state, dir.path(), &[ladder_finding("qocr")]);

        let (f, root) =
            finding_from_last_scan(&state, "qocr", false).expect("id must resolve from state");
        assert_eq!(f.class_rule, "kysely.SelectQueryBuilder.execute");
        assert_eq!(
            std::path::PathBuf::from(&root),
            std::fs::canonicalize(dir.path()).unwrap(),
            "suppress needs the recorded scan root for its waiver file"
        );
        assert!(
            finding_from_last_scan(&state, "zzzz", false).is_none(),
            "an id from a different scan must fall through to a live re-scan"
        );
    }

    #[test]
    fn explicit_dev_overrides_bypass_the_last_scan_state() {
        // --retrieved/--specs-file/--judgments ask for a live re-scan of those
        // exact inputs; stale state must not shadow them.
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("last-scan.json");
        save_last_scan(&state, dir.path(), &[ladder_finding("qocr")]);
        assert!(finding_from_last_scan(&state, "qocr", true).is_none());
    }

    #[test]
    fn missing_or_corrupt_state_is_just_no_last_scan() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("last-scan.json");
        assert!(load_last_scan(&state).is_none(), "missing file");
        std::fs::write(&state, "not json").unwrap();
        assert!(load_last_scan(&state).is_none(), "corrupt file");
    }
}
