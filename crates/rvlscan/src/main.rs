use std::io::IsTerminal;
mod render;
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
}

#[derive(Subcommand)]
enum IndexCmd {
    /// Build the index from a retriever packet stream. Explicit and off the
    /// hook path: a cold full load is never paid during a commit.
    Init {
        #[arg(long)]
        retrieved: PathBuf,
    },
    /// Re-index from a packet stream. What a post-commit hook invokes.
    Reindex {
        #[arg(long)]
        retrieved: PathBuf,
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
                control: String::new(),
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
fn resolve_findings(
    store: &CacheStore,
    keyset: &Keyset,
    stream: &str,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    verbose: bool,
) -> anyhow::Result<(
    Vec<rvl_propagate::Finding>,
    Vec<rvl_triage::TriagedItem>,
    Vec<rvl_core::Site>,
)> {
    let (sites, repo_cfg, skipped) = rvl_core::parse_stream(stream);
    findings_from_sites(
        store, keyset, sites, &repo_cfg, skipped, specs_file, judgments, verbose,
    )
}

/// The pipeline shared by the packet-stream path and the incremental path:
/// verified specs + already-assembled sites -> propagation -> triage. The
/// incremental caller hands its merged (reused + freshly retrieved) sites here
/// directly, skipping `parse_stream`.
#[allow(clippy::too_many_arguments)]
fn findings_from_sites(
    store: &CacheStore,
    keyset: &Keyset,
    sites: Vec<rvl_core::Site>,
    repo_cfg: &rvl_core::RepoConfig,
    skipped: usize,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    verbose: bool,
) -> anyhow::Result<(
    Vec<rvl_propagate::Finding>,
    Vec<rvl_triage::TriagedItem>,
    Vec<rvl_core::Site>,
)> {
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
            println!(
                "spec cache {} (schema {}, {:?})",
                loaded.envelope.content_version, loaded.envelope.schema, loaded.source
            );
            serde_json::to_string(&loaded.envelope.specs)?
        }
    };

    anyhow::ensure!(
        !sites.is_empty(),
        "no parseable sites in the retrieved packet stream"
    );
    let cache = rvl_spec::SpecCache::load(&specs_text)?;
    let served = cache.served_bound(repo_cfg);
    let findings = rvl_propagate::propagate_all(&sites, &cache, &served);

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
    let verdict_rows: Vec<(String, rvl_core::Verdict, String)> = findings
        .iter()
        .map(|f| (f.site_id.clone(), f.verdict, f.reason.clone()))
        .collect();
    let items = rvl_triage::triage(&sites, &verdict_rows, &judgments);
    Ok((findings, items, sites))
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
    path: &std::path::Path,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
    color: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let start = std::time::Instant::now();
    let stream = resolve_packet_stream(retrieved, path)?;
    let (findings, items, sites) =
        resolve_findings(store, keyset, &stream, specs_file, judgments, true)?;
    render_scan_output(path, &findings, &items, &sites, out, color, start)
}

/// Render the ladder + optional `--out` JSON for a completed scan. Shared by
/// the packet-stream path and the incremental path so both report identically.
fn render_scan_output(
    path: &std::path::Path,
    findings: &[rvl_propagate::Finding],
    items: &[rvl_triage::TriagedItem],
    sites: &[rvl_core::Site],
    out: Option<&std::path::Path>,
    color: Option<&str>,
    start: std::time::Instant,
) -> anyhow::Result<ExitCode> {
    let decided = findings.iter().filter(|f| f.verdict.is_decided()).count();
    let unknown = findings
        .iter()
        .filter(|f| f.reason.starts_with("no spec"))
        .count();
    let coverage = render::Coverage {
        decided,
        total: sites.len(),
        unknown,
    };
    let mut ladder_findings = triage_to_findings(items);

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

    let elapsed = format!("scan complete in {:.2}s", start.elapsed().as_secs_f64());
    print!(
        "{}",
        render::render_ladder(&ladder_findings, coverage, &elapsed, stdout_color(color))
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

#[allow(clippy::too_many_arguments)]
fn run_scan_incremental(
    store: &CacheStore,
    keyset: &Keyset,
    index_dir: &std::path::Path,
    path: &std::path::Path,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
    color: Option<&str>,
    strict: bool,
) -> anyhow::Result<ExitCode> {
    let start = std::time::Instant::now();
    let candidates = walk_source_files(path);
    anyhow::ensure!(
        !candidates.is_empty(),
        "no supported source files found under {}; pass --retrieved to scan a prebuilt packet stream",
        path.display()
    );

    let index = rvl_index::PacketIndex::open(&index_dir.join("packets.redb"))?;
    let name = snapshot_name(path);
    let root = path.to_path_buf();

    let scan = incremental_sites(&index, path, &candidates, |changed| {
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
    })?;

    // One-line reuse summary to stderr; the ladder itself goes to stdout.
    eprintln!(
        "incremental: reused {} files from index, retrieved {} changed",
        scan.reused_files, scan.retrieved_files
    );
    if let Some(note) = &scan.degraded_note {
        eprintln!("incremental: degraded (fail-open): {note}");
    }

    let (findings, items, sites) = findings_from_sites(
        store,
        keyset,
        scan.sites,
        &scan.repo_cfg,
        0,
        specs_file,
        judgments,
        true,
    )?;
    render_scan_output(path, &findings, &items, &sites, out, color, start)
}

#[allow(clippy::too_many_arguments)]
fn run_explain(
    store: &CacheStore,
    keyset: &Keyset,
    id: &str,
    path: &std::path::Path,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    color: Option<&str>,
) -> anyhow::Result<ExitCode> {
    let stream = resolve_packet_stream(retrieved, path)?;
    let (_findings, items, _sites) =
        resolve_findings(store, keyset, &stream, specs_file, judgments, false)?;
    let ladder_findings = triage_to_findings(&items);
    let Some(f) = ladder_findings.iter().find(|f| f.id == id) else {
        eprintln!(
            "no finding with id '{id}' in this scan (ids are shown in the ladder's 'explain:' hint)"
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
    id: &str,
    path: &std::path::Path,
    reason: Option<&str>,
    expires: Option<&str>,
    retrieved: Option<&std::path::Path>,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
) -> anyhow::Result<ExitCode> {
    // Re-run the same resolve -> triage pipeline explain uses so the id resolves
    // to exactly the finding the user saw in the ladder.
    let stream = resolve_packet_stream(retrieved, path)?;
    let (_findings, items, _sites) =
        resolve_findings(store, keyset, &stream, specs_file, judgments, false)?;
    let ladder_findings = triage_to_findings(&items);
    let Some(f) = ladder_findings.iter().find(|f| f.id == id) else {
        eprintln!(
            "no finding with id '{id}' in this scan (ids are shown in the ladder's 'explain:' hint)"
        );
        return Ok(ExitCode::FAILURE);
    };

    let w = waiver::Waiver {
        rule: f.class_rule.clone(),
        paths: vec![],
        expires: expires.unwrap_or("").trim().to_string(),
        reason: reason.unwrap_or("").trim().to_string(),
    };
    let file = path.join(".revelara.yaml");
    waiver::append_waiver(&file, &w)?;

    println!("waived rule `{}` (finding {})", f.class_rule, f.id);
    if !w.expires.is_empty() {
        println!("expires {}", w.expires);
    }
    println!("wrote {}", file.display());
    println!("this waiver is a local file; commit .revelara.yaml so your team shares it via git");
    Ok(ExitCode::SUCCESS)
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
                    &path,
                    retrieved.as_deref(),
                    specs_file.as_deref(),
                    judgments.as_deref(),
                    out.as_deref(),
                    color.as_deref(),
                )
            }
        }
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
            &id,
            &path.unwrap_or_else(|| PathBuf::from(".")),
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
        Cmd::Index { cmd } => {
            let idx = rvl_index::PacketIndex::open(&cfg.index_dir.join("packets.redb"))?;
            match cmd {
                IndexCmd::Init { retrieved } | IndexCmd::Reindex { retrieved } => {
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
                    println!(
                        "indexed {indexed} file(s) | unreadable {missing} | unparseable lines {skipped}"
                    );
                    Ok(ExitCode::SUCCESS)
                }
                IndexCmd::Status => {
                    println!(
                        "{} file(s) indexed at {}",
                        idx.len()?,
                        cfg.index_dir.display()
                    );
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
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

    fn touch(path: &Path) {
        std::fs::write(path, "").unwrap();
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
}
