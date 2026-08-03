use std::io::IsTerminal;
mod render;
mod shared_config;

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

/// A source language rvlscan knows how to retrieve packets for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lang {
    Go,
    Python,
}

impl Lang {
    /// The retriever helper's base name.
    fn helper_base(self) -> &'static str {
        match self {
            Lang::Go => "goindex",
            Lang::Python => "pyindex",
        }
    }
    /// The env var that overrides helper discovery for this language.
    fn env_override(self) -> &'static str {
        match self {
            Lang::Go => "RVLSCAN_GOINDEX",
            Lang::Python => "RVLSCAN_PYINDEX",
        }
    }
}

impl std::fmt::Display for Lang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Lang::Go => "Go",
            Lang::Python => "Python",
        })
    }
}

/// How a resolved helper is invoked. A Go helper (or a pyindex executable on
/// PATH) runs directly; a pyindex `.py` script runs under `python3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperKind {
    Executable,
    PyScript,
}

/// A helper located on disk, ready to be turned into a command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedHelper {
    path: PathBuf,
    kind: HelperKind,
}

/// Directory names never worth descending into during language detection.
const SKIP_DIRS: &[&str] = &[".git", "node_modules", "target", "vendor", "__pycache__"];

/// Detect which supported languages have source under `root`. Pure and
/// bounded: marker files (`go.mod`, `pyproject.toml`, `setup.py`) short-circuit,
/// otherwise a walk that skips vendored/build dirs looks for `*.go` / `*.py`.
/// Order is stable (Go before Python) so a multi-language repo runs its helpers
/// in a deterministic order.
fn detect_languages(root: &Path) -> Vec<Lang> {
    let mut go = root.join("go.mod").is_file();
    let mut py = root.join("pyproject.toml").is_file() || root.join("setup.py").is_file();
    if !(go && py) {
        walk_for_sources(root, &mut go, &mut py);
    }
    let mut out = Vec::new();
    if go {
        out.push(Lang::Go);
    }
    if py {
        out.push(Lang::Python);
    }
    out
}

/// Bounded directory walk: sets `go`/`py` when a `.go`/`.py` file is seen, and
/// stops early once both are found. Skips `.git`, `node_modules`, `target`,
/// `vendor`, `__pycache__` so a big checkout does not turn detection into a
/// full-tree crawl.
fn walk_for_sources(root: &Path, go: &mut bool, py: &mut bool) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if *go && *py {
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
                match entry.path().extension().and_then(|e| e.to_str()) {
                    Some("go") => *go = true,
                    Some("py") => *py = true,
                    _ => {}
                }
            }
        }
    }
}

/// Classify a resolved helper path into how it must be invoked. Go helpers are
/// always executables; a Python helper is a `python3` script when it ends in
/// `.py`, otherwise an executable on PATH.
fn classify_helper(lang: Lang, path: &Path) -> ResolvedHelper {
    let kind = match lang {
        Lang::Go => HelperKind::Executable,
        Lang::Python if path.extension().and_then(|e| e.to_str()) == Some("py") => {
            HelperKind::PyScript
        }
        Lang::Python => HelperKind::Executable,
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
    // (2) adjacent to the rvlscan binary.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join(base);
            if cand.is_file() {
                return Ok(classify_helper(lang, &cand));
            }
            if lang == Lang::Python {
                let cand_py = dir.join(format!("{base}.py"));
                if cand_py.is_file() {
                    return Ok(classify_helper(lang, &cand_py));
                }
            }
        }
    }
    // (3) on PATH.
    if let Some(found) = find_on_path(base) {
        return Ok(classify_helper(lang, &found));
    }
    if lang == Lang::Python {
        if let Some(found) = find_on_path("pyindex.py") {
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
/// `root`, tagging the snapshot `name`. Pure, so command construction is
/// unit-testable without spawning a process.
fn helper_argv(helper: &ResolvedHelper, root: &Path, name: &str) -> Vec<String> {
    let root = root.display().to_string();
    let helper_path = helper.path.display().to_string();
    let tail = [
        "--retrieve".to_string(),
        "--root".to_string(),
        root,
        "--name".to_string(),
        name.to_string(),
    ];
    match helper.kind {
        HelperKind::Executable => std::iter::once(helper_path).chain(tail).collect(),
        HelperKind::PyScript => std::iter::once("python3".to_string())
            .chain(std::iter::once(helper_path))
            .chain(tail)
            .collect(),
    }
}

/// Run a resolved helper over `root` and return its stdout (the JSONL packet
/// stream). A non-zero exit surfaces the helper's stderr in the error.
fn run_helper(helper: &ResolvedHelper, root: &Path, name: &str) -> anyhow::Result<String> {
    let argv = helper_argv(helper, root, name);
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
    let name = std::fs::canonicalize(path)
        .ok()
        .as_deref()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "repo".to_string());
    let mut combined = String::new();
    for lang in langs {
        let helper = resolve_helper(lang)?;
        let out = run_helper(&helper, path, &name)?;
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

    let (sites, repo_cfg, skipped) = rvl_core::parse_stream(stream);
    anyhow::ensure!(
        !sites.is_empty(),
        "no parseable sites in the retrieved packet stream"
    );
    let cache = rvl_spec::SpecCache::load(&specs_text)?;
    let served = cache.served_bound(&repo_cfg);
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
    let ladder_findings = triage_to_findings(&items);
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
        } => run_scan(
            &store,
            &keyset,
            &path.unwrap_or_else(|| PathBuf::from(".")),
            retrieved.as_deref(),
            specs_file.as_deref(),
            judgments.as_deref(),
            out.as_deref(),
            color.as_deref(),
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
            &id,
            &path.unwrap_or_else(|| PathBuf::from(".")),
            retrieved.as_deref(),
            specs_file.as_deref(),
            judgments.as_deref(),
            color.as_deref(),
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
        let argv = helper_argv(&helper, Path::new("/repo"), "repo");
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
        let argv = helper_argv(&helper, Path::new("/repo"), "repo");
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
