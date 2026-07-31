use clap::{Parser, Subcommand};
use rvl_cache::{offline_from_env, CacheStore, HttpFetcher, Keyset, SyncOutcome};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "rvlscan", version, about = "Revelara reliability scanner")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan retrieved packets against the signed spec cache: spec matching,
    /// propagation, triage. Deterministic, no model calls.
    Scan {
        /// Retriever packet stream (JSONL) from a language helper.
        #[arg(long)]
        retrieved: PathBuf,
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
    },
    /// Refresh the spec cache from the Revelara API (async-safe, never
    /// blocks a scan; RVLSCAN_OFFLINE=1 disables all fetches).
    Sync,
    /// Spec-cache maintenance.
    Cache {
        #[command(subcommand)]
        cmd: CacheCmd,
    },
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

/// All runtime configuration, resolved once. Env-only today; when the
/// config-file surface lands, the three-way merge (default / file / env)
/// happens in this constructor and nowhere else. The signing keyset is
/// deliberately NOT here: pinned keys are compiled in, and a configurable
/// keyset would be the verification bypass the distribution contract forbids.
struct Config {
    cache_dir: PathBuf,
    offline: bool,
    base_url: String,
    org_key: String,
}

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
        Self {
            cache_dir,
            offline: offline_from_env(std::env::var("RVLSCAN_OFFLINE").ok().as_deref()),
            base_url: std::env::var("RVLSCAN_API_BASE")
                .unwrap_or_else(|_| "https://api.revelara.ai".into()),
            org_key: std::env::var("RVLSCAN_ORG_KEY").unwrap_or_default(),
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

/// The scan: packets + verified specs -> propagation -> triage. Deterministic,
/// no model calls. Undecided outcomes stay undecided and are reported in the
/// coverage section; they are never promoted to a violation.
fn run_scan(
    store: &CacheStore,
    keyset: &Keyset,
    retrieved: &std::path::Path,
    specs_file: Option<&std::path::Path>,
    judgments: Option<&std::path::Path>,
    out: Option<&std::path::Path>,
) -> anyhow::Result<ExitCode> {
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

    let stream = std::fs::read_to_string(retrieved)?;
    let (sites, repo_cfg, skipped) = rvl_core::parse_stream(&stream);
    anyhow::ensure!(
        !sites.is_empty(),
        "no parseable sites in {}",
        retrieved.display()
    );
    let cache = rvl_spec::SpecCache::load(&specs_text)?;
    let served = cache.served_bound(&repo_cfg);
    let findings = rvl_propagate::propagate_all(&sites, &cache, &served);

    println!(
        "sites {} | specs {} | unparseable lines {skipped}",
        sites.len(),
        cache.len()
    );

    // Coverage: every outcome class reported, undecided included.
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        *counts.entry(f.verdict.as_str()).or_insert(0) += 1;
    }
    let n = sites.len().max(1);
    println!("\n{:<16} {:>6} {:>8}", "verdict", "n", "share");
    for (k, v) in &counts {
        println!("{k:<16} {v:>6} {:>7.1}%", 100.0 * *v as f64 / n as f64);
    }
    let decided = findings.iter().filter(|f| f.verdict.is_decided()).count();
    println!(
        "\ndecided {decided}/{} ({:.1}%) — undecided sites are reported, never counted as violations",
        sites.len(),
        100.0 * decided as f64 / n as f64
    );

    // Triage: collapse violations into reader-facing classes.
    let judgments: Vec<rvl_triage::ClassJudgment> = match judgments {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => Vec::new(),
    };
    let verdict_rows: Vec<(String, rvl_core::Verdict, String)> = findings
        .iter()
        .map(|f| (f.site_id.clone(), f.verdict, f.reason.clone()))
        .collect();
    let items = rvl_triage::triage(&sites, &verdict_rows, &judgments);
    if !items.is_empty() {
        println!("\ntriaged items ({}):", items.len());
        for it in items.iter().take(20) {
            println!(
                "  [{:<9}] {} {} — {} site(s)",
                it.disposition, it.class.client_type, it.class.method, it.site_count
            );
        }
    }

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
            retrieved,
            specs_file,
            judgments,
            out,
        } => run_scan(
            &store,
            &keyset,
            &retrieved,
            specs_file.as_deref(),
            judgments.as_deref(),
            out.as_deref(),
        ),
        Cmd::Sync => {
            if !cfg.offline && cfg.org_key.is_empty() {
                anyhow::bail!("RVLSCAN_ORG_KEY is not set (or set RVLSCAN_OFFLINE=1)");
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

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
