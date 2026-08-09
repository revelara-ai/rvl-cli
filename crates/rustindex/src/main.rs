//! rustindex CLI — the Rust retriever helper.
//!
//!     rustindex --retrieve --root <repo> --name <snapshot>   # full load
//!     rustindex --retrieve --root <repo> --files a.rs,b.rs   # incremental
//!     rustindex --packet-schema                              # negotiate
//!
//! Matches the argv contract `rvlscan` builds in `helper_argv` for an
//! Executable helper. The incremental path is a filtered full run: the
//! rust-analyzer `scip` engine has no per-file mode, so the cold cost is paid
//! and only the requested files' sites are emitted.

use anyhow::Context;

/// Exit code meaning "I ran correctly and am declining to analyse this tree".
/// Must agree with `HELPER_EXIT_ABSTAIN` in rvlscan (po-av01j.102): rvlscan
/// degrades this language and scans the rest of the repo, instead of aborting.
/// 2 stays the generic failure code, so the two are never confused.
const EXIT_ABSTAIN: i32 = 3;

/// Must agree with `HELPER_EXIT_PREREQ_MISSING` in rvlscan (po-av01j.147): the
/// toolchain this helper drives is not installed. rvlscan renders it as
/// "helper not installed" with the install hint, rather than as a failure.
const EXIT_PREREQ_MISSING: i32 = 4;

fn main() {
    if let Err(e) = run() {
        eprintln!("rustindex: {e:#}");
        let code = if e.downcast_ref::<rustindex::ra::Abstain>().is_some() {
            EXIT_ABSTAIN
        } else if e.downcast_ref::<rustindex::ra::MissingPrereq>().is_some() {
            EXIT_PREREQ_MISSING
        } else {
            2
        };
        std::process::exit(code);
    }
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut retrieve = false;
    let mut root: Option<String> = None;
    let mut name: Option<String> = None;
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--packet-schema" => {
                println!("{}", rvl_core::PACKET_SCHEMA);
                return Ok(());
            }
            "--retrieve" => retrieve = true,
            "--root" => {
                i += 1;
                root = Some(args.get(i).context("--root needs a path")?.clone());
            }
            "--name" => {
                i += 1;
                name = Some(args.get(i).context("--name needs a value")?.clone());
            }
            "--files" => {
                i += 1;
                files = args
                    .get(i)
                    .context("--files needs a comma-separated list")?
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            other => anyhow::bail!(
                "unknown argument `{other}` (see --retrieve/--root/--name/--files/--packet-schema)"
            ),
        }
        i += 1;
    }
    anyhow::ensure!(
        retrieve,
        "nothing to do: pass --retrieve (or --packet-schema)"
    );
    let root = std::path::PathBuf::from(root.context("--retrieve requires --root <repo>")?);
    anyhow::ensure!(
        root.is_dir(),
        "--root {} is not a directory",
        root.display()
    );
    let root = std::fs::canonicalize(&root).unwrap_or(root);
    let snapshot = name.unwrap_or_else(|| {
        root.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "repo".into())
    });

    // Engine discovery + identity (pin/checksum), then the build-dep gate:
    // a workspace that does not load ABSTAINS — no heuristic tier.
    let ra = rustindex::ra::discover()?;
    let lock_pre_existing = root.join("Cargo.lock").is_file();
    rustindex::ra::require_workspace_loads(&root)?;
    let lock = rustindex::ra::lockfile_provenance(&root, lock_pre_existing);
    if !lock.pre_existing {
        eprintln!(
            "rustindex: no committed Cargo.lock; resolution was minted at scan time \
             (generated lockfile sha256 {} recorded in provenance)",
            lock.sha256
        );
    }

    let index = rustindex::ra::run_scip(&ra, &root)?;
    let only = if files.is_empty() {
        None
    } else {
        Some(files.as_slice())
    };
    let derived = rustindex::derive::derive(&root, &snapshot, &index, only);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    use std::io::Write;

    for site in &derived.sites {
        let mut v = serde_json::to_value(site)?;
        // Parity with the sibling helpers: emit the unique site_key downstream
        // indexes join on (rvl_index::site_key must agree).
        v["site_key"] = serde_json::Value::String(site.site_key());
        writeln!(out, "{}", serde_json::to_string(&v)?)?;
    }

    // Repo-scoped construction facts (bound evidence).
    if !derived.repo_config.constructions.is_empty() {
        let mut v = serde_json::to_value(&derived.repo_config)?;
        v["kind"] = serde_json::Value::String("repo_config".into());
        v["packet_schema"] = serde_json::Value::from(rvl_core::PACKET_SCHEMA);
        writeln!(out, "{}", serde_json::to_string(&v)?)?;
    }

    // Workspace/engine provenance: which engine produced this stream, and
    // which dependency resolution it saw. Unknown `kind`s are routed away
    // from Site parsing by rvl_core::parse_stream.
    let prov = serde_json::json!({
        "kind": "rust_workspace_provenance",
        "packet_schema": rvl_core::PACKET_SCHEMA,
        "snapshot_id": snapshot,
        "rust_analyzer": {
            "version": ra.version_line,
            "sha256": ra.sha256,
            "pinned_version": rustindex::ra::PINNED_VERSION,
            "matches_pin": ra.matches_pin,
        },
        "cargo_lockfile": {
            "pre_existing": lock.pre_existing,
            "generated": !lock.pre_existing,
            "sha256": lock.sha256,
            "bytes": lock.bytes,
        },
    });
    writeln!(out, "{}", serde_json::to_string(&prov)?)?;
    Ok(())
}
