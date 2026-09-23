//! rustindex CLI — the Rust retriever helper.
//!
//! ```text
//! rustindex --retrieve --root <repo> --name <snapshot>   # full load
//! rustindex --retrieve --root <repo> --files a.rs,b.rs   # incremental
//! rustindex --packet-schema                              # negotiate
//! ```
//!
//! Matches the argv contract `rvl` builds in `helper_argv` for an
//! Executable helper. The incremental path is a filtered full run: the
//! rust-analyzer `scip` engine has no per-file mode, so the cold cost is paid
//! and only the requested files' sites are emitted.
//!
//! `--root` is the REPO, not a cargo workspace: every `Cargo.toml` under it
//! is discovered (`crate::workspace`), loaded and indexed, so a polyglot
//! monorepo whose crates sit in a subdirectory is scanned rather than
//! abstained on (po-pk3fp.11). A workspace that fails to load is declined on
//! its own; the RUN abstains only when nothing loads.
//!
//! This module is the CLI, not the bin. The `rustindex` executable is a bin
//! target of the `rvl` PACKAGE (`crates/rvl/src/bin/rustindex.rs`), a one-line
//! shim over [`run`]; see the note at the top of `crates/cindex/src/lib.rs`
//! for why release packaging forces that placement.

use anyhow::Context;

/// Exit code meaning "I ran correctly and am declining to analyse this tree".
/// Must agree with `HELPER_EXIT_ABSTAIN` in rvl (po-av01j.102): rvl
/// degrades this language and scans the rest of the repo, instead of aborting.
/// 2 stays the generic failure code, so the two are never confused.
const EXIT_ABSTAIN: i32 = 3;

/// Must agree with `HELPER_EXIT_PREREQ_MISSING` in rvl (po-av01j.147): the
/// toolchain this helper drives is not installed. rvl renders it as
/// "helper not installed" with the install hint, rather than as a failure.
const EXIT_PREREQ_MISSING: i32 = 4;

/// The `rustindex` CLI entry point. Called by the `rvl` package's
/// `rustindex` bin.
pub fn run() {
    if let Err(e) = execute() {
        eprintln!("rustindex: {e:#}");
        let code = if e.downcast_ref::<crate::ra::Abstain>().is_some() {
            EXIT_ABSTAIN
        } else if e.downcast_ref::<crate::ra::MissingPrereq>().is_some() {
            EXIT_PREREQ_MISSING
        } else {
            2
        };
        std::process::exit(code);
    }
}

fn execute() -> anyhow::Result<()> {
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

    // Engine discovery + identity (pin/checksum), then workspace discovery and
    // the build-dep gate. A workspace that does not load ABSTAINS -- no
    // heuristic tier -- and since po-pk3fp.11 that abstention is PER
    // WORKSPACE: a polyglot monorepo keeps the crates that did load.
    let ra = crate::ra::discover()?;
    let workspaces = crate::workspace::discover_workspaces(&root);
    if workspaces.is_empty() {
        return Err(crate::ra::Abstain(format!(
            "no Cargo.toml under {}, so there is no cargo workspace to load; rustindex abstains \
             rather than guessing (no heuristic tier, per the engine charter)",
            root.display()
        ))
        .into());
    }
    let load = crate::workspace::load_workspaces(&root, &workspaces);
    for declined in &load.declined {
        eprintln!(
            "rustindex: WARNING: the workspace at {} did not load and is NOT indexed: {}",
            display_rel(&declined.rel),
            declined.reason
        );
    }
    // Every workspace declining is an abstention for the RUN. Emitting an
    // empty stream at exit 0 would report code that was never looked at as
    // "Rust scanned and clean" -- the collapse goindex fixed in po-av01j.131.
    if load.loaded.is_empty() {
        return Err(crate::ra::Abstain(format!(
            "all {} cargo workspace(s) under {} failed to load; rustindex abstains rather than \
             reporting a scan of nothing as clean",
            workspaces.len(),
            root.display()
        ))
        .into());
    }

    let only = if files.is_empty() {
        None
    } else {
        Some(files.as_slice())
    };

    // One scip run per workspace, concatenated. rust-analyzer emits paths
    // relative to the tree it was pointed at, so each index is rebased onto
    // the repo root before derivation: file_path, snippet paths and the
    // --files filter stay repo-relative whatever nesting the repo uses.
    let mut sites = Vec::new();
    let mut indexed: Vec<&str> = Vec::new();
    let mut repo_config = rvl_core::RepoConfig {
        snapshot_id: snapshot.clone(),
        ..Default::default()
    };
    for ws in &load.loaded {
        // An incremental run names repo-relative files; a workspace holding
        // none of them would cost a cold rust-analyzer load for nothing.
        if !crate::workspace::wanted(&ws.rel, only) {
            continue;
        }
        indexed.push(&ws.rel);
        if !ws.lock.pre_existing {
            eprintln!(
                "rustindex: no committed Cargo.lock in {}; resolution was minted at scan time \
                 (generated lockfile sha256 {} recorded in provenance)",
                display_rel(&ws.rel),
                ws.lock.sha256
            );
        }
        let mut index = crate::ra::run_scip(&ra, &ws.dir)?;
        crate::workspace::rebase_index(&mut index, &ws.rel);
        let derived = crate::derive::derive(&root, &snapshot, &index, only);
        sites.extend(derived.sites);
        repo_config.absorb(derived.repo_config);
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    use std::io::Write;

    for site in &sites {
        let mut v = serde_json::to_value(site)?;
        // Parity with the sibling helpers: emit the unique site_key downstream
        // indexes join on (rvl_index::site_key must agree).
        v["site_key"] = serde_json::Value::String(site.site_key());
        writeln!(out, "{}", serde_json::to_string(&v)?)?;
    }

    // Repo-scoped construction facts (bound evidence).
    if !repo_config.constructions.is_empty() {
        let mut v = serde_json::to_value(&repo_config)?;
        v["kind"] = serde_json::Value::String("repo_config".into());
        v["packet_schema"] = serde_json::Value::from(rvl_core::PACKET_SCHEMA);
        writeln!(out, "{}", serde_json::to_string(&v)?)?;
    }

    // Workspace/engine provenance: which engine produced this stream, and
    // which dependency resolution it saw. Unknown `kind`s are routed away
    // from Site parsing by rvl_core::parse_stream.
    // Workspace/engine provenance: which engine produced this stream, which
    // dependency resolution it saw, and WHICH WORKSPACES it saw -- including
    // the ones that declined, so a consumer can tell "this crate was declined"
    // from "this crate was clean". Unknown `kind`s are routed away from Site
    // parsing by rvl_core::parse_stream.
    let primary = &load.loaded[0].lock;
    let mut workspace_records: Vec<serde_json::Value> = load
        .loaded
        .iter()
        .map(|ws| {
            serde_json::json!({
                "path": ws.rel,
                "loaded": true,
                // False on an incremental run that named no file here: the
                // workspace loaded, and its sites were deliberately not read.
                "indexed": indexed.contains(&ws.rel.as_str()),
                "cargo_lockfile": {
                    "pre_existing": ws.lock.pre_existing,
                    "generated": !ws.lock.pre_existing,
                    "sha256": ws.lock.sha256,
                    "bytes": ws.lock.bytes,
                },
            })
        })
        .collect();
    workspace_records.extend(
        load.declined
            .iter()
            .map(|d| serde_json::json!({ "path": d.rel, "loaded": false, "reason": d.reason })),
    );
    let prov = serde_json::json!({
        "kind": "rust_workspace_provenance",
        "packet_schema": rvl_core::PACKET_SCHEMA,
        "snapshot_id": snapshot,
        "rust_analyzer": {
            "version": ra.version_line,
            "sha256": ra.sha256,
            "pinned_version": crate::ra::PINNED_VERSION,
            "matches_pin": ra.matches_pin,
        },
        // Kept at the top level for readers that predate the per-workspace
        // array: on a single-workspace repo it is exactly what it always was.
        "cargo_lockfile": {
            "pre_existing": primary.pre_existing,
            "generated": !primary.pre_existing,
            "sha256": primary.sha256,
            "bytes": primary.bytes,
        },
        "workspaces": workspace_records,
        "workspaces_loaded": load.loaded.len(),
        "workspaces_indexed": indexed.len(),
        "workspaces_declined": load.declined.len(),
    });
    writeln!(out, "{}", serde_json::to_string(&prov)?)?;
    Ok(())
}

/// A workspace's repo-relative directory for humans: `.` at the scan root.
fn display_rel(rel: &str) -> &str {
    if rel.is_empty() {
        "."
    } else {
        rel
    }
}
