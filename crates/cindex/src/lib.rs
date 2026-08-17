//! cindex — the C/C++ retriever helper for rvl.
//!
//! Engine (DECIDED, po-ae75b.9): the libclang C API, runtime-loaded via
//! `clang-sys`'s `runtime` feature. LibTooling is the pre-registered escape
//! valve and is NOT used. Release packaging vendors a pinned, checksummed
//! LLVM; a dev build finds the system libclang (LIBCLANG_PATH overrides).
//!
//! Retrieval only: this helper decides nothing about reliability, it only
//! says what the code is. See README.md for the packet contract, the
//! compile-db rules, and the C/C++ typing tiers.
//!
//! WHY THIS IS A LIBRARY AND NOT A BINARY (po-av01j.154 release fix): the
//! `cindex` executable is a bin target of the `rvl` PACKAGE
//! (`crates/rvl/src/bin/cindex.rs`), which is a one-line shim over [`run`].
//! It has to live there because cargo-dist builds one app from one cargo
//! package: an app's archive can only contain that package's own bins, so a
//! `cindex` bin defined here would never be packed next to `rvl` — and being
//! next to `rvl` is exactly how `resolve_helper` finds it after a `brew
//! install`. Two packages cannot both define a `cindex` bin (cargo warns
//! "output filename collision" and the winner at `target/<profile>/cindex`
//! is arbitrary), so this crate deliberately ships no bin of its own.

use std::path::PathBuf;
use std::process::ExitCode;

mod retrieve;

/// The packet contract version this emitter stamps. Must agree with
/// `rvl_core::PACKET_SCHEMA` and the other helpers' constants.
const PACKET_SCHEMA: u32 = 2;

fn usage() -> ! {
    eprintln!(
        "usage: cindex --retrieve --root <repo> --name <snapshot> [--files a.c,b.c]\n\
         \x20      cindex --packet-schema\n\
         \x20      cindex --engine-check"
    );
    std::process::exit(2);
}

/// The `cindex` CLI entry point. Called by the `rvl` package's `cindex` bin.
pub fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut do_retrieve = false;
    let mut do_schema = false;
    let mut do_engine_check = false;
    let mut root: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut files: Vec<String> = Vec::new();

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--retrieve" => do_retrieve = true,
            "--packet-schema" => do_schema = true,
            "--engine-check" => do_engine_check = true,
            "--root" => root = Some(PathBuf::from(it.next().unwrap_or_else(|| usage()))),
            "--name" => name = Some(it.next().unwrap_or_else(|| usage()).clone()),
            "--files" => {
                files = it
                    .next()
                    .unwrap_or_else(|| usage())
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }
            _ => usage(),
        }
    }

    if do_schema {
        println!("{PACKET_SCHEMA}");
        return ExitCode::SUCCESS;
    }
    if do_engine_check {
        return match retrieve::load_engine() {
            Ok(version) => {
                println!("{version}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::FAILURE
            }
        };
    }
    if !do_retrieve {
        usage();
    }
    let (Some(root), Some(name)) = (root, name) else {
        usage()
    };
    match retrieve::run(&root, &name, &files) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cindex: {e:#}");
            ExitCode::FAILURE
        }
    }
}
