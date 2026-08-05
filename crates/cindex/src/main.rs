//! cindex — the C/C++ retriever helper for rvlscan.
//!
//! Engine (DECIDED, po-ae75b.9): the libclang C API, runtime-loaded via
//! `clang-sys`'s `runtime` feature. LibTooling is the pre-registered escape
//! valve and is NOT used. Release packaging vendors a pinned, checksummed
//! LLVM; a dev build finds the system libclang (LIBCLANG_PATH overrides).
//!
//! Retrieval only: this helper decides nothing about reliability, it only
//! says what the code is. See README.md for the packet contract, the
//! compile-db rules, and the C/C++ typing tiers.

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

fn main() -> ExitCode {
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
