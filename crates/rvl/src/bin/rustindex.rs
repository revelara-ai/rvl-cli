//! The `rustindex` executable: the Rust retriever helper.
//!
//! All of it lives in the `rustindex` crate; this file exists only to make the
//! binary a target of the `rvl` PACKAGE, so release packaging can pack it
//! beside `rvl`. See `crates/rvl/src/bin/cindex.rs` for the full reasoning.

fn main() {
    rustindex::cli::run()
}
