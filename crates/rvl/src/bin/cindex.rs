//! The `cindex` executable: the C/C++ retriever helper.
//!
//! All of it lives in the `cindex` crate; this file exists only to make the
//! binary a target of the `rvl` PACKAGE. cargo-dist builds one app per cargo
//! package and an app's archive can hold only that package's own bins, so a
//! `cindex` bin declared over in `crates/cindex` could never be packed beside
//! `rvl` — and beside `rvl` is precisely where `resolve_helper` looks after a
//! `brew install`. Declaring it here is what makes
//! `[package.metadata.dist] binaries` in Cargo.toml a true statement.

fn main() -> std::process::ExitCode {
    cindex::run()
}
