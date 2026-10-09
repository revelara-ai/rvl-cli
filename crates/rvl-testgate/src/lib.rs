//! The one place a live test may skip (po-av01j.99).
//!
//! A golden or end-to-end test that drives a real engine (libclang, node and
//! `typescript`, a JDK, rust-analyzer, the Go toolchain, ...) cannot run on a
//! machine without that engine, so on a developer workstation it prints a
//! `SKIP` line and returns. In CI that same return is a lane nobody tested
//! reading as green: building `cindex` was once taken as proof that the C/C++
//! lane ran, while libclang, which it loads at process start, was not
//! installed anywhere on the runner.
//!
//! So every skip goes through [`skip`], and CI exports
//! `RVLSCAN_REQUIRE_ENGINES=1`, which turns each one into a failure that names
//! the missing engine. `tests/skip_contract.rs` holds the suite to this: a
//! test that prints its own `SKIP` line fails the build.

use std::ffi::OsStr;
use std::fmt::Display;

/// Set (to anything but empty or `0`) where every engine is provisioned, so a
/// test that cannot reach its engine fails instead of skipping. CI sets it.
pub const REQUIRE_ENGINES_ENV: &str = "RVLSCAN_REQUIRE_ENGINES";

/// Whether a value of [`REQUIRE_ENGINES_ENV`] forbids skipping. Split from the
/// environment read so the rule is testable without mutating the process.
pub fn requires(value: Option<&OsStr>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "0")
}

/// True when this process may not skip a test for a missing engine.
pub fn engines_required() -> bool {
    requires(std::env::var_os(REQUIRE_ENGINES_ENV).as_deref())
}

/// Record that `test` cannot run because of `why`. Prints a `SKIP` line and
/// returns, so the caller can return early; panics instead when engines are
/// required, so the test fails with the reason.
#[track_caller]
pub fn skip(test: &str, why: impl Display) {
    if engines_required() {
        panic!(
            "{test}: {why}. {REQUIRE_ENGINES_ENV} is set, so a test that cannot reach its \
             engine fails instead of skipping: provision the engine on this runner"
        );
    }
    eprintln!("SKIP {test}: {why}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_empty_or_zero_switch_allows_a_skip() {
        assert!(!requires(None));
        assert!(!requires(Some(OsStr::new(""))));
        assert!(!requires(Some(OsStr::new("0"))));
    }

    #[test]
    fn any_other_value_forbids_a_skip() {
        assert!(requires(Some(OsStr::new("1"))));
        assert!(requires(Some(OsStr::new("true"))));
    }
}
