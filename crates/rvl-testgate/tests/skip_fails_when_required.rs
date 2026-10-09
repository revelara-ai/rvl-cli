//! `skip` under `RVLSCAN_REQUIRE_ENGINES`. This file holds exactly ONE test:
//! it writes the process environment, and a second test in the same binary
//! would race it.

use rvl_testgate::{skip, REQUIRE_ENGINES_ENV};

#[test]
fn a_skip_is_a_failure_once_engines_are_required() {
    std::env::remove_var(REQUIRE_ENGINES_ENV);
    // Without the switch a skip returns, so the caller can return early.
    skip("some_live_test", "no libclang available");

    std::env::set_var(REQUIRE_ENGINES_ENV, "1");
    let err = std::panic::catch_unwind(|| skip("some_live_test", "no libclang available"))
        .expect_err("a skip must fail the test when engines are required");
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("some_live_test") && msg.contains("no libclang available"),
        "the failure must name the test and the missing engine: {msg}"
    );
    assert!(
        msg.contains(REQUIRE_ENGINES_ENV),
        "the failure must name the switch that made it fatal: {msg}"
    );
}
