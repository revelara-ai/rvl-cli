//! The keyset every signed spec-cache artifact is verified against.
//!
//! A RELEASE BUILD TRUSTS THE PINNED KEYS AND NOTHING ELSE. The keys are
//! compiled in (`rvl_cache::PINNED_KEYSET_HEX`) so that no file, flag or
//! environment variable can widen what a shipped binary accepts; see
//! `shared_config.rs` for why a config-file keyset is refused.
//!
//! A DEBUG BUILD ALSO READS `RVL_TEST_KEYSET_HEX` (po-97wqs). The private
//! halves of the pinned keys are not in this repo, by design, so without a
//! seam no test could run the binary on a verified commercial tier, and the
//! paths that only a signed tier reaches (the empty-API-corpus warning is one)
//! were checked by the compiler alone. The seam is gated on
//! `debug_assertions`, which the `release` and `dist` profiles leave off: the
//! code below the gate is not in the shipped binary, and the CLI suite holds
//! both halves of that (`no_cargo_profile_turns_debug_assertions_on`,
//! `a_release_build_ignores_the_test_keyset_variable`).

use rvl_cache::Keyset;

/// Debug builds only: comma-separated ed25519 verifying keys, hex encoded,
/// trusted IN ADDITION to the pinned keyset.
#[cfg(debug_assertions)]
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

/// The keyset this binary verifies signed artifacts against.
pub fn trusted_keyset() -> anyhow::Result<Keyset> {
    #[cfg(debug_assertions)]
    if let Ok(extra) = std::env::var(TEST_KEYSET_ENV) {
        let mut keys = rvl_cache::PINNED_KEYSET_HEX.to_vec();
        keys.extend(extra.split(',').map(str::trim).filter(|k| !k.is_empty()));
        let added = keys.len() - rvl_cache::PINNED_KEYSET_HEX.len();
        if added > 0 {
            // Announced on stderr every time, the same contract `--specs-file`
            // has: a widened trust root must never apply quietly.
            eprintln!(
                "WARNING: trusting {added} TEST signing key(s) from {TEST_KEYSET_ENV} \
                 (debug builds only; a release build ignores this variable)"
            );
            return Keyset::from_hex(&keys);
        }
    }
    Keyset::from_hex(rvl_cache::PINNED_KEYSET_HEX)
}
