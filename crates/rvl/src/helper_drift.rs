//! The helper version handshake, and the drift statement built from it
//! (po-8ozxg).
//!
//! po-vd7ii made a stale helper DIAGNOSABLE: the roll-call names the file that
//! ran and where resolution found it. The reader still had to notice that the
//! path was not the one they expected, and know that it was old. This module
//! is the half that makes the drift announce itself.
//!
//! ## The handshake
//!
//! A helper answers `--packet-schema` with two lines:
//!
//! ```text
//! 2
//! content-version 3fa91c0b77de
//! ```
//!
//! Line 1 is the packet contract version, unchanged, so a consumer that reads
//! only the first line keeps working. Line 2 is the first
//! [`CONTENT_VERSION_LEN`] hex digits of a sha256 over the helper's own source.
//! For a scripted helper that source is the one file that runs, so rvl can
//! compute the same value from the file without spawning anything; see
//! [`content_version`].
//!
//! A hash says "different", never "older". The one case where age is known is
//! a helper that answers with line 1 alone: it was built before the handshake
//! existed.

use sha2::Digest as _;

/// Hex digits of sha256 a content version carries. 48 bits: this identifies
/// one build of one helper against its sibling, it does not resist an
/// adversary, and twelve digits still fit in a line a person reads.
pub const CONTENT_VERSION_LEN: usize = 12;

/// The key that opens the second line of a `--packet-schema` reply.
const CONTENT_VERSION_KEY: &str = "content-version";

/// The content version of a helper that is ONE source file: what `pyindex.py`,
/// `tsindex.js` and `javaindex.java` each report about themselves.
pub fn content_version(bytes: &[u8]) -> String {
    let mut hex = hex::encode(sha2::Sha256::digest(bytes));
    hex.truncate(CONTENT_VERSION_LEN);
    hex
}

/// Read the content version out of a helper's `--packet-schema` reply.
///
/// `None` for anything that is not a well-formed reply carrying one: a helper
/// that predates the handshake (line 1 only), and also a program that is not
/// a helper at all and printed something else. The caller cannot tell those
/// apart and does not need to; neither can be confirmed as the shipped helper.
pub fn parse_handshake(stdout: &str) -> Option<String> {
    let mut lines = stdout.lines();
    lines.next()?.trim().parse::<u32>().ok()?;
    lines.find_map(|line| {
        let version = line.trim().strip_prefix(CONTENT_VERSION_KEY)?.trim();
        let well_formed = !version.is_empty() && version.chars().all(|c| c.is_ascii_hexdigit());
        well_formed.then(|| version.to_ascii_lowercase())
    })
}

/// What to tell the reader about a helper that ran (`ran`, `None` when it
/// reported no version) beside the copy this rvl ships (`shipped`). `None`
/// when the two agree.
///
/// `shipped_label` names the sibling the way the roll-call names a source:
/// "the bundled /opt/rvl/goindex", "the copy embedded in this rvl".
pub fn describe(ran: Option<&str>, shipped: &str, shipped_label: &str) -> Option<String> {
    match ran {
        Some(v) if v == shipped => None,
        Some(v) => Some(format!(
            "differs from {shipped_label} (content {v}, shipped {shipped})"
        )),
        None => Some(format!(
            "reports no content version, so it is older than {shipped_label} (shipped {shipped})"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_version_is_a_short_sha256_prefix() {
        // sha256("") = e3b0c44298fc1c14...
        assert_eq!(content_version(b""), "e3b0c44298fc");
        assert_ne!(content_version(b"a"), content_version(b"b"));
    }

    #[test]
    fn a_two_line_reply_carries_the_version() {
        assert_eq!(
            parse_handshake("2\ncontent-version 3fa91c0b77de\n").as_deref(),
            Some("3fa91c0b77de")
        );
        // CRLF from a helper on another platform, and upper-case hex.
        assert_eq!(
            parse_handshake("2\r\ncontent-version 3FA91C0B77DE\r\n").as_deref(),
            Some("3fa91c0b77de")
        );
    }

    #[test]
    fn a_reply_without_a_version_is_none() {
        // Every helper before po-8ozxg.
        assert_eq!(parse_handshake("2\n"), None);
        assert_eq!(parse_handshake(""), None);
        assert_eq!(parse_handshake("2\ncontent-version \n"), None);
        assert_eq!(parse_handshake("2\ncontent-version not-hex\n"), None);
    }

    #[test]
    fn output_that_is_not_a_handshake_is_none() {
        // A stub that ignores its arguments and prints a packet stream.
        assert_eq!(
            parse_handshake("{\"packet_schema\":2}\ncontent-version abc123\n"),
            None
        );
    }

    #[test]
    fn equal_versions_are_not_drift() {
        assert_eq!(describe(Some("abc"), "abc", "the bundled x"), None);
    }

    #[test]
    fn different_versions_differ_and_a_missing_one_is_older() {
        let differs = describe(Some("abc"), "def", "the bundled x").unwrap();
        assert!(differs.contains("differs from the bundled x"), "{differs}");
        assert!(
            differs.contains("abc") && differs.contains("def"),
            "{differs}"
        );
        assert!(!differs.contains("older"), "a hash has no order: {differs}");

        let older = describe(None, "def", "the bundled x").unwrap();
        assert!(older.contains("reports no content version"), "{older}");
        assert!(older.contains("older than the bundled x"), "{older}");
    }
}
