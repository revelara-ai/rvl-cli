//! The roots rvl trusts for TLS are webpki-roots, compiled in, with no
//! revocation. Eight eMudhra intermediates under these two roots had their
//! keys compromised (CVE-2026-111943, 2026-10-17); webpki-roots 1.0.10
//! removed both roots, so a lockfile that falls back to an older version
//! fails here.

const DISTRUSTED: [&[u8]; 2] = [b"AAA Certificate Services", b"emSign ECC Root CA - G3"];

#[test]
fn no_emudhra_compromised_root_is_trusted() {
    for anchor in webpki_roots::TLS_SERVER_ROOTS {
        let subject: &[u8] = anchor.subject.as_ref();
        for name in DISTRUSTED {
            assert!(
                !subject.windows(name.len()).any(|w| w == name),
                "webpki-roots still trusts {}",
                String::from_utf8_lossy(name)
            );
        }
    }
}
