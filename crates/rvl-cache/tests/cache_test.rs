//! Spec-cache distribution acceptance tests (po-3t3oj.13): signing,
//! versioning, atomic install with last-good, quarantine, schema range,
//! offline kill switch, hash-conditional sync, air-gapped import.

use ed25519_dalek::Signer;
use rvl_cache::*;
use std::cell::Cell;

struct TestKeys {
    signing: ed25519_dalek::SigningKey,
    keyset: Keyset,
}

fn keys() -> TestKeys {
    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let hex_pub = hex::encode(signing.verifying_key().to_bytes());
    let keyset = Keyset::from_hex(&[hex_pub.as_str()]).unwrap();
    TestKeys { signing, keyset }
}

fn envelope_bytes(schema: u32, content_version: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": schema,
        "content_version": content_version,
        "specs": {"apis": [], "configs": []}
    }))
    .unwrap()
}

fn sign_b64(k: &TestKeys, bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(k.signing.sign(bytes).to_bytes())
}

fn store() -> (tempfile::TempDir, CacheStore) {
    let dir = tempfile::tempdir().unwrap();
    let s = CacheStore::open(dir.path()).unwrap();
    (dir, s)
}

// --- signing ---

#[test]
fn verify_good_bad_and_missing_signature() {
    let k = keys();
    let bytes = envelope_bytes(1, "2026-07-30.1");
    let sig = sign_b64(&k, &bytes);
    assert!(k.keyset.verify_detached(&bytes, Some(&sig)).is_ok());
    // tampered payload
    let mut tampered = bytes.clone();
    tampered[0] ^= 1;
    assert!(k.keyset.verify_detached(&tampered, Some(&sig)).is_err());
    // missing sig = failed sig, by definition
    assert!(k.keyset.verify_detached(&bytes, None).is_err());
}

#[test]
fn additive_rotation_accepts_any_pinned_key() {
    let old = keys();
    let new = keys();
    let both = Keyset::from_hex(&[
        hex::encode(old.signing.verifying_key().to_bytes()).as_str(),
        hex::encode(new.signing.verifying_key().to_bytes()).as_str(),
    ])
    .unwrap();
    let bytes = envelope_bytes(1, "2026-07-30.1");
    assert!(both
        .verify_detached(&bytes, Some(&sign_b64(&old, &bytes)))
        .is_ok());
    assert!(both
        .verify_detached(&bytes, Some(&sign_b64(&new, &bytes)))
        .is_ok());
}

// --- install / last-good / quarantine ---

#[test]
fn install_is_atomic_and_retains_last_good() {
    let k = keys();
    let (_d, s) = store();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    let v2 = envelope_bytes(1, "2026-07-30.1");

    let out = s.install(&v1, &sign_b64(&k, &v1), &k.keyset);
    assert_eq!(
        out,
        SyncOutcome::Installed {
            content_version: "2026-07-29.1".into()
        }
    );
    let out = s.install(&v2, &sign_b64(&k, &v2), &k.keyset);
    assert_eq!(
        out,
        SyncOutcome::Installed {
            content_version: "2026-07-30.1".into()
        }
    );

    // current is v2, last-good is v1
    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-07-30.1");
    assert_eq!(loaded.source, LoadSource::Current);
    assert!(s.current_hash().is_some());
}

#[test]
fn bad_signature_is_quarantined_and_store_untouched() {
    let k = keys();
    let other = keys(); // signature from a key NOT in the keyset
    let (_d, s) = store();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    s.install(&v1, &sign_b64(&k, &v1), &k.keyset);

    let evil = envelope_bytes(1, "2026-07-30.9");
    let out = s.install(&evil, &sign_b64(&other, &evil), &k.keyset);
    assert!(matches!(out, SyncOutcome::Rejected { .. }));

    // current still v1, and the rejected artifact is preserved for forensics
    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-07-29.1");
}

#[test]
fn tampered_current_falls_back_to_last_good_on_load() {
    let k = keys();
    let (dir, s) = store();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    let v2 = envelope_bytes(1, "2026-07-30.1");
    s.install(&v1, &sign_b64(&k, &v1), &k.keyset);
    s.install(&v2, &sign_b64(&k, &v2), &k.keyset);

    // corrupt current on disk after install (post-download tamper)
    let current = dir.path().join("current").join("specs.json");
    let mut bytes = std::fs::read(&current).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&current, &bytes).unwrap();

    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.source, LoadSource::LastGood);
    assert_eq!(loaded.envelope.content_version, "2026-07-29.1");
}

// --- schema versioning ---

#[test]
fn newer_schema_keeps_current_and_emits_one_hint() {
    let k = keys();
    let (_d, s) = store();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    s.install(&v1, &sign_b64(&k, &v1), &k.keyset);

    let future = envelope_bytes(u32::MAX, "2026-07-30.1");
    let out = s.install(&future, &sign_b64(&k, &future), &k.keyset);
    let SyncOutcome::SchemaTooNew { hint } = out else {
        panic!("expected SchemaTooNew, got {out:?}");
    };
    assert!(
        hint.contains("upgrade"),
        "hint must tell the user to upgrade: {hint}"
    );

    // never blocks: the old cache still loads
    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-07-29.1");
}

// --- staleness ---

#[test]
fn staleness_note_appears_only_when_old() {
    assert!(staleness_note("2026-07-01.3", "2026-07-30").is_some());
    assert!(staleness_note("2026-07-28.1", "2026-07-30").is_none());
    // malformed versions never panic, they just don't produce a note
    assert!(staleness_note("garbage", "2026-07-30").is_none());
}

/// The note names the exact cache it measured, so it cannot be read as a
/// warning about another one (po-7ocbd).
#[test]
fn staleness_note_names_the_full_content_version() {
    let note = staleness_note("2026-09-17.1a2b3c4d", "2026-10-08").unwrap();
    assert_eq!(
        note,
        "spec cache 2026-09-17.1a2b3c4d is 21 days old; run 'rvl sync' to refresh"
    );
}

fn loaded_at(content_version: &str, today: &str) -> Loaded {
    Loaded {
        envelope: serde_json::from_slice(&envelope_bytes(1, content_version)).unwrap(),
        source: LoadSource::Current,
        artifact_sha256: String::new(),
        upgrade_hint: None,
        staleness_note: staleness_note(content_version, today),
    }
}

/// Two tiers load in one scan. A stale OSS tier beside a current commercial
/// tier must say which one is stale (po-7ocbd): the warning and the loaded
/// line of one tier carry the same label and the same version.
#[test]
fn tier_lines_say_which_tier_they_describe() {
    let today = "2026-10-08";
    let commercial = loaded_at("2026-10-07.88644acd", today);
    let oss = loaded_at("2026-09-17.1a2b3c4d", today);

    assert_eq!(
        commercial.summary_line(Tier::Commercial),
        "spec cache 2026-10-07.88644acd (schema 1, Current)"
    );
    assert_eq!(commercial.staleness_line(Tier::Commercial), None);

    assert_eq!(
        oss.summary_line(Tier::Oss),
        "oss tier 2026-09-17.1a2b3c4d (schema 1, Current)"
    );
    assert_eq!(
        oss.staleness_line(Tier::Oss).unwrap(),
        "oss tier: spec cache 2026-09-17.1a2b3c4d is 21 days old; run 'rvl sync' to refresh"
    );
    // A stale commercial tier needs no prefix: "spec cache" is its label.
    let old = loaded_at("2026-09-17.1a2b3c4d", today);
    assert_eq!(
        old.staleness_line(Tier::Commercial).unwrap(),
        "spec cache 2026-09-17.1a2b3c4d is 21 days old; run 'rvl sync' to refresh"
    );
}

// --- offline kill switch ---

#[test]
fn offline_env_semantics() {
    assert!(offline_from_env(Some("1")));
    assert!(!offline_from_env(Some("0")));
    assert!(!offline_from_env(None));
}

struct PanickingFetcher;
impl Fetcher for PanickingFetcher {
    fn fetch(&self, _: Option<&str>) -> anyhow::Result<Fetched> {
        panic!("fetch attempted while offline");
    }
}

#[test]
fn offline_sync_never_touches_the_network() {
    let k = keys();
    let (_d, s) = store();
    assert_eq!(
        sync(&s, &PanickingFetcher, &k.keyset, true),
        SyncOutcome::Offline
    );
}

// --- sync ---

struct FixedFetcher {
    bytes: Vec<u8>,
    sig: String,
    called_with: Cell<Option<Option<String>>>,
}
impl Fetcher for FixedFetcher {
    fn fetch(&self, current_hash: Option<&str>) -> anyhow::Result<Fetched> {
        self.called_with.set(Some(current_hash.map(String::from)));
        if current_hash == Some(sha256_hex(&self.bytes).as_str()) {
            return Ok(Fetched::NotModified);
        }
        Ok(Fetched::New {
            bytes: self.bytes.clone(),
            sig_b64: self.sig.clone(),
        })
    }
}

#[test]
fn sync_installs_then_reports_up_to_date_via_hash_conditional() {
    let k = keys();
    let (_d, s) = store();
    let bytes = envelope_bytes(1, "2026-07-30.1");
    let f = FixedFetcher {
        sig: sign_b64(&k, &bytes),
        bytes,
        called_with: Cell::new(None),
    };

    let out = sync(&s, &f, &k.keyset, false);
    assert_eq!(
        out,
        SyncOutcome::Installed {
            content_version: "2026-07-30.1".into()
        }
    );
    assert_eq!(
        f.called_with.take(),
        Some(None),
        "first sync sends no conditional hash"
    );

    let out = sync(&s, &f, &k.keyset, false);
    assert_eq!(out, SyncOutcome::UpToDate);
    let sent = f
        .called_with
        .take()
        .flatten()
        .expect("second sync must send the installed hash");
    assert_eq!(sent.len(), 64);
}

struct FailingFetcher;
impl Fetcher for FailingFetcher {
    fn fetch(&self, _: Option<&str>) -> anyhow::Result<Fetched> {
        anyhow::bail!("connection refused")
    }
}

#[test]
fn fetch_failure_is_an_outcome_not_an_error() {
    let k = keys();
    let (_d, s) = store();
    let out = sync(&s, &FailingFetcher, &k.keyset, false);
    assert!(matches!(out, SyncOutcome::FetchFailed { .. }));
}

// --- "never published" is not "network down" (po-gcn3q) ---

struct NotPublishedFetcher;
impl Fetcher for NotPublishedFetcher {
    fn fetch(&self, _: Option<&str>) -> anyhow::Result<Fetched> {
        Ok(Fetched::NotPublished {
            url: "https://api.example.test/api/v1/scanner/spec-cache".into(),
        })
    }
}

#[test]
fn not_published_is_its_own_outcome_and_keeps_the_installed_cache() {
    let k = keys();
    let (_d, s) = store();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    s.install(&v1, &sign_b64(&k, &v1), &k.keyset);

    let out = sync(&s, &NotPublishedFetcher, &k.keyset, false);
    let SyncOutcome::NotPublished { url } = out else {
        panic!("expected NotPublished, got {out:?}");
    };
    assert!(url.ends_with("/api/v1/scanner/spec-cache"));
    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-07-29.1");
}

#[test]
fn not_published_message_names_the_endpoint_and_is_not_a_network_message() {
    let msg = not_published_message("https://api.example.test/api/v1/scanner/spec-cache");
    assert!(msg.contains("https://api.example.test/api/v1/scanner/spec-cache"));
    assert!(msg.contains("404"), "{msg}");
    assert!(msg.contains("published"), "{msg}");
    assert!(!msg.contains("fetch failed"), "{msg}");
}

/// A loopback server that answers every request with `status` and an empty
/// body, then closes. Returns its base URL.
fn serve_status(status: &'static str) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
        }
    });
    base
}

#[test]
fn http_404_on_the_artifact_is_not_published_for_both_tiers() {
    let base = serve_status("404 Not Found");
    let commercial = HttpFetcher {
        base_url: base.clone(),
        org_key: "k".into(),
    };
    let Ok(Fetched::NotPublished { url }) = commercial.fetch(None) else {
        panic!("commercial 404 must be NotPublished");
    };
    assert_eq!(url, format!("{base}/api/v1/scanner/spec-cache"));

    let oss = OssHttpFetcher {
        base_url: base.clone(),
    };
    let Ok(Fetched::NotPublished { url }) = oss.fetch(None) else {
        panic!("oss 404 must be NotPublished");
    };
    assert_eq!(url, format!("{base}/api/v1/scanner/spec-cache/oss"));
}

#[test]
fn server_errors_and_dead_networks_stay_fetch_failed() {
    let k = keys();
    let (_d, s) = store();

    let f = HttpFetcher {
        base_url: serve_status("500 Internal Server Error"),
        org_key: "k".into(),
    };
    let out = sync(&s, &f, &k.keyset, false);
    assert!(matches!(out, SyncOutcome::FetchFailed { .. }), "{out:?}");

    // A port nothing listens on: bind, read the address, drop the listener.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", l.local_addr().unwrap())
    };
    let f = OssHttpFetcher { base_url: dead };
    let out = sync(&s, &f, &k.keyset, false);
    assert!(matches!(out, SyncOutcome::FetchFailed { .. }), "{out:?}");
}

// --- air-gapped import ---

#[test]
fn import_verifies_identically_no_bypass() {
    let k = keys();
    let other = keys();
    let (_d, s) = store();
    let dir = tempfile::tempdir().unwrap();
    let art = dir.path().join("specs.json");
    let sig = dir.path().join("specs.json.sig");
    let bytes = envelope_bytes(1, "2026-07-30.1");

    // good import installs
    std::fs::write(&art, &bytes).unwrap();
    std::fs::write(&sig, sign_b64(&k, &bytes)).unwrap();
    let out = s.import(&art, &sig, &k.keyset).unwrap();
    assert_eq!(
        out,
        SyncOutcome::Installed {
            content_version: "2026-07-30.1".into()
        }
    );

    // wrong-key import is rejected with identical verification
    std::fs::write(&sig, sign_b64(&other, &bytes)).unwrap();
    let out = s.import(&art, &sig, &k.keyset).unwrap();
    assert!(matches!(out, SyncOutcome::Rejected { .. }));
}

#[test]
fn install_failure_reports_install_failed_not_fetch_failed() {
    let k = keys();
    let dir = tempfile::tempdir().unwrap();
    let s = CacheStore::open(dir.path()).unwrap();
    let v1 = envelope_bytes(1, "2026-07-29.1");
    s.install(&v1, &sign_b64(&k, &v1), &k.keyset);
    // Make the store root read-only so the staging write fails.
    let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o555);
    std::fs::set_permissions(dir.path(), perms.clone()).unwrap();
    let v2 = envelope_bytes(1, "2026-07-30.1");
    let out = s.install(&v2, &sign_b64(&k, &v2), &k.keyset);
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(dir.path(), perms).unwrap();
    assert!(
        matches!(out, SyncOutcome::InstallFailed { .. }),
        "got {out:?}"
    );
    // and the previously installed cache still loads
    let loaded = s.load(&k.keyset, "2026-07-30").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-07-29.1");
}

#[test]
fn rejected_dir_is_pruned() {
    let k = keys();
    let bad = keys();
    let (dir, s) = store();
    for i in 0..12 {
        let evil = envelope_bytes(1, &format!("2026-07-{:02}.1", i + 1));
        let out = s.install(&evil, &sign_b64(&bad, &evil), &k.keyset);
        assert!(matches!(out, SyncOutcome::Rejected { .. }));
        // distinct millisecond stamps so prune ordering is deterministic
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let n = std::fs::read_dir(dir.path().join("rejected"))
        .unwrap()
        .count();
    assert!(
        n <= REJECTED_KEEP * 2,
        "rejected/ grew unbounded: {n} files"
    );
}

// --- judgments inside the signed envelope (po-av01j.106) ---

/// An envelope carrying the ratified judgments corpus beside the specs.
fn envelope_with_judgments(content_version: &str, severity: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": content_version,
        "specs": {"apis": [], "configs": []},
        "judgments": [{
            "api": "requests.get",
            "scope": "runtime",
            "verdict": "surface",
            "severity": severity,
            "fix": "Pass timeout=(connect, read). RC-019.",
            "control": "RC-019"
        }]
    }))
    .unwrap()
}

/// The corpus survives the real install + verify + load round trip. Before
/// po-av01j.106 there was nowhere in the envelope for it to ride, so a scan had
/// nothing to grade findings with and every one came out advisory.
#[test]
fn judgments_ride_inside_the_verified_envelope() {
    let k = keys();
    let (_d, s) = store();
    let bytes = envelope_with_judgments("2026-08-13.jj", "high");
    assert!(matches!(
        s.install(&bytes, &sign_b64(&k, &bytes), &k.keyset),
        SyncOutcome::Installed { .. }
    ));

    let loaded = s.load(&k.keyset, "2026-08-13").unwrap();
    let js = loaded
        .envelope
        .judgments
        .expect("judgments must survive the load path");
    let js = js.as_array().expect("judgments is a JSON array");
    assert_eq!(js.len(), 1);
    assert_eq!(js[0]["api"], "requests.get");
    assert_eq!(js[0]["scope"], "runtime");
    // The field that decides whether a commit is wedged.
    assert_eq!(js[0]["severity"], "high");
    assert_eq!(js[0]["control"], "RC-019");
}

/// The signature covers the judgments because it covers the whole artifact.
/// Demoting the ratified severity — the one edit that would silently turn a
/// blocking gate back into an advisory one — must fail verification, be
/// quarantined, and leave the previous good corpus serving.
#[test]
fn tampering_with_a_judgment_fails_verification() {
    let k = keys();
    let (_d, s) = store();
    let good = envelope_with_judgments("2026-08-13.jj", "high");
    let sig = sign_b64(&k, &good);
    s.install(&good, &sig, &k.keyset);

    // Same signature, judgments demoted to advisory.
    let tampered = envelope_with_judgments("2026-08-13.jj", "low");
    assert_ne!(good, tampered, "test bug: the tamper changed nothing");
    assert!(
        k.keyset.verify_detached(&tampered, Some(&sig)).is_err(),
        "a demoted judgment verified: judgments are outside the signature"
    );
    assert!(matches!(
        s.install(&tampered, &sig, &k.keyset),
        SyncOutcome::Rejected { .. }
    ));
    // The store still serves the untampered corpus.
    let loaded = s.load(&k.keyset, "2026-08-13").unwrap();
    assert_eq!(
        loaded.envelope.judgments.unwrap().as_array().unwrap()[0]["severity"],
        "high"
    );
}

/// NEW BINARY / OLD CACHE. Every artifact in the field predates the judgments
/// section; each must load unchanged and grade nothing, which is advisory —
/// the floor, never an error.
#[test]
fn an_artifact_without_judgments_still_loads() {
    let k = keys();
    let (_d, s) = store();
    let bytes = envelope_bytes(1, "2026-08-13.1");
    s.install(&bytes, &sign_b64(&k, &bytes), &k.keyset);

    let loaded = s.load(&k.keyset, "2026-08-13").unwrap();
    assert!(
        loaded.envelope.judgments.is_none(),
        "an absent judgments section must be None, not an error"
    );
}

/// OLD BINARY / NEW CACHE, simulated the only way a running binary can see it:
/// an envelope carrying a section this build does not model. Unknown fields are
/// ignored rather than rejected, which is why the factory could add `judgments`
/// without bumping the schema — a bump would have made every deployed binary
/// decline the artifact and pin itself to its last-good cache.
#[test]
fn an_unknown_envelope_section_is_ignored_not_rejected() {
    let k = keys();
    let (_d, s) = store();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": "2026-08-13.future",
        "specs": {"apis": [], "configs": []},
        "judgments": [],
        "some_future_lane": [{"whatever": true}]
    }))
    .unwrap();
    assert!(matches!(
        s.install(&bytes, &sign_b64(&k, &bytes), &k.keyset),
        SyncOutcome::Installed { .. }
    ));
    let loaded = s.load(&k.keyset, "2026-08-13").unwrap();
    assert_eq!(loaded.envelope.content_version, "2026-08-13.future");
}

/// po-av01j.176: a conditional GET that the server answers 304 must resolve to
/// NotModified, never to a signature failure.
///
/// The regression this pins is subtle and was live for as long as sync existed.
/// `HttpFetcher::fetch` handled 304 in an `Err(ureq::Error::Status(304, _))`
/// arm, but ureq reserves `Error::Status` for 4xx/5xx and hands a 304 back as
/// `Ok`. So the arm never fired: the response fell through to the success path,
/// an EMPTY body was read, the detached signature was fetched separately as a
/// real 200, and verification of zero bytes against a valid signature failed.
/// Users saw "signature does not verify against any pinned key" — a tampering
/// message — for a correct, healthy cache hit. It stayed hidden because syncs
/// normally follow a version change, which takes the 200 path.
///
/// A live loopback server rather than a fake Fetcher on purpose: the bug lived
/// in the ureq status handling itself, so a hand-rolled Fetcher stub would have
/// reproduced nothing and passed against the broken code.
#[test]
fn a_304_is_up_to_date_not_a_signature_failure() {
    use std::io::{BufRead, BufReader, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut conditional = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                    break;
                }
                if line.to_ascii_lowercase().starts_with("if-none-match:") {
                    conditional = true;
                }
            }
            // Mirror the real handler: a conditional hit is 304 with NO body,
            // and it never touches storage.
            let response = if conditional {
                "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\nContent-Length: 0\r\n\r\n"
                    .to_string()
            } else {
                let body = "{\"schema\":1}";
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
            };
            let _ = stream.write_all(response.as_bytes());
        }
    });

    let fetcher = HttpFetcher {
        base_url: base,
        org_key: "pk_test".into(),
    };
    match fetcher.fetch(Some("abc")) {
        Ok(Fetched::NotModified) => {}
        Ok(Fetched::New { bytes, .. }) => panic!(
            "a 304 was treated as a fresh artifact carrying {} byte(s); the empty \
             body then fails signature verification",
            bytes.len()
        ),
        Ok(Fetched::NotPublished { url }) => panic!("a 304 from {url} is not a 404"),
        Err(e) => panic!("a 304 must not be an error: {e}"),
    }
}

// --- tier filter (po-7wgx3) ---

/// A keyed install: the OSS vocabulary tier under `oss/` and a commercial
/// tier carrying judgments beside it, both signed by the same keyset.
fn keyed_install(k: &TestKeys) -> (tempfile::TempDir, CacheStore, CacheStore) {
    let (dir, commercial) = store();
    let oss = commercial.subdir_store(OSS_DIR).unwrap();
    let oss_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": "2026-07-30.1",
        "specs": {"apis": [], "configs": [], "server": ["oss-vocabulary"]}
    }))
    .unwrap();
    assert!(matches!(
        oss.install(&oss_bytes, &sign_b64(k, &oss_bytes), &k.keyset),
        SyncOutcome::Installed { .. }
    ));
    let com_bytes = envelope_with_judgments("2026-07-30.1", "blocking");
    assert!(matches!(
        commercial.install(&com_bytes, &sign_b64(k, &com_bytes), &k.keyset),
        SyncOutcome::Installed { .. }
    ));
    (dir, commercial, oss)
}

#[test]
fn tier_filter_both_layers_the_commercial_tier_over_oss() {
    let k = keys();
    let (_d, commercial, oss) = keyed_install(&k);
    let t = load_tiered(&commercial, &oss, &k.keyset, "2026-07-30", TierFilter::Both);
    assert!(t.oss.is_some() && t.commercial.is_some());
    assert!(t.judgments().is_some());
    let (_base, overlay) = t.spec_texts().unwrap().unwrap();
    assert!(overlay.is_some());
}

#[test]
fn tier_filter_oss_only_behaves_like_a_no_key_install() {
    let k = keys();
    let (_d, commercial, oss) = keyed_install(&k);
    let t = load_tiered(
        &commercial,
        &oss,
        &k.keyset,
        "2026-07-30",
        TierFilter::OssOnly,
    );
    assert!(t.oss.is_some());
    assert!(t.commercial.is_none(), "the commercial tier must not load");
    assert!(t.judgments().is_none(), "no judgments: everything advisory");
    let (base, overlay) = t.spec_texts().unwrap().unwrap();
    assert!(base.contains("oss-vocabulary"));
    assert!(overlay.is_none(), "no commercial overlay to merge");
}

#[test]
fn tier_filter_oss_only_never_falls_back_to_the_commercial_tier() {
    let k = keys();
    let (_d, commercial) = store();
    let oss = commercial.subdir_store(OSS_DIR).unwrap();
    let com_bytes = envelope_with_judgments("2026-07-30.1", "blocking");
    commercial.install(&com_bytes, &sign_b64(&k, &com_bytes), &k.keyset);
    let t = load_tiered(
        &commercial,
        &oss,
        &k.keyset,
        "2026-07-30",
        TierFilter::OssOnly,
    );
    assert!(!t.any());
    assert!(t.spec_texts().unwrap().is_none());
}
