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
    let signing = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
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
