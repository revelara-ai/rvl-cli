//! Cache-replay rendering for scan submissions, ported from rvl-cli
//! `internal/commands/scan_cached_output.go` (po-72d5d).
//!
//! The Revelara API deduplicates scan submissions by `idempotency_key`. When
//! the same scan parts and metadata are submitted twice inside the dedup
//! window, the second submission gets the first one's stored `ScanResponse`
//! back and no risk processing runs at all.
//!
//! Until the server started marking those bodies with `cached: true`, a replay
//! was indistinguishable from a fresh scan, so this CLI reprinted
//! `[NEW] R-0XX ...` for risks that had been created on an earlier run. That is
//! actively misleading: it reads as "your change introduced these" when nothing
//! was created or updated by the command that just ran.
//!
//! The rendering below makes a replay unmistakable in three places: the
//! headline, the findings heading, and the per-risk status marker.

use crate::scan_submit::ScanResponse;
use std::io::Write;

/// The first line of the human-readable scan output. Servers that predate the
/// `cached` field always yield the original wording, so nothing changes for
/// them.
pub fn scan_submit_headline(cached: bool) -> &'static str {
    if cached {
        "Scan replayed from server cache (cached: no new processing; risks below are the previous result)"
    } else {
        "Scan submitted successfully"
    }
}

/// The per-finding status column. On a replay the marker is prefixed with
/// "was" so an eye scanning for `[NEW]` does not find one: the status describes
/// what happened on the ORIGINAL scan, not on this invocation.
pub fn scan_status_marker(status: &str, cached: bool) -> String {
    let marker = match status {
        "created" => "NEW",
        "updated" => "UPD",
        _ => return "---".to_string(),
    };
    if cached {
        format!("was {marker}")
    } else {
        marker.to_string()
    }
}

/// Write the findings block. Risk rows go to `out`; per-finding server warnings
/// go to `err_out` (they were once parsed but never printed, so a server-side
/// partial accept of a finding's fields was invisible).
pub fn print_scan_findings(out: &mut dyn Write, err_out: &mut dyn Write, response: &ScanResponse) {
    let Some(findings) = response.findings.as_ref().filter(|f| !f.is_empty()) else {
        return;
    };
    if response.cached {
        let _ = writeln!(
            out,
            "Findings (cached: from the earlier scan, nothing was created or updated by this run):"
        );
    } else {
        let _ = writeln!(out, "Findings:");
    }
    for f in findings {
        let _ = writeln!(
            out,
            "  [{}] {}: {} (score: {}, {})",
            scan_status_marker(&f.status, response.cached),
            f.risk_code,
            f.title,
            f.score,
            f.priority
        );
        for w in &f.warnings {
            let _ = writeln!(err_out, "        warning [{}]: {w}", f.risk_code);
        }
    }
    let _ = writeln!(out);
}

/// Write the cache-replay note to `err_out` for the output modes whose stdout
/// is machine-readable (`--format json`). Those modes pass the `cached` field
/// through in the JSON body already; this line is for the human reading the CI
/// log.
pub fn note_cached_scan(err_out: &mut dyn Write, response: &ScanResponse) {
    if !response.cached {
        return;
    }
    let _ = writeln!(
        err_out,
        "note: cached scan replay (no new processing); findings are the previous result for this identical submission"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_submit::{ScanResponse, ScanResult};

    // The API replays a previously-processed ScanResponse when the
    // submission's idempotency_key matches a recent scan. The replay used to be
    // indistinguishable from a fresh scan, so the CLI happily reprinted
    // "[NEW] R-0XX ..." for risks created on some earlier run. These tests pin
    // the cache-hit rendering and the old-server fallback.

    #[test]
    fn cached_falls_back_to_fresh_on_old_servers() {
        // A server that predates the `cached` field sends no such key. The CLI
        // must behave exactly as before: fresh rendering, [NEW] markers.
        let resp: ScanResponse = serde_json::from_str(
            r#"{"scan_id":"s1","service":"svc","findings":[],"timestamp":"now"}"#,
        )
        .expect("unmarshal");
        assert!(!resp.cached, "absent cached field must decode as false");
        assert_eq!(
            scan_submit_headline(resp.cached),
            "Scan submitted successfully"
        );
    }

    #[test]
    fn cached_decodes_true() {
        let resp: ScanResponse = serde_json::from_str(
            r#"{"scan_id":"s1","service":"svc","findings":[],"timestamp":"now","cached":true}"#,
        )
        .expect("unmarshal");
        assert!(resp.cached, "cached:true must decode as true");
        let headline = scan_submit_headline(resp.cached);
        assert!(headline.contains("cached"), "{headline}");
        assert!(headline.contains("no new processing"), "{headline}");
    }

    fn cached_test_response(cached: bool) -> ScanResponse {
        let mut resp = ScanResponse {
            scan_id: "s1".into(),
            service: "checkout-api".into(),
            cached,
            ..Default::default()
        };
        resp.findings = Some(vec![
            ScanResult {
                risk_code: "R-001".into(),
                title: "Missing timeout".into(),
                status: "created".into(),
                score: 70,
                priority: "high".into(),
                ..Default::default()
            },
            ScanResult {
                risk_code: "R-002".into(),
                title: "No circuit breaker".into(),
                status: "updated".into(),
                score: 55,
                priority: "medium".into(),
                ..Default::default()
            },
            ScanResult {
                risk_code: "R-003".into(),
                title: "Stale runbook".into(),
                status: "unchanged".into(),
                score: 20,
                priority: "low".into(),
                ..Default::default()
            },
        ]);
        resp
    }

    fn render(cached: bool) -> (String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        print_scan_findings(&mut out, &mut err, &cached_test_response(cached));
        (
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn fresh_keeps_new_markers() {
        let (got, _) = render(false);
        assert!(got.contains("Findings:\n"), "{got}");
        assert!(got.contains("[NEW] R-001"), "{got}");
        assert!(got.contains("[UPD] R-002"), "{got}");
        assert!(
            !got.contains("cached"),
            "fresh scan must not mention cache: {got}"
        );
    }

    #[test]
    fn cached_suppresses_new_markers() {
        let (got, _) = render(true);
        assert!(!got.contains("[NEW]"), "{got}");
        assert!(!got.contains("[UPD]"), "{got}");
        assert!(got.contains("[was NEW] R-001"), "{got}");
        assert!(got.contains("[was UPD] R-002"), "{got}");
        assert!(got.contains("cached"), "{got}");
        // The risk rows themselves are unchanged apart from the marker.
        assert!(
            got.contains("R-003: Stale runbook (score: 20, low)"),
            "{got}"
        );
    }

    #[test]
    fn unknown_status_stays_a_dash_row() {
        assert_eq!(scan_status_marker("unchanged", false), "---");
        assert_eq!(scan_status_marker("unchanged", true), "---");
    }

    #[test]
    fn warnings_go_to_stderr() {
        let mut resp = cached_test_response(true);
        resp.findings.as_mut().unwrap()[0].warnings = vec!["severity coerced".into()];
        let mut out = Vec::new();
        let mut err = Vec::new();
        print_scan_findings(&mut out, &mut err, &resp);
        let out = String::from_utf8(out).unwrap();
        let err = String::from_utf8(err).unwrap();
        assert!(!out.contains("severity coerced"), "{out}");
        assert!(err.contains("warning [R-001]: severity coerced"), "{err}");
    }

    #[test]
    fn note_only_fires_on_a_replay() {
        let mut err = Vec::new();
        note_cached_scan(&mut err, &cached_test_response(false));
        assert!(err.is_empty(), "fresh scan must not print the note");

        let mut err = Vec::new();
        note_cached_scan(&mut err, &cached_test_response(true));
        let err = String::from_utf8(err).unwrap();
        assert!(err.contains("cached scan replay"), "{err}");
    }
}
