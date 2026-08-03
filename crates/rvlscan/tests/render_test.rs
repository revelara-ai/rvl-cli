//! Severity-ladder output acceptance tests (po-3t3oj.9).

// The render module is compiled into the binary crate; the integration test
// exercises it through a thin re-export path is not available, so these unit
// tests live alongside via `include!` of the source under test.
#[path = "../src/render.rs"]
mod render;

use render::*;

fn f(id_seed: &str, sev: &str, disp: &str, crit: u32) -> Finding {
    Finding {
        id: finding_id(id_seed),
        site: "internal/billing/client.go:42".into(),
        description: "http.Client without Timeout".into(),
        disposition: disp.into(),
        severity: sev.into(),
        incident_count: if crit > 0 { 12 } else { 0 },
        critical_count: crit,
        control: "RC-019".into(),
        fix: "set a Timeout or thread a ctx deadline".into(),
        site_count: 3,
        example_sites: vec!["a.go:1".into(), "b.go:2".into()],
        class_rule: "pkg.T.M".into(),
        suppressed: false,
    }
}

// --- color resolution ---

#[test]
fn color_auto_honors_no_color_and_tty() {
    assert!(
        !ColorMode::Auto.resolve(true, true),
        "NO_COLOR set -> no color"
    );
    assert!(
        !ColorMode::Auto.resolve(false, false),
        "not a tty -> no color"
    );
    assert!(
        ColorMode::Auto.resolve(false, true),
        "tty and no NO_COLOR -> color"
    );
    assert!(ColorMode::Always.resolve(true, false), "Always overrides");
    assert!(!ColorMode::Never.resolve(false, true), "Never overrides");
}

// --- finding id ---

#[test]
fn finding_carries_class_rule_waiver_key() {
    // The class_rule field is the waiver key threaded through to the suppress
    // path; the ladder itself just carries it.
    assert_eq!(f("x", "high", "surface", 0).class_rule, "pkg.T.M");
}

#[test]
fn finding_id_is_stable_and_short() {
    assert_eq!(
        finding_id("pkg.Client.Do:runtime"),
        finding_id("pkg.Client.Do:runtime")
    );
    assert_ne!(finding_id("a"), finding_id("b"));
    assert_eq!(finding_id("anything").len(), 4);
}

// --- severity classification ---

#[test]
fn high_surface_is_blocking_medium_is_advisory() {
    assert_eq!(classify(&f("x", "high", "surface", 0)), Section::Blocking);
    assert_eq!(classify(&f("x", "medium", "surface", 0)), Section::Advisory);
}

#[test]
fn critical_incidents_elevate_medium_to_blocking() {
    // A medium finding that matches critical corpus incidents blocks: the
    // corpus says this shape takes systems down.
    assert_eq!(classify(&f("x", "medium", "surface", 2)), Section::Blocking);
}

#[test]
fn low_value_is_suppressed_and_unjudged_is_advisory_never_blocking() {
    assert_eq!(
        classify(&f("x", "high", "low_value", 5)),
        Section::Suppressed
    );
    // An un-triaged finding must never block a commit on its own.
    let u = f("x", "", "unjudged", 0);
    assert_eq!(classify(&u), Section::Advisory);
}

// --- ladder ---

#[test]
fn ladder_groups_by_severity_with_blocked_footer() {
    let findings = vec![
        f("block1", "high", "surface", 2),
        f("adv1", "medium", "surface", 0),
        f("hidden", "low", "low_value", 0),
    ];
    let cov = Coverage {
        resolved: 58,
        total: 59,
        abstain_no_spec: 1,
        abstain_bounds: 0,
        abstain_judge: 0,
        abstain_other: 0,
    };
    let out = render_ladder(&findings, cov, "0.4s (warm)", false);

    assert!(out.contains("BLOCKING"), "blocking section present");
    assert!(out.contains("ADVISORY"), "advisory section present");
    assert!(out.contains("COVERAGE"), "coverage section present");
    assert!(
        out.contains("58/59 API surfaces resolved (98%)"),
        "resolved counts + percent shown"
    );
    assert!(
        out.contains("1 abstain") && out.contains("1 no spec"),
        "abstain breakdown reported"
    );
    assert!(out.contains("blocked"), "footer says blocked");
    // low_value must not appear anywhere.
    assert!(
        !out.contains(&finding_id("hidden")),
        "suppressed finding must not render"
    );
    // incident evidence surfaces on the blocking finding.
    assert!(
        out.contains("12 corpus incidents") && out.contains("2 critical"),
        "incident counts shown"
    );
}

#[test]
fn suppressed_finding_is_hidden_and_counted_in_footer() {
    // A waiver-suppressed finding classifies as Suppressed regardless of its
    // base severity/disposition, stays out of the ladder body, and shows up in
    // the clean footer's suppressed count.
    let mut waived = f("waived1", "high", "surface", 2);
    waived.suppressed = true;
    assert_eq!(
        classify(&waived),
        Section::Suppressed,
        "suppressed by waiver"
    );

    let findings = vec![f("adv1", "medium", "surface", 0), waived];
    let out = render_ladder(
        &findings,
        Coverage {
            resolved: 5,
            total: 5,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        false,
    );
    // The suppressed finding does not render in BLOCKING/ADVISORY.
    assert!(
        !out.contains(&finding_id("waived1")),
        "suppressed finding must not render in the ladder body"
    );
    assert!(!out.contains("BLOCKING"), "no blocking section");
    // Footer reports it, and still says commit clean (suppressed never blocks).
    assert!(
        out.contains("1 suppressed"),
        "footer shows suppressed count"
    );
    assert!(
        out.contains("commit clean"),
        "suppressed does not block commit"
    );
}

#[test]
fn zero_suppressed_omits_the_suppressed_footer_clause() {
    let out = render_ladder(
        &[f("adv1", "medium", "surface", 0)],
        Coverage {
            resolved: 1,
            total: 1,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        false,
    );
    assert!(
        !out.contains("suppressed"),
        "no suppressed clause when count is 0"
    );
    assert!(out.contains("commit clean"));
}

#[test]
fn ladder_with_no_blocking_says_commit_clean() {
    let findings = vec![f("adv1", "medium", "surface", 0)];
    let out = render_ladder(
        &findings,
        Coverage {
            resolved: 10,
            total: 10,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        false,
    );
    assert!(out.contains("commit clean"), "no blocking -> clean footer");
    assert!(!out.contains("\u{2717} blocked"), "must not claim blocked");
}

#[test]
fn no_color_mode_emits_no_ansi_escapes() {
    let out = render_ladder(
        &[f("b", "high", "surface", 1)],
        Coverage {
            resolved: 1,
            total: 1,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        false,
    );
    assert!(
        !out.contains('\x1b'),
        "no-color output must contain no ANSI escapes"
    );
    // ...and color mode DOES emit them.
    let colored = render_ladder(
        &[f("b", "high", "surface", 1)],
        Coverage {
            resolved: 1,
            total: 1,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        true,
    );
    assert!(
        colored.contains('\x1b'),
        "color output must contain ANSI escapes"
    );
}

#[test]
fn hook_ladder_shows_counts_not_named_incidents() {
    // The hook path shows incident COUNTS only; named incidents are reserved
    // for explain.
    let out = render_ladder(
        &[f("b", "high", "surface", 2)],
        Coverage {
            resolved: 1,
            total: 1,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
        },
        "0.1s",
        false,
    );
    assert!(out.contains("12 corpus incidents"));
    assert!(
        !out.contains("rvl.ai/i/"),
        "named incident links belong in explain, not the ladder"
    );
}

// --- explain ---

#[test]
fn explain_shows_named_incidents_control_and_fix() {
    let finding = f("e", "high", "surface", 2);
    let incidents = vec![
        (
            "Cloudflare outage 2025-11-18".to_string(),
            true,
            "rvl.ai/i/inc-ej6".to_string(),
        ),
        (
            "AWS us-east-1 2025-10-20".to_string(),
            true,
            "rvl.ai/i/inc-xzt".to_string(),
        ),
    ];
    let out = render_explain(&finding, &incidents, false);
    assert!(
        out.contains("Cloudflare outage 2025-11-18"),
        "named incident shown"
    );
    assert!(out.contains("(critical)"), "criticality shown");
    assert!(out.contains("rvl.ai/i/inc-ej6"), "incident link shown");
    assert!(out.contains("RC-019"), "control shown");
    assert!(out.contains("set a Timeout"), "fix shown");
    assert!(
        out.contains(&format!("rvlscan suppress {}", finding.id)),
        "suppress hint shown"
    );
}
