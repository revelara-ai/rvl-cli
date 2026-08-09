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

// --- the exit-code predicate (po-av01j.94) ---

/// Coverage is orthogonal to the blocking verdict; these tests don't assert on
/// it, so one fully-resolved value serves.
fn cov() -> Coverage {
    Coverage {
        resolved: 1,
        total: 1,
        abstain_no_spec: 0,
        abstain_bounds: 0,
        abstain_judge: 0,
        abstain_other: 0,
        degraded: Vec::new(),
        degraded_note: None,
        lang_status: Vec::new(),
    }
}

#[test]
fn blocking_count_agrees_with_the_footer_it_gates_on() {
    // `blocking_count` is what `scan` turns into its exit code. It must count
    // exactly what the ladder puts under BLOCKING — never a second opinion,
    // or the printed verdict and the process status can diverge again.
    let findings = vec![
        f("b1", "high", "surface", 0),   // blocking: base severity
        f("b2", "medium", "surface", 3), // blocking: elevated by incidents
        f("a1", "medium", "surface", 0), // advisory
        f("s1", "high", "low_value", 0), // suppressed by disposition
        f("u1", "", "unjudged", 0),      // advisory: never blocks alone
    ];
    assert_eq!(blocking_count(&findings), 2);
    assert!(render_ladder(&findings, cov(), None, "0.1s", false).contains("blocked"));

    // A waived high-severity surface finding is not blocking, so the gate
    // opens: this is the whole point of the waiver apparatus.
    let mut waived = f("w1", "high", "surface", 4);
    waived.suppressed = true;
    assert_eq!(blocking_count(&[waived.clone()]), 0);
    assert!(render_ladder(&[waived], cov(), None, "0.1s", false).contains("commit clean"));

    // Nothing at all is trivially clean.
    assert_eq!(blocking_count(&[]), 0);
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
        degraded: Vec::new(),
        degraded_note: None,
        lang_status: Vec::new(),
    };
    let out = render_ladder(&findings, cov, None, "0.4s (warm)", false);

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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
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
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        None,
        "0.1s",
        false,
    );
    assert!(out.contains("12 corpus incidents"));
    assert!(
        !out.contains("rvl.ai/i/"),
        "named incident links belong in explain, not the ladder"
    );
}

// --- config lane coverage ---

#[test]
fn config_coverage_renders_resolution_abstain_levers_and_sightings() {
    let cc = ConfigCoverage {
        resolved: 3,
        total: 6,
        abstain_no_spec: 1,
        abstain_outside_repo: 2,
        abstain_other: 0,
        unparseable_files: 1,
        sightings: vec![
            ("circleci".to_string(), 1, false),
            ("terraform".to_string(), 4, false),
        ],
    };
    let out = render_ladder(
        &[],
        Coverage {
            resolved: 1,
            total: 1,
            abstain_no_spec: 0,
            abstain_bounds: 0,
            abstain_judge: 0,
            abstain_other: 0,
            degraded: Vec::new(),
            degraded_note: None,
            lang_status: Vec::new(),
        },
        Some(&cc),
        "0.1s",
        false,
    );
    assert!(out.contains("config: 3/6 settings resolved"), "{out}");
    assert!(
        out.contains("1 no spec") && out.contains("2 set outside repo"),
        "abstain levers named: {out}"
    );
    assert!(out.contains("1 config file unparseable"), "{out}");
    assert!(
        out.contains("unsupported config formats sighted: circleci (1) \u{00b7} terraform (4)"),
        "identity-only sightings rendered: {out}"
    );
}

#[test]
fn empty_config_coverage_renders_nothing_extra() {
    let empty = ConfigCoverage::default();
    let base = |cfg| {
        render_ladder(
            &[],
            Coverage {
                resolved: 1,
                total: 1,
                abstain_no_spec: 0,
                abstain_bounds: 0,
                abstain_judge: 0,
                abstain_other: 0,
                degraded: Vec::new(),
                degraded_note: None,
                lang_status: Vec::new(),
            },
            cfg,
            "0.1s",
            false,
        )
    };
    assert_eq!(
        base(None),
        base(Some(&empty)),
        "an empty lane leaves the ladder untouched"
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

// po-av01j.136 defect 2. One line saying "unsupported config formats" for both
// cases was actively misleading: on a Terraform repo it reported 109 Gatekeeper
// policies as unsupported Kubernetes, in a run where the Kubernetes lane
// resolved 288 settings. A supported format with nothing to retrieve is not a
// coverage gap and must not be counted as one.
#[test]
fn sightings_split_unsupported_formats_from_supported_ones_with_nothing_to_take() {
    let cc = ConfigCoverage {
        resolved: 288,
        total: 910,
        sightings: vec![
            ("kubernetes".to_string(), 109, true),
            ("skaffold".to_string(), 13, false),
        ],
        ..Default::default()
    };
    let out = render_ladder(&[], Coverage::default(), Some(&cc), "0.1s", false);

    let unsupported = out
        .lines()
        .find(|l| l.contains("unsupported config formats sighted"))
        .unwrap_or_default();
    assert!(
        unsupported.contains("skaffold (13)"),
        "a format with no retriever belongs in the authoring queue: {out}"
    );
    assert!(
        !unsupported.contains("kubernetes"),
        "a SUPPORTED format must never be listed as unsupported: {out}"
    );

    let supported = out
        .lines()
        .find(|l| l.contains("supported formats, nothing to retrieve"))
        .unwrap_or_default();
    assert!(
        supported.contains("kubernetes (109)"),
        "the count is still reported, under an accurate label: {out}"
    );
    assert!(
        !supported.contains("skaffold"),
        "the two categories must not bleed: {out}"
    );
}

// Neither line may appear when its category is empty -- a heading with nothing
// under it reads as a finding of its own.
#[test]
fn a_category_with_no_sightings_prints_no_line() {
    let only_supported = ConfigCoverage {
        resolved: 1,
        total: 1,
        sightings: vec![("kubernetes".to_string(), 4, true)],
        ..Default::default()
    };
    let out = render_ladder(
        &[],
        Coverage::default(),
        Some(&only_supported),
        "0.1s",
        false,
    );
    assert!(
        !out.contains("unsupported config formats sighted"),
        "no unsupported formats were sighted, so that line must be absent: {out}"
    );
    assert!(
        out.contains("supported formats, nothing to retrieve"),
        "{out}"
    );
}

// po-av01j.139. An empty G1 lane used to abort the whole scan with exit 1,
// "the scan could not complete". In hook mode that is the ORDINARY case: a
// commit whose changed files carry no retrievable call site. The scan ran
// fine; it had nothing to look at, and it must say so rather than either
// printing a meaningless 0/0 or failing the commit.
#[test]
fn an_empty_g1_lane_says_so_instead_of_rendering_a_meaningless_zero() {
    let out = render_ladder(&[], Coverage::default(), None, "0.1s", false);
    assert!(
        out.contains("no API call sites in scope"),
        "an empty lane must state it ran and found nothing: {out}"
    );
    assert!(
        !out.contains("0/0 API surfaces resolved"),
        "a bare 0/0 tells the reader nothing: {out}"
    );
    assert!(
        out.contains("commit clean"),
        "nothing to scan is a CLEAN result, never a failure: {out}"
    );
}

// The other lanes must survive an empty G1 lane. The old abort discarded their
// findings along with everything else, which is how a config-only change lost
// its config findings.
#[test]
fn config_and_degradation_still_render_when_there_are_no_call_sites() {
    let cc = ConfigCoverage {
        resolved: 516,
        total: 871,
        abstain_no_spec: 279,
        ..Default::default()
    };
    let cov = Coverage {
        degraded: vec![DegradedLang {
            lang: "C#".into(),
            abstained: false,
            reason: "no csindex helper found".into(),
        }],
        ..Default::default()
    };
    let out = render_ladder(&[], cov, Some(&cc), "0.1s", false);
    assert!(
        out.contains("no API call sites in scope"),
        "empty G1 lane still reported: {out}"
    );
    assert!(
        out.contains("config: 516/871 settings resolved"),
        "the config lane has its own findings and must still render: {out}"
    );
    assert!(
        out.contains("C#") && out.contains("retriever failed"),
        "a degraded language is the REASON G1 can be empty, so it must show: {out}"
    );
}

// po-av01j.139, second half. Found on apache/airflow: the incremental pass
// degraded (pyindex failed on a 7690-file Python repo) and the coverage line
// still read "no API call sites in scope -- nothing to resolve". There WERE
// call sites; the retriever never got to them. Printing the two alike is the
// exact confusion this bead exists to remove, and the first fix reintroduced
// it in the other direction.
#[test]
fn an_empty_lane_after_a_degraded_pass_says_incomplete_not_nothing_to_resolve() {
    let cov = Coverage {
        degraded_note: Some("retrieval failed (running retriever helper `python3`)".into()),
        ..Default::default()
    };
    let out = render_ladder(&[], cov, None, "0.1s", false);
    assert!(
        out.contains("INCOMPLETE") && out.contains("python3"),
        "an empty lane after a failed retrieval must say it never looked: {out}"
    );
    assert!(
        !out.contains("nothing to resolve"),
        "'nothing to resolve' is a false claim when retrieval failed: {out}"
    );
}

// The truthful case must keep its truthful wording.
#[test]
fn an_empty_lane_with_no_degradation_still_reads_as_nothing_to_scan() {
    let out = render_ladder(&[], Coverage::default(), None, "0.1s", false);
    assert!(out.contains("nothing to resolve"), "{out}");
    assert!(!out.contains("INCOMPLETE"), "{out}");
}

// A PARTIAL pass must be flagged too: the percentage describes the reused
// portion, not the repo, and a reader comparing it to a previous run would
// otherwise read a retrieval failure as a coverage regression.
#[test]
fn a_partial_pass_flags_that_coverage_describes_less_than_the_repo() {
    let cov = Coverage {
        resolved: 10,
        total: 12,
        degraded_note: Some("retrieval failed (helper `python3`)".into()),
        ..Default::default()
    };
    let out = render_ladder(&[], cov, None, "0.1s", false);
    assert!(
        out.contains("PARTIAL") && out.contains("10/12"),
        "a partial pass reports its number AND that it is partial: {out}"
    );
}

// po-av01j.128 / po-av01j.132. Silence must never be ambiguous. Before this, a
// language that ran and found nothing, one whose helper declined, and one
// nothing here can read all produced the same output: none. On a Rust repo with
// four C files, cindex parsed all four and correctly found no I/O, and the
// report mentioned C nowhere.
#[test]
fn every_language_seen_is_named_including_the_ones_that_found_nothing() {
    let cov = Coverage {
        resolved: 100,
        total: 200,
        lang_status: vec![
            LangStatus {
                lang: "Rust".into(),
                state: LangState::Scanned,
                detail: "853".into(),
            },
            // The case that used to vanish: ran, looked, found nothing.
            LangStatus {
                lang: "C/C++".into(),
                state: LangState::Scanned,
                detail: "0".into(),
            },
            LangStatus {
                lang: "TypeScript".into(),
                state: LangState::Abstained,
                detail: "no installed node_modules".into(),
            },
            LangStatus {
                lang: "Ruby".into(),
                state: LangState::Unsupported,
                detail: "412 files".into(),
            },
        ],
        ..Default::default()
    };
    let out = render_ladder(&[], cov, None, "0.1s", false);
    assert!(out.contains("Rust 853 sites"), "{out}");
    assert!(
        out.contains("C/C++ 0 sites"),
        "a clean zero must be VISIBLE, not silent: {out}"
    );
    assert!(out.contains("TypeScript abstained"), "{out}");
    assert!(
        out.contains("Ruby not supported (412 files)"),
        "the third state must be reported: {out}"
    );
}

#[test]
fn a_failed_language_is_distinguishable_from_one_that_abstained() {
    let cov = Coverage {
        lang_status: vec![
            LangStatus {
                lang: "Python".into(),
                state: LangState::Failed,
                detail: "helper missing".into(),
            },
            LangStatus {
                lang: "Go".into(),
                state: LangState::Abstained,
                detail: "no modules".into(),
            },
        ],
        ..Default::default()
    };
    let out = render_ladder(&[], cov, None, "0.1s", false);
    assert!(out.contains("Python FAILED"), "{out}");
    assert!(out.contains("Go abstained"), "{out}");
    assert!(
        !out.contains("Go FAILED") && !out.contains("Python abstained"),
        "an abstention is the tool working; a failure is not: {out}"
    );
}

// Nothing seen means no line at all: an empty roll-call heading reads as a
// finding of its own.
#[test]
fn no_languages_seen_prints_no_roll_call() {
    let out = render_ladder(&[], Coverage::default(), None, "0.1s", false);
    assert!(!out.contains("languages:"), "{out}");
}
