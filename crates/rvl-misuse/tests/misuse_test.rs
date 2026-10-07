//! Misuse-lane evaluator tests. Sites are built the way the retrievers build
//! them: one aggregate per (function, class, identity), with the class and
//! the count in const_args.

use rvl_core::{ConstArg, Site, CONST_ARG_MISUSE_CLASS, CONST_ARG_MISUSE_COUNT, SITE_KIND_MISUSE};
use rvl_misuse::{evaluate, MisuseFinding};
use rvl_spec::MisuseSpec;

fn shape(file: &str, line: u32, class: &str, identity: &str, count: u32) -> Site {
    let arg = |name: &str, value: String| ConstArg {
        name: name.into(),
        value,
        how: "aggregate".into(),
        ..Default::default()
    };
    Site {
        file_path: file.into(),
        line_number: line,
        symbol: format!("f{line}"),
        client_type: identity.into(),
        site_kind: SITE_KIND_MISUSE.into(),
        const_args: vec![
            arg(CONST_ARG_MISUSE_CLASS, class.into()),
            arg(CONST_ARG_MISUSE_COUNT, count.to_string()),
        ],
        ..Default::default()
    }
}

fn spec(class: &str, type_name: &str, role: &str, control: &str) -> MisuseSpec {
    MisuseSpec {
        class: class.into(),
        type_name: type_name.into(),
        control: control.into(),
        role: role.into(),
        severity: String::new(),
        confidence: 0.9,
        rationale: String::new(),
    }
}

fn one<'a>(findings: &'a [MisuseFinding], class: &str) -> &'a MisuseFinding {
    let hits: Vec<_> = findings.iter().filter(|f| f.class == class).collect();
    assert_eq!(hits.len(), 1, "want one {class} finding: {findings:?}");
    hits[0]
}

#[test]
fn no_spec_means_no_judgment() {
    let sites = [shape("svc/a.go", 10, "discarded_error", "os.Remove", 2)];
    assert!(evaluate(&sites, &[]).is_empty());
    // A spec for another class does not judge this one.
    let other = [spec("missing_await", "*", "violates", "RC-029")];
    assert!(evaluate(&sites, &other).is_empty());
}

#[test]
fn a_class_wide_spec_collapses_every_site_into_one_finding_under_its_control() {
    let sites: Vec<Site> = (1..=8)
        .map(|i| shape("svc/a.go", i * 10, "discarded_error", "os.Remove", 2))
        .collect();
    let findings = evaluate(
        &sites,
        &[spec("discarded_error", "*", "violates", "RC-029")],
    );
    let f = one(&findings, "discarded_error");
    assert_eq!(f.control, "RC-029");
    assert_eq!(f.occurrences, 16, "the count is the total, not the packets");
    assert_eq!(f.evidence.len(), 5, "evidence is capped: {:?}", f.evidence);
    assert_eq!(f.evidence[0], "svc/a.go:10");
    assert!(
        f.reason.contains("16") && f.reason.contains("8 function(s)"),
        "{}",
        f.reason
    );
    assert!(f.fix.contains("RC-029"), "{}", f.fix);
}

#[test]
fn an_allowed_identity_beats_the_class_wide_entry() {
    let sites = [
        shape("svc/a.go", 10, "discarded_error", "os.File.Close", 4),
        shape("svc/a.go", 20, "discarded_error", "os.Remove", 1),
    ];
    let specs = [
        spec("discarded_error", "*", "violates", "RC-029"),
        spec("discarded_error", "os.File.Close", "allowed", ""),
    ];
    let findings = evaluate(&sites, &specs);
    let f = one(&findings, "discarded_error");
    assert_eq!(f.occurrences, 1);
    assert_eq!(f.evidence, ["svc/a.go:20"]);

    // With every site allowed there is no finding at all.
    assert!(evaluate(&sites[..1], &specs).is_empty());
}

#[test]
fn an_exact_violates_entry_judges_only_its_identity() {
    let sites = [
        shape("app/a.py", 5, "overbroad_catch", "BaseException", 1),
        shape("app/a.py", 9, "overbroad_catch", "Exception", 3),
    ];
    let findings = evaluate(
        &sites,
        &[spec(
            "overbroad_catch",
            "BaseException",
            "violates",
            "RC-029",
        )],
    );
    let f = one(&findings, "overbroad_catch");
    assert_eq!((f.occurrences, f.evidence.len()), (1, 1));
}

#[test]
fn severity_is_the_class_default_unless_the_spec_tunes_it_and_is_never_high() {
    let sites = [
        shape("app/a.py", 5, "overbroad_catch", "Exception", 1),
        shape("app/a.py", 9, "blocking_in_async", "requests.get", 1),
    ];
    let mut specs = vec![
        spec("overbroad_catch", "*", "violates", "RC-029"),
        spec("blocking_in_async", "*", "violates", "RC-019"),
    ];
    let findings = evaluate(&sites, &specs);
    assert_eq!(one(&findings, "overbroad_catch").severity, "low");
    assert_eq!(one(&findings, "blocking_in_async").severity, "medium");

    specs[0].severity = "medium".into();
    specs[1].severity = "high".into();
    let findings = evaluate(&sites, &specs);
    assert_eq!(one(&findings, "overbroad_catch").severity, "medium");
    assert_eq!(
        one(&findings, "blocking_in_async").severity,
        "medium",
        "the lane is advisory: a spec cannot make it block"
    );
}

#[test]
fn a_spec_below_the_confidence_floor_and_an_unknown_role_match_nothing() {
    let sites = [shape("app/a.py", 5, "missing_await", "coroutine", 1)];
    let mut shaky = spec("missing_await", "*", "violates", "RC-029");
    shaky.confidence = 0.1;
    assert!(evaluate(&sites, &[shaky]).is_empty());
    assert!(evaluate(&sites, &[spec("missing_await", "*", "maybe", "RC-029")]).is_empty());
    // A violates entry with no control cannot be a control-mapped finding.
    assert!(evaluate(&sites, &[spec("missing_await", "*", "violates", "")]).is_empty());
}

#[test]
fn sites_outside_runtime_scope_and_other_kinds_are_not_judged() {
    let specs = [spec("discarded_error", "*", "violates", "RC-029")];
    let in_tests = shape("svc/a_test.go", 10, "discarded_error", "os.Remove", 1);
    let mut g1 = shape("svc/a.go", 10, "discarded_error", "os.Remove", 1);
    g1.site_kind = String::new();
    assert!(evaluate(&[in_tests, g1], &specs).is_empty());
}

#[test]
fn one_class_under_two_controls_is_two_findings() {
    let sites = [
        shape("app/a.py", 5, "blocking_in_async", "requests.get", 1),
        shape("app/a.py", 9, "blocking_in_async", "time.sleep", 1),
    ];
    let specs = [
        spec("blocking_in_async", "requests.get", "violates", "RC-019"),
        spec("blocking_in_async", "time.sleep", "violates", "RC-029"),
    ];
    let findings = evaluate(&sites, &specs);
    assert_eq!(findings.len(), 2, "{findings:?}");
}

#[test]
fn the_local_shape_classes_say_what_was_seen_and_are_never_high() {
    // Each class is named for the shape, and its words do not claim the
    // defect: a query on a loop variable is not called an N+1, and SQL text
    // built in a call is not called an injection.
    for (class, identity, severity, words) in [
        (
            "retry_shape",
            "constant_delay",
            "medium",
            "retry delay shape(s)",
        ),
        (
            "loop_variable_query",
            "all",
            "low",
            "query call(s) on a relation of a loop variable",
        ),
        (
            "sql_concat_in_call",
            "execute",
            "medium",
            "query call(s) take SQL text that is built in the call",
        ),
        (
            "print_logging",
            "fmt.Println",
            "low",
            "print-style output call(s)",
        ),
        (
            "latency_scalar_metric",
            "prometheus_client.Gauge",
            "low",
            "latency metric(s) are registered as a gauge or a counter",
        ),
    ] {
        let sites = [shape("svc/a.py", 10, class, identity, 2)];
        let mut s = spec(class, "*", "violates", "RC-022");
        let findings = evaluate(&sites, std::slice::from_ref(&s));
        let f = one(&findings, class);
        assert_eq!(f.severity, severity, "{class}");
        assert!(f.reason.starts_with(&format!("2 {words}")), "{}", f.reason);
        assert!(
            !f.reason.contains("N+1") && !f.reason.contains("injection"),
            "{}",
            f.reason
        );
        s.severity = "high".into();
        let findings = evaluate(&sites, &[s]);
        assert_eq!(one(&findings, class).severity, severity, "{class}");
    }
}

#[test]
fn one_retry_identity_can_be_allowed_and_the_others_stay() {
    let sites = [
        shape("svc/a.go", 10, "retry_shape", "constant_delay", 1),
        shape("svc/a.go", 10, "retry_shape", "unbounded_attempts", 1),
    ];
    let specs = [
        spec("retry_shape", "*", "violates", "RC-022"),
        spec("retry_shape", "constant_delay", "allowed", ""),
    ];
    let findings = evaluate(&sites, &specs);
    assert_eq!(one(&findings, "retry_shape").occurrences, 1);
}
