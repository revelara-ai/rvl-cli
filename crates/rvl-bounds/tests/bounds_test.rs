//! Unsized-construction lane evaluator tests. Sites are built the way the
//! retrievers build them: one packet per construction, the class and the
//! observed setters and options riding const_args.

use rvl_bounds::{evaluate, BoundFinding};
use rvl_core::{
    ConstArg, Site, Verdict, BOUND_HOW_NAME, BOUND_HOW_TYPE, CONST_ARG_BOUND_CLASS,
    CONST_ARG_BOUND_ESCAPES, CONST_ARG_BOUND_OPAQUE, SITE_KIND_UNSIZED,
};
use rvl_spec::ConstructionBoundSpec;

fn arg(name: &str, value: &str, how: &str) -> ConstArg {
    ConstArg {
        name: name.into(),
        value: value.into(),
        how: how.into(),
        ..Default::default()
    }
}

fn construction(file: &str, line: u32, type_name: &str, class: &str, seen: Vec<ConstArg>) -> Site {
    let mut const_args = vec![arg(CONST_ARG_BOUND_CLASS, class, "aggregate")];
    const_args.extend(seen);
    Site {
        file_path: file.into(),
        line_number: line,
        symbol: "open".into(),
        method: "Open".into(),
        client_type: type_name.into(),
        site_kind: SITE_KIND_UNSIZED.into(),
        const_args,
        ..Default::default()
    }
}

fn spec(type_name: &str, class: &str, control: &str, bounded_by: &[&str]) -> ConstructionBoundSpec {
    ConstructionBoundSpec {
        type_name: type_name.into(),
        class: class.into(),
        control: control.into(),
        bounded_by: bounded_by.iter().map(|s| s.to_string()).collect(),
        unbounded_values: vec!["0".into(), "-1".into(), "None".into()],
        default_bounded: false,
        confidence: 0.9,
        rationale: "test".into(),
    }
}

fn pool_spec() -> ConstructionBoundSpec {
    spec(
        "database/sql.DB",
        "pool",
        "RC-055",
        &["SetMaxOpenConns", "SetConnMaxLifetime"],
    )
}

fn only(findings: Vec<BoundFinding>) -> BoundFinding {
    assert_eq!(
        findings.len(),
        1,
        "one finding per (class, control): {findings:?}"
    );
    findings.into_iter().next().unwrap()
}

#[test]
fn a_pool_with_no_setter_in_scope_violates_the_specs_control() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![],
    )];
    let f = only(evaluate(&sites, &[pool_spec()]));
    assert_eq!(f.verdict, Verdict::Violates);
    assert_eq!((f.class.as_str(), f.control.as_str()), ("pool", "RC-055"));
    assert_eq!(f.evidence, ["svc/db.go:12"]);
    assert!(f.reason.contains("1 of 1"), "{}", f.reason);
    assert_ne!(f.severity, "high", "the lane is advisory");
}

#[test]
fn a_literal_bound_satisfies() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![arg("SetMaxOpenConns", "25", "literal")],
    )];
    assert_eq!(
        only(evaluate(&sites, &[pool_spec()])).verdict,
        Verdict::Satisfies
    );
}

#[test]
fn a_non_constant_bound_is_a_name_and_is_credited_without_a_value() {
    // The bead's constraint: db.SetMaxOpenConns(cfg.Max) is a NAME. It is
    // bounded. The value is never resolved and never reported, even when the
    // name's text happens to equal an unbounded sentinel.
    for value in ["cfg.Max", "0"] {
        let sites = [construction(
            "svc/db.go",
            12,
            "database/sql.DB",
            "pool",
            vec![arg("SetMaxOpenConns", value, BOUND_HOW_NAME)],
        )];
        let f = only(evaluate(&sites, &[pool_spec()]));
        assert_eq!(f.verdict, Verdict::Satisfies, "{value}");
        assert!(
            !f.reason.contains(value),
            "no value is claimed: {}",
            f.reason
        );
    }
}

#[test]
fn a_resolved_value_that_means_no_limit_violates() {
    let sites = [construction(
        "app/work.py",
        8,
        "queue.Queue",
        "queue",
        vec![arg("maxsize", "0", "literal")],
    )];
    let specs = [spec("queue.Queue", "queue", "RC-055", &["maxsize", "arg0"])];
    let f = only(evaluate(&sites, &specs));
    assert_eq!(f.verdict, Verdict::Violates);
    assert!(
        f.reason.contains("maxsize") && f.reason.contains('0'),
        "{}",
        f.reason
    );
}

#[test]
fn an_observation_the_spec_does_not_name_is_not_a_bound() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![arg("Ping", "", BOUND_HOW_NAME)],
    )];
    assert_eq!(
        only(evaluate(&sites, &[pool_spec()])).verdict,
        Verdict::Violates
    );
}

#[test]
fn an_escaping_value_bounded_on_its_type_elsewhere_abstains() {
    // The value is returned and a setter runs on the same type somewhere
    // else. That is evidence to abstain on, never to pass and never to fail.
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![
            arg(CONST_ARG_BOUND_ESCAPES, "returned", "aggregate"),
            arg("SetMaxOpenConns", "", BOUND_HOW_TYPE),
        ],
    )];
    let f = only(evaluate(&sites, &[pool_spec()]));
    assert_eq!(f.verdict, Verdict::Abstain);
    assert!(f.reason.contains("leaves"), "{}", f.reason);
}

#[test]
fn an_escaping_value_with_no_setter_anywhere_violates() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![arg(CONST_ARG_BOUND_ESCAPES, "returned", "aggregate")],
    )];
    assert_eq!(
        only(evaluate(&sites, &[pool_spec()])).verdict,
        Verdict::Violates
    );
}

#[test]
fn a_type_level_observation_never_bounds_a_value_that_stays_in_scope() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![arg("SetMaxOpenConns", "", BOUND_HOW_TYPE)],
    )];
    assert_eq!(
        only(evaluate(&sites, &[pool_spec()])).verdict,
        Verdict::Violates
    );
}

#[test]
fn options_the_retriever_could_not_see_abstain_unless_a_bound_is_visible() {
    // Queue(**opts): the bound may be inside opts. Not a pass, not a fail.
    let specs = [spec("queue.Queue", "queue", "RC-067", &["maxsize", "arg0"])];
    let opaque = arg(CONST_ARG_BOUND_OPAQUE, "**opts", "aggregate");
    let sites = [construction(
        "app/work.py",
        8,
        "queue.Queue",
        "queue",
        vec![opaque.clone()],
    )];
    assert_eq!(only(evaluate(&sites, &specs)).verdict, Verdict::Abstain);

    // Queue(maxsize=10, **opts): the visible bound decides.
    let sites = [construction(
        "app/work.py",
        8,
        "queue.Queue",
        "queue",
        vec![opaque, arg("maxsize", "10", "literal")],
    )];
    assert_eq!(only(evaluate(&sites, &specs)).verdict, Verdict::Satisfies);
}

#[test]
fn a_library_default_that_is_finite_bounds_a_construction_that_sets_nothing() {
    // @lru_cache keeps 128 entries by default. Only an explicit "no limit"
    // value makes it unbounded.
    let mut lru = spec(
        "functools.lru_cache",
        "cache",
        "RC-067",
        &["maxsize", "arg0"],
    );
    lru.default_bounded = true;
    let bare = construction("app/c.py", 3, "functools.lru_cache", "cache", vec![]);
    assert_eq!(
        only(evaluate(
            std::slice::from_ref(&bare),
            std::slice::from_ref(&lru)
        ))
        .verdict,
        Verdict::Satisfies
    );
    let forever = construction(
        "app/c.py",
        9,
        "functools.lru_cache",
        "cache",
        vec![arg("maxsize", "None", "literal")],
    );
    let f = only(evaluate(&[bare, forever], &[lru]));
    assert_eq!(f.verdict, Verdict::Violates);
    assert_eq!(f.evidence, ["app/c.py:9"]);
}

#[test]
fn no_spec_means_no_finding() {
    let sites = [construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![],
    )];
    assert!(evaluate(&sites, &[]).is_empty());
    // A spec for another type, a spec for another class of the same type, and
    // a spec under the confidence floor all judge nothing.
    let mut weak = pool_spec();
    weak.confidence = 0.3;
    let others = [
        spec(
            "redis.ConnectionPool",
            "pool",
            "RC-055",
            &["max_connections"],
        ),
        spec("database/sql.DB", "cache", "RC-055", &["SetMaxOpenConns"]),
        weak,
    ];
    assert!(evaluate(&sites, &others).is_empty());
}

#[test]
fn test_scope_sites_and_other_site_kinds_are_not_judged() {
    let mut g1 = construction("svc/db.go", 3, "database/sql.DB", "pool", vec![]);
    g1.site_kind = String::new();
    let sites = [
        construction("svc/db_test.go", 12, "database/sql.DB", "pool", vec![]),
        g1,
    ];
    assert!(evaluate(&sites, &[pool_spec()]).is_empty());
}

#[test]
fn findings_group_by_class_and_control_and_cap_evidence() {
    let mut sites: Vec<Site> = (1..=7)
        .map(|n| construction("svc/read.go", n, "io.ReadAll", "read", vec![]))
        .collect();
    sites.push(construction(
        "svc/read.go",
        40,
        "io.ReadAll",
        "read",
        vec![arg("net/http.MaxBytesReader", "", "call")],
    ));
    sites.push(construction(
        "svc/db.go",
        12,
        "database/sql.DB",
        "pool",
        vec![],
    ));
    let specs = [
        pool_spec(),
        spec(
            "io.ReadAll",
            "read",
            "RC-067",
            &["io.LimitReader", "net/http.MaxBytesReader"],
        ),
    ];
    let findings = evaluate(&sites, &specs);
    assert_eq!(findings.len(), 2);
    let read = findings.iter().find(|f| f.class == "read").unwrap();
    assert_eq!(read.verdict, Verdict::Violates);
    assert!(read.reason.contains("7 of 8"), "{}", read.reason);
    assert_eq!(read.evidence.len(), 5, "evidence is capped");
    assert!(findings
        .iter()
        .any(|f| f.class == "pool" && f.control == "RC-055"));
}
