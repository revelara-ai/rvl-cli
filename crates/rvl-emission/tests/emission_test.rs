//! G4 emission-lane evaluator tests (po-av01j.5). Sites are built the way the
//! per-language emitters build them: aggregates per (function, framework,
//! category) with the category and count riding const_args.

use rvl_core::{
    ConstArg, Site, Verdict, CONST_ARG_EMISSION_CATEGORY, CONST_ARG_EMISSION_COUNT,
    SITE_KIND_EMISSION,
};
use rvl_emission::{evaluate, EmissionFinding};
use rvl_spec::EmissionSpec;

fn emission(
    file: &str,
    line: u32,
    symbol: &str,
    framework: &str,
    category: &str,
    count: u32,
) -> Site {
    Site {
        file_path: file.into(),
        line_number: line,
        symbol: symbol.into(),
        method: "emit".into(),
        client_type: framework.into(),
        site_kind: SITE_KIND_EMISSION.into(),
        const_args: vec![
            ConstArg {
                name: CONST_ARG_EMISSION_CATEGORY.into(),
                value: category.into(),
                how: "aggregate".into(),
                ..Default::default()
            },
            ConstArg {
                name: CONST_ARG_EMISSION_COUNT.into(),
                value: count.to_string(),
                how: "aggregate".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

fn call(file: &str, line: u32, symbol: &str, client_type: &str, method: &str) -> Site {
    Site {
        file_path: file.into(),
        line_number: line,
        symbol: symbol.into(),
        method: method.into(),
        client_type: client_type.into(),
        ..Default::default()
    }
}

fn spec(type_name: &str, category: &str, control: &str, role: &str) -> EmissionSpec {
    EmissionSpec {
        type_name: type_name.into(),
        category: category.into(),
        control: control.into(),
        role: role.into(),
        confidence: 0.9,
        rationale: String::new(),
    }
}

fn finding<'a>(findings: &'a [EmissionFinding], control: &str) -> &'a EmissionFinding {
    findings
        .iter()
        .find(|f| f.control == control)
        .unwrap_or_else(|| panic!("no {control} finding"))
}

fn seed_specs() -> Vec<EmissionSpec> {
    vec![
        // A plain log emission is NOT RC-027 evidence (capture-vs-swallow is
        // about error paths); it counts as minimal surrounding telemetry for
        // RC-061. Only error_capture-category shapes serve RC-027.
        spec("log/slog.Logger", "log", "RC-061", "satisfies"),
        spec("logging.Logger", "error_capture", "RC-027", "satisfies"),
        spec("except_handler", "error_capture", "RC-027", "violates"),
        spec("otel.Tracer", "trace", "RC-046", "satisfies"),
        spec("openai.OpenAI", "", "RC-061", "anchor"),
    ]
}

#[test]
fn swallowed_error_paths_violate_error_monitoring() {
    // Two functions whose except blocks emit nothing: positive evidence of a
    // swallow gap. The counts sum across aggregates, never one row per block.
    let emissions = vec![
        emission(
            "app/api.py",
            10,
            "handler",
            "except_handler",
            "error_capture",
            3,
        ),
        emission(
            "app/db.py",
            40,
            "query",
            "except_handler",
            "error_capture",
            1,
        ),
    ];
    let f = evaluate(&[], &emissions, &seed_specs());
    let rc27 = finding(&f, "RC-027");
    assert_eq!(rc27.verdict, Verdict::Violates, "{}", rc27.reason);
    assert!(
        rc27.reason.contains("4 error path(s)") && rc27.reason.contains("2 function(s)"),
        "counts must roll up across aggregates: {}",
        rc27.reason
    );
    assert_eq!(rc27.severity, "medium", "emission findings are advisory");
}

#[test]
fn captured_error_paths_satisfy_error_monitoring() {
    let emissions = vec![emission(
        "app/api.py",
        10,
        "handler",
        "logging.Logger",
        "error_capture",
        2,
    )];
    let f = evaluate(&[], &emissions, &seed_specs());
    let rc27 = finding(&f, "RC-027");
    assert_eq!(rc27.verdict, Verdict::Satisfies, "{}", rc27.reason);
}

#[test]
fn no_error_inventory_abstains_rather_than_guessing() {
    // A log-only inventory says nothing about error paths; a pre-G4 stream
    // says nothing at all. Both abstain.
    let emissions = vec![emission("a.go", 1, "f", "log/slog.Logger", "log", 5)];
    let f = evaluate(&[], &emissions, &seed_specs());
    assert_eq!(finding(&f, "RC-027").verdict, Verdict::Abstain);

    let none = evaluate(&[], &[], &seed_specs());
    assert_eq!(finding(&none, "RC-027").verdict, Verdict::Abstain);
}

#[test]
fn missing_specs_abstain_every_control() {
    let emissions = vec![emission(
        "a.py",
        1,
        "f",
        "except_handler",
        "error_capture",
        1,
    )];
    let calls = vec![call("a.py", 2, "f", "openai.OpenAI", "create")];
    let f = evaluate(&calls, &emissions, &[]);
    for c in ["RC-027", "RC-046", "RC-061"] {
        assert_eq!(
            finding(&f, c).verdict,
            Verdict::Abstain,
            "{c} must abstain with no specs loaded"
        );
    }
}

#[test]
fn test_scope_emissions_and_anchors_do_not_drive_verdicts() {
    // A swallowing except block in a test file is not a production gap.
    let emissions = vec![emission(
        "tests/test_api.py",
        10,
        "test_handler",
        "except_handler",
        "error_capture",
        2,
    )];
    let f = evaluate(&[], &emissions, &seed_specs());
    assert_eq!(
        finding(&f, "RC-027").verdict,
        Verdict::Abstain,
        "test-scope swallows are not runtime evidence"
    );
}

#[test]
fn tracing_absent_at_io_boundaries_violates_when_inventory_present() {
    // Anchors + a log inventory (G4 emitter ran) + zero trace emissions:
    // positive evidence tracing is absent.
    let calls = vec![
        call("svc/db.go", 12, "Load", "database/sql.DB", "QueryContext"),
        call("svc/db.go", 30, "Prune", "database/sql.DB", "ExecContext"),
    ];
    let emissions = vec![emission(
        "svc/db.go",
        14,
        "Load",
        "log/slog.Logger",
        "log",
        4,
    )];
    let f = evaluate(&calls, &emissions, &seed_specs());
    let rc46 = finding(&f, "RC-046");
    assert_eq!(rc46.verdict, Verdict::Violates, "{}", rc46.reason);
    assert!(
        rc46.reason.contains("no span instrumentation"),
        "{}",
        rc46.reason
    );
}

#[test]
fn tracing_covering_every_io_function_satisfies() {
    let calls = vec![call(
        "svc/db.go",
        12,
        "Load",
        "database/sql.DB",
        "QueryContext",
    )];
    let emissions = vec![emission("svc/db.go", 11, "Load", "otel.Tracer", "trace", 1)];
    let f = evaluate(&calls, &emissions, &seed_specs());
    assert_eq!(
        finding(&f, "RC-046").verdict,
        Verdict::Satisfies,
        "{}",
        finding(&f, "RC-046").reason
    );
}

#[test]
fn partial_tracing_names_the_uncovered_functions() {
    let calls = vec![
        call("svc/db.go", 12, "Load", "database/sql.DB", "QueryContext"),
        call("svc/http.go", 20, "Fetch", "net/http.Client", "Do"),
    ];
    let emissions = vec![emission("svc/db.go", 11, "Load", "otel.Tracer", "trace", 1)];
    let f = evaluate(&calls, &emissions, &seed_specs());
    let rc46 = finding(&f, "RC-046");
    assert_eq!(rc46.verdict, Verdict::Violates, "{}", rc46.reason);
    assert!(rc46.reason.contains("1 of 2"), "{}", rc46.reason);
    assert!(
        rc46.evidence.iter().any(|e| e.contains("Fetch")),
        "the uncovered function must be named: {:?}",
        rc46.evidence
    );
}

#[test]
fn tracing_abstains_on_a_pre_g4_stream() {
    // Anchors but not one emission packet anywhere: the retriever predates
    // G4, so absence of spans is not evidence.
    let calls = vec![call(
        "svc/db.go",
        12,
        "Load",
        "database/sql.DB",
        "QueryContext",
    )];
    let f = evaluate(&calls, &[], &seed_specs());
    assert_eq!(finding(&f, "RC-046").verdict, Verdict::Abstain);
}

#[test]
fn tracing_is_not_applicable_without_io_anchors() {
    let emissions = vec![emission("a.go", 1, "f", "log/slog.Logger", "log", 2)];
    let f = evaluate(&[], &emissions, &seed_specs());
    assert_eq!(finding(&f, "RC-046").verdict, Verdict::NotApplicable);
}

#[test]
fn llm_call_with_no_surrounding_emission_violates() {
    let calls = vec![call(
        "app/llm.py",
        33,
        "summarize",
        "openai.OpenAI",
        "create",
    )];
    // Inventory exists (a log elsewhere) but the LLM function emits nothing.
    let emissions = vec![emission(
        "app/api.py",
        5,
        "handler",
        "log/slog.Logger",
        "log",
        2,
    )];
    let f = evaluate(&calls, &emissions, &seed_specs());
    let rc61 = finding(&f, "RC-061");
    assert_eq!(rc61.verdict, Verdict::Violates, "{}", rc61.reason);
    assert!(rc61.reason.contains("1 of 1"), "{}", rc61.reason);
}

#[test]
fn llm_call_with_surrounding_log_emission_satisfies() {
    let calls = vec![call(
        "app/llm.py",
        33,
        "summarize",
        "openai.OpenAI",
        "create",
    )];
    let emissions = vec![emission(
        "app/llm.py",
        35,
        "summarize",
        "log/slog.Logger",
        "log",
        1,
    )];
    let f = evaluate(&calls, &emissions, &seed_specs());
    assert_eq!(
        finding(&f, "RC-061").verdict,
        Verdict::Satisfies,
        "{}",
        finding(&f, "RC-061").reason
    );
}

#[test]
fn llm_lane_is_not_applicable_without_recognized_anchors() {
    let calls = vec![call(
        "svc/db.go",
        12,
        "Load",
        "database/sql.DB",
        "QueryContext",
    )];
    let emissions = vec![emission(
        "svc/db.go",
        11,
        "Load",
        "log/slog.Logger",
        "log",
        1,
    )];
    let f = evaluate(&calls, &emissions, &seed_specs());
    assert_eq!(finding(&f, "RC-061").verdict, Verdict::NotApplicable);
}

#[test]
fn low_confidence_emission_specs_match_nothing() {
    // A shaky spec is applied to every aggregate of that shape at once — the
    // same multiplier logic as the G1 confidence floor.
    let mut specs = seed_specs();
    for s in &mut specs {
        s.confidence = 0.3;
    }
    let emissions = vec![emission(
        "a.py",
        1,
        "f",
        "except_handler",
        "error_capture",
        1,
    )];
    let f = evaluate(&[], &emissions, &specs);
    assert_eq!(
        finding(&f, "RC-027").verdict,
        Verdict::Abstain,
        "a low-confidence spec must not mint a violation"
    );
}
