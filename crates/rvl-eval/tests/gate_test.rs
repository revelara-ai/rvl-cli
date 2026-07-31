//! Destination-gate acceptance tests (po-3t3oj.1).
//!
//! Criterion 1: per-language precision as Wilson 95% LB (target >= 0.90,
//! n >= 50 violates), with fail-closed provenance enforcement: seed-set
//! refusal, consumed refusal, sample-size bar, quarantine-registry
//! requirement, grounding-corpus overlap refusal.

use rvl_eval::gate::*;
use rvl_eval::stats::wilson_lower_bound;

const MANIFEST_OK: &str = r#"
set_id: eval-go-v1
language: go
minted: "2026-07-30"
registry_version: 1
consumed: false
repos:
  - repo: go-gitea/gitea
    frozen_sha: "a30d865b781b4611826bf44d60e44d9f6e8fdf4e"
sampling_frame: >
  All post-triage violates verdicts produced by engine 0.1.0 on the frozen
  SHAs above, 412 total, sampled uniformly at random with seed 7.
sample_size: 50
adjudication:
  protocol: panel adjudication WITH source access
  panel: "3x model panel"
  adjudicator: "josebiro"
  date: "2026-07-30"
"#;

const SEED_SETS_YAML: &str = r#"
registry_version: 1
updated: "2026-07-30"
seed_sets:
  - name: ppi-labels
    artifact: artifacts/ppi_labels.json
    repo: revelara-ai/experiments
    contents: 74 PPI labels
    gate_eligible: false
    reason: packet-conditional labels
  - name: eval-go-v0
    artifact: artifacts/machine_gold.json
    repo: revelara-ai/experiments
    contents: machine gold
    gate_eligible: false
    reason: machine-labeled
"#;

fn registry() -> Registry {
    Registry {
        registry_version: 1,
        repos: vec!["go-gitea/gitea".into(), "influxdata/telegraf".into()],
    }
}

fn gold(violates: usize, satisfies: usize, unsure: usize) -> Vec<GoldRow> {
    let mut rows = Vec::new();
    let mk = |adj: AdjudicatedVerdict, i: usize| GoldRow {
        file_path: format!("pkg/f{i}.go"),
        line_number: i as u64 + 1,
        adjudicated: adj,
    };
    for i in 0..violates {
        rows.push(mk(AdjudicatedVerdict::Violates, i));
    }
    for i in 0..satisfies {
        rows.push(mk(AdjudicatedVerdict::Satisfies, violates + i));
    }
    for i in 0..unsure {
        rows.push(mk(AdjudicatedVerdict::Unsure, violates + satisfies + i));
    }
    rows
}

// --- Wilson lower bound ---

#[test]
fn wilson_lb_known_values() {
    // 45/50: LB ~= 0.7864; 50/50: LB ~= 0.9287 (z = 1.96)
    assert!((wilson_lower_bound(45, 50) - 0.7864).abs() < 1e-3);
    assert!((wilson_lower_bound(50, 50) - 0.9287).abs() < 1e-3);
    // degenerate cases
    assert_eq!(wilson_lower_bound(0, 0), 0.0);
    assert!(wilson_lower_bound(0, 50) < 0.01);
}

// --- Manifest parsing ---

#[test]
fn manifest_parses_complete() {
    let m = parse_manifest(MANIFEST_OK).expect("complete manifest must parse");
    assert_eq!(m.set_id, "eval-go-v1");
    assert_eq!(m.language, "go");
    assert_eq!(m.registry_version, 1);
    assert!(!m.consumed);
    assert_eq!(m.sample_size, 50);
    assert_eq!(m.repos.len(), 1);
    assert_eq!(m.adjudication.adjudicator, "josebiro");
}

#[test]
fn manifest_missing_field_is_error() {
    // strip the adjudication block: population doc incomplete -> not valid gate evidence
    let broken = MANIFEST_OK.split("adjudication:").next().unwrap();
    assert!(parse_manifest(broken).is_err());
}

#[test]
fn seed_set_names_parse() {
    let names = parse_seed_set_names(SEED_SETS_YAML).unwrap();
    assert_eq!(names, vec!["ppi-labels".to_string(), "eval-go-v0".to_string()]);
}

// --- Provenance validation (fail-closed) ---

#[test]
fn valid_set_passes_and_reports_registry_version() {
    let m = parse_manifest(MANIFEST_OK).unwrap();
    let v = validate_gate_set(&m, &["ppi-labels".into()], &registry(), &[]).unwrap();
    assert_eq!(v, 1);
}

#[test]
fn seed_set_is_refused() {
    let mut m = parse_manifest(MANIFEST_OK).unwrap();
    m.set_id = "eval-go-v0".into(); // designated seed set
    let err = validate_gate_set(
        &m,
        &["ppi-labels".into(), "eval-go-v0".into()],
        &registry(),
        &[],
    )
    .unwrap_err();
    assert_eq!(err, Refusal::SeedSet("eval-go-v0".into()));
}

#[test]
fn consumed_set_is_refused() {
    let mut m = parse_manifest(MANIFEST_OK).unwrap();
    m.consumed = true;
    let err = validate_gate_set(&m, &[], &registry(), &[]).unwrap_err();
    assert_eq!(err, Refusal::Consumed("eval-go-v1".into()));
}

#[test]
fn small_sample_is_refused() {
    let mut m = parse_manifest(MANIFEST_OK).unwrap();
    m.sample_size = 49;
    let err = validate_gate_set(&m, &[], &registry(), &[]).unwrap_err();
    assert_eq!(err, Refusal::SampleTooSmall(49));
}

#[test]
fn unquarantined_repo_is_refused() {
    let mut m = parse_manifest(MANIFEST_OK).unwrap();
    m.repos[0].repo = "torvalds/linux".into(); // not in the registry
    let err = validate_gate_set(&m, &[], &registry(), &[]).unwrap_err();
    assert_eq!(err, Refusal::RepoNotQuarantined("torvalds/linux".into()));
}

#[test]
fn grounding_overlap_is_refused() {
    let m = parse_manifest(MANIFEST_OK).unwrap();
    let err = validate_gate_set(&m, &[], &registry(), &["go-gitea/gitea".into()]).unwrap_err();
    assert_eq!(err, Refusal::GroundingOverlap("go-gitea/gitea".into()));
}

#[test]
fn missing_registry_is_fail_closed() {
    let err = load_registry(std::path::Path::new("/nonexistent/quarantine.yaml")).unwrap_err();
    assert!(matches!(err, Refusal::RegistryUnavailable(_)));
}

#[test]
fn missing_gate_inputs_are_typed_refusals_not_generic_errors() {
    // A missing manifest must surface as EvidenceUnreadable (CLI exit 2),
    // never as a generic error that collides with the metric-fail exit code.
    let err = load_gate_inputs(
        std::path::Path::new("/nonexistent/eval-go-v1"),
        std::path::Path::new("/nonexistent/seed_sets.yaml"),
        std::path::Path::new("/nonexistent/quarantine.yaml"),
        std::path::Path::new("/nonexistent/grounding.txt"),
    )
    .unwrap_err();
    assert!(matches!(err, Refusal::EvidenceUnreadable(_)));
}

#[test]
fn typoed_adjudication_refuses_at_parse() {
    // "Violates" (wrong case) must be a parse error, not silently counted as
    // decided-but-not-confirmed (which would deflate precision).
    let row: std::result::Result<GoldRow, _> =
        serde_json::from_str(r#"{"file_path":"a.go","line_number":1,"adjudicated":"Violates"}"#);
    assert!(row.is_err());
    // unknown sibling keys (e.g. the sampled-on engine verdict) stay tolerated
    let row: std::result::Result<GoldRow, _> = serde_json::from_str(
        r#"{"file_path":"a.go","line_number":1,"engine":"violates","adjudicated":"violates"}"#,
    );
    assert!(row.is_ok());
}

#[test]
fn registry_loads_from_quarantine_yaml() {
    let dir = std::env::temp_dir().join("rvl_eval_gate_test_registry");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("quarantine.yaml");
    std::fs::write(
        &path,
        r#"
registry_version: 3
updated: "2026-07-30"
policy:
  fail_mode: closed
quarantined_repos:
  - repo: go-gitea/gitea
    language: go
    frozen_sha: "abc"
    status: qualified
    designated: "2026-07-30"
    rationale: test
"#,
    )
    .unwrap();
    let reg = load_registry(&path).unwrap();
    assert_eq!(reg.registry_version, 3);
    assert_eq!(reg.repos, vec!["go-gitea/gitea".to_string()]);
}

// --- Gate scoring ---

#[test]
fn precision_wilson_lb_pass_and_fail() {
    // 50 decided, all confirmed: precision 1.0, Wilson LB ~0.9287 -> PASS at 0.90
    let s = score_gate(&gold(50, 0, 0), 50, 0.90).unwrap();
    assert_eq!(s.n_decided, 50);
    assert_eq!(s.confirmed_violates, 50);
    assert!((s.precision - 1.0).abs() < 1e-9);
    assert!((s.wilson_lb - 0.9287).abs() < 1e-3);
    assert!(s.pass);

    // 45/50 confirmed: precision 0.90 but Wilson LB ~0.786 -> FAIL at 0.90.
    // The gate verdict is taken on the lower bound, not the point estimate.
    let s = score_gate(&gold(45, 5, 0), 50, 0.90).unwrap();
    assert!((s.precision - 0.90).abs() < 1e-9);
    assert!(!s.pass);
}

#[test]
fn unsure_rows_are_excluded_but_counted() {
    // 52 decided (50 violates + 2 satisfies) + 3 unsure
    let s = score_gate(&gold(50, 2, 3), 50, 0.90).unwrap();
    assert_eq!(s.n_decided, 52);
    assert_eq!(s.n_unsure, 3);
    assert_eq!(s.confirmed_violates, 50);
}

#[test]
fn too_few_decided_is_refused() {
    // 48 decided < sample_size 50 -> refuse, fail-closed
    let err = score_gate(&gold(40, 8, 2), 50, 0.90).unwrap_err();
    assert_eq!(
        err,
        Refusal::GoldTooSmall { decided: 48, required: 50 }
    );
}
