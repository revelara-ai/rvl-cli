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
    assert_eq!(
        names,
        vec!["ppi-labels".to_string(), "eval-go-v0".to_string()]
    );
}

// --- Provenance validation (fail-closed) ---

#[test]
fn valid_set_passes_and_reports_registry_version() {
    let m = parse_manifest(MANIFEST_OK).unwrap();
    let v = validate_gate_set(&m, &["ppi-labels".into()], &registry(), &[]).unwrap();
    assert_eq!(v, 1);
}

/// C# gate-set scaffolding (po-av01j.10): the gate machinery is
/// language-generic, and this pins that a `language: csharp` manifest flows
/// through provenance validation under the same terms as Go — the mint
/// workflow (HITL, per the po-ae75b.2 relative-formula protocol) relies on
/// this path existing before any eval-csharp-v1 set is minted.
#[test]
fn csharp_manifest_validates_under_the_same_terms() {
    let yaml = MANIFEST_OK
        .replace("set_id: eval-go-v1", "set_id: eval-csharp-v1")
        .replace("language: go", "language: csharp");
    let m = parse_manifest(&yaml).unwrap();
    assert_eq!(m.language, "csharp");
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

// --- Withdrawal (po-av01j.119) ---

/// A withdrawal block appended to an otherwise valid manifest.
fn withdrawn(yaml: &str) -> String {
    format!(
        "{yaml}
withdrawn:
  date: \"2026-08-06\"
  by: \"Joseph Bironas\"
  reason: >
    Minted against spec cache 2026-08-06.3ee53dec, whose own provenance stamp
    reads NEVER valid as gate evidence, as a precision claim, or as a
    comparator baseline. See po-av01j.119.
"
    )
}

#[test]
fn absent_withdrawal_is_the_default_and_still_validates() {
    // Backward compatibility in the safe direction: no block means not
    // withdrawn, which is the only reading that lets existing sets parse.
    let m = parse_manifest(MANIFEST_OK).unwrap();
    assert!(m.withdrawn.is_none());
    assert!(validate_gate_set(&m, &[], &registry(), &[]).is_ok());
}

#[test]
fn withdrawn_set_is_refused_with_its_reason() {
    let m = parse_manifest(&withdrawn(MANIFEST_OK)).unwrap();
    let w = m.withdrawn.as_ref().expect("withdrawal must parse");
    assert_eq!(w.by, "Joseph Bironas");
    let err = validate_gate_set(&m, &[], &registry(), &[]).unwrap_err();
    match err {
        Refusal::Withdrawn {
            ref set_id,
            ref reason,
        } => {
            assert_eq!(set_id, "eval-go-v1");
            // The reason travels INTO the refusal. A bare "withdrawn" would
            // send the reader back to the file that is already refusing them.
            assert!(reason.contains("2026-08-06.3ee53dec"));
        }
        other => panic!("expected Withdrawn, got {other:?}"),
    }
    // and it must say so in the operator-visible message
    assert!(err.to_string().contains("withdrawn"));
}

#[test]
fn withdrawal_outranks_every_other_refusal() {
    // A withdrawn set is usually ALSO wrong in some mechanical way, and the
    // mechanical complaint is the less useful one: "repo not quarantined"
    // invites fixing the registry entry and re-running. Order the check first
    // so the answer is the human decision, not the symptom.
    let mut m = parse_manifest(&withdrawn(MANIFEST_OK)).unwrap();
    m.consumed = true;
    m.sample_size = 3;
    m.repos[0].repo = "torvalds/linux".into();
    let err = validate_gate_set(
        &m,
        &["eval-go-v1".into()],
        &registry(),
        &["go-gitea/gitea".into()],
    )
    .unwrap_err();
    assert!(matches!(err, Refusal::Withdrawn { .. }), "got {err:?}");
}

#[test]
fn withdrawal_without_a_reason_refuses_at_parse() {
    // A withdrawal that records no reason is not a withdrawal record. It would
    // refuse the set while telling the next reader nothing about why, which is
    // how a bad number gets quietly re-minted.
    let blank = MANIFEST_OK.to_string()
        + "
withdrawn:
  date: \"2026-08-06\"
  by: \"Joseph Bironas\"
  reason: \"   \"
";
    assert!(parse_manifest(&blank).is_err());
    let missing = MANIFEST_OK.to_string()
        + "
withdrawn:
  date: \"2026-08-06\"
  by: \"Joseph Bironas\"
";
    assert!(parse_manifest(&missing).is_err());
}

#[test]
fn withdrawal_cannot_declare_itself_rescinded() {
    // deny_unknown_fields, for the same reason provenance_check.py refuses
    // unknown stamp keys: an invented field ("rescinded: true") reads as
    // authoritative to a human and is enforced by nothing.
    let sneaky = MANIFEST_OK.to_string()
        + "
withdrawn:
  date: \"2026-08-06\"
  by: \"Joseph Bironas\"
  reason: \"contaminated cache\"
  rescinded: true
";
    assert!(parse_manifest(&sneaky).is_err());
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
        Refusal::GoldTooSmall {
            decided: 48,
            required: 50
        }
    );
}

// --- The minikube DEV/DOGFOOD spec cache (po-av01j.80) ---
//
// A spec corpus can be usable and still be worthless as evidence. This one is:
// the 2026-08-03 mint (po-av01j.68) authored specs from packet streams over
// four repos reserved for minting gate sets, then hardcoded
// repo='seed/minikube-test' on every surface, so quarantine enforcement passed
// by MISLABELLING rather than by the data being clean. Withdrawing the specs
// whose api_type is internal to a quarantined repo removes what is
// identifiable; the relabelling made the rest unidentifiable, and no amount of
// filtering recovers it.
//
// So the rebuilt cache is fenced off from gate mode two ways, and both are
// pinned here. The first is nominal and the second is structural — which is
// why both exist.

/// The artifact's identity, as published: `spec_cache_artifacts.content_version`,
/// the storage key, and what `rvl cache status` prints.
const DEV_CACHE_CONTENT_VERSION: &str = "2026-08-05.3e263575";

/// The repos that may have taught the surviving shared-library specs. All four
/// Go entries are status=qualified in quarantine.yaml, i.e. the entire
/// qualified Go gate-mint pool. Mirrors
/// rvlscan-eval registry/grounding/2026-08-05.3e263575.txt.
const DEV_CACHE_GROUNDING: &[&str] = &[
    "go-gitea/gitea",
    "influxdata/telegraf",
    "minio/minio",
    "temporalio/temporal",
    "twentyhq/twenty",
];

/// Verbatim from rvlscan-eval registry/seed_sets.yaml (trimmed to the fields
/// the harness reads). If the registry entry is ever dropped, this test still
/// passes but stops describing reality — which is why
/// `dev_cache_grounding_refuses_every_qualified_go_gate_set` below does not
/// depend on the registry at all.
const DEV_CACHE_SEED_SETS_YAML: &str = r#"
registry_version: 1
updated: "2026-08-05"
seed_sets:
  - name: ppi-labels
    artifact: artifacts/ppi_labels.json
    gate_eligible: false
    reason: packet-conditional labels
  - name: "2026-08-05.3e263575"
    artifact: spec-cache/2026-08-05.3e263575.json
    gate_eligible: false
    reason: quarantine-derived specs removed BUT shared-library provenance unrecoverable
"#;

#[test]
fn dev_cache_is_registered_as_a_seed_set_and_refused_by_identity() {
    let names = parse_seed_set_names(DEV_CACHE_SEED_SETS_YAML).unwrap();
    assert!(
        names.iter().any(|n| n == DEV_CACHE_CONTENT_VERSION),
        "the dev cache must be designated in seed_sets.yaml under its content_version"
    );

    let mut m = parse_manifest(MANIFEST_OK).unwrap();
    m.set_id = DEV_CACHE_CONTENT_VERSION.into();
    let err = validate_gate_set(&m, &names, &registry(), &[]).unwrap_err();

    assert_eq!(err, Refusal::SeedSet(DEV_CACHE_CONTENT_VERSION.into()));
    assert_eq!(
        err.to_string(),
        "refused: 2026-08-05.3e263575 is a seed set (permanently gate-ineligible)"
    );
}

/// The load-bearing one. The seed-set check only fires when the artifact is
/// submitted under its own name, which a gate set named `eval-go-v1` never
/// would. The grounding check needs no cooperation: ship this cache's
/// grounding manifest and EVERY gate set pinned to a repo that may have taught
/// it is refused, whatever that set is called. Since the manifest lists the
/// whole qualified Go pool, no Go gate set can be scored against this cache.
#[test]
fn dev_cache_grounding_refuses_every_qualified_go_gate_set() {
    let grounding: Vec<String> = DEV_CACHE_GROUNDING.iter().map(|s| s.to_string()).collect();

    for repo in [
        "go-gitea/gitea",
        "influxdata/telegraf",
        "minio/minio",
        "temporalio/temporal",
    ] {
        let mut m = parse_manifest(MANIFEST_OK).unwrap();
        m.set_id = "eval-go-v1".into(); // NOT the seed-set name: nominal check cannot help
        m.repos[0].repo = repo.into();

        let reg = Registry {
            registry_version: 2,
            repos: DEV_CACHE_GROUNDING.iter().map(|s| s.to_string()).collect(),
        };
        let err = validate_gate_set(&m, &[], &reg, &grounding).unwrap_err();

        assert_eq!(err, Refusal::GroundingOverlap(repo.into()));
        assert_eq!(
            err.to_string(),
            format!("refused: gate-set repo {repo} present in grounding corpus")
        );
    }
}

/// The fence must not be so wide it refuses the recovery path. Re-authoring
/// from a signed-off corpus (po-av01j.78 -> .69) yields a cache whose grounding
/// does NOT include the gate pool, and a gate set pinned to a quarantined repo
/// must then validate normally. A check that refuses everything proves nothing.
#[test]
fn a_clean_grounding_corpus_still_validates() {
    let m = parse_manifest(MANIFEST_OK).unwrap();
    let clean = vec!["revelara-ai/backend".to_string(), "zulip/zulip".to_string()];
    let v = validate_gate_set(&m, &["ppi-labels".into()], &registry(), &clean).unwrap();
    assert_eq!(v, 1);
}

// ---------------------------------------------------------------------------
// TypeScript gate sets need lockfile provenance, not just a frozen SHA
// (po-av01j.117).
//
// Go and Python retrieval work on a bare checkout. TypeScript does not: tsindex
// resolves client types through the TS compiler, which needs node_modules, and
// on a bare clone that resolution fails SILENTLY rather than erroring. Measured
// on infisical at one fixed SHA, changing only whether deps were installed:
// 1,911 -> 83,927 sites. Same commit, 44x the stream.
//
// So for TypeScript a frozen SHA does not determine the packet stream, and a
// manifest carrying only a SHA is claiming a reproducibility it cannot deliver.
// ---------------------------------------------------------------------------

const TS_MANIFEST_NO_DEPS: &str = r#"
set_id: eval-ts-v1
language: typescript
minted: "2026-08-06"
registry_version: 4
consumed: false
repos:
  - repo: n8n-io/n8n
    frozen_sha: "b1c2d3e4f5a60718293a4b5c6d7e8f9012345678"
sampling_frame: >
  Placeholder frame; this manifest exists to prove a TS set without dependency
  provenance is refused.
sample_size: 50
adjudication:
  protocol: three-lens panel
  panel: "3x model panel"
  adjudicator: "Joseph Bironas"
  date: "2026-08-06"
"#;

const TS_MANIFEST_WITH_DEPS: &str = r#"
set_id: eval-ts-v1
language: typescript
minted: "2026-08-06"
registry_version: 4
consumed: false
repos:
  - repo: n8n-io/n8n
    frozen_sha: "b1c2d3e4f5a60718293a4b5c6d7e8f9012345678"
    deps:
      - package_manager: "pnpm@10.33.2"
        lockfile: "pnpm-lock.yaml"
        lockfile_sha256: "3b1f0c9d8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
sampling_frame: >
  Placeholder frame with dependency provenance pinned.
sample_size: 50
adjudication:
  protocol: three-lens panel
  panel: "3x model panel"
  adjudicator: "Joseph Bironas"
  date: "2026-08-06"
"#;

fn ts_registry() -> Registry {
    let mut r = registry();
    r.repos.push("n8n-io/n8n".to_string());
    r
}

#[test]
fn typescript_set_without_dependency_provenance_is_refused() {
    let m = parse_manifest(TS_MANIFEST_NO_DEPS).expect("manifest itself is well-formed");
    let err = validate_gate_set(&m, &[], &ts_registry(), &[]).unwrap_err();
    match err {
        Refusal::MissingDepsProvenance { repo, .. } => assert_eq!(repo, "n8n-io/n8n"),
        other => panic!("expected MissingDepsProvenance, got {other:?}"),
    }
}

#[test]
fn typescript_set_with_dependency_provenance_validates() {
    let m = parse_manifest(TS_MANIFEST_WITH_DEPS).expect("must parse");
    validate_gate_set(&m, &[], &ts_registry(), &[]).expect("pinned deps must validate");
}

#[test]
fn non_typescript_sets_do_not_require_dependency_provenance() {
    // The Go and Python retrievers read a bare checkout, so demanding a
    // lockfile there would be ceremony. eval-go-v1 is already minted without
    // one and must keep validating -- this is the backward-compatibility pin.
    let m = parse_manifest(MANIFEST_OK).expect("must parse");
    validate_gate_set(&m, &["ppi-labels".into()], &registry(), &[])
        .expect("a Go set needs no dependency provenance");
}

#[test]
fn dependency_provenance_rejects_a_blank_lockfile_hash() {
    // An empty hash would satisfy "a deps block is present" while pinning
    // nothing at all, which is worse than omitting it: it looks like provenance
    // in review. Fail closed.
    let yaml = TS_MANIFEST_WITH_DEPS.replace(
        "3b1f0c9d8e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c",
        "",
    );
    let m = parse_manifest(&yaml).expect("parses");
    let err = validate_gate_set(&m, &[], &ts_registry(), &[]).unwrap_err();
    assert!(
        matches!(err, Refusal::MissingDepsProvenance { .. }),
        "blank lockfile hash must refuse, got {err:?}"
    );
}

#[test]
fn lockfile_hash_mismatch_is_detected_against_a_checkout() {
    // The mint-time check: what is on disk must be what the manifest pins.
    let pinned = DepsPin {
        package_manager: "npm@10.2.4".into(),
        lockfile: "package-lock.json".into(),
        lockfile_sha256: "a".repeat(64),
    };
    // sha256("") is the well-known empty-string digest.
    let actual = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert!(check_lockfile_matches(&pinned, actual).is_err());
    let ok = DepsPin {
        lockfile_sha256: actual.to_string(),
        ..pinned
    };
    assert!(check_lockfile_matches(&ok, actual).is_ok());
}
