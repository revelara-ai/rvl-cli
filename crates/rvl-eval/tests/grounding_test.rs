//! The grounding-overlap fence (po-av01j.90).
//!
//! This refusal is what stops a gate set being scored against an engine that
//! was TAUGHT by the same repos. It compared raw strings with exact byte
//! equality, so the manifest format the collection pipeline actually emits
//! (`getsentry_sentry`, not `getsentry/sentry`) matched nothing, every time,
//! silently.

use rvl_eval::gate::{
    check_manifest_matches_artifact, normalize_repo_id, parse_grounding_manifest, parse_seed_sets,
    Refusal,
};
use std::path::Path;

#[test]
fn normalize_matches_the_python_source_of_truth() {
    // tools/quarantine_check.py::normalize -- strip, lowercase, / -> _.
    // Two normalizers that drift are worse than one that is wrong.
    assert_eq!(normalize_repo_id("go-gitea/gitea"), "go-gitea_gitea");
    assert_eq!(normalize_repo_id("  GoGitea/Gitea  "), "gogitea_gitea");
    assert_eq!(normalize_repo_id("getsentry_sentry"), "getsentry_sentry");
}

#[test]
fn the_pipeline_json_manifest_is_understood() {
    // THE BEAD'S SCENARIO. The operator passes the pipeline's own manifest.json
    // (the honest choice). Before this it parsed as junk lines with no error and
    // zero matches, so a gate run against a cache grounded on gitea PASSED.
    let json = r#"[
      {"label": "getsentry_sentry", "commit": "abc"},
      {"label": "go-gitea_gitea", "commit": "def"},
      {"label": "polaris"}
    ]"#;
    let got = parse_grounding_manifest(json);
    assert!(got.contains(&"go-gitea_gitea".to_string()), "got {got:?}");
    assert!(got.contains(&"getsentry_sentry".to_string()));
    assert_eq!(got.len(), 3);
}

#[test]
fn the_hand_written_txt_manifest_still_works_and_is_normalized() {
    // The form po-av01j.80 shipped must keep working, and must now normalize so
    // it compares equal to the pin regardless of spelling.
    let txt = "# grounding corpus\ngo-gitea/gitea\n\nGetSentry/Sentry\n";
    let got = parse_grounding_manifest(txt);
    assert_eq!(got, vec!["go-gitea_gitea", "getsentry_sentry"]);
}

#[test]
fn a_pin_matches_the_pipeline_spelling_of_the_same_repo() {
    // The actual fence: `go-gitea/gitea` in the gate manifest must be caught by
    // `go-gitea_gitea` in the grounding manifest. This is the comparison that
    // silently found nothing.
    let grounding = parse_grounding_manifest(r#"[{"label": "go-gitea_gitea"}]"#);
    assert!(grounding.contains(&normalize_repo_id("go-gitea/gitea")));
}

#[test]
fn an_empty_or_comment_only_manifest_yields_nothing_to_check() {
    // The caller refuses on an empty result. "No identities" is no evidence,
    // not "no overlap" -- these were three separate silent fail-open paths.
    assert!(parse_grounding_manifest("").is_empty());
    assert!(parse_grounding_manifest("# nothing here\n\n").is_empty());
}

#[test]
fn json_that_does_not_parse_fails_closed() {
    // Found by writing a tautological assertion and then reading it. Falling
    // through to the line reader turned `{ this is not json` into a junk
    // "identity" -- non-empty, so the empty-manifest refusal never fired, so a
    // manifest nobody could read PASSED. Same fail-open as (b) in the bead,
    // wearing a different hat.
    assert!(
        parse_grounding_manifest("{ this is not json").is_empty(),
        "unparseable JSON must yield nothing so the caller refuses"
    );
    assert!(parse_grounding_manifest("[{\"label\": broken").is_empty());
}

#[test]
fn a_declared_grounding_manifest_binds_the_run() {
    // registry/seed_sets.yaml carries a per-artifact grounding_manifest pointer
    // that was parsed away and never read, so the CLI-supplied manifest was
    // unbound: any manifest would be believed.
    let yaml = r#"
seed_sets:
  - name: "2026-08-05.3e263575"
    gate_eligible: false
    reason: dev cache
    grounding_manifest: registry/grounding/2026-08-05.3e263575.txt
  - name: ppi-labels
    gate_eligible: false
    reason: tuning
"#;
    let sets = parse_seed_sets(yaml).unwrap();

    // Right manifest for the artifact: admitted.
    assert!(check_manifest_matches_artifact(
        &sets,
        "2026-08-05.3e263575",
        Path::new("/somewhere/else/2026-08-05.3e263575.txt")
    )
    .is_ok());

    // Wrong manifest for the artifact: refused.
    let err = check_manifest_matches_artifact(
        &sets,
        "2026-08-05.3e263575",
        Path::new("/tmp/some-other-manifest.txt"),
    )
    .expect_err("a manifest that is not the artifact's must be refused");
    assert!(matches!(err, Refusal::GroundingManifestMismatch { .. }));

    // An artifact that declares nothing makes no claim, so no refusal.
    assert!(
        check_manifest_matches_artifact(&sets, "ppi-labels", Path::new("/tmp/anything.txt"))
            .is_ok()
    );

    // An artifact not in the registry at all is not this check's business.
    assert!(check_manifest_matches_artifact(&sets, "unknown", Path::new("/tmp/x.txt")).is_ok());
}

#[test]
fn the_guard_does_not_depend_on_its_caller_having_normalized() {
    // Caught by breaking two pre-existing tests. `validate_gate_set` is public
    // and takes a plain Vec<String>; when normalization lived only in
    // parse_grounding_manifest, a caller passing raw `owner/name` got ZERO
    // matches and a silent pass -- the same fail-open this bead closes, moved
    // one function upstream. A guard that depends on its caller having been
    // careful is not a guard.
    use rvl_eval::gate::{parse_manifest, validate_gate_set, Registry};

    let manifest = parse_manifest(
        r#"
set_id: eval-go-v1
language: go
minted: "2026-08-06"
registry_version: 3
consumed: false
repos:
  - repo: go-gitea/gitea
    frozen_sha: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
sampling_frame: post-triage violates
sample_size: 50
adjudication:
  protocol: source-grounded
  panel: "3"
  adjudicator: josebiro
  date: "2026-08-06"
"#,
    )
    .unwrap();
    let registry = Registry {
        registry_version: 3,
        repos: vec!["go-gitea/gitea".to_string()],
    };

    for spelling in ["go-gitea/gitea", "go-gitea_gitea", "GO-GITEA/GITEA"] {
        let err = validate_gate_set(&manifest, &[], &registry, &[spelling.to_string()])
            .expect_err("overlap must be caught however the manifest spells the repo");
        assert!(
            matches!(err, Refusal::GroundingOverlap(_)),
            "spelling {spelling} produced {err:?}"
        );
    }
}
