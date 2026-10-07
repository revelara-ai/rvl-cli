//! A RELEASE CARRIES AN SBOM AND SLSA PROVENANCE (po-fao1r).
//!
//! Nothing here can run a release, so the release configuration is held to the
//! contract instead, where a regression fails at PR time and not at tag time:
//!
//!   * dist-workspace.toml asks cargo-dist for a CycloneDX SBOM, and the
//!     generated release.yml really produces one;
//!   * release.yml calls the SLSA provenance workflow with exactly the
//!     permissions the generator needs;
//!   * that workflow pins slsa-github-generator by release tag and uploads the
//!     provenance to the release;
//!   * `ci/slsa-subjects.sh` attests the file set the release uploads, and
//!     refuses an empty one.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The crate directory, read at run time. `cargo test` sets CARGO_MANIFEST_DIR
/// for every test process; a binary reused from a shared CARGO_TARGET_DIR still
/// carries the compile-time path of whichever checkout built it, which may be gone.
fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

fn repo_root() -> PathBuf {
    manifest_dir().join("../..")
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The lines of `text` that are not YAML/TOML comments, so a key that is only
/// mentioned in a comment does not satisfy a check.
fn live_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// The body of the top-level-in-`jobs` job `name` in a workflow: every line
/// after its `  name:` header up to the next job header.
fn job_body<'a>(workflow: &'a str, name: &str) -> Vec<&'a str> {
    let header = format!("  {name}:");
    let is_job_header =
        |l: &str| l.starts_with("  ") && !l.starts_with("   ") && !l.trim_start().starts_with('#');
    workflow
        .lines()
        .skip_while(|l| l.trim_end() != header)
        .skip(1)
        .take_while(|l| !is_job_header(l))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn dist_config_asks_for_an_sbom_and_the_provenance_job() {
    let toml = read("dist-workspace.toml");
    let live = live_lines(&toml);
    assert!(
        live.contains(&"cargo-cyclonedx = true"),
        "dist-workspace.toml must set `cargo-cyclonedx = true`"
    );
    assert!(
        live.contains(&r#"post-announce-jobs = ["./slsa-provenance"]"#),
        "dist-workspace.toml must run ./slsa-provenance as a post-announce job"
    );
}

#[test]
fn generated_release_workflow_builds_the_sbom() {
    let release = read(".github/workflows/release.yml");
    let global = job_body(&release, "build-global-artifacts");
    assert!(
        global.iter().any(|l| l.starts_with("cargo cyclonedx")),
        "release.yml is stale: regenerate it with `dist generate`"
    );
}

#[test]
fn generated_release_workflow_calls_the_provenance_job_with_its_permissions() {
    let release = read(".github/workflows/release.yml");
    let job = job_body(&release, "custom-slsa-provenance");
    assert!(
        job.contains(&"uses: ./.github/workflows/slsa-provenance.yml"),
        "release.yml is stale: regenerate it with `dist generate`. Got: {job:?}"
    );
    // The generator needs all three and a called workflow cannot hold more
    // than its caller grants, so a missing one fails the release at startup.
    for permission in [
        r#""actions": "read""#,
        r#""contents": "write""#,
        r#""id-token": "write""#,
    ] {
        assert!(job.contains(&permission), "missing {permission}: {job:?}");
    }
}

#[test]
fn provenance_workflow_pins_the_generator_by_tag_and_uploads_to_the_release() {
    let workflow = read(".github/workflows/slsa-provenance.yml");
    let live = live_lines(&workflow);

    assert!(
        live.contains(&"workflow_call:"),
        "must be callable from release.yml"
    );

    const GENERATOR: &str =
        "uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@";
    let pins: Vec<&str> = live
        .iter()
        .filter_map(|l| l.strip_prefix(GENERATOR))
        .collect();
    assert_eq!(pins.len(), 1, "exactly one call to the generator: {pins:?}");
    // The generator refuses to run unless it is referenced by a release tag
    // (it verifies its own ref), so a SHA pin here breaks every release.
    let version = pins[0].strip_prefix('v').unwrap_or("");
    let parts: Vec<&str> = version.split('.').collect();
    assert!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "generator must be pinned as @vMAJOR.MINOR.PATCH, got @{}",
        pins[0]
    );

    assert!(live.contains(&"upload-assets: true"));
    assert!(live.contains(&"upload-tag-name: ${{ github.ref_name }}"));
    assert!(live.contains(&"provenance-name: rvl.intoto.jsonl"));
    assert!(
        live.iter().any(|l| l.contains("ci/slsa-subjects.sh")),
        "subjects must come from ci/slsa-subjects.sh"
    );
}

fn run_subjects(dir: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(repo_root().join("ci/slsa-subjects.sh"))
        .arg(dir)
        .output()
        .expect("run ci/slsa-subjects.sh")
}

#[test]
fn subjects_are_the_uploaded_files_without_the_granular_manifests() {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in [
        ("rvl-x86_64-unknown-linux-gnu.tar.xz", "archive"),
        ("rvl.cdx.xml", "sbom"),
        ("dist-manifest.json", "{}"),
        // The host job deletes these before it uploads; they are not assets.
        ("x86_64-unknown-linux-gnu-dist-manifest.json", "{}"),
        ("global-dist-manifest.json", "{}"),
    ] {
        std::fs::write(dir.path().join(name), body).unwrap();
    }

    let out = run_subjects(dir.path());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let rows: Vec<(&str, &str)> = stdout
        .lines()
        .map(|l| l.split_once("  ").expect("`<sha256>  <name>`"))
        .collect();
    let names: Vec<&str> = rows.iter().map(|(_, name)| *name).collect();
    assert_eq!(
        names,
        [
            "dist-manifest.json",
            "rvl-x86_64-unknown-linux-gnu.tar.xz",
            "rvl.cdx.xml"
        ]
    );
    // sha256("sbom")
    assert_eq!(
        rows[2].0,
        "98f3ae1ef67113d8140d4f6cb8d2830070e21ea48f091be519659846c771a374"
    );
}

#[test]
fn subjects_refuse_an_empty_release() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("global-dist-manifest.json"), "{}").unwrap();

    let out = run_subjects(dir.path());
    assert!(
        !out.status.success(),
        "an empty subject list must fail the job"
    );
    assert!(out.stdout.is_empty(), "nothing may be attested on failure");
    assert!(String::from_utf8_lossy(&out.stderr).contains("no release artifacts"));
}
