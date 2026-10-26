//! The OSS spec cache users get, scanned.
//!
//! Every other end-to-end test scans with seed specs, so a publisher change
//! that drops a section, or publishes it empty, breaks scanning with no test
//! failing: a missing section loads silently as an empty one (every
//! `SpecFile` section is `#[serde(default)]`). The `oss-spec-cache` workflow
//! fetches the served OSS artifact and its detached signature and runs
//! [`the_served_oss_spec_cache`] on them. The check:
//!
//!   * installs the artifact as the OSS tier, which verifies its signature
//!     against the pinned keyset, as `rvl sync` does;
//!   * requires every section in [`REQUIRED`] to be present and non-empty;
//!   * scans the fixtures of every lane it holds with `--oss-only` and
//!     requires the lane to decide at least one site.
//!
//! Every `SpecFile` section is in exactly one of three lists, and
//! [`every_spec_file_section_has_one_place_in_the_check`] fails when a new
//! one is in none. The other tests here run the same check on a signed copy
//! of a cache built from the seed specs, so the check itself is tested by
//! `cargo test`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the workflow puts the fetched artifact. Its signature is read from
/// the same path with `.sig` appended.
const ARTIFACT_ENV: &str = "RVL_OSS_SPEC_CACHE";

/// Mirrors `TEST_KEYSET_ENV` in `crates/rvl/src/keyset.rs`: the debug-only
/// variable that adds a test verifying key to the pinned keyset.
const TEST_KEYSET_ENV: &str = "RVL_TEST_KEYSET_HEX";

/// The sections the OSS artifact must carry, each non-empty. These are the
/// vocabulary rulesets docs/scanning.md ("What the free tier contains") says
/// the free tier carries, and the causal factor codes, which are not a
/// judgment ruleset.
const REQUIRED: &[&str] = &["server", "emissions", "config_keys", "control_factors"];

/// The sections the OSS artifact leaves out by design: the judgment rulesets
/// docs/scanning.md says are commercial-only. Each one feeds the call-site
/// lane alone, so that lane decides no site on the OSS tier and the check
/// does not hold it.
const COMMERCIAL_ONLY: &[(&str, &str)] = &[
    (
        "apis",
        "the per-API verdicts on blocking behavior and boundedness",
    ),
    (
        "configs",
        "what a client configuration type proves about the boundedness of its calls",
    ),
    (
        "scopes",
        "whether the boundedness control applies to a scope class",
    ),
    (
        "decorators",
        "which decorator argument values mean no bound",
    ),
];

/// The sections the publisher does not write yet, each with the work that
/// adds it. While one is absent its lane is dark and not held. Once the
/// artifact carries it, the check holds its lane like any other and says to
/// move the section to [`REQUIRED`].
const TRACKED_ABSENT: &[(&str, &str)] = &[
    (
        "misuse_shapes",
        "the publisher writing the misuse-shape specs of the misuse lane",
    ),
    (
        "construction_bounds",
        "the publisher writing the construction-bound specs of the unsized-construction lane",
    ),
];

/// A fixture the check scans, and the engine its language needs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Fixture {
    GoMain,
    GoTrace,
    GoMisuse,
    GoBounds,
    PyMain,
    PyMisuse,
    PyBounds,
    TsMain,
    ConfigSites,
}

impl Fixture {
    /// The fixture directory, relative to the workspace root.
    fn dir(self) -> &'static str {
        match self {
            Fixture::GoMain => "helpers/goindex/testdata/fixture",
            Fixture::GoTrace => "helpers/goindex/testdata/tracefixture",
            Fixture::GoMisuse => "helpers/goindex/testdata/misusefixture",
            Fixture::GoBounds => "helpers/goindex/testdata/boundsfixture",
            Fixture::PyMain => "helpers/pyindex/testdata/fixture",
            Fixture::PyMisuse => "helpers/pyindex/testdata/fixture_misuse",
            Fixture::PyBounds => "helpers/pyindex/testdata/fixture_bounds",
            Fixture::TsMain => "helpers/tsindex/testdata/fixture",
            Fixture::ConfigSites => "crates/rvl/tests/fixtures/config_sites",
        }
    }

    /// The language the scan must report `scanned`, as `lang_status` names
    /// it. None for the config lane, which needs no retriever.
    fn lang(self) -> Option<&'static str> {
        match self {
            Fixture::GoMain | Fixture::GoTrace | Fixture::GoMisuse | Fixture::GoBounds => {
                Some("Go")
            }
            Fixture::PyMain | Fixture::PyMisuse | Fixture::PyBounds => Some("Python"),
            Fixture::TsMain => Some("TypeScript"),
            Fixture::ConfigSites => None,
        }
    }
}

/// A lane the check can hold: the section that feeds it, the fixtures that
/// exercise it, and how a decided site of it reads in the `--out` document.
struct Lane {
    name: &'static str,
    section: &'static str,
    fixtures: &'static [Fixture],
    /// The class prefix of the lane's findings. These lanes surface only
    /// their violations, so a finding is a decided site. None for the config
    /// lane, whose decided sites are its `config_sites` rows.
    finding_prefix: Option<&'static str>,
}

const LANES: &[Lane] = &[
    Lane {
        name: "server-entry",
        section: "server",
        fixtures: &[
            Fixture::GoMain,
            Fixture::GoTrace,
            Fixture::PyMain,
            Fixture::TsMain,
        ],
        finding_prefix: Some("server_entry."),
    },
    Lane {
        name: "emission",
        section: "emissions",
        fixtures: &[
            Fixture::GoMain,
            Fixture::GoTrace,
            Fixture::PyMain,
            Fixture::PyMisuse,
            Fixture::TsMain,
        ],
        finding_prefix: Some("emission."),
    },
    Lane {
        name: "config",
        section: "config_keys",
        fixtures: &[Fixture::ConfigSites],
        finding_prefix: None,
    },
    Lane {
        name: "misuse",
        section: "misuse_shapes",
        fixtures: &[Fixture::GoMisuse, Fixture::PyMisuse],
        finding_prefix: Some("misuse."),
    },
    Lane {
        name: "unsized-construction",
        section: "construction_bounds",
        fixtures: &[Fixture::GoBounds, Fixture::PyBounds],
        finding_prefix: Some("unsized."),
    },
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Whether `specs` carries `section` with at least one entry.
fn carries(specs: &serde_json::Value, section: &str) -> bool {
    specs
        .get(section)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|a| !a.is_empty())
}

/// What is wrong with the sections of `specs`, and the notes on tracked
/// absences that are absent no more.
fn section_problems(specs: &serde_json::Value) -> (Vec<String>, Vec<String>) {
    let problems = REQUIRED
        .iter()
        .filter(|s| !carries(specs, s))
        .map(|s| format!("required section `{s}` is missing or empty"))
        .collect();
    let notes = TRACKED_ABSENT
        .iter()
        .filter(|(s, _)| carries(specs, s))
        .map(|(s, _)| {
            format!("section `{s}` is published now: its lane is held; move it to REQUIRED")
        })
        .collect();
    (problems, notes)
}

/// The lanes the check holds on `specs`: each lane fed by a required
/// section, and each lane fed by a tracked absence the artifact now carries.
fn held_lanes(specs: &serde_json::Value) -> Vec<&'static Lane> {
    LANES
        .iter()
        .filter(|l| REQUIRED.contains(&l.section) || carries(specs, l.section))
        .collect()
}

/// The helpers the scans run, from this checkout, or None when an engine is
/// missing (a SKIP on a workstation, a failure under
/// `RVLSCAN_REQUIRE_ENGINES`).
struct Helpers {
    goindex: PathBuf,
}

fn helpers(test: &str, dir: &Path) -> Option<Helpers> {
    let root = workspace_root();
    let goindex = dir.join("goindex");
    match Command::new("go")
        .arg("build")
        .env_remove("GOROOT")
        .arg("-o")
        .arg(&goindex)
        .arg(".")
        .current_dir(root.join("helpers/goindex"))
        .output()
    {
        Ok(out) => assert!(
            out.status.success(),
            "goindex failed to build: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(e) => {
            rvl_testgate::skip(test, format_args!("go toolchain not available: {e}"));
            return None;
        }
    }
    match Command::new("node")
        .args(["-e", "require('typescript')"])
        .current_dir(root.join("helpers/tsindex"))
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(_) => {
            rvl_testgate::skip(test, "tsindex needs `npm ci` (typescript missing)");
            return None;
        }
        Err(e) => {
            rvl_testgate::skip(test, format_args!("node not available: {e}"));
            return None;
        }
    }
    if let Err(e) = Command::new("python3").arg("--version").output() {
        rvl_testgate::skip(test, format_args!("python3 not available: {e}"));
        return None;
    }
    Some(Helpers { goindex })
}

/// Scan `fixture` on the OSS tier installed under `cache` and return its
/// `--out` document, or the problem that kept it from one.
fn scan(
    fixture: Fixture,
    cache: &Path,
    work: &Path,
    helpers: &Helpers,
    test_key: Option<&str>,
) -> Result<serde_json::Value, String> {
    let root = workspace_root();
    let out = work.join(format!("{fixture:?}.json"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rvl"));
    cmd.arg("scan")
        .arg(root.join(fixture.dir()))
        .arg("--oss-only")
        .arg("--out")
        .arg(&out)
        .env("RVL_CACHE_DIR", cache)
        .env("HOME", work.join("home"))
        // The tier under test is the one installed here: no background check
        // may replace it.
        .env("RVL_OFFLINE", "1")
        .env("RVL_GOINDEX", &helpers.goindex)
        .env("RVL_PYINDEX", root.join("helpers/pyindex/pyindex.py"))
        .env("RVL_TSINDEX", root.join("helpers/tsindex/tsindex.js"))
        .env_remove(TEST_KEYSET_ENV)
        .env_remove("RVL_BASE_REF")
        .env_remove("GITHUB_BASE_REF")
        .env_remove("CI_MERGE_REQUEST_TARGET_BRANCH_NAME");
    if let Some(key) = test_key {
        cmd.env(TEST_KEYSET_ENV, key);
    }
    let run = cmd.output().expect("failed to run rvl");
    let stderr = String::from_utf8_lossy(&run.stderr);
    if !matches!(run.status.code(), Some(0) | Some(3)) {
        return Err(format!(
            "{}: rvl scan exited {:?}: {stderr}",
            fixture.dir(),
            run.status.code()
        ));
    }
    let doc: serde_json::Value = std::fs::read(&out)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| format!("{}: no readable --out document: {stderr}", fixture.dir()))?;
    if let Some(lang) = fixture.lang() {
        let state = doc["coverage"]["lang_status"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["lang"] == lang)
            .map(|s| s["state"].as_str().unwrap_or_default().to_string());
        if state.as_deref() != Some("scanned") {
            return Err(format!(
                "{}: the {lang} lane is {state:?}, not scanned: {stderr}",
                fixture.dir()
            ));
        }
    }
    Ok(doc)
}

/// The decided sites of `lane` in one `--out` document.
fn decided(lane: &Lane, doc: &serde_json::Value) -> usize {
    match lane.finding_prefix {
        Some(prefix) => doc["findings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["class"].as_str().is_some_and(|c| c.starts_with(prefix)))
            .count(),
        None => doc["config_sites"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| matches!(s["verdict"].as_str(), Some("violates" | "satisfies")))
            .count(),
    }
}

/// The outcome of the check: what fails it, and what it notes.
struct Report {
    problems: Vec<String>,
    notes: Vec<String>,
}

/// Run the whole check on an artifact and its detached signature. Verifies
/// against the pinned keyset, plus `test_key` (hex) when a test signed the
/// artifact. None when a missing engine skipped the scans.
fn check(test: &str, bytes: &[u8], sig_b64: &str, test_key: Option<&str>) -> Option<Report> {
    let work = tempfile::tempdir().unwrap();
    let mut keys = rvl_cache::PINNED_KEYSET_HEX.to_vec();
    keys.extend(test_key);
    let keyset = rvl_cache::Keyset::from_hex(&keys).unwrap();

    let cache = work.path().join("cache");
    let store = rvl_cache::CacheStore::open(&cache.join(rvl_cache::OSS_DIR)).unwrap();
    match store.install(bytes, sig_b64, &keyset) {
        rvl_cache::SyncOutcome::Installed { .. } => {}
        other => {
            return Some(Report {
                problems: vec![format!("the artifact does not install: {other:?}")],
                notes: Vec::new(),
            });
        }
    }
    let envelope: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    let specs = &envelope["specs"];
    let (mut problems, notes) = section_problems(specs);

    let lanes = held_lanes(specs);
    let fixtures: BTreeSet<Fixture> = lanes
        .iter()
        .flat_map(|l| l.fixtures.iter().copied())
        .collect();
    let helpers = helpers(test, work.path())?;
    let mut docs = Vec::new();
    for f in fixtures {
        match scan(f, &cache, work.path(), &helpers, test_key) {
            Ok(doc) => docs.push((f, doc)),
            Err(e) => problems.push(e),
        }
    }
    for lane in lanes {
        let counts: Vec<(Fixture, usize)> = docs
            .iter()
            .filter(|(f, _)| lane.fixtures.contains(f))
            .map(|(f, doc)| (*f, decided(lane, doc)))
            .collect();
        if counts.iter().all(|(_, n)| *n == 0) {
            problems.push(format!(
                "the {} lane (section `{}`) decides no site in its fixtures: {counts:?}",
                lane.name, lane.section
            ));
        }
    }
    Some(Report { problems, notes })
}

/// THE SERVED ARTIFACT. Run by the `oss-spec-cache` workflow, which fetches
/// it into `$RVL_OSS_SPEC_CACHE`; ignored by a plain `cargo test`, which has
/// no artifact to read.
#[test]
#[ignore = "needs the served OSS artifact in $RVL_OSS_SPEC_CACHE (the oss-spec-cache workflow)"]
fn the_served_oss_spec_cache() {
    let artifact = std::env::var_os(ARTIFACT_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("{ARTIFACT_ENV} names no artifact"));
    let mut sig = artifact.clone().into_os_string();
    sig.push(".sig");
    let bytes =
        std::fs::read(&artifact).unwrap_or_else(|e| panic!("reading {}: {e}", artifact.display()));
    let sig = std::fs::read_to_string(&sig)
        .unwrap_or_else(|e| panic!("reading the signature of {}: {e}", artifact.display()));

    let Some(report) = check("the_served_oss_spec_cache", &bytes, &sig, None) else {
        return;
    };
    for (section, what) in COMMERCIAL_ONLY {
        eprintln!("not held: `{section}`, commercial-only ({what})");
    }
    for (section, until) in TRACKED_ABSENT {
        eprintln!("not held while absent: `{section}`, until {until}");
    }
    for note in &report.notes {
        eprintln!("note: {note}");
    }
    assert!(
        report.problems.is_empty(),
        "the served OSS spec cache fails the check:\n  {}",
        report.problems.join("\n  ")
    );
}

/// Each `SpecFile` section is required, commercial-only or a tracked
/// absence, and only one of them. A section added to `SpecFile` fails here
/// until the check knows what to expect of it.
#[test]
fn every_spec_file_section_has_one_place_in_the_check() {
    let sections: BTreeSet<String> = serde_json::to_value(rvl_spec::SpecFile::default())
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let mut placed: Vec<&str> = REQUIRED.to_vec();
    placed.extend(COMMERCIAL_ONLY.iter().map(|(s, _)| *s));
    placed.extend(TRACKED_ABSENT.iter().map(|(s, _)| *s));
    let unique: BTreeSet<String> = placed.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        unique.len(),
        placed.len(),
        "a section is in two lists: {placed:?}"
    );
    assert_eq!(
        unique, sections,
        "SpecFile sections and the check's lists differ"
    );
    for lane in LANES {
        assert!(
            !COMMERCIAL_ONLY.iter().any(|(s, _)| *s == lane.section),
            "the {} lane is fed by a commercial-only section",
            lane.name
        );
    }
}

/// A copy of an OSS cache: the seed specs of the lanes the OSS tier feeds,
/// plus one causal factor entry, as the specs of a signed envelope.
fn seed_oss_specs() -> serde_json::Value {
    let read = |rel: &str| -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join(rel);
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    };
    serde_json::json!({
        "server": read("testdata/server_specs_seed.json")["server"],
        "emissions": read("fixtures/g4_seed_specs.json")["emissions"],
        "config_keys": read("fixtures/config_sites_specs.json")["config_keys"],
        "control_factors": [{"control": "RC-027", "factors": ["CF-0007"]}],
    })
}

/// Sign an envelope carrying `specs` with a fresh key. Returns the bytes, the
/// signature and the public half, hex encoded.
fn sign(specs: &serde_json::Value) -> (Vec<u8>, String, String) {
    use base64::Engine;
    use ed25519_dalek::Signer;

    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "content_version": format!("{}.1", rvl_cache::today_utc()),
        "specs": specs,
    }))
    .unwrap();
    let sig = base64::engine::general_purpose::STANDARD.encode(signing.sign(&bytes).to_bytes());
    (bytes, sig, hex::encode(signing.verifying_key().to_bytes()))
}

#[cfg(debug_assertions)]
#[test]
fn the_check_passes_on_a_cache_carrying_every_required_section() {
    let (bytes, sig, key) = sign(&seed_oss_specs());
    let test = "the_check_passes_on_a_cache_carrying_every_required_section";
    let Some(report) = check(test, &bytes, &sig, Some(&key)) else {
        return;
    };
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert!(report.notes.is_empty(), "{:?}", report.notes);
}

/// The test of the check itself: the same cache with `server` removed fails,
/// on the section and on the lane it feeds.
#[cfg(debug_assertions)]
#[test]
fn the_check_fails_on_a_cache_with_a_required_section_removed() {
    let mut specs = seed_oss_specs();
    specs.as_object_mut().unwrap().remove("server");
    let (bytes, sig, key) = sign(&specs);
    let test = "the_check_fails_on_a_cache_with_a_required_section_removed";
    let Some(report) = check(test, &bytes, &sig, Some(&key)) else {
        return;
    };
    assert_eq!(
        report.problems.len(),
        2,
        "the section and its lane, nothing else: {:?}",
        report.problems
    );
    assert!(
        report.problems[0].contains("`server` is missing or empty"),
        "{:?}",
        report.problems
    );
    assert!(
        report.problems[1].contains("server-entry lane"),
        "{:?}",
        report.problems
    );
}

/// Every required section, removed or published empty, fails the section
/// check on its own.
#[test]
fn each_required_section_missing_or_empty_is_a_problem() {
    let full = seed_oss_specs();
    assert!(section_problems(&full).0.is_empty());
    for section in REQUIRED {
        for emptied in [false, true] {
            let mut specs = full.clone();
            let obj = specs.as_object_mut().unwrap();
            if emptied {
                obj.insert(section.to_string(), serde_json::json!([]));
            } else {
                obj.remove(*section);
            }
            assert_eq!(
                section_problems(&specs).0,
                vec![format!("required section `{section}` is missing or empty")],
            );
        }
    }
}

/// A tracked absence the artifact carries is noted and its lane is held; the
/// commercial-only call-site lane never is.
#[test]
fn a_published_tracked_section_holds_its_lane() {
    let held = |specs: &serde_json::Value| -> Vec<&str> {
        held_lanes(specs).iter().map(|l| l.name).collect()
    };
    let mut specs = seed_oss_specs();
    assert_eq!(held(&specs), ["server-entry", "emission", "config"]);
    specs["misuse_shapes"] = serde_json::json!([{"class": "overbroad_catch", "type": "*"}]);
    specs["apis"] = serde_json::json!([{"type": "requests", "method": "get"}]);
    assert_eq!(
        held(&specs),
        ["server-entry", "emission", "config", "misuse"]
    );
    let (problems, notes) = section_problems(&specs);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(notes[0].contains("`misuse_shapes`"), "{notes:?}");
}

/// A signature by a key outside the keyset fails the check before any scan.
#[test]
fn an_artifact_signed_by_another_key_fails_the_check() {
    let (bytes, sig, _) = sign(&seed_oss_specs());
    let report = check("an_artifact_signed_by_another_key", &bytes, &sig, None).unwrap();
    assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
    assert!(
        report.problems[0].contains("does not verify"),
        "{:?}",
        report.problems
    );
}
