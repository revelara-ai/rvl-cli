//! A FRESH INSTALL SCANS (po-aml3h).
//!
//! The regression these tests exist for: `brew install rvlscan` delivered the
//! binary and none of the seven retriever helpers, so the first scan of any
//! real repository died on "no retriever for N of the N language(s) in this
//! repo, so it cannot be scanned honestly" before looking at a single line.
//!
//! Every test here runs a COPY of the binary in an otherwise empty directory,
//! with HOME pointed at a tempdir. That is not ceremony: the developer machine
//! that runs the suite usually has `make helpers` output sitting next to
//! `target/debug/rvlscan`, which resolution finds first and which would make
//! these tests pass without the feature existing at all.

use std::path::{Path, PathBuf};
use std::process::Command;

/// "The scan RAN" — clean (0) or gate-fired (3). Anything else is the scanner
/// itself failing, which is what a helperless machine used to produce.
const EXIT_BLOCKED: i32 = 3;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/rvlscan lives two levels under the workspace root")
        .to_path_buf()
}

fn seed_specs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("background_jobs_specs.json")
}

/// The rvlscan binary copied into an EMPTY directory, i.e. what a package
/// manager hands a user before any helper has been installed by hand.
fn lone_binary(bin_dir: &Path) -> PathBuf {
    std::fs::create_dir_all(bin_dir).unwrap();
    let dest = bin_dir.join("rvlscan");
    std::fs::copy(env!("CARGO_BIN_EXE_rvlscan"), &dest).expect("copying the scanner binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    dest
}

/// A small polyglot repo: one production source per embedded-script language,
/// each with the marker file language detection short-circuits on.
fn polyglot_fixture(dir: &Path) -> PathBuf {
    let repo = dir.join("repo");
    std::fs::create_dir_all(&repo).unwrap();

    std::fs::write(repo.join("pyproject.toml"), "[project]\nname = \"svc\"\n").unwrap();
    std::fs::write(
        repo.join("svc.py"),
        "import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n",
    )
    .unwrap();

    std::fs::write(repo.join("tsconfig.json"), "{\"compilerOptions\":{}}\n").unwrap();
    std::fs::write(
        repo.join("svc.ts"),
        "export async function fetchIt(url: string): Promise<string> {\n  \
         const r = await fetch(url);\n  return r.text();\n}\n",
    )
    .unwrap();

    std::fs::write(
        repo.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion>\
         <groupId>svc</groupId><artifactId>svc</artifactId><version>1</version></project>\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("Svc.java"),
        "public class Svc {\n  public static void main(String[] a) {\n    \
         System.out.println(\"hi\");\n  }\n}\n",
    )
    .unwrap();

    repo
}

/// The versioned directory the embedded scripts are written to under `home`.
fn helper_cache(home: &Path) -> PathBuf {
    home.join(".revelara")
        .join("helpers")
        .join(env!("CARGO_PKG_VERSION"))
}

fn scan(bin: &Path, repo: &Path, home: &Path, cache: &Path, out: &Path) -> std::process::Output {
    let mut cmd = Command::new(bin);
    cmd.arg("scan")
        .arg(repo)
        .arg("--specs-file")
        .arg(seed_specs())
        .arg("--out")
        .arg(out)
        .env("HOME", home)
        .env("RVLSCAN_CACHE_DIR", cache);
    // Nothing pre-arranged: no override may reach in and satisfy a language
    // the embedded copy is supposed to satisfy.
    for var in [
        "RVLSCAN_GOINDEX",
        "RVLSCAN_PYINDEX",
        "RVLSCAN_RUSTINDEX",
        "RVLSCAN_TSINDEX",
        "RVLSCAN_CSINDEX",
        "RVLSCAN_JAVAINDEX",
        "RVLSCAN_CINDEX",
        "RVLSCAN_HELPER_DIR",
        "RVLSCAN_ALLOW_MISSING_HELPERS",
    ] {
        cmd.env_remove(var);
    }
    cmd.output().expect("failed to run rvlscan")
}

/// THE ACCEPTANCE TEST. A lone binary, an empty HOME, a polyglot repo, and no
/// environment: the scan must run, and it must run on scripts it wrote out of
/// itself.
#[test]
fn a_lone_binary_materializes_its_scripted_retrievers_and_scans() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let cache = helper_cache(&home);
    assert!(
        !cache.exists(),
        "the helper cache must be absent before the first scan, or this proves nothing"
    );

    let bin = lone_binary(&dir.path().join("bin"));
    let repo = polyglot_fixture(dir.path());
    let out = scan(
        &bin,
        &repo,
        &home,
        &dir.path().join("cache"),
        &dir.path().join("findings.json"),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // The regression, named exactly: a helperless machine used to stop here.
    assert!(
        !stderr.contains("cannot be scanned honestly"),
        "a fresh install must not fail the preflight helper probe:\n{stderr}"
    );
    assert!(
        matches!(out.status.code(), Some(0) | Some(EXIT_BLOCKED)),
        "scan must reach a verdict, got {:?}\n{stdout}\n{stderr}",
        out.status.code()
    );

    // Every embedded script was written out, byte-identical to the source of
    // truth in `helpers/`. Comparing against the repo file (not just "the file
    // exists") is what catches an include_str! pointed at the wrong path.
    for (name, source) in [
        ("pyindex.py", "helpers/pyindex/pyindex.py"),
        ("tsindex.js", "helpers/tsindex/tsindex.js"),
        ("javaindex.java", "helpers/javaindex/javaindex.java"),
    ] {
        let extracted = cache.join(name);
        assert!(
            extracted.is_file(),
            "{name} was not materialized under {}\n{stdout}\n{stderr}",
            cache.display()
        );
        assert_eq!(
            std::fs::read_to_string(&extracted).unwrap(),
            std::fs::read_to_string(workspace_root().join(source)).unwrap(),
            "the extracted {name} must match the helper it was embedded from"
        );
    }

    // USED, not merely written: the roll-call names the real resolved path and
    // says where it came from, which is the only place a shadowing helper is
    // visible at all.
    for (lang, name) in [
        ("Python", "pyindex.py"),
        ("TypeScript", "tsindex.js"),
        ("Java", "javaindex.java"),
    ] {
        let expected = format!("{lang} {} (embedded)", cache.join(name).display());
        assert!(
            stdout.contains(&expected),
            "the retrievers roll-call must report `{expected}`:\n{stdout}"
        );
    }
}

/// A corrupted extracted script is REPAIRED on the next run rather than driven
/// as-is: a stale or truncated helper is a silently wrong scan, which is worse
/// than the loud failure this bead replaced.
#[test]
fn a_corrupted_extracted_script_is_rewritten_on_the_next_scan() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let cache = helper_cache(&home);
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = polyglot_fixture(dir.path());
    let findings = dir.path().join("findings.json");
    let cache_dir = dir.path().join("cache");

    scan(&bin, &repo, &home, &cache_dir, &findings);
    let script = cache.join("pyindex.py");
    assert!(script.is_file(), "first scan must extract pyindex.py");

    std::fs::write(&script, "raise SystemExit('clobbered')\n").unwrap();
    scan(&bin, &repo, &home, &cache_dir, &findings);
    assert_eq!(
        std::fs::read_to_string(&script).unwrap(),
        std::fs::read_to_string(workspace_root().join("helpers/pyindex/pyindex.py")).unwrap(),
        "a clobbered helper must be restored from the embedded copy"
    );
}

/// A helper deliberately installed NEXT TO the binary still wins over the
/// embedded copy: `make helpers`, a release archive's goindex, and an operator
/// debugging a patched retriever all depend on that precedence, and the
/// roll-call must say which one actually ran.
#[test]
fn a_helper_next_to_the_binary_outranks_the_embedded_copy() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    let adjacent = bin_dir.join("pyindex.py");
    std::fs::write(&adjacent, "import sys\nsys.exit(3)\n").unwrap();

    let repo = polyglot_fixture(dir.path());
    let out = scan(
        &bin,
        &repo,
        &home,
        &dir.path().join("cache"),
        &dir.path().join("findings.json"),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        stdout.contains(&format!("Python {} (bundled)", adjacent.display())),
        "an adjacent helper must outrank the embedded copy, and be named as `bundled`:\n{stdout}"
    );
}
