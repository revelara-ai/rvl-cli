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
    run_retrying_etxtbsy(&mut cmd)
}

/// Spawn `cmd`, retrying briefly on `ETXTBSY` ("Text file busy").
///
/// Not flake papering: this is a known Linux fork/exec race and it belongs to
/// the harness, not to the scanner. These tests COPY the binary and then
/// execute the copy; while `fs::copy` holds a write descriptor on the
/// destination, any fork elsewhere in this multi-threaded test process
/// inherits that descriptor, and the kernel refuses to exec a file that is
/// open for writing until the last such descriptor closes. It surfaced only
/// under a full `cargo test` — several test binaries spawning at once widen
/// the window — which is exactly the run the commit gate uses.
fn run_retrying_etxtbsy(cmd: &mut Command) -> std::process::Output {
    for _ in 0..50 {
        match cmd.output() {
            Ok(o) => return o,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("failed to run rvlscan: {e:?}"),
        }
    }
    panic!("rvlscan stayed ETXTBSY for a second; the copied binary never became executable")
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

/// Adds C# to a fixture repo. Split out because C# is the one language whose
/// retriever is deliberately NOT shipped, so most tests want a repo without it.
fn add_csharp(repo: &Path) {
    std::fs::write(
        repo.join("Svc.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup>\
         <TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>\n",
    )
    .unwrap();
    std::fs::write(
        repo.join("Svc.cs"),
        "public class Svc { public static void Main() { System.Console.WriteLine(1); } }\n",
    )
    .unwrap();
}

/// csindex is the one retriever rvlscan does not carry, so its install hint
/// names a canonical build location — and a location we name is a location the
/// binary must search. Found there with NO env var, and reported as the user's
/// own install rather than as something we shipped.
///
/// This is the gap the real target repo exposed: Google's Online Boutique is
/// five languages including C#, and it hard-failed after the embedded scripts
/// landed because the only route to csindex was an env var the hint itself
/// told you to set to a path it had just chosen for you.
#[test]
fn csindex_is_discovered_at_the_canonical_helper_dir_with_no_env_var() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let canonical = home.join(".revelara").join("helpers").join("csindex");
    std::fs::create_dir_all(&canonical).unwrap();
    let dll = canonical.join("csindex.dll");
    // Stands in for a real `dotnet build -o ~/.revelara/helpers/csindex`: this
    // test is about RESOLUTION, and driving Roslyn would need a .NET SDK on
    // every machine that runs the suite.
    std::fs::write(&dll, "not a real assembly\n").unwrap();

    let bin = lone_binary(&dir.path().join("bin"));
    let repo = polyglot_fixture(dir.path());
    add_csharp(&repo);
    let out = scan(
        &bin,
        &repo,
        &home,
        &dir.path().join("cache"),
        &dir.path().join("findings.json"),
    );
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    assert!(
        !stderr.contains("cannot be scanned honestly"),
        "an installed csindex must satisfy the preflight probe:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("C# {} (installed)", dll.display())),
        "the roll-call must name the canonical path and credit the user's install:\n{stdout}"
    );
    // The stand-in cannot actually retrieve, and that is fine: C# degrades and
    // the other four languages are still scanned. What must NOT happen is the
    // scan dying because one language's toolchain is unusable.
    assert!(
        matches!(out.status.code(), Some(0) | Some(EXIT_BLOCKED)),
        "an unusable helper degrades its language, it does not sink the scan: {:?}\n{stderr}",
        out.status.code()
    );
}

/// Without that install, a C# repo still fails CLOSED — a gate that cannot read
/// a language the repo contains must not report "clean" — and the failure says
/// exactly what to run, with no follow-up environment step.
#[test]
fn a_missing_csindex_fails_closed_with_a_single_actionable_command() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = polyglot_fixture(dir.path());
    add_csharp(&repo);
    let out = scan(
        &bin,
        &repo,
        &home,
        &dir.path().join("cache"),
        &dir.path().join("findings.json"),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        stderr.contains("cannot be scanned honestly"),
        "a language with no retriever must not pass silently:\n{stderr}"
    );
    assert!(
        stderr.contains("dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex"),
        "the failure must carry the one command that fixes it:\n{stderr}"
    );
    assert!(
        !stderr.contains("RVLSCAN_CSINDEX="),
        "the command writes where rvlscan looks, so no env var may be demanded:\n{stderr}"
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
