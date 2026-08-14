//! `rvlscan doctor [--fix]` end to end (po-av01j.169).
//!
//! Every test runs a COPY of the binary in an otherwise empty directory with
//! HOME pointed at a tempdir, for the same reason `fresh_install.rs` does: the
//! developer machine that runs this suite has `make helpers` output sitting
//! next to `target/debug/rvlscan` and a populated `~/.revelara`, either of
//! which would make a doctor test pass without the feature existing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The doctor's "a gap remains" code. Reuses the binary's existing contract:
/// 1 already means "the scan could not complete".
const EXIT_GAP: i32 = 1;

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

/// See `fresh_install::run_retrying_etxtbsy`: a fork elsewhere in this
/// multi-threaded test process can inherit the write descriptor `fs::copy`
/// holds on the freshly written binary, and the kernel refuses to exec a file
/// that is open for writing.
fn run(cmd: &mut Command) -> std::process::Output {
    for _ in 0..50 {
        match cmd.output() {
            Ok(o) => return o,
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("failed to run rvlscan: {e:?}"),
        }
    }
    panic!("rvlscan stayed ETXTBSY for a second")
}

/// A doctor invocation with NOTHING pre-arranged: empty HOME, empty cache,
/// no helper overrides, offline so no repair can reach the network.
fn doctor(bin: &Path, repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin);
    cmd.arg("doctor")
        .arg(repo)
        .args(args)
        .env("HOME", home)
        .env("RVLSCAN_CACHE_DIR", home.join("cache"))
        .env("RVLSCAN_OFFLINE", "1");
    for var in [
        "RVLSCAN_GOINDEX",
        "RVLSCAN_PYINDEX",
        "RVLSCAN_RUSTINDEX",
        "RVLSCAN_TSINDEX",
        "RVLSCAN_CSINDEX",
        "RVLSCAN_JAVAINDEX",
        "RVLSCAN_CINDEX",
        "RVLSCAN_HELPER_DIR",
        "RVL_API_KEY",
        "RVL_API_URL",
        "RVLSCAN_ORG_KEY",
        "RVLSCAN_SRC",
    ] {
        cmd.env_remove(var);
    }
    run(&mut cmd)
}

fn write(path: &Path, body: &str) {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// A repo with the two lanes that survive manual setup BY DESIGN (C#, which
/// needs a .NET SDK plus a build; TypeScript, which needs the pinned
/// compiler) alongside two that do not.
fn polyglot_fixture(dir: &Path) -> PathBuf {
    let repo = dir.join("repo");
    write(&repo.join("pyproject.toml"), "[project]\nname = \"svc\"\n");
    write(
        &repo.join("svc.py"),
        "import requests\n\n\ndef f(u):\n    return requests.get(u)\n",
    );
    write(&repo.join("tsconfig.json"), "{\"compilerOptions\":{}}\n");
    write(
        &repo.join("svc.ts"),
        "export const f = (u: string) => fetch(u);\n",
    );
    write(
        &repo.join("pom.xml"),
        "<project><modelVersion>4.0.0</modelVersion><groupId>s</groupId>\
         <artifactId>s</artifactId><version>1</version></project>\n",
    );
    write(&repo.join("Svc.java"), "public class Svc { }\n");
    write(
        &repo.join("Svc.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
    );
    write(&repo.join("Svc.cs"), "class Svc { void M() { } }\n");
    repo
}

/// A machine with no helpers must be told every gap for the languages THIS
/// repo contains, with an exact command for each one.
#[test]
fn a_bare_machine_is_told_every_gap_with_a_command() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = polyglot_fixture(dir.path());

    let out = doctor(&bin, &repo, &home, &[]);
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        out.status.code(),
        Some(EXIT_GAP),
        "a machine with no spec cache and no csindex has gaps: {stdout}"
    );

    // Repo-aware: it reports the languages this tree actually contains.
    for lang in ["Python", "TypeScript", "C#", "Java"] {
        assert!(stdout.contains(lang), "{lang} lane missing from: {stdout}");
    }
    // csindex is the deliberate manual step, and its gap must carry the one
    // command that closes it — landing in the dir resolution already searches,
    // never "and now export RVLSCAN_CSINDEX".
    assert!(
        stdout.contains("csindex") && stdout.contains("dotnet"),
        "the C# gap must name the dotnet build: {stdout}"
    );
    assert!(
        !stdout.contains("RVLSCAN_CSINDEX"),
        "a hint that names a canonical path must not also demand an env var: {stdout}"
    );
    // No spec cache is a gap, not a silent zero.
    assert!(
        stdout.contains("no verifiable spec cache"),
        "the spec cache gap must be reported: {stdout}"
    );
    // Every FAIL row carries a command.
    let mut pending: Option<&str> = None;
    for line in stdout.lines() {
        if let Some(prev) = pending.take() {
            assert!(
                line.trim_start().starts_with("fix:"),
                "this FAIL row has no command under it:\n  {prev}\n  {line}"
            );
        }
        if line.trim_start().starts_with("FAIL") {
            pending = Some(line);
        }
    }
}

/// The whole point of being repo-aware: a Go shop must never be shown a .NET
/// instruction it will never need.
#[test]
fn a_go_only_repo_is_never_told_about_dotnet() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = dir.path().join("gorepo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");

    let stdout = String::from_utf8(doctor(&bin, &repo, &home, &[]).stdout).unwrap();
    assert!(stdout.contains("Go"), "{stdout}");
    for noise in ["csindex", "C#", "javaindex", "pyindex"] {
        assert!(
            !stdout.contains(noise),
            "a Go repo must not be told about {noise}: {stdout}"
        );
    }
}

/// The slot labels are the diagnosis. A helper next to the binary is
/// `bundled`; one the user built into the canonical dir is `installed`. Only
/// this output distinguishes them, and a stale helper shadowing the shipped
/// one is invisible everywhere else.
#[test]
fn the_roll_call_names_the_slot_each_helper_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);

    // Adjacent to the binary -> bundled.
    let goindex = bin_dir.join("goindex");
    write(&goindex, "#!/bin/sh\nexit 0\n");
    // Built by the user into ~/.revelara/helpers/csindex -> installed.
    let csindex = home.join(".revelara").join("helpers").join("csindex");
    write(&csindex.join("csindex.dll"), "");

    let repo = dir.path().join("repo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");
    write(
        &repo.join("Svc.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\" />\n",
    );
    write(&repo.join("Svc.cs"), "class Svc { void M() { } }\n");

    let stdout = String::from_utf8(doctor(&bin, &repo, &home, &[]).stdout).unwrap();
    let go_row = stdout
        .lines()
        .find(|l| l.contains("Go (goindex)"))
        .unwrap_or_default();
    assert!(
        go_row.contains("(bundled)") && go_row.contains(goindex.to_str().unwrap()),
        "a helper shipped next to the binary must read `bundled` with its real path: {go_row}"
    );
    let cs_row = stdout
        .lines()
        .find(|l| l.contains("C# (csindex)"))
        .unwrap_or_default();
    assert!(
        cs_row.contains("(installed)"),
        "a helper the USER built must read `installed`, not as something we shipped: {cs_row}"
    );
}

/// A lane whose runtime prereq is genuinely absent degrades THAT lane and
/// says why. The others are untouched — a polyglot repo missing one toolchain
/// still has the rest worth reading.
#[test]
fn a_missing_runtime_degrades_only_its_own_lane() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    // A native Go helper next to the binary: no interpreter, so its lane
    // cannot be affected by an empty PATH.
    write(&bin_dir.join("goindex"), "#!/bin/sh\nexit 0\n");

    let repo = dir.path().join("repo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");
    write(&repo.join("pyproject.toml"), "[project]\nname = \"svc\"\n");
    write(
        &repo.join("svc.py"),
        "import requests\n\n\ndef f(u):\n    return requests.get(u)\n",
    );

    // An empty PATH is the cheapest honest way to make `python3` absent.
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let mut cmd = Command::new(&bin);
    cmd.arg("doctor")
        .arg(&repo)
        .env("HOME", &home)
        .env("PATH", &empty)
        .env("RVLSCAN_CACHE_DIR", home.join("cache"))
        .env("RVLSCAN_OFFLINE", "1");
    let stdout = String::from_utf8(run(&mut cmd).stdout).unwrap();

    let go_row = stdout
        .lines()
        .find(|l| l.contains("Go (goindex)"))
        .unwrap_or_default();
    assert!(
        go_row.trim_start().starts_with("PASS"),
        "the Go lane needs no interpreter, so it must survive: {go_row}"
    );
    let py_row = stdout
        .lines()
        .find(|l| l.contains("Python (pyindex)"))
        .unwrap_or_default();
    assert!(
        py_row.trim_start().starts_with("FAIL") && py_row.contains("python3"),
        "the Python lane must name the runtime that is missing: {py_row}"
    );
}

/// `--fix` closes what it can without sudo, announces each action, and a
/// second run does nothing at all.
#[test]
fn fix_extracts_the_embedded_helpers_and_then_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));

    // No C#: the csindex build is a minute of dotnet and is exercised by its
    // printed-command path instead.
    let repo = dir.path().join("repo");
    write(&repo.join("pyproject.toml"), "[project]\nname = \"svc\"\n");
    write(
        &repo.join("svc.py"),
        "import requests\n\n\ndef f(u):\n    return requests.get(u)\n",
    );
    write(&repo.join("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>s</groupId><artifactId>s</artifactId><version>1</version></project>\n");
    write(&repo.join("Svc.java"), "public class Svc { }\n");

    let first = doctor(&bin, &repo, &home, &["--fix"]);
    let announced = String::from_utf8(first.stderr).unwrap();
    for script in ["pyindex.py", "javaindex.java"] {
        assert!(
            announced.contains(script),
            "every action must be announced before it runs: {announced}"
        );
    }
    let helper_dir = home
        .join(".revelara")
        .join("helpers")
        .join(env!("CARGO_PKG_VERSION"));
    for script in ["pyindex.py", "javaindex.java"] {
        assert!(
            helper_dir.join(script).is_file(),
            "--fix must materialize {script}"
        );
    }

    let second = doctor(&bin, &repo, &home, &["--fix"]);
    let again = String::from_utf8(second.stderr).unwrap();
    assert!(
        again.contains("nothing to repair"),
        "re-running --fix on a repaired machine must be a clean no-op: {again}"
    );
    assert!(
        !again.contains("extracted"),
        "--fix must not rewrite helpers that are already correct: {again}"
    );
}

/// Offline, `--fix` refuses to reach the network and PRINTS the command
/// instead — the same discipline as anything needing sudo.
#[test]
fn fix_prints_rather_than_runs_what_it_may_not_do() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = dir.path().join("repo");
    write(&repo.join("tsconfig.json"), "{\"compilerOptions\":{}}\n");
    write(
        &repo.join("svc.ts"),
        "export const f = (u: string) => fetch(u);\n",
    );

    let out = doctor(&bin, &repo, &home, &["--fix"]);
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("RVLSCAN_OFFLINE=1"),
        "the refusal must say why: {stderr}"
    );
    // The pinned install is printed verbatim, pin included: a bare
    // `npm install typescript` resolves to the 7.x native port, which crashes
    // tsindex mid-run.
    assert!(
        stderr.contains("typescript@^5.9.3") || stderr.contains("nothing to repair"),
        "the PINNED command must be printed when it cannot be run: {stderr}"
    );
}

#[test]
fn an_unknown_format_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let bin = lone_binary(&dir.path().join("bin"));
    let repo = dir.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let out = doctor(&bin, &repo, &home, &["--format", "yaml"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "unknown --format must be exit 2"
    );
}

#[test]
fn json_output_is_parseable_and_carries_the_slots() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    write(&bin_dir.join("goindex"), "#!/bin/sh\nexit 0\n");
    let repo = dir.path().join("repo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");

    let out = doctor(&bin, &repo, &home, &["--format", "json"]);
    let doc: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.stdout).unwrap()).expect("stdout must be JSON");
    let checks = doc["checks"].as_array().expect("checks array");
    let go = checks
        .iter()
        .find(|c| c["label"].as_str().unwrap_or("").contains("goindex"))
        .expect("the Go lane must be reported");
    assert_eq!(go["status"], "PASS");
    assert!(
        go["detail"].as_str().unwrap().contains("bundled"),
        "the slot must survive into JSON: {go}"
    );
}
