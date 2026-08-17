//! `rvl doctor [--fix]` end to end (po-av01j.169).
//!
//! Every test runs a COPY of the binary in an otherwise empty directory with
//! HOME pointed at a tempdir, for the same reason `fresh_install.rs` does: the
//! developer machine that runs this suite has `make helpers` output sitting
//! next to `target/debug/rvl` and a populated `~/.revelara`, either of
//! which would make a doctor test pass without the feature existing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The doctor's "a gap remains" code. Reuses the binary's existing contract:
/// 1 already means "the scan could not complete".
const EXIT_GAP: i32 = 1;

fn lone_binary(bin_dir: &Path) -> PathBuf {
    std::fs::create_dir_all(bin_dir).unwrap();
    let dest = bin_dir.join("rvl");
    std::fs::copy(env!("CARGO_BIN_EXE_rvl"), &dest).expect("copying the scanner binary");
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
            Err(e) => panic!("failed to run rvl: {e:?}"),
        }
    }
    panic!("rvl stayed ETXTBSY for a second")
}

/// A doctor invocation with NOTHING pre-arranged: empty HOME, empty cache,
/// no helper overrides, offline so no repair can reach the network.
fn doctor(bin: &Path, repo: &Path, home: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(bin);
    cmd.arg("doctor")
        .arg(repo)
        .args(args)
        .env("HOME", home)
        .env("RVL_CACHE_DIR", home.join("cache"))
        .env("RVL_OFFLINE", "1");
    for var in [
        "RVL_GOINDEX",
        "RVL_PYINDEX",
        "RVL_RUSTINDEX",
        "RVL_TSINDEX",
        "RVL_CSINDEX",
        "RVL_JAVAINDEX",
        "RVL_CINDEX",
        "RVL_HELPER_DIR",
        "RVL_API_KEY",
        "RVL_API_URL",
        "RVL_SRC",
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

/// Like [`write`], and executable: for stubs the doctor will actually RUN
/// (the cindex `--engine-check` probe), not merely resolve.
fn write_exec(path: &Path, body: &str) {
    write(path, body);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
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
    // never "and now export RVL_CSINDEX".
    assert!(
        stdout.contains("csindex") && stdout.contains("dotnet"),
        "the C# gap must name the dotnet build: {stdout}"
    );
    assert!(
        !stdout.contains("RVL_CSINDEX"),
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

/// A doctor invocation whose PATH we control completely, so a tool can be
/// present or absent by choice rather than by luck of the test machine.
fn doctor_with_path(bin: &Path, repo: &Path, home: &Path, path: &Path) -> std::process::Output {
    let mut cmd = Command::new(bin);
    cmd.arg("doctor")
        .arg(repo)
        .env("HOME", home)
        .env("PATH", path)
        .env("RVL_CACHE_DIR", home.join("cache"))
        .env("RVL_OFFLINE", "1");
    for var in ["RVL_RUST_ANALYZER", "RVL_HELPER_DIR", "RVL_SRC"] {
        cmd.env_remove(var);
    }
    run(&mut cmd)
}

fn row<'a>(stdout: &'a str, needle: &str) -> &'a str {
    stdout
        .lines()
        .find(|l| l.contains(needle))
        .unwrap_or_default()
}

/// The fix line printed under a non-passing row, or "".
fn fix_under<'a>(stdout: &'a str, needle: &str) -> &'a str {
    let mut lines = stdout.lines();
    while let Some(l) = lines.next() {
        if l.contains(needle) {
            let next = lines.next().unwrap_or_default();
            if next.trim_start().starts_with("fix:") {
                return next;
            }
            return "";
        }
    }
    ""
}

/// A lane whose runtime prereq is genuinely absent degrades THAT lane and
/// says why. The others are untouched — a polyglot repo missing one toolchain
/// still has the rest worth reading. Since po-av01j.206 the Go lane is probed
/// too (goindex shells the `go` tool), so the sandbox PATH carries `go` and
/// nothing else: Go survives on its own merits, Python fails on its own.
#[test]
fn a_missing_runtime_degrades_only_its_own_lane() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    write(&bin_dir.join("goindex"), "#!/bin/sh\nexit 0\n");

    let repo = dir.path().join("repo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");
    write(&repo.join("pyproject.toml"), "[project]\nname = \"svc\"\n");
    write(
        &repo.join("svc.py"),
        "import requests\n\n\ndef f(u):\n    return requests.get(u)\n",
    );

    // A closed PATH carrying only `go`: python3 is absent by construction.
    let toolbin = dir.path().join("toolbin");
    std::fs::create_dir_all(&toolbin).unwrap();
    let real_go = which("go");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real_go, toolbin.join("go")).unwrap();
    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &toolbin).stdout).unwrap();

    let go_row = row(&stdout, "Go (goindex)");
    assert!(
        go_row.trim_start().starts_with("PASS") && go_row.contains("drives `go`"),
        "the Go lane has its toolchain, so it must survive AND say what it probed: {go_row}"
    );
    let py_row = row(&stdout, "Python (pyindex)");
    assert!(
        py_row.trim_start().starts_with("FAIL") && py_row.contains("python3"),
        "the Python lane must name the runtime that is missing: {py_row}"
    );
}

/// First match for `name` on the CURRENT process PATH; panics with the reason
/// when the test machine cannot provide it.
fn which(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(name))
                .find(|c| c.is_file())
        })
        .unwrap_or_else(|| panic!("this test machine has no `{name}`"))
}

/// po-av01j.209's doctor half: `runtime_for(Executable) → None` used to
/// short-circuit the Go lane to "PASS ... native — no runtime prereq" while
/// the scan's goindex exited 2 for want of the `go` tool. The doctor verdict
/// must AGREE with what a scan does: no `go`, no PASS — and the gap carries
/// its install line, exactly like a missing python3.
#[test]
fn a_go_repo_without_the_go_tool_is_a_gap_not_a_pass() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    write(&bin_dir.join("goindex"), "#!/bin/sh\nexit 0\n");
    let repo = dir.path().join("repo");
    write(&repo.join("go.mod"), "module svc\n\ngo 1.21\n");
    write(&repo.join("main.go"), "package main\n\nfunc main() {}\n");
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &empty).stdout).unwrap();
    let go_row = row(&stdout, "Go (goindex)");
    assert!(
        go_row.trim_start().starts_with("FAIL") && go_row.contains("`go` is not installed"),
        "doctor must probe the tool the scan will shell: {go_row}"
    );
    assert!(
        fix_under(&stdout, "Go (goindex)").contains("install go"),
        "and the gap must carry its install line:\n{stdout}"
    );
    assert!(
        !stdout.contains("no runtime prereq"),
        "the false claim po-av01j.206 deletes must be gone everywhere:\n{stdout}"
    );
}

/// po-av01j.206, the Rust lane: rustindex needs rust-analyzer AND a loadable
/// cargo workspace, and doctor never probed either. Absent both, the lane
/// reports two named gaps with their commands; with both present (presence is
/// the probe — a full `cargo metadata` load per repo is too expensive), the
/// lane passes and says what it found.
#[test]
fn the_rust_lane_probes_rust_analyzer_and_cargo() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    write(&bin_dir.join("rustindex"), "#!/bin/sh\nexit 0\n");
    let repo = dir.path().join("repo");
    write(
        &repo.join("Cargo.toml"),
        "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n",
    );
    write(&repo.join("src/main.rs"), "fn main() {}\n");

    // Machine-shape 1: neither tool anywhere.
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &empty).stdout).unwrap();
    let ra_row = row(&stdout, "Rust (rustindex)");
    assert!(
        ra_row.trim_start().starts_with("FAIL") && ra_row.contains("rust-analyzer"),
        "the missing engine must be named: {ra_row}"
    );
    assert!(
        fix_under(&stdout, "Rust (rustindex)").contains("rustup component add rust-analyzer"),
        "the fix line must be the scan error's own command:\n{stdout}"
    );
    let cargo_row = row(&stdout, "Rust workspace (cargo)");
    assert!(
        cargo_row.trim_start().starts_with("FAIL") && cargo_row.contains("cargo metadata"),
        "the workspace prerequisite must be probed too: {cargo_row}"
    );

    // Machine-shape 2: both present (dummy files are enough — the probe is
    // presence, deliberately not an execution).
    let toolbin = dir.path().join("toolbin");
    std::fs::create_dir_all(&toolbin).unwrap();
    write(&toolbin.join("rust-analyzer"), "#!/bin/sh\nexit 0\n");
    write(&toolbin.join("cargo"), "#!/bin/sh\nexit 0\n");
    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &toolbin).stdout).unwrap();
    let ra_row = row(&stdout, "Rust (rustindex)");
    assert!(
        ra_row.trim_start().starts_with("PASS") && ra_row.contains("rust-analyzer at"),
        "a healthy machine still passes, naming what it found: {ra_row}"
    );
    assert!(
        row(&stdout, "Rust workspace (cargo)").is_empty(),
        "no cargo gap row on a machine that has cargo:\n{stdout}"
    );
}

/// po-av01j.206, the C/C++ lane: cindex dlopens libclang at process start
/// (clang-sys `runtime` feature — libclang is NOT linked), so "native binary
/// present" proves nothing. The probe shells the helper's own
/// `--engine-check` rather than reimplementing libclang discovery; a failing
/// engine is a gap carrying the helper's own message and the install line,
/// and a loading engine passes with the clang version.
#[test]
fn the_c_lane_probes_libclang_through_engine_check() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin_dir = dir.path().join("bin");
    let bin = lone_binary(&bin_dir);
    let repo = dir.path().join("repo");
    write(&repo.join("main.c"), "int main(void) { return 0; }\n");
    let empty = dir.path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    // Machine-shape: the engine cannot load. The stub prints the same message
    // the real cindex --engine-check does.
    write_exec(
        &bin_dir.join("cindex"),
        "#!/bin/sh\nif [ \"$1\" = \"--engine-check\" ]; then\n\
         echo 'cindex requires libclang (engine pin po-ae75b.9) and none could be loaded' >&2\n\
         exit 1\nfi\nexit 0\n",
    );
    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &empty).stdout).unwrap();
    let c_row = row(&stdout, "C/C++ (cindex)");
    assert!(
        c_row.trim_start().starts_with("FAIL") && c_row.contains("libclang"),
        "a broken engine must be a named gap: {c_row}"
    );
    assert!(
        fix_under(&stdout, "C/C++ (cindex)").contains("LIBCLANG_PATH"),
        "and carry the install line:\n{stdout}"
    );

    // Machine-shape: the engine loads.
    write_exec(
        &bin_dir.join("cindex"),
        "#!/bin/sh\nif [ \"$1\" = \"--engine-check\" ]; then\n\
         echo 'clang version 17.0.6'\nexit 0\nfi\nexit 0\n",
    );
    let stdout = String::from_utf8(doctor_with_path(&bin, &repo, &home, &empty).stdout).unwrap();
    let c_row = row(&stdout, "C/C++ (cindex)");
    assert!(
        c_row.trim_start().starts_with("PASS") && c_row.contains("clang version 17.0.6"),
        "a loading engine passes with its version: {c_row}"
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
        stderr.contains("RVL_OFFLINE=1"),
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
