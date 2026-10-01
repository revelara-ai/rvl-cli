//! A HELPER THAT IS NOT THE ONE THIS BINARY SHIPS MUST SAY SO (po-8ozxg).
//!
//! po-vd7ii made stale-helper drift DIAGNOSABLE: the "retrievers:" roll-call
//! names the file that ran and where resolution found it. A reader still had
//! to know that a path under ~/.local/bin was a week older than the binary
//! beside it. This makes the drift SELF-ANNOUNCING: when the helper that ran
//! is not the copy this rvl ships and both exist, the scan compares their
//! content versions and warns.
//!
//! WARN ONLY. A different helper is often deliberate (someone developing
//! pyindex points `RVL_PYINDEX` at their checkout), so the scan runs it, says
//! what it ran, and exits as it would have.

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

fn combined(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The pyindex source this build of rvl embeds.
fn shipped_pyindex() -> String {
    let p = manifest_dir().join("../../helpers/pyindex/pyindex.py");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()))
}

fn python3_present() -> bool {
    Command::new("python3").arg("--version").output().is_ok()
}

/// A one-file Python repo and a scan of it with `RVL_PYINDEX` pointed at
/// `helper`.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("app.py"), "def add(a, b):\n    return a + b\n").unwrap();
        std::fs::write(dir.path().join("specs.json"), r#"{"apis":[],"configs":[]}"#).unwrap();
        Fixture { dir }
    }

    fn write_helper(&self, name: &str, body: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        p
    }

    fn scan(&self, helper: &Path) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_rvl"))
            .current_dir(self.dir.path().join("repo"))
            .env("HOME", self.dir.path().join("home"))
            .env("RVL_CACHE_DIR", self.dir.path().join("cache"))
            .env("RVL_INDEX_DIR", self.dir.path().join("index"))
            .env("RVL_OFFLINE", "1")
            .env("RVL_PYINDEX", helper)
            .args(["scan", ".", "--specs-file"])
            .arg(self.dir.path().join("specs.json"))
            .output()
            .unwrap()
    }
}

#[test]
fn a_helper_that_differs_from_the_shipped_copy_is_named_as_drift() {
    if !python3_present() {
        eprintln!("skipping: no python3 on this machine");
        return;
    }
    let f = Fixture::new();
    // One trailing comment: the same retriever, a different file.
    let helper = f.write_helper(
        "pyindex.py",
        &format!("{}\n# a local edit\n", shipped_pyindex()),
    );
    let out = f.scan(&helper);
    let all = combined(&out);
    assert!(
        all.contains("helper drift"),
        "a pyindex that is not the shipped one must be announced:\n{all}"
    );
    let drift_line = all
        .lines()
        .find(|l| l.contains("helper drift"))
        .unwrap_or_default();
    assert!(
        drift_line.contains("Python") && drift_line.contains(&helper.display().to_string()),
        "the warning must name the language and the file that ran:\n{all}"
    );
    assert!(
        drift_line.contains("differs from"),
        "two known versions that disagree are a difference, not an age:\n{all}"
    );
}

#[test]
fn an_identical_copy_of_the_shipped_helper_is_not_drift() {
    if !python3_present() {
        eprintln!("skipping: no python3 on this machine");
        return;
    }
    let f = Fixture::new();
    let helper = f.write_helper("pyindex.py", &shipped_pyindex());
    let out = f.scan(&helper);
    let all = combined(&out);
    assert!(
        all.contains("retrievers:"),
        "the scan must have run:\n{all}"
    );
    assert!(
        !all.contains("helper drift"),
        "the same bytes at another path are the same helper:\n{all}"
    );
}

/// Every helper built before this bead answers `--packet-schema` with the
/// schema integer alone. Beside a shipped copy that does carry a version, that
/// silence is the drift: the helper is older than the handshake.
#[cfg(unix)]
#[test]
fn a_helper_that_predates_the_handshake_is_named_as_older() {
    let f = Fixture::new();
    let helper = f.write_helper(
        "pyindex-old",
        "#!/bin/sh\n\
         case \"$*\" in *--packet-schema*) echo 2; exit 0;; esac\n\
         echo '{\"packet_schema\":2,\"kind\":\"retrieval_stats\",\"snapshot_id\":\"x\",\
         \"lang\":\"python\",\"files_total\":1,\"files_parsed\":1,\"files_failed\":0,\"sites\":0}'\n",
    );
    let out = f.scan(&helper);
    let all = combined(&out);
    let drift_line = all
        .lines()
        .find(|l| l.contains("helper drift"))
        .unwrap_or_else(|| panic!("a version-less helper beside a shipped one is drift:\n{all}"));
    assert!(drift_line.contains("reports no content version"), "{all}");
}

/// A NATIVE helper has no source file for rvl to hash, so it is asked. The
/// stub here answers with the version the shipped pyindex reports about
/// itself, which also pins the two halves of the contract together: what the
/// script says and what rvl computes for the copy it embeds are one number.
#[cfg(unix)]
#[test]
fn a_native_helper_that_reports_the_shipped_version_is_not_drift() {
    if !python3_present() {
        eprintln!("skipping: no python3 on this machine");
        return;
    }
    let reply = Command::new("python3")
        .arg(manifest_dir().join("../../helpers/pyindex/pyindex.py"))
        .arg("--packet-schema")
        .output()
        .unwrap();
    let reply = String::from_utf8(reply.stdout).unwrap();
    assert!(
        reply
            .lines()
            .nth(1)
            .unwrap_or_default()
            .starts_with("content-version "),
        "pyindex must answer the handshake: {reply:?}"
    );
    let f = Fixture::new();
    let helper = f.write_helper(
        "pyindex-native",
        &format!(
            "#!/bin/sh\n\
             case \"$*\" in *--packet-schema*) printf '%s' '{reply}'; exit 0;; esac\n\
             echo '{{\"packet_schema\":2,\"kind\":\"retrieval_stats\",\"snapshot_id\":\"x\",\
             \"lang\":\"python\",\"files_total\":1,\"files_parsed\":1,\"files_failed\":0,\"sites\":0}}'\n"
        ),
    );
    let out = f.scan(&helper);
    let all = combined(&out);
    assert!(
        all.contains("retrievers:"),
        "the scan must have run:\n{all}"
    );
    assert!(
        !all.contains("helper drift"),
        "a helper reporting the shipped version is the shipped helper:\n{all}"
    );
}
