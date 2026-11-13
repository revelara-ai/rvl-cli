//! The one place a live test may skip (po-av01j.99).
//!
//! A golden or end-to-end test that drives a real engine (libclang, node and
//! `typescript`, a JDK, rust-analyzer, the Go toolchain, ...) cannot run on a
//! machine without that engine, so on a developer workstation it prints a
//! `SKIP` line and returns. In CI that same return is a lane nobody tested
//! reading as green: building `cindex` was once taken as proof that the C/C++
//! lane ran, while libclang, which it loads at process start, was not
//! installed anywhere on the runner.
//!
//! So every skip goes through [`skip`], and CI exports
//! `RVLSCAN_REQUIRE_ENGINES=1`, which turns each one into a failure that names
//! the missing engine. `tests/skip_contract.rs` holds the suite to this: a
//! test that prints its own `SKIP` line fails the build.

use std::ffi::OsStr;
use std::fmt::Display;
use std::path::{Path, PathBuf};

/// Set (to anything but empty or `0`) where every engine is provisioned, so a
/// test that cannot reach its engine fails instead of skipping. CI sets it.
pub const REQUIRE_ENGINES_ENV: &str = "RVLSCAN_REQUIRE_ENGINES";

/// Whether a value of [`REQUIRE_ENGINES_ENV`] forbids skipping. Split from the
/// environment read so the rule is testable without mutating the process.
pub fn requires(value: Option<&OsStr>) -> bool {
    matches!(value, Some(v) if !v.is_empty() && v != "0")
}

/// True when this process may not skip a test for a missing engine.
pub fn engines_required() -> bool {
    requires(std::env::var_os(REQUIRE_ENGINES_ENV).as_deref())
}

/// Record that `test` cannot run because of `why`. Prints a `SKIP` line and
/// returns, so the caller can return early; panics instead when engines are
/// required, so the test fails with the reason.
#[track_caller]
pub fn skip(test: &str, why: impl Display) {
    if engines_required() {
        panic!(
            "{test}: {why}. {REQUIRE_ENGINES_ENV} is set, so a test that cannot reach its \
             engine fails instead of skipping: provision the engine on this runner"
        );
    }
    eprintln!("SKIP {test}: {why}");
}

/// The profile directory (`target/<profile>`) above this test executable,
/// where cargo puts every workspace bin and CI lays out the engine bundles.
/// Cargo before 1.100 runs a test from `target/<profile>/deps/<test>`; from
/// 1.100 on, from `target/<profile>/build/<package>/<hash>/out/<test>`.
pub fn profile_dir() -> PathBuf {
    profile_dir_of(&std::env::current_exe().expect("test executable path"))
}

fn profile_dir_of(exe: &Path) -> PathBuf {
    exe.ancestors()
        .find(|dir| {
            matches!(
                dir.file_name().and_then(OsStr::to_str),
                Some("deps" | "build")
            )
        })
        .and_then(Path::parent)
        .unwrap_or_else(|| {
            panic!(
                "{} is under no target/<profile>/deps or build",
                exe.display()
            )
        })
        .to_path_buf()
}

/// Write `body` to `path` as an executable that may be run at once, even
/// while other threads of this test process are spawning children.
///
/// A file this process writes is open for writing while it is written, and a
/// child forked by another thread in that window holds the write descriptor
/// until its own exec. The kernel refuses to exec a file that anyone holds
/// open for writing, so running it fails with "Text file busy". Renaming does
/// not help on its own: the inherited descriptor follows the inode, not the
/// name. So the bytes are written by a `/bin/sh` child, whose descriptor no
/// fork of ours can inherit, under a temporary name; this process then sets
/// the mode and renames it into place, so `path` never exists half-written
/// or without its execute bit.
///
/// `body` travels as an argument, which bounds it at the kernel's per-argument
/// limit (128 KiB on Linux): ample for a test stub, not for a binary.
#[cfg(unix)]
pub fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let name = path.file_name().expect("an executable needs a file name");
    let tmp = path.with_file_name(format!(".{}.partial", name.to_string_lossy()));
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", r#"printf '%s' "$2" > "$1""#, "write_executable"])
        .arg(&tmp)
        .arg(body)
        .stdin(std::process::Stdio::null())
        .status()
        .unwrap_or_else(|e| panic!("writing {}: /bin/sh did not start: {e}", tmp.display()));
    assert!(
        status.success(),
        "writing {}: /bin/sh {status}",
        tmp.display()
    );
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", tmp.display()));
    std::fs::rename(&tmp, path)
        .unwrap_or_else(|e| panic!("rename {} to {}: {e}", tmp.display(), path.display()));
}

/// Without execute bits there is nothing to race: write the file.
#[cfg(not(unix))]
pub fn write_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_empty_or_zero_switch_allows_a_skip() {
        assert!(!requires(None));
        assert!(!requires(Some(OsStr::new(""))));
        assert!(!requires(Some(OsStr::new("0"))));
    }

    #[test]
    fn any_other_value_forbids_a_skip() {
        assert!(requires(Some(OsStr::new("1"))));
        assert!(requires(Some(OsStr::new("true"))));
    }

    #[test]
    fn the_profile_dir_is_found_in_both_cargo_test_layouts() {
        let want = Path::new("/w/target/debug");
        assert_eq!(
            profile_dir_of(Path::new("/w/target/debug/deps/golden-ab12")),
            want
        );
        assert_eq!(
            profile_dir_of(Path::new(
                "/w/target/debug/build/cindex/ab12/out/golden-ab12"
            )),
            want
        );
    }
}
