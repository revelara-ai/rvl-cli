//! Which libclang the helper loads, and how (po-av01j.49).
//!
//! A RELEASE archive ships a pinned, checksummed libclang beside `cindex`
//! (see `libclang.pin` and `ci/fetch-libclang.sh`), so scan results do not
//! depend on whatever clang the scanning machine happens to have. The
//! resolution order is:
//!
//! 1. `LIBCLANG_PATH`: an explicit operator override, honored as-is.
//! 2. The vendored bundle, `<dir of the real cindex>/libclang/`. The exe path
//!    is canonicalized first, because Homebrew runs `cindex` through a
//!    symlink in its `bin` and the bundle sits beside the Caskroom original.
//! 3. The system search `clang-sys` does. A binary built with
//!    `CINDEX_REQUIRE_VENDORED_LIBCLANG` set (release CI sets it) refuses this
//!    step and fails closed: a release that silently scans with a different
//!    clang is exactly the irreproducibility the pin exists to remove.
//!
//! The vendored library cannot locate its own builtin headers (`stddef.h`
//! and friends): it reports a RELATIVE resource dir. A missing builtin header
//! is a fatal diagnostic, yet the TU still comes back non-null and would be
//! counted as parsed. So on the vendored path every TU gets an explicit
//! `-resource-dir` pointing at the bundle's pinned headers.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The bundle directory, beside the `cindex` executable.
pub const BUNDLE_DIR: &str = "libclang";

/// The library file inside the bundle. Matches the member basename the pin
/// file names for each target (the parity test in tests/libclang_pin.rs
/// holds the two together).
pub const LIB_NAME: &str = if cfg!(target_os = "macos") {
    "libclang.dylib"
} else if cfg!(windows) {
    "libclang.dll"
} else {
    "libclang.so"
};

/// Set at BUILD time by release CI. A binary built with it never falls back
/// to the system search.
pub const REQUIRE_VENDORED: bool = option_env!("CINDEX_REQUIRE_VENDORED_LIBCLANG").is_some();

/// Where the engine comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `LIBCLANG_PATH` names the library (or its directory).
    Override(PathBuf),
    /// The pinned bundle shipped beside `cindex`.
    Vendored {
        lib: PathBuf,
        /// Passed to every TU as `-resource-dir`; holds `include/`.
        resource_dir: PathBuf,
    },
    /// Whatever `clang-sys` finds on this machine (dev builds only).
    System,
}

impl Source {
    /// Extra parse args every TU needs under this engine.
    pub fn parse_args(&self) -> Vec<String> {
        match self {
            Source::Vendored { resource_dir, .. } => vec![
                "-resource-dir".to_string(),
                resource_dir.to_string_lossy().into_owned(),
            ],
            _ => Vec::new(),
        }
    }

    /// A short tag for `--engine-check`, so a doctor shows which engine
    /// actually loaded.
    pub fn describe(&self) -> String {
        match self {
            Source::Override(p) => format!("LIBCLANG_PATH {}", p.display()),
            Source::Vendored { lib, .. } => format!("vendored {}", lib.display()),
            Source::System => "system".to_string(),
        }
    }
}

/// Decide the engine source. Pure apart from reading the filesystem, so the
/// order is unit-testable: `libclang_path` is the `LIBCLANG_PATH` value,
/// `exe` the running executable, `require_vendored` normally
/// [`REQUIRE_VENDORED`].
pub fn resolve(
    libclang_path: Option<&OsStr>,
    exe: Option<&Path>,
    require_vendored: bool,
) -> Result<Source, String> {
    if let Some(p) = libclang_path.filter(|p| !p.is_empty()) {
        return Ok(Source::Override(PathBuf::from(p)));
    }
    let bundle = exe
        .and_then(|e| e.canonicalize().ok())
        .and_then(|e| e.parent().map(|d| d.join(BUNDLE_DIR)));
    if let Some(bundle) = &bundle {
        let lib = bundle.join(LIB_NAME);
        let include = bundle.join("include");
        match (lib.is_file(), include.is_dir()) {
            (true, true) => {
                return Ok(Source::Vendored {
                    lib,
                    resource_dir: bundle.clone(),
                })
            }
            // Half a bundle is a broken install, not a reason to quietly scan
            // with a different clang.
            (true, false) | (false, true) => {
                return Err(format!(
                    "the vendored libclang bundle at {} is incomplete (needs {LIB_NAME} and \
                     include/); reinstall rvl, or point LIBCLANG_PATH at a libclang",
                    bundle.display()
                ))
            }
            (false, false) => {}
        }
    }
    if require_vendored {
        let at = bundle
            .map(|b| b.display().to_string())
            .unwrap_or_else(|| format!("<dir of cindex>/{BUNDLE_DIR}"));
        return Err(format!(
            "this release build of cindex ships a pinned libclang at {at}, and it is missing; \
             reinstall rvl, or point LIBCLANG_PATH at a libclang to override the pin"
        ));
    }
    Ok(Source::System)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake install: `<tmp>/bin/cindex`, optionally with a bundle beside it.
    fn install(lib: bool, include: bool) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("cindex");
        std::fs::write(&exe, b"").unwrap();
        let bundle = bin.join(BUNDLE_DIR);
        if lib {
            std::fs::create_dir_all(&bundle).unwrap();
            std::fs::write(bundle.join(LIB_NAME), b"").unwrap();
        }
        if include {
            std::fs::create_dir_all(bundle.join("include")).unwrap();
        }
        (tmp, exe)
    }

    #[test]
    fn libclang_path_overrides_even_a_vendored_bundle() {
        let (_t, exe) = install(true, true);
        let got = resolve(Some(OsStr::new("/opt/llvm/lib")), Some(&exe), true).unwrap();
        assert_eq!(got, Source::Override(PathBuf::from("/opt/llvm/lib")));
        assert!(got.parse_args().is_empty());
    }

    #[test]
    fn an_empty_libclang_path_is_not_an_override() {
        let (_t, exe) = install(false, false);
        assert_eq!(
            resolve(Some(OsStr::new("")), Some(&exe), false).unwrap(),
            Source::System
        );
    }

    #[test]
    fn the_bundle_beside_the_exe_wins_over_the_system_search() {
        let (_t, exe) = install(true, true);
        let got = resolve(None, Some(&exe), false).unwrap();
        let dir = exe
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .join(BUNDLE_DIR);
        assert_eq!(
            got,
            Source::Vendored {
                lib: dir.join(LIB_NAME),
                resource_dir: dir.clone(),
            }
        );
        assert_eq!(
            got.parse_args(),
            vec![
                "-resource-dir".to_string(),
                dir.to_string_lossy().into_owned()
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_exe_finds_the_bundle_beside_its_target() {
        // Homebrew links Caskroom/.../cindex into its bin; the bundle is
        // beside the original, never beside the link.
        let (t, exe) = install(true, true);
        let links = t.path().join("brew-bin");
        std::fs::create_dir_all(&links).unwrap();
        let link = links.join("cindex");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        match resolve(None, Some(&link), true).unwrap() {
            Source::Vendored { lib, .. } => {
                assert_eq!(
                    lib,
                    exe.canonicalize()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .join(BUNDLE_DIR)
                        .join(LIB_NAME)
                )
            }
            other => panic!("expected the vendored bundle, got {other:?}"),
        }
    }

    #[test]
    fn a_half_bundle_fails_closed() {
        for (lib, include) in [(true, false), (false, true)] {
            let (_t, exe) = install(lib, include);
            let err = resolve(None, Some(&exe), false).unwrap_err();
            assert!(err.contains("incomplete"), "{err}");
        }
    }

    #[test]
    fn no_bundle_is_the_system_search_in_a_dev_build() {
        let (_t, exe) = install(false, false);
        assert_eq!(resolve(None, Some(&exe), false).unwrap(), Source::System);
    }

    #[test]
    fn no_bundle_fails_closed_in_a_release_build() {
        let (_t, exe) = install(false, false);
        let err = resolve(None, Some(&exe), true).unwrap_err();
        assert!(err.contains("pinned libclang"), "{err}");
        assert!(err.contains(BUNDLE_DIR), "{err}");
    }

    #[test]
    fn a_release_build_still_honors_libclang_path() {
        let (_t, exe) = install(false, false);
        assert!(matches!(
            resolve(Some(OsStr::new("/x/libclang.so")), Some(&exe), true).unwrap(),
            Source::Override(_)
        ));
    }
}
