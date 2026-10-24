//! Which ONNX Runtime library the model lane loads, and how.
//!
//! A RELEASE archive ships a pinned, checksummed ONNX Runtime beside `rvl`
//! (see `onnxruntime.pin` and `ci/fetch-onnxruntime.sh`), so model verdicts do
//! not depend on whatever runtime the scanning machine has. The order is the
//! one `cindex` uses for libclang:
//!
//! 1. `RVL_ONNXRUNTIME`: an explicit operator override (the library file, or
//!    the directory holding it), honored as-is.
//! 2. The vendored bundle, `<dir of the real rvl>/onnxruntime/`. The exe path
//!    is canonicalized first, because Homebrew runs `rvl` through a symlink in
//!    its `bin` and the bundle sits beside the Caskroom original.
//! 3. The system loader's search for the library name (dev builds only). A
//!    binary built with `RVL_REQUIRE_VENDORED_ONNXRUNTIME` set (release CI
//!    sets it) refuses this step and fails closed.
//!
//! The library is loaded once per process: ONNX Runtime keeps one global API
//! table, so a second, different path is an error rather than a silent reuse.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context as _, Result};

/// The operator override: the library, or a directory holding [`LIB_NAME`].
pub const OVERRIDE_ENV: &str = "RVL_ONNXRUNTIME";

/// The bundle directory, beside the `rvl` executable.
pub const BUNDLE_DIR: &str = "onnxruntime";

/// The library file inside the bundle. Matches the member basename the pin
/// names for each target (tests/onnxruntime_pin.rs holds the two together).
pub const LIB_NAME: &str = if cfg!(target_os = "macos") {
    "libonnxruntime.dylib"
} else if cfg!(windows) {
    "onnxruntime.dll"
} else {
    "libonnxruntime.so"
};

/// Set at BUILD time by release CI. A binary built with it never falls back
/// to the system search.
pub const REQUIRE_VENDORED: bool = option_env!("RVL_REQUIRE_VENDORED_ONNXRUNTIME").is_some();

/// Where the runtime comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// `RVL_ONNXRUNTIME` names the library (or its directory).
    Override(PathBuf),
    /// The pinned bundle shipped beside `rvl`.
    Vendored(PathBuf),
    /// Whatever the system loader finds for [`LIB_NAME`] (dev builds only).
    System,
}

impl Source {
    /// The path handed to the loader.
    pub fn lib(&self) -> PathBuf {
        match self {
            Source::Override(p) if p.is_dir() => p.join(LIB_NAME),
            Source::Override(p) | Source::Vendored(p) => p.clone(),
            Source::System => PathBuf::from(LIB_NAME),
        }
    }

    /// A short tag for a doctor or a coverage line: which runtime loaded.
    pub fn describe(&self) -> String {
        match self {
            Source::Override(p) => format!("{OVERRIDE_ENV} {}", p.display()),
            Source::Vendored(p) => format!("vendored {}", p.display()),
            Source::System => format!("system {LIB_NAME}"),
        }
    }
}

/// Decide the runtime source. Pure apart from reading the filesystem, so the
/// order is unit-testable: `override_path` is the `RVL_ONNXRUNTIME` value,
/// `exe` the running executable, `require_vendored` normally
/// [`REQUIRE_VENDORED`].
pub fn resolve(
    override_path: Option<&OsStr>,
    exe: Option<&Path>,
    require_vendored: bool,
) -> Result<Source> {
    if let Some(p) = override_path.filter(|p| !p.is_empty()) {
        return Ok(Source::Override(PathBuf::from(p)));
    }
    let bundle = exe
        .and_then(|e| e.canonicalize().ok())
        .and_then(|e| e.parent().map(|d| d.join(BUNDLE_DIR)));
    if let Some(bundle) = &bundle {
        let lib = bundle.join(LIB_NAME);
        if lib.is_file() {
            return Ok(Source::Vendored(lib));
        }
        // A bundle directory without its library is a broken install, not a
        // reason to quietly infer with a different runtime.
        if bundle.is_dir() {
            bail!(
                "the vendored ONNX Runtime bundle at {} has no {LIB_NAME}; reinstall rvl, or \
                 point {OVERRIDE_ENV} at an ONNX Runtime library",
                bundle.display()
            );
        }
    }
    if require_vendored {
        let at = bundle
            .map(|b| b.display().to_string())
            .unwrap_or_else(|| format!("<dir of rvl>/{BUNDLE_DIR}"));
        bail!(
            "this release build of rvl ships a pinned ONNX Runtime at {at}, and it is missing; \
             reinstall rvl, or point {OVERRIDE_ENV} at an ONNX Runtime library to override the pin"
        );
    }
    Ok(Source::System)
}

/// Resolve from this process's environment and executable.
pub fn resolve_from_env() -> Result<Source> {
    let exe = std::env::current_exe().ok();
    resolve(
        std::env::var_os(OVERRIDE_ENV).as_deref(),
        exe.as_deref(),
        REQUIRE_VENDORED,
    )
}

/// The loaded runtime: the library path and the environment sessions are
/// built in.
pub struct Runtime {
    pub lib: PathBuf,
    pub(crate) env: ort::environment::Environment,
}

static LOADED: OnceLock<Runtime> = OnceLock::new();

/// Load the runtime from `source` once for the process and return it. A later
/// call with the same library returns the loaded one; a different library
/// is an error, because ONNX Runtime cannot be loaded twice.
pub fn load(source: &Source) -> Result<&'static Runtime> {
    let lib = source.lib();
    if let Some(rt) = LOADED.get() {
        if rt.lib != lib {
            bail!(
                "ONNX Runtime is already loaded from {}; cannot also load {}",
                rt.lib.display(),
                lib.display()
            );
        }
        return Ok(rt);
    }
    let env = ort::init_from(&lib)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("load ONNX Runtime ({})", source.describe()))?
        .with_name("rvl")
        .build()
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("create the ONNX Runtime environment")?;
    // Another thread may have won the race; its runtime is the one in use.
    let rt = LOADED.get_or_init(|| Runtime {
        lib: lib.clone(),
        env,
    });
    if rt.lib != lib {
        bail!(
            "ONNX Runtime is already loaded from {}; cannot also load {}",
            rt.lib.display(),
            lib.display()
        );
    }
    Ok(rt)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake install: `<tmp>/bin/rvl`, optionally with a bundle beside it.
    fn install(bundle: bool, lib: bool) -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("rvl");
        std::fs::write(&exe, b"").unwrap();
        if bundle {
            std::fs::create_dir_all(bin.join(BUNDLE_DIR)).unwrap();
        }
        if lib {
            std::fs::write(bin.join(BUNDLE_DIR).join(LIB_NAME), b"").unwrap();
        }
        (tmp, exe)
    }

    fn bundled_lib(exe: &Path) -> PathBuf {
        let dir = exe.canonicalize().unwrap();
        dir.parent().unwrap().join(BUNDLE_DIR).join(LIB_NAME)
    }

    #[test]
    fn the_override_wins_even_over_a_vendored_bundle() {
        let (_t, exe) = install(true, true);
        let got = resolve(Some(OsStr::new("/opt/ort/lib")), Some(&exe), true).unwrap();
        assert_eq!(got, Source::Override(PathBuf::from("/opt/ort/lib")));
    }

    #[test]
    fn an_override_naming_a_directory_loads_the_library_in_it() {
        let tmp = tempfile::tempdir().unwrap();
        let got = Source::Override(tmp.path().to_path_buf());
        assert_eq!(got.lib(), tmp.path().join(LIB_NAME));
    }

    #[test]
    fn an_empty_override_is_not_an_override() {
        let (_t, exe) = install(false, false);
        let got = resolve(Some(OsStr::new("")), Some(&exe), false).unwrap();
        assert_eq!(got, Source::System);
    }

    #[test]
    fn the_bundle_beside_the_exe_wins_over_the_system_search() {
        let (_t, exe) = install(true, true);
        let got = resolve(None, Some(&exe), false).unwrap();
        assert_eq!(got, Source::Vendored(bundled_lib(&exe)));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_exe_finds_the_bundle_beside_its_target() {
        let (t, exe) = install(true, true);
        let link_dir = t.path().join("brew-bin");
        std::fs::create_dir_all(&link_dir).unwrap();
        let link = link_dir.join("rvl");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let got = resolve(None, Some(&link), true).unwrap();
        assert_eq!(got, Source::Vendored(bundled_lib(&exe)));
    }

    #[test]
    fn a_bundle_without_its_library_fails_closed() {
        let (_t, exe) = install(true, false);
        let err = resolve(None, Some(&exe), false).unwrap_err().to_string();
        assert!(err.contains("has no"), "{err}");
    }

    #[test]
    fn a_release_build_never_falls_back_to_the_system_runtime() {
        let (_t, exe) = install(false, false);
        let err = resolve(None, Some(&exe), true).unwrap_err().to_string();
        assert!(err.contains("pinned ONNX Runtime"), "{err}");
        assert!(err.contains(OVERRIDE_ENV), "{err}");
    }

    #[test]
    fn a_dev_build_without_a_bundle_uses_the_system_search() {
        let (_t, exe) = install(false, false);
        let got = resolve(None, Some(&exe), false).unwrap();
        assert_eq!(got, Source::System);
        assert_eq!(got.lib(), PathBuf::from(LIB_NAME));
    }
}
