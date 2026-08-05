//! rust-analyzer discovery, pin verification, the workspace-load gate, and
//! the `scip` invocation (wayfinder po-ae75b.8, binding).
//!
//! Pinning: the engine is a PINNED release of rust-analyzer, distributed as
//! the rustup component matching the toolchain. Identity is enforced in
//! layers, all recorded into the stream's provenance record:
//! - version: compared against [`PINNED_VERSION`]; a mismatch warns (or fails
//!   under `RVLSCAN_RUSTINDEX_STRICT_PIN=1`) — the moniker fixture test is
//!   the behavioral canary for an upgrade that changes moniker shapes.
//! - checksum: when `RVLSCAN_RUST_ANALYZER_SHA256` is set, the binary's
//!   sha256 MUST match it (fail closed). The actual sha256 is always
//!   computed and recorded so any stream can be audited after the fact.

use anyhow::Context;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The pinned rust-analyzer release this helper is validated against
/// (rustup component of the pinned toolchain).
pub const PINNED_VERSION: &str = "1.96.0";

/// Env var overriding rust-analyzer discovery.
pub const ENV_RA_PATH: &str = "RVLSCAN_RUST_ANALYZER";
/// Env var carrying the expected sha256 of the rust-analyzer binary.
/// When set, a mismatch is fatal (fail closed).
pub const ENV_RA_SHA256: &str = "RVLSCAN_RUST_ANALYZER_SHA256";
/// Env var making a version-pin mismatch fatal instead of a warning.
pub const ENV_STRICT_PIN: &str = "RVLSCAN_RUSTINDEX_STRICT_PIN";

/// The discovered engine's identity, recorded into stream provenance.
#[derive(Debug, Clone)]
pub struct RaIdentity {
    pub path: PathBuf,
    /// Full `rust-analyzer --version` line.
    pub version_line: String,
    /// sha256 of the binary at `path`.
    pub sha256: String,
    /// Whether `version_line` carries [`PINNED_VERSION`].
    pub matches_pin: bool,
}

/// First matching file named `name` on `PATH`.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(name))
        .find(|cand| cand.is_file())
}

/// Locate rust-analyzer ([`ENV_RA_PATH`] override, then PATH), verify its
/// identity against the pin and optional checksum, and return it.
pub fn discover() -> anyhow::Result<RaIdentity> {
    let path = match std::env::var_os(ENV_RA_PATH) {
        Some(p) => {
            let p = PathBuf::from(p);
            anyhow::ensure!(
                p.is_file(),
                "{ENV_RA_PATH} points at {} which does not exist",
                p.display()
            );
            p
        }
        None => find_on_path("rust-analyzer").context(
            "no rust-analyzer found: set RVLSCAN_RUST_ANALYZER to the binary, or install the \
             rustup component (`rustup component add rust-analyzer`)",
        )?,
    };

    let out = Command::new(&path)
        .arg("--version")
        .output()
        .with_context(|| format!("running {} --version", path.display()))?;
    anyhow::ensure!(
        out.status.success(),
        "{} --version exited {}",
        path.display(),
        out.status
    );
    let version_line = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let bytes =
        std::fs::read(&path).with_context(|| format!("reading {} for checksum", path.display()))?;
    let sha256 = hex::encode(sha2::Sha256::digest(&bytes));

    if let Ok(expected) = std::env::var(ENV_RA_SHA256) {
        let expected = expected.trim().to_ascii_lowercase();
        anyhow::ensure!(
            sha256 == expected,
            "rust-analyzer checksum mismatch (fail closed): {} has sha256 {sha256}, \
             {ENV_RA_SHA256} expects {expected}",
            path.display()
        );
    }

    let matches_pin = version_line.contains(PINNED_VERSION);
    if !matches_pin {
        let msg = format!(
            "rust-analyzer version `{version_line}` does not match the pinned {PINNED_VERSION}; \
             moniker shapes may differ from the validated engine"
        );
        if std::env::var(ENV_STRICT_PIN)
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            anyhow::bail!("{msg} ({ENV_STRICT_PIN}=1)");
        }
        eprintln!("rustindex: WARNING: {msg}");
    }

    Ok(RaIdentity {
        path,
        version_line,
        sha256,
        matches_pin,
    })
}

/// The build-dep gate (binding): the cargo workspace must LOAD — metadata,
/// dependency resolution, and by extension build scripts and the proc-macro
/// server rust-analyzer runs on top of it. A workspace that fails to load
/// ABSTAINS: exit with an error, never fall back to a heuristic tier.
pub fn require_workspace_loads(root: &Path) -> anyhow::Result<()> {
    let out = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata (is cargo installed?)")?;
    anyhow::ensure!(
        out.status.success(),
        "cargo workspace under {} failed to load; rustindex abstains rather than guessing \
         (no heuristic tier, per the engine charter). cargo metadata said: {}",
        root.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(())
}

/// Lockfile provenance: whether `Cargo.lock` pre-existed, and the sha256 of
/// the lockfile that the load actually used. A missing committed lockfile
/// means the resolution was minted at scan time; snapshotting the generated
/// lockfile's digest (and size) into provenance keeps the run reproducible
/// evidence rather than an unrepeatable observation.
#[derive(Debug, Clone)]
pub struct LockfileProvenance {
    pub pre_existing: bool,
    pub sha256: String,
    pub bytes: usize,
}

/// Capture lockfile provenance for `root`. `pre_existing` must be sampled
/// BEFORE the workspace-load gate runs (cargo metadata writes the lockfile).
pub fn lockfile_provenance(root: &Path, pre_existing: bool) -> LockfileProvenance {
    match std::fs::read(root.join("Cargo.lock")) {
        Ok(bytes) => LockfileProvenance {
            pre_existing,
            sha256: hex::encode(sha2::Sha256::digest(&bytes)),
            bytes: bytes.len(),
        },
        Err(_) => LockfileProvenance {
            pre_existing,
            sha256: String::new(),
            bytes: 0,
        },
    }
}

/// Run `rust-analyzer scip <root>` and parse the resulting index. The output
/// file is written to the system temp dir and removed after parsing.
pub fn run_scip(ra: &RaIdentity, root: &Path) -> anyhow::Result<scip::types::Index> {
    let out_path = std::env::temp_dir().join(format!(
        "rustindex-{}-{}.scip",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    let out = Command::new(&ra.path)
        .arg("scip")
        .arg(root)
        .arg("--output")
        .arg(&out_path)
        .output()
        .with_context(|| format!("running {} scip", ra.path.display()))?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&out_path);
        anyhow::bail!(
            "rust-analyzer scip exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let bytes = std::fs::read(&out_path)
        .with_context(|| format!("reading scip output {}", out_path.display()))?;
    let _ = std::fs::remove_file(&out_path);
    let index: scip::types::Index = protobuf::Message::parse_from_bytes(&bytes)
        .context("parsing SCIP protobuf from rust-analyzer")?;
    Ok(index)
}
