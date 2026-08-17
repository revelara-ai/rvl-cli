//! Install-method detection for the `status` CLI update nag, ported from
//! rvl-cli `internal/commands/upgrade_hint.go` (po-t1mu7) and re-based on
//! how THIS binary is actually distributed (po-av01j.185 item 1).
//!
//! rvl-cli shipped two ways: a Homebrew CASK and `go install`. The Rust
//! binary drops `go install` — a v2 user who ran it would be handed a v1
//! Go binary — and gains the two ways this workspace is installed from
//! source: `make install` (BINDIR defaults to `~/.local/bin`) and
//! `cargo install` (CARGO_HOME/bin, else `~/.cargo/bin`).
//!
//! The releases URL is printed unconditionally by the caller, so an
//! unrecognized path just omits the command rather than guessing.

use std::path::{Path, PathBuf};

/// The tap ships `rvl` as a CASK, not a formula (see `dist-workspace.toml`),
/// so the upgrade needs `--cask`: `brew upgrade rvl` alone resolves against
/// formulae first and reports "No available formula".
pub const UPGRADE_CMD_BREW: &str = "brew upgrade --cask revelara-ai/tap/rvl";
/// A source install via the workspace Makefile (`PREFIX=$HOME/.local`).
pub const UPGRADE_CMD_MAKE: &str = "git pull && make install   (in your rvl checkout)";
/// A source install via cargo.
pub const UPGRADE_CMD_CARGO: &str =
    "cargo install --git https://github.com/revelara-ai/rvl-cli --locked rvl";

/// The upgrade instruction matching how this binary was installed, or
/// `None` when the method cannot be determined. Symlinks are resolved
/// first: the brew cask links `$(brew --prefix)/bin/rvl` into the
/// Caskroom, so the resolved path is the reliable signal.
pub fn upgrade_command() -> Option<&'static str> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    upgrade_command_for_path(&exe, |k| std::env::var(k).ok())
}

/// Classify an executable path. Split from [`upgrade_command`] for
/// testability; `getenv` stands in for the process environment.
pub fn upgrade_command_for_path(
    exe: &Path,
    getenv: impl Fn(&str) -> Option<String>,
) -> Option<&'static str> {
    let lower = exe.to_string_lossy().to_lowercase();

    // Homebrew: cask binaries resolve into a Caskroom (formulae into a
    // Cellar); the prefix markers cover /opt/homebrew, /usr/local/Homebrew
    // and /home/linuxbrew/.linuxbrew.
    for marker in ["/caskroom/", "/cellar/", "/homebrew/", "/.linuxbrew/"] {
        if lower.contains(marker) {
            return Some(UPGRADE_CMD_BREW);
        }
    }

    let dir = exe.parent()?;

    // cargo install: CARGO_HOME/bin wins, then the default ~/.cargo/bin.
    let mut cargo_bins: Vec<PathBuf> = Vec::new();
    if let Some(home) = getenv("CARGO_HOME").filter(|s| !s.is_empty()) {
        cargo_bins.push(PathBuf::from(home).join("bin"));
    }
    if let Some(home) = getenv("HOME").filter(|s| !s.is_empty()) {
        cargo_bins.push(PathBuf::from(home).join(".cargo").join("bin"));
    }
    if cargo_bins.iter().any(|b| dir == b) {
        return Some(UPGRADE_CMD_CARGO);
    }

    // `make install`: the Makefile's PREFIX defaults to $HOME/.local, so
    // $HOME/.local/bin is the one path this workspace itself writes to.
    if let Some(home) = getenv("HOME").filter(|s| !s.is_empty()) {
        if dir == PathBuf::from(home).join(".local").join("bin") {
            return Some(UPGRADE_CMD_MAKE);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn brew_cask_and_cellar_paths_map_to_the_cask_upgrade() {
        let e = env(&[("HOME", "/home/u")]);
        for p in [
            "/opt/homebrew/Caskroom/rvl/1.0.0/rvl",
            "/usr/local/Caskroom/rvl/1.0.0/rvl",
            "/opt/homebrew/Cellar/rvl/1.0.0/bin/rvl",
            "/home/linuxbrew/.linuxbrew/bin/rvl",
        ] {
            assert_eq!(
                upgrade_command_for_path(Path::new(p), &e),
                Some(UPGRADE_CMD_BREW),
                "{p}"
            );
        }
    }

    #[test]
    fn cargo_bin_dirs_map_to_the_cargo_upgrade() {
        assert_eq!(
            upgrade_command_for_path(
                Path::new("/home/u/.cargo/bin/rvl"),
                env(&[("HOME", "/home/u")])
            ),
            Some(UPGRADE_CMD_CARGO)
        );
        assert_eq!(
            upgrade_command_for_path(
                Path::new("/opt/cargo/bin/rvl"),
                env(&[("HOME", "/home/u"), ("CARGO_HOME", "/opt/cargo")])
            ),
            Some(UPGRADE_CMD_CARGO)
        );
    }

    #[test]
    fn make_install_default_bindir_maps_to_the_make_upgrade() {
        assert_eq!(
            upgrade_command_for_path(
                Path::new("/home/u/.local/bin/rvl"),
                env(&[("HOME", "/home/u")])
            ),
            Some(UPGRADE_CMD_MAKE)
        );
    }

    #[test]
    fn unrecognized_paths_yield_no_command() {
        let e = env(&[("HOME", "/home/u")]);
        for p in ["/usr/bin/rvl", "/usr/local/bin/rvl", "/home/u/.cargo/rvl"] {
            assert_eq!(upgrade_command_for_path(Path::new(p), &e), None, "{p}");
        }
    }

    #[test]
    fn go_install_path_is_not_claimed() {
        // rvl-cli pointed ~/go/bin at `go install ...rvl-cli@latest`. This
        // binary must NOT: that command would replace a v2 install with the
        // frozen Go v1. Unknown is the honest answer; the releases link is
        // printed either way.
        assert_eq!(
            upgrade_command_for_path(Path::new("/home/u/go/bin/rvl"), env(&[("HOME", "/home/u")])),
            None
        );
    }
}
