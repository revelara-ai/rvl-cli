//! Semver comparison for installed-vs-served drift, mirroring rvl-cli's
//! `internal/plugin/semver.go` so both surfaces report drift identically.
//!
//! Two callers: plugin-content drift (`rvl-skills`) and the `status` CLI
//! update nag (`rvl-data`). rvl-cli uses the one `plugin.SemVerNewer` for
//! both, so this crate does too.

/// Strip build metadata (after `+`) from a version string.
/// "0.2.0+abc123f" -> "0.2.0"; "dev-abc123f+abc123f" -> "dev-abc123f".
pub fn semver_base(version: &str) -> &str {
    version.split('+').next().unwrap_or(version)
}

/// True when `available` is newer than `installed` (MAJOR.MINOR.PATCH,
/// build metadata stripped). Non-semver values (e.g. "dev" builds) fall
/// back to string inequality on the base portion, so a drifted dev build
/// still reports as an update.
pub fn semver_newer(installed: &str, available: &str) -> bool {
    let (i, a) = (semver_base(installed), semver_base(available));
    match (parse_semver(i), parse_semver(a)) {
        (Some(ip), Some(ap)) => ap > ip,
        _ => i != a,
    }
}

/// "MAJOR.MINOR.PATCH" as a numeric triple; None when not that shape.
fn parse_semver(v: &str) -> Option<[u64; 3]> {
    let mut it = v.split('.');
    let out = [
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ];
    if it.next().is_some() {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_strips_build_metadata() {
        assert_eq!(semver_base("0.2.0+abc123f"), "0.2.0");
        assert_eq!(semver_base("dev-abc123f+abc123f"), "dev-abc123f");
        assert_eq!(semver_base("0.2.0"), "0.2.0");
    }

    #[test]
    fn newer_compares_numeric_triples() {
        assert!(semver_newer("0.2.0", "0.3.0"));
        assert!(semver_newer("0.2.0", "0.2.1"));
        assert!(semver_newer("0.9.9", "1.0.0"));
        assert!(!semver_newer("0.3.0", "0.2.9"));
        assert!(!semver_newer("0.2.0", "0.2.0"));
        // Build metadata is stripped before comparing.
        assert!(!semver_newer("0.2.0+aaa", "0.2.0+bbb"));
    }

    #[test]
    fn newer_falls_back_to_string_inequality_for_non_semver() {
        assert!(semver_newer("dev-1", "dev-2"));
        assert!(!semver_newer("dev-1", "dev-1"));
        assert!(semver_newer("dev", "0.2.0"));
    }
}
