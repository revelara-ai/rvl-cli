//! The `status` CLI update check, ported from rvl-cli
//! `internal/api.FetchLatestCLIVersion` (po-av01j.185 item 1).
//!
//! WHY THIS IS LOAD-BEARING: the v1 -> v2 cutover plan's P4 step chases
//! stragglers off the Go CLI with exactly this nag, and the server-side
//! dedup fix means a v1 user can move to v2 without upgrading first — so
//! the nag is the only thing that tells a holdout to move at all.
//!
//! Same release feed as rvl-cli, deliberately: after the repo-rename dance
//! ruled on po-av01j.154 the Rust workspace IS `revelara-ai/rvl-cli`, so
//! the URL, the cask URLs, and the git remotes all keep pointing at one
//! place. Failure is always silent (`None`): an update hint is never worth
//! failing `status` over.

use std::time::Duration;

/// Where the released binary's version comes from. Public so a test (or a
/// self-hosted fork) can point the check somewhere else.
pub const RELEASES_API: &str = "https://api.github.com/repos/revelara-ai/rvl-cli/releases/latest";

/// rvl-cli's 5s budget: `status` already made one live API call by the
/// time this runs, and a slow GitHub must not double the command's wall
/// time.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The latest released version (`tag_name` with any leading `v` stripped),
/// or `None` on any error — offline, rate-limited, private repo, 404.
pub fn fetch_latest_cli_version() -> Option<String> {
    fetch_latest_cli_version_from(RELEASES_API)
}

fn fetch_latest_cli_version_from(url: &str) -> Option<String> {
    let resp = ureq::get(url)
        .timeout(TIMEOUT)
        .set("Accept", "application/vnd.github+json")
        .call()
        .ok()?;
    let body: serde_json::Value = serde_json::from_reader(resp.into_reader()).ok()?;
    let tag = body.get("tag_name")?.as_str()?;
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    if tag.is_empty() {
        return None;
    }
    Some(tag.to_string())
}

/// The nag block `status` prints, or `None` when there is nothing to say.
/// Split from the fetch so the rendering is testable without a network.
///
/// rvl-cli prints the whole block on STDERR (nag and "up to date" alike)
/// so a piped `status` stays parseable; the caller does the same.
pub fn update_notice(current: &str, latest: Option<&str>) -> Option<String> {
    let latest = latest?;
    let current = current.strip_prefix('v').unwrap_or(current);
    if !rvl_core::semver::semver_newer(current, latest) {
        return Some(format!("\nCLI: v{current} (up to date)\n"));
    }
    let mut out = format!("\nCLI update available: v{current} -> v{latest}\n");
    if let Some(cmd) = crate::upgrade_hint::upgrade_command() {
        out.push_str(&format!("  Upgrade: {cmd}\n"));
    }
    out.push_str("  Release: https://github.com/revelara-ai/rvl-cli/releases/latest\n");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_latest_version_prints_nothing() {
        assert_eq!(update_notice("1.0.0", None), None);
    }

    #[test]
    fn same_or_newer_local_version_reports_up_to_date() {
        assert_eq!(
            update_notice("1.0.0", Some("1.0.0")).unwrap(),
            "\nCLI: v1.0.0 (up to date)\n"
        );
        assert_eq!(
            update_notice("1.1.0", Some("1.0.0")).unwrap(),
            "\nCLI: v1.1.0 (up to date)\n"
        );
    }

    #[test]
    fn older_local_version_nags_and_always_links_the_release() {
        let out = update_notice("1.0.0", Some("1.2.3")).unwrap();
        assert!(
            out.starts_with("\nCLI update available: v1.0.0 -> v1.2.3\n"),
            "got: {out}"
        );
        assert!(out.contains("https://github.com/revelara-ai/rvl-cli/releases/latest"));
    }

    #[test]
    fn a_leading_v_on_either_side_is_tolerated() {
        assert_eq!(
            update_notice("v1.0.0", Some("1.0.0")).unwrap(),
            "\nCLI: v1.0.0 (up to date)\n"
        );
    }
}
