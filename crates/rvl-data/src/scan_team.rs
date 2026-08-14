//! The team side of `scan`, ported from rvl-cli
//! `internal/commands/scan_team.go` (po-77b6w.1, org-ownership spec
//! Decisions 1-2):
//!
//!   * [`apply_team_assignments`] carries `.revelara.yaml` `team:` values (repo
//!     default + per-component) on the scan submission; `--team=<slug>`
//!     overrides the whole submission (bootstrap path for horizontal engineers
//!     scanning repos they cannot commit to).
//!   * [`warn_unknown_teams`] is a pre-submit did-you-mean against the org's
//!     known team slugs (`GET /api/v1/teams/slugs`). Loud, NEVER blocking:
//!     agents must be able to run headless, and creating a team on first sight
//!     is legitimate.

use crate::project_config::ProjectConfig;
use crate::scan_submit::ScanRequest;
use std::io::Write;

/// Resolve the team fields on the scan request. Precedence: the `--team`
/// override beats `.revelara.yaml`. The override applies to the WHOLE
/// submission (repo default and components alike), so component teams are
/// dropped when it is set.
pub fn apply_team_assignments(
    scan_req: &mut ScanRequest,
    project_cfg: Option<&ProjectConfig>,
    team_override: &str,
) {
    if !team_override.is_empty() {
        scan_req.team = team_override.to_string();
        scan_req.team_source = "override".to_string();
        scan_req.component_teams.clear();
        return;
    }
    let Some(cfg) = project_cfg else {
        return;
    };
    if !cfg.team.is_empty() {
        scan_req.team = cfg.team.clone();
    }
    for c in &cfg.components {
        if c.name.is_empty() || c.team.is_empty() {
            continue;
        }
        scan_req
            .component_teams
            .insert(c.name.clone(), c.team.clone());
    }
}

/// Mirror of the server-side team slugify: lowercase, trim, whitespace and
/// underscore runs become hyphens, invalid characters are dropped, hyphen runs
/// collapse, 2..63 chars. Used only for the did-you-mean preview; the server
/// remains authoritative.
pub fn slugify_team_preview(name: &str) -> String {
    let mut s = String::new();
    for r in name.trim().to_lowercase().chars() {
        if r.is_whitespace() || r == '_' || r == '-' {
            s.push('-');
        } else if r.is_ascii_lowercase() || r.is_ascii_digit() {
            s.push(r);
        }
    }
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    let mut s = s.trim_matches('-').to_string();
    if s.len() > 63 {
        s = s[..63].trim_matches('-').to_string();
    }
    if s.len() < 2 {
        return String::new();
    }
    s
}

/// The distinct team values carried on the request, in deterministic order
/// (repo-level first, then component teams by component name).
pub fn scan_request_teams(scan_req: &ScanRequest) -> Vec<String> {
    fn add(teams: &mut Vec<String>, team: &str) {
        if !team.is_empty() && !teams.iter().any(|t| t == team) {
            teams.push(team.to_string());
        }
    }
    let mut teams: Vec<String> = Vec::new();
    add(&mut teams, &scan_req.team);
    // BTreeMap iterates by component name, matching Go's sorted key order.
    for team in scan_req.component_teams.values() {
        add(&mut teams, team);
    }
    teams
}

/// Edit distance between two strings. Small inputs only (team slugs), so the
/// simple O(len(a)*len(b)) DP is fine.
fn levenshtein(a: &str, b: &str) -> usize {
    let ar: Vec<char> = a.chars().collect();
    let br: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=br.len()).collect();
    let mut curr = vec![0usize; br.len() + 1];
    for i in 1..=ar.len() {
        curr[0] = i;
        for j in 1..=br.len() {
            let cost = usize::from(ar[i - 1] != br[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[br.len()]
}

/// Up to `max` known slugs closest to `target`: prefix matches first, then
/// slugs within edit distance 3, ordered by distance.
pub fn nearest_slugs(target: &str, known: &[String], max: usize) -> Vec<String> {
    let mut cands: Vec<(&String, usize)> = known
        .iter()
        .filter(|k| k.as_str() != target)
        .filter_map(|k| {
            let d = if k.starts_with(target) || target.starts_with(k.as_str()) {
                0 // prefix relationship ranks first
            } else {
                levenshtein(target, k)
            };
            (d <= 3).then_some((k, d))
        })
        .collect();
    cands.sort_by_key(|(_, d)| *d); // stable: ties keep input order
    cands
        .into_iter()
        .take(max)
        .map(|(k, _)| k.clone())
        .collect()
}

/// Print a did-you-mean warning for every team value on the request whose
/// slugified preview is not among the org's known slugs. `known_slugs == None`
/// means the lookup failed (offline, old server) and the check is skipped
/// entirely. Never blocks, never changes the request.
pub fn warn_unknown_teams(
    out: &mut dyn Write,
    known_slugs: Option<&[String]>,
    scan_req: &ScanRequest,
) {
    let Some(known_slugs) = known_slugs else {
        return;
    };
    for team in scan_request_teams(scan_req) {
        let slug = slugify_team_preview(&team);
        if slug.is_empty() {
            let _ = writeln!(
                out,
                "Warning: team {team:?} slugifies to nothing usable and will be ignored by the server."
            );
            continue;
        }
        if known_slugs.contains(&slug) {
            continue;
        }
        let mut msg = format!(
            "Warning: team {team:?} (slug {slug:?}) is not a known team in your organization"
        );
        let near = nearest_slugs(&slug, known_slugs, 3);
        if !near.is_empty() {
            msg.push_str("; nearest known: ");
            msg.push_str(&near.join(", "));
        }
        msg.push_str(". Proceeding creates a new team.");
        let _ = writeln!(out, "{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_config::ProjectComponent;

    fn project_cfg() -> ProjectConfig {
        ProjectConfig {
            project: "checkout-api".into(),
            team: "checkout".into(),
            components: vec![
                ProjectComponent {
                    name: "api".into(),
                    path: "cmd/api".into(),
                    team: String::new(),
                },
                ProjectComponent {
                    name: "worker".into(),
                    path: "cmd/worker".into(),
                    team: "payments".into(),
                },
            ],
            ..Default::default()
        }
    }

    // Resolution order: --team overrides the whole submission (repo default
    // AND components); otherwise .revelara.yaml team: (repo default) plus
    // per-component team: entries apply.

    #[test]
    fn file_values_are_carried() {
        let mut req = ScanRequest::default();
        apply_team_assignments(&mut req, Some(&project_cfg()), "");
        assert_eq!(req.team, "checkout");
        // The server defaults team_source to "scan" when it is omitted.
        assert_eq!(req.team_source, "");
        assert_eq!(req.component_teams.len(), 1);
        assert_eq!(req.component_teams["worker"], "payments");
    }

    #[test]
    fn override_wins_over_file_and_drops_component_teams() {
        let mut req = ScanRequest::default();
        apply_team_assignments(&mut req, Some(&project_cfg()), "platform");
        assert_eq!(req.team, "platform");
        assert_eq!(req.team_source, "override");
        assert!(req.component_teams.is_empty());
    }

    #[test]
    fn override_works_without_a_config_file() {
        let mut req = ScanRequest::default();
        apply_team_assignments(&mut req, None, "platform");
        assert_eq!(req.team, "platform");
        assert_eq!(req.team_source, "override");
    }

    #[test]
    fn no_team_info_leaves_the_request_untouched() {
        let mut req = ScanRequest::default();
        let cfg = ProjectConfig {
            project: "p".into(),
            ..Default::default()
        };
        apply_team_assignments(&mut req, Some(&cfg), "");
        assert_eq!(req.team, "");
        assert_eq!(req.team_source, "");
        assert!(req.component_teams.is_empty());
    }

    // Slugify contract (hygiene layer 1): lowercase, trim, whitespace and
    // underscores -> hyphens, no affix stripping, invalid chars dropped,
    // 2..63 chars.
    #[test]
    fn slugify_preview_matches_the_server_contract() {
        for (input, want) in [
            ("Checkout", "checkout"),
            (" checkout ", "checkout"),
            ("Checkout Team", "checkout-team"),
            ("checkout_team", "checkout-team"),
            ("platform-team", "platform-team"),
            ("pay/ments", "payments"),
            ("x", ""),
            ("", ""),
        ] {
            assert_eq!(slugify_team_preview(input), want, "input {input:?}");
        }
    }

    #[test]
    fn nearest_slugs_ranks_prefix_then_distance() {
        let known: Vec<String> = ["checkout", "payments", "platform", "data-eng"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            nearest_slugs("chekout", &known, 3)
                .first()
                .map(String::as_str),
            Some("checkout")
        );
        // Prefix relationships rank first.
        assert_eq!(
            nearest_slugs("pay", &known, 3).first().map(String::as_str),
            Some("payments")
        );
        // Nothing near: distance > 3 from everything.
        assert!(nearest_slugs("zzzzzzzzzz", &known, 3).is_empty());
    }

    fn warn(known: Option<&[String]>, req: &ScanRequest) -> String {
        let mut buf = Vec::new();
        warn_unknown_teams(&mut buf, known, req);
        String::from_utf8(buf).unwrap()
    }

    fn slugs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // The did-you-mean contract: loud on unknown teams (with suggestions),
    // silent on known ones, skipped entirely when the slug lookup failed
    // (None), and never anything but warnings.

    #[test]
    fn unknown_team_warns_with_suggestion() {
        let req = ScanRequest {
            team: "Chekout".into(),
            ..Default::default()
        };
        let out = warn(Some(&slugs(&["checkout", "payments"])), &req);
        assert!(out.contains("is not a known team"), "{out}");
        assert!(out.contains("checkout"), "{out}");
        assert!(out.contains("creates a new team"), "{out}");
    }

    #[test]
    fn known_team_is_silent() {
        // "Checkout Team" slugifies to checkout-team, which is known.
        let req = ScanRequest {
            team: "Checkout Team".into(),
            ..Default::default()
        };
        assert_eq!(warn(Some(&slugs(&["checkout-team"])), &req), "");
    }

    #[test]
    fn none_slug_list_skips_the_check() {
        let req = ScanRequest {
            team: "anything".into(),
            ..Default::default()
        };
        assert_eq!(warn(None, &req), "");
    }

    #[test]
    fn component_teams_are_checked_too() {
        let mut req = ScanRequest {
            team: "checkout".into(),
            ..Default::default()
        };
        req.component_teams
            .insert("worker".into(), "paymments".into());
        let out = warn(Some(&slugs(&["checkout"])), &req);
        assert!(out.contains("paymments"), "{out}");
    }

    #[test]
    fn empty_org_team_list_warns_but_does_not_block() {
        let req = ScanRequest {
            team: "checkout".into(),
            ..Default::default()
        };
        let out = warn(Some(&[]), &req);
        assert!(out.contains("creates a new team"), "{out}");
    }

    #[test]
    fn unusable_team_name_warns_that_the_server_ignores_it() {
        let req = ScanRequest {
            team: "x".into(),
            ..Default::default()
        };
        let out = warn(Some(&slugs(&["checkout"])), &req);
        assert!(out.contains("slugifies to nothing usable"), "{out}");
    }
}
