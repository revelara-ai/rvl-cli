//! The submission-side view of `.revelara.yaml`, ported from rvl-cli
//! `internal/project/config.go` (`LoadProjectConfigFrom`).
//!
//! Only the keys a scan submission needs are read: `project`, `criticality`,
//! the repo-level `team:`, and the `components:` list (name / path / team).
//! Every other key is tolerated and ignored. That matches the convention the
//! scanner crate already follows for this shared file: `waiver.rs` owns the
//! `scanner.waivers` / `scanner.bounds` view and `agent.rs` owns the
//! agent-consent view, each narrow so one consumer can never break another.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// `.revelara.yaml`, submission-side subset.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    pub project: String,
    pub criticality: String,
    /// The repo-level owning team (org-ownership spec Decision 1: ownership is
    /// declared in-repo, and only in-repo). Carried on scan submissions; the
    /// server slugifies it and creates the team on first sight. Per-component
    /// ownership goes on [`ProjectComponent::team`]; `scan --team=<slug>`
    /// overrides both.
    pub team: String,
    pub components: Vec<ProjectComponent>,
}

impl ProjectConfig {
    /// Map the human-friendly `criticality:` label to the 0.0-1.0 multiplier
    /// the risk register scores with (rvl-cli `ProjectConfig.CriticalityScore`).
    /// Unknown or empty labels default to 0.0 — no boost — so a typo can never
    /// silently inflate a repo's risk scores.
    ///
    /// The platform applies `1.0 + (business_criticality * 0.25)`, so a repo
    /// that declares a criticality and does NOT send this scores every risk
    /// LOWER than rvl-cli scored the same findings.
    pub fn criticality_score(&self) -> f64 {
        match self.criticality.as_str() {
            "hobby" => 0.0,
            "internal" => 0.25,
            "customer-facing" => 0.6,
            "critical" => 1.0,
            _ => 0.0,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct ProjectComponent {
    pub name: String,
    pub path: String,
    /// The component-level owning team; overrides the repo-level
    /// [`ProjectConfig::team`] for this component.
    pub team: String,
}

/// Parse a `.revelara.yaml` document. Malformed YAML yields `None`, mirroring
/// Go's `yaml.Unmarshal` error path: a broken config is never load-bearing.
pub fn parse(text: &str) -> Option<ProjectConfig> {
    serde_yaml::from_str::<ProjectConfig>(text).ok()
}

/// Read `.revelara.yaml` from `target`'s git root, falling back to the
/// directory itself when it is not a git repository (rvl-cli
/// `LoadProjectConfigFrom`). A missing or unparseable file yields `None`.
pub fn load_project_config_from(target: &Path) -> Option<ProjectConfig> {
    let root = git_root(target).unwrap_or_else(|| target.to_path_buf());
    let text = std::fs::read_to_string(root.join(".revelara.yaml")).ok()?;
    parse(&text)
}

fn git_root(dir: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let root = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if root.is_empty() {
        return None;
    }
    Some(PathBuf::from(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `.revelara.yaml` team contract: a top-level `team:` (repo default)
    /// plus per-component `team:` entries. A non-git temp dir exercises the
    /// directory-itself fallback in [`load_project_config_from`].
    #[test]
    fn load_reads_team_fields() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".revelara.yaml"),
            "project: checkout-api\n\
             criticality: customer-facing\n\
             team: checkout\n\
             components:\n\
             \x20   - name: api\n\
             \x20     path: cmd/api\n\
             \x20   - name: worker\n\
             \x20     path: cmd/worker\n\
             \x20     team: payments\n",
        )
        .unwrap();

        let cfg = load_project_config_from(dir.path()).expect("config must load");
        assert_eq!(cfg.project, "checkout-api");
        assert_eq!(cfg.team, "checkout");
        assert_eq!(cfg.components.len(), 2);
        // Inherits the repo default: no per-component override.
        assert_eq!(cfg.components[0].team, "");
        assert_eq!(cfg.components[1].team, "payments");
    }

    /// Unknown keys (waivers, bounds, agent consent) belong to other consumers
    /// of the same file and must never break this view.
    #[test]
    fn unknown_keys_are_tolerated() {
        let cfg = parse(
            "project: svc\n\
             scanner:\n\
             \x20 use_agent: allow\n\
             \x20 waivers:\n\
             \x20   - matcher: x\n",
        )
        .expect("must parse");
        assert_eq!(cfg.project, "svc");
        assert_eq!(cfg.team, "");
    }

    /// Every documented label plus the two default-to-zero cases, exactly as
    /// rvl-cli's `TestCriticalityScore` pins them.
    #[test]
    fn criticality_score_matches_rvl_cli() {
        for (label, want) in [
            ("hobby", 0.0),
            ("internal", 0.25),
            ("customer-facing", 0.6),
            ("critical", 1.0),
            ("", 0.0),
            ("unknown", 0.0),
        ] {
            let cfg = ProjectConfig {
                criticality: label.to_string(),
                ..Default::default()
            };
            assert_eq!(cfg.criticality_score(), want, "criticality: {label:?}");
        }
    }

    #[test]
    fn missing_file_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_project_config_from(dir.path()).is_none());
    }

    #[test]
    fn malformed_yaml_is_none() {
        assert!(parse("project: [unclosed\n").is_none());
    }
}
