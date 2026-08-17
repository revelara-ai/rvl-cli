//! Per-finding component attribution, ported from rvl-cli
//! `internal/project/mapping.go` (`MapFindingsToComponents`).
//!
//! Without this, every finding in a multi-component repo lands on the bare
//! service label: the register splits between `myapp` and `myapp/api`, and the
//! `component_teams` map the submission already carries has no finding bound to
//! it. The scan still succeeds, which is exactly why the gap survived — a green
//! scan that degraded the register.

use crate::project_config::ProjectConfig;
use serde_json::Value;
use std::collections::BTreeSet;

/// Set `linked_services` on each finding from its evidence paths, matched
/// against `.revelara.yaml` `components:`. Longest component path wins, so a
/// nested `services/x/frontend/` beats its parent `services/x/`.
///
/// Three rules, in rvl-cli's order:
///
///  1. A finding that already carries a non-empty `linked_services` is left
///     alone (the scanner or skill already attributed it).
///  2. An explicit `component: <name>` field wins outright:
///     `linked_services = ["<project>/<name>"]`.
///  3. Otherwise every `evidence[].path` is matched against the component
///     paths; unmatched paths contribute nothing, and a finding whose paths all
///     miss keeps NO `linked_services` key (the bare-service warning covers it).
///
/// Go collects the matches in a `map[string]bool`, whose range order is
/// randomized, so a multi-component finding has no defined order there. This
/// emits them sorted: deterministic, and identical to Go whenever a finding
/// matches a single component (the overwhelmingly common case).
pub fn map_findings_to_components(findings: &mut [Value], project_cfg: &ProjectConfig) {
    if project_cfg.components.is_empty() {
        return;
    }

    // Longest path first: the first prefix hit is then the best one.
    let mut sorted: Vec<(&str, &str)> = project_cfg
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.path.as_str()))
        .collect();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.1.len()));

    let project = project_cfg.project.as_str();

    for finding in findings.iter_mut() {
        let Some(obj) = finding.as_object_mut() else {
            continue;
        };

        // 1. Already attributed.
        if let Some(Value::Array(existing)) = obj.get("linked_services") {
            if !existing.is_empty() {
                continue;
            }
        }

        // 2. Explicit component field (set by skills).
        if let Some(Value::String(name)) = obj.get("component") {
            if !name.is_empty() {
                let linked = Value::Array(vec![Value::String(format!("{project}/{name}"))]);
                obj.insert("linked_services".to_string(), linked);
                continue;
            }
        }

        // 3. Longest-prefix match on the evidence paths.
        let Some(Value::Array(evidence)) = obj.get("evidence") else {
            continue;
        };
        let mut matched: BTreeSet<String> = BTreeSet::new();
        for ev in evidence {
            let Some(Value::String(path)) = ev.get("path") else {
                continue;
            };
            if path.is_empty() {
                continue;
            }
            for (name, comp_path) in &sorted {
                if path.starts_with(comp_path) {
                    matched.insert(format!("{project}/{name}"));
                    break; // longest prefix wins
                }
            }
        }
        if matched.is_empty() {
            continue;
        }
        let linked = Value::Array(matched.into_iter().map(Value::String).collect());
        obj.insert("linked_services".to_string(), linked);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_config::{ProjectComponent, ProjectConfig};
    use serde_json::json;

    fn cfg() -> ProjectConfig {
        ProjectConfig {
            project: "audit-test".to_string(),
            components: vec![
                ProjectComponent {
                    name: "api".to_string(),
                    path: "cmd/api".to_string(),
                    team: String::new(),
                },
                ProjectComponent {
                    name: "worker".to_string(),
                    path: "cmd/worker".to_string(),
                    team: String::new(),
                },
            ],
            ..Default::default()
        }
    }

    fn linked(v: &Value) -> Option<Vec<String>> {
        Some(
            v.get("linked_services")?
                .as_array()?
                .iter()
                .map(|s| s.as_str().unwrap_or_default().to_string())
                .collect(),
        )
    }

    /// The regression this module exists for: an evidence path under a declared
    /// component produces `linked_services: ["<project>/<component>"]`.
    #[test]
    fn evidence_path_maps_to_component() {
        let mut findings = vec![json!({
            "title": "Missing timeout",
            "evidence": [{"path": "cmd/api/handler.go", "line": 12}],
        })];
        map_findings_to_components(&mut findings, &cfg());
        assert_eq!(
            linked(&findings[0]),
            Some(vec!["audit-test/api".to_string()])
        );
    }

    /// A finding whose paths match NO component keeps no `linked_services` key
    /// at all, rather than an empty array or a guessed attribution.
    #[test]
    fn unmatched_path_gets_no_linked_services() {
        let mut findings = vec![json!({
            "title": "Docs drift",
            "evidence": [{"path": "docs/readme.md"}],
        })];
        map_findings_to_components(&mut findings, &cfg());
        assert!(findings[0].get("linked_services").is_none());
    }

    /// A batch mixing hits and a miss: only the hits gain the field, and the
    /// miss is untouched (this is the shape a real repo submits).
    #[test]
    fn mixed_batch_maps_only_matching_findings() {
        let mut findings = vec![
            json!({"title": "A", "evidence": [{"path": "cmd/api/a.go"}]}),
            json!({"title": "B", "evidence": [{"path": "vendor/x/b.go"}]}),
            json!({"title": "C", "evidence": [{"path": "cmd/worker/c.go"}]}),
        ];
        map_findings_to_components(&mut findings, &cfg());
        assert_eq!(
            linked(&findings[0]),
            Some(vec!["audit-test/api".to_string()])
        );
        assert!(findings[1].get("linked_services").is_none());
        assert_eq!(
            linked(&findings[2]),
            Some(vec!["audit-test/worker".to_string()])
        );
    }

    /// Longest prefix wins: a nested component beats the parent that also
    /// prefixes the path.
    #[test]
    fn longest_prefix_wins() {
        let nested = ProjectConfig {
            project: "shop".to_string(),
            components: vec![
                ProjectComponent {
                    name: "svc".to_string(),
                    path: "services/x/".to_string(),
                    team: String::new(),
                },
                ProjectComponent {
                    name: "frontend".to_string(),
                    path: "services/x/frontend/".to_string(),
                    team: String::new(),
                },
            ],
            ..Default::default()
        };
        let mut findings = vec![json!({
            "evidence": [{"path": "services/x/frontend/app.ts"}],
        })];
        map_findings_to_components(&mut findings, &nested);
        assert_eq!(
            linked(&findings[0]),
            Some(vec!["shop/frontend".to_string()])
        );
    }

    /// An explicit `component:` field (set by a skill) wins over evidence paths.
    #[test]
    fn explicit_component_field_wins() {
        let mut findings = vec![json!({
            "component": "worker",
            "evidence": [{"path": "cmd/api/handler.go"}],
        })];
        map_findings_to_components(&mut findings, &cfg());
        assert_eq!(
            linked(&findings[0]),
            Some(vec!["audit-test/worker".to_string()])
        );
    }

    /// A finding that already carries `linked_services` is never rewritten.
    #[test]
    fn existing_linked_services_preserved() {
        let mut findings = vec![json!({
            "linked_services": ["other/thing"],
            "evidence": [{"path": "cmd/api/handler.go"}],
        })];
        map_findings_to_components(&mut findings, &cfg());
        assert_eq!(linked(&findings[0]), Some(vec!["other/thing".to_string()]));
    }

    /// A config with no components is a no-op: nothing to attribute to.
    #[test]
    fn no_components_is_a_noop() {
        let mut findings = vec![json!({"evidence": [{"path": "cmd/api/handler.go"}]})];
        map_findings_to_components(
            &mut findings,
            &ProjectConfig {
                project: "svc".to_string(),
                ..Default::default()
            },
        );
        assert!(findings[0].get("linked_services").is_none());
    }

    /// A finding with several evidence paths across components lists both, in
    /// deterministic (sorted) order.
    #[test]
    fn multiple_components_are_sorted() {
        let mut findings = vec![json!({
            "evidence": [
                {"path": "cmd/worker/w.go"},
                {"path": "cmd/api/a.go"},
            ],
        })];
        map_findings_to_components(&mut findings, &cfg());
        assert_eq!(
            linked(&findings[0]),
            Some(vec![
                "audit-test/api".to_string(),
                "audit-test/worker".to_string()
            ])
        );
    }
}
