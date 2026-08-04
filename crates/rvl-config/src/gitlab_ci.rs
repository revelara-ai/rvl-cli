//! GitLab CI retriever (`.gitlab-ci.yml`): the second CI system of family
//! (1), sharing the family plumbing the GitHub Actions retriever proved.
//!
//! Emits per-job facts:
//!
//!   * `job.timeout` — job-level, else the `default:` block (the provenance
//!     chain records the fallthrough), else UNRESOLVABLE: the project-level
//!     timeout is a GitLab setting no committed file can see.
//!   * `job.retry` — job-level, else `default:`, else the documented `0`.
//!   * `job.allow_failure` — explicit, else the documented default, which is
//!     `true` for manual jobs (`when: manual`) and `false` otherwise.
//!
//! `include:`-only files are valid GitLab CI and emit zero packets (the
//! included files are not fetched: no remote reads on the scan path).

use crate::{render_value, ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};
use serde_yaml::Value;

pub struct GitlabCi;

/// Top-level keys that configure the pipeline rather than define a job.
const RESERVED: &[&str] = &[
    "default",
    "include",
    "stages",
    "variables",
    "workflow",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
];

impl ConfigRetriever for GitlabCi {
    fn format_id(&self) -> &'static str {
        "gitlab-ci"
    }

    /// Only the canonical root file. Alternate `ci/` locations are a project
    /// setting (unresolvable from the repo) and out of scope for family (1).
    fn matches(&self, rel_path: &str) -> bool {
        rel_path == ".gitlab-ci.yml"
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let mut out = Retrieved::default();
        let Ok(doc) = serde_yaml::from_str::<Value>(contents) else {
            out.unparseable = 1;
            return out;
        };
        let Some(root) = doc.as_mapping() else {
            out.unparseable = 1;
            return out;
        };

        let default_block = get(root, "default").and_then(Value::as_mapping);
        let dget = |k: &str| default_block.and_then(|d| get(d, k));

        let packet = |unit: &str,
                      key: &str,
                      value: Option<String>,
                      resolution: Resolution,
                      provenance: Vec<ProvenanceStep>| ConfigPacket {
            snapshot_id: snapshot_id.to_string(),
            format: "gitlab-ci".to_string(),
            file_path: rel_path.to_string(),
            line: 0,
            unit: unit.to_string(),
            key: key.to_string(),
            resolved_value: value,
            resolution,
            provenance,
        };

        for (job_key, job_val) in root {
            let Some(job_id) = job_key.as_str() else {
                continue;
            };
            // Reserved sections and hidden templates (`.name`) are not jobs.
            if RESERVED.contains(&job_id) || job_id.starts_with('.') {
                continue;
            }
            let Some(job) = job_val.as_mapping() else {
                continue;
            };
            let unit = format!("job:{job_id}");
            let jpath = |k: &str| format!("{job_id}.{k}");

            // job.timeout: job > default block > project setting (outside repo).
            match (get(job, "timeout"), dget("timeout")) {
                (Some(v), _) => out.packets.push(packet(
                    &unit,
                    "job.timeout",
                    Some(render_value(v)),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(rel_path, &jpath("timeout"), "explicit")],
                )),
                (None, Some(v)) => out.packets.push(packet(
                    &unit,
                    "job.timeout",
                    Some(render_value(v)),
                    Resolution::AsAuthored,
                    vec![
                        ProvenanceStep::new(rel_path, &jpath("timeout"), "absent"),
                        ProvenanceStep::new(rel_path, "default.timeout", "default-block"),
                    ],
                )),
                (None, None) => out.packets.push(packet(
                    &unit,
                    "job.timeout",
                    None,
                    Resolution::Unresolvable,
                    vec![
                        ProvenanceStep::new(rel_path, &jpath("timeout"), "absent"),
                        ProvenanceStep::new(rel_path, "default.timeout", "absent"),
                        ProvenanceStep::new("", "project CI timeout", "project-setting"),
                    ],
                )),
            }

            // job.retry: job > default block > documented 0.
            match (get(job, "retry"), dget("retry")) {
                (Some(v), _) => out.packets.push(packet(
                    &unit,
                    "job.retry",
                    Some(render_value(v)),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(rel_path, &jpath("retry"), "explicit")],
                )),
                (None, Some(v)) => out.packets.push(packet(
                    &unit,
                    "job.retry",
                    Some(render_value(v)),
                    Resolution::AsAuthored,
                    vec![
                        ProvenanceStep::new(rel_path, &jpath("retry"), "absent"),
                        ProvenanceStep::new(rel_path, "default.retry", "default-block"),
                    ],
                )),
                (None, None) => out.packets.push(packet(
                    &unit,
                    "job.retry",
                    Some("0".to_string()),
                    Resolution::PlatformDefault,
                    vec![
                        ProvenanceStep::new(rel_path, &jpath("retry"), "absent"),
                        ProvenanceStep::new("", "retry", "platform-default"),
                    ],
                )),
            }

            // job.allow_failure: explicit, else the documented default —
            // `true` for manual jobs, `false` otherwise. That nuance is a
            // FORMAT fact (GitLab docs), not a judgment, so it belongs here.
            match get(job, "allow_failure") {
                Some(v) => out.packets.push(packet(
                    &unit,
                    "job.allow_failure",
                    Some(render_value(v)),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(
                        rel_path,
                        &jpath("allow_failure"),
                        "explicit",
                    )],
                )),
                None => {
                    let manual = get(job, "when").and_then(Value::as_str) == Some("manual");
                    let default = if manual { "true" } else { "false" };
                    out.packets.push(packet(
                        &unit,
                        "job.allow_failure",
                        Some(default.to_string()),
                        Resolution::PlatformDefault,
                        vec![
                            ProvenanceStep::new(rel_path, &jpath("allow_failure"), "absent"),
                            ProvenanceStep::new(
                                "",
                                if manual {
                                    "allow_failure (manual job)"
                                } else {
                                    "allow_failure"
                                },
                                "platform-default",
                            ),
                        ],
                    ));
                }
            }
        }
        out
    }
}

fn get<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(yaml: &str) -> Retrieved {
        GitlabCi.retrieve(".gitlab-ci.yml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    #[test]
    fn matches_only_the_root_file() {
        assert!(GitlabCi.matches(".gitlab-ci.yml"));
        assert!(!GitlabCi.matches("sub/.gitlab-ci.yml"));
        assert!(!GitlabCi.matches(".github/workflows/ci.yml"));
    }

    #[test]
    fn job_timeout_falls_through_the_default_block_with_a_chain() {
        let got = packets("default:\n  timeout: 30m\nbuild:\n  script: make\n");
        let p = find(&got, "job:build", "job.timeout");
        assert_eq!(p.resolved_value.as_deref(), Some("30m"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].key_path, "default.timeout");
        assert_eq!(p.provenance[1].role, "default-block");
    }

    #[test]
    fn job_timeout_without_any_committed_setting_is_unresolvable() {
        // The project-level timeout is a GitLab setting; the repo cannot know
        // it, so the packet is unresolvable and the lane will abstain.
        let got = packets("build:\n  script: make\n");
        let p = find(&got, "job:build", "job.timeout");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance.last().unwrap().role, "project-setting");
    }

    #[test]
    fn explicit_job_timeout_wins_over_the_default_block() {
        let got = packets("default:\n  timeout: 30m\nbuild:\n  script: make\n  timeout: 90m\n");
        let p = find(&got, "job:build", "job.timeout");
        assert_eq!(p.resolved_value.as_deref(), Some("90m"));
        assert_eq!(p.provenance.len(), 1);
    }

    #[test]
    fn reserved_sections_and_hidden_templates_are_not_jobs() {
        let got = packets(
            "stages: [test]\nvariables:\n  X: '1'\n.template:\n  script: shared\nbuild:\n  script: make\n",
        );
        assert!(
            got.packets.iter().all(|p| p.unit == "job:build"),
            "only real jobs emit packets: {:?}",
            got.packets
        );
    }

    #[test]
    fn manual_jobs_default_allow_failure_true_others_false() {
        let got = packets("deploy:\n  script: ship\n  when: manual\nbuild:\n  script: make\n");
        assert_eq!(
            find(&got, "job:deploy", "job.allow_failure")
                .resolved_value
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            find(&got, "job:build", "job.allow_failure")
                .resolved_value
                .as_deref(),
            Some("false")
        );
    }

    #[test]
    fn retry_defaults_to_zero_and_renders_structured_values() {
        let got = packets("build:\n  script: make\n  retry:\n    max: 2\nlint:\n  script: lint\n");
        assert_eq!(
            find(&got, "job:build", "job.retry")
                .resolved_value
                .as_deref(),
            Some(r#"{"max":2}"#)
        );
        let lint = find(&got, "job:lint", "job.retry");
        assert_eq!(lint.resolved_value.as_deref(), Some("0"));
        assert_eq!(lint.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn include_only_files_are_valid_and_emit_nothing() {
        let got = packets("include:\n  - project: group/ci\n    file: ci.yml\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0, "an include-only file is not malformed");
    }

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("build: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }
}
