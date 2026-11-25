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
//!   * `job.post-deploy-check` (RC-058) — on a job whose script deploys:
//!     `none`, or `undecided:` and why, with the guard predicate
//!     `job.deploy-class` (see [`crate::deploy_check`]). A script entry
//!     that deploys is the deploy step; what may check it is a later entry
//!     of the job or its `after_script`, the deploy entry itself, or a job
//!     of a later stage.
//!
//! `include:`-only files are valid GitLab CI and emit zero packets (the
//! included files are not fetched: no remote reads on the scan path).

use crate::deploy_check;
use crate::{
    render_value, ConfigPacket, ConfigPredicate, ConfigRetriever, ProvenanceStep, Resolution,
    Retrieved,
};
use serde_yaml::{Mapping, Value};

pub struct GitlabCi;

/// The stages of a pipeline with no `stages:` list, in order.
const DEFAULT_STAGES: &[&str] = &["build", "test", "deploy"];

/// The stage of a job with no `stage:`.
const DEFAULT_STAGE: &str = "test";

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

    /// The scanned root's name says whether the repository is sample
    /// material, on which the post-deploy check fact abstains.
    fn retrieve_with_root(
        &self,
        root: &std::path::Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        let mut out = self.retrieve(rel_path, contents, snapshot_id);
        if let Some(t) = crate::non_production::root_token(root) {
            let why = format!("non-production repository: {t}");
            for p in out
                .packets
                .iter_mut()
                .filter(|p| p.key == deploy_check::KEY)
            {
                crate::non_production::undecide(p, &why);
            }
        }
        out
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
            key: crate::key_ledger::declared("gitlab-ci", key),
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

            // job.post-deploy-check: only a job whose script deploys.
            if let Some((value, class, at)) = post_deploy(contents, root, job_id, job) {
                out.packets.push(packet(
                    &unit,
                    deploy_check::KEY,
                    Some(value),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(rel_path, &at, "explicit")],
                ));
                out.predicates.push(ConfigPredicate {
                    file_path: rel_path.to_string(),
                    unit: unit.clone(),
                    key: crate::key_ledger::declared("gitlab-ci", deploy_check::CLASS_KEY),
                    values: vec![class.to_string()],
                });
            }

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

/// The script entries of a job's `key` (a list, or one string).
fn entries<'a>(job: &'a Mapping, key: &str) -> Vec<&'a str> {
    match get(job, key) {
        Some(Value::String(s)) => vec![s.as_str()],
        Some(Value::Sequence(seq)) => seq.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

/// The position of a job's stage in the pipeline, or None for a stage the
/// pipeline does not list.
fn stage_index(root: &Mapping, job: &Mapping) -> Option<usize> {
    let listed: Vec<&str> = match get(root, "stages").and_then(Value::as_sequence) {
        Some(seq) => seq.iter().filter_map(Value::as_str).collect(),
        None => DEFAULT_STAGES.to_vec(),
    };
    let stage = get(job, "stage")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_STAGE);
    std::iter::once(".pre")
        .chain(listed)
        .chain(std::iter::once(".post"))
        .position(|s| s == stage)
}

/// A job's RC-058 facts: the [`deploy_check::KEY`] value, the
/// [`deploy_check::CLASS_KEY`] value and the path of the deploy entry, or
/// None when no script entry deploys.
fn post_deploy(
    contents: &str,
    root: &Mapping,
    job_id: &str,
    job: &Mapping,
) -> Option<(String, &'static str, String)> {
    let script: Vec<(&str, usize, &str)> = ["before_script", "script"]
        .into_iter()
        .flat_map(|k| {
            entries(job, k)
                .into_iter()
                .enumerate()
                .map(move |(i, e)| (k, i, e))
        })
        .collect();
    let (at, deploy) = script
        .iter()
        .enumerate()
        .rev()
        .find_map(|(at, (_, _, e))| deploy_check::in_run(e).map(|d| (at, d)))?;
    let (key, idx, own) = script[at];
    let path = format!("{job_id}.{key}[{idx}] deploys: {}", deploy.kind);

    let env = get(job, "environment").and_then(deploy_check::environment_name);
    let conditions: String = ["only", "rules"]
        .iter()
        .filter_map(|k| get(job, k))
        .map(deploy_check::text_of)
        .collect();
    let checked =
        |w: String, at: String| Some(format!("a check may follow the deploy: {at} ({w})"));
    let why = if let Some(m) = deploy_check::test_cluster(contents) {
        Some(format!("test cluster or rehearsal in the pipeline: {m}"))
    } else if let Some(t) = [Some(job_id), env]
        .into_iter()
        .flatten()
        .find_map(deploy_check::non_production_token)
    {
        Some(format!("non-production job: {t}"))
    } else if conditions.contains("merge_request") {
        Some("deploys a merge request".to_string())
    } else if let Some(m) = deploy_check::preview(own) {
        Some(format!("deploys a pull request or a preview: {m}"))
    } else if let Some(w) = deploy_check::check_word(own) {
        checked(w, "the deploy entry".into())
    } else if let Some(w) = script[at + 1..]
        .iter()
        .map(|(_, _, e)| *e)
        .chain(entries(job, "after_script"))
        .find_map(deploy_check::check_word)
    {
        checked(w, "a later script entry".into())
    } else {
        let stage = stage_index(root, job);
        root.iter()
            .filter_map(|(k, v)| Some((k.as_str()?, v.as_mapping()?)))
            .filter(|(k, _)| !RESERVED.contains(k) && !k.starts_with('.'))
            .filter(|(_, j)| stage.is_some_and(|s| stage_index(root, j).is_some_and(|o| o > s)))
            .find_map(|(k, j)| {
                let text: String = std::iter::once(k.to_string())
                    .chain(
                        ["before_script", "script", "after_script"]
                            .iter()
                            .flat_map(|f| entries(j, f))
                            .map(str::to_string),
                    )
                    .collect::<Vec<_>>()
                    .join(" ");
                deploy_check::check_word(&text).map(|w| (k, w))
            })
            .and_then(|(k, w)| checked(w, format!("job {k} of a later stage")))
    };
    Some((deploy_check::value(why), deploy.class(), path))
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

    /// `job.post-deploy-check` and `job.deploy-class` of each deploy job.
    fn deploy_sites(got: &Retrieved) -> Vec<(String, String, String)> {
        got.packets
            .iter()
            .filter(|p| p.key == deploy_check::KEY)
            .map(|p| {
                let class = got
                    .predicates
                    .iter()
                    .find(|f| f.unit == p.unit && f.key == deploy_check::CLASS_KEY)
                    .map(|f| f.values.join(","))
                    .unwrap_or_default();
                (p.unit.clone(), p.resolved_value.clone().unwrap(), class)
            })
            .collect()
    }

    const PIPELINE: &str = "stages: [build, deploy, verify]\nbuild:\n  stage: build\n  script: make\ndeploy:\n  stage: deploy\n  environment: production\n  script:\n    - echo deploying\n    - kubectl apply -f k8s/\n";

    #[test]
    fn a_deploy_job_with_nothing_after_it_is_none_and_its_twin_is_not() {
        let got = packets(PIPELINE);
        assert_eq!(
            deploy_sites(&got),
            vec![("job:deploy".into(), "none".into(), "deploy".into())]
        );
        assert_eq!(
            find(&got, "job:deploy", deploy_check::KEY).provenance[0].key_path,
            "deploy.script[1] deploys: kubectl apply"
        );
        let later = format!("{PIPELINE}smoke:\n  stage: verify\n  script: ./smoke.sh\n");
        assert_eq!(
            deploy_sites(&packets(&later))[0].1,
            "undecided: a check may follow the deploy: job smoke of a later stage (smoke)"
        );
        let after = PIPELINE.replace(
            "    - kubectl apply -f k8s/\n",
            "    - kubectl apply -f k8s/\n    - curl -f https://example.com/\n",
        );
        assert_eq!(
            deploy_sites(&packets(&after))[0].1,
            "undecided: a check may follow the deploy: a later script entry (curl)"
        );
    }

    #[test]
    fn an_earlier_stage_is_no_check_and_a_terraform_apply_is_its_own_class() {
        let earlier = PIPELINE.replace(
            "build:\n  stage: build\n  script: make",
            "test:\n  stage: build\n  script: make test",
        );
        assert_eq!(deploy_sites(&packets(&earlier))[0].1, "none");
        let tf = "apply:\n  stage: deploy\n  script:\n    - terraform init\n    - terraform apply -auto-approve\n";
        assert_eq!(
            deploy_sites(&packets(tf)),
            vec![("job:apply".into(), "none".into(), "terraform".into())]
        );
    }

    #[test]
    fn non_production_and_merge_request_deploys_abstain() {
        for (yaml, want) in [
            (
                PIPELINE.replace("environment: production", "environment:\n    name: review/$CI_COMMIT_REF_SLUG"),
                "non-production job: review",
            ),
            (
                format!("{PIPELINE}  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n"),
                "deploys a merge request",
            ),
            (
                format!("{PIPELINE}e2e:\n  stage: build\n  script: k3d cluster create ci\n"),
                "test cluster or rehearsal in the pipeline: k3d",
            ),
        ] {
            let got = deploy_sites(&packets(&yaml));
            assert_eq!(
                got.iter().find(|s| s.0 == "job:deploy").unwrap().1,
                format!("undecided: {want}"),
                "{yaml}"
            );
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("gitlab-examples");
        let got = GitlabCi.retrieve_with_root(&root, ".gitlab-ci.yml", PIPELINE, "snap");
        assert_eq!(
            deploy_sites(&got)[0].1,
            "undecided: non-production repository: examples"
        );
    }

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("build: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }
}
