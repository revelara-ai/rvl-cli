//! GitHub Actions workflow retriever (`.github/workflows/*.yml`): the first
//! format of family (1), and the format that proves the lane machinery on the
//! cleanest case (wayfinder po-ae75b.1 item 2).
//!
//! Emits FACTS about the keys the G6 control set cares about (change
//! management RC-013/014, supply chain RC-045, least privilege RC-044):
//!
//!   * `job.timeout-minutes` — explicit, else the documented 360-minute
//!     platform default.
//!   * `job.continue-on-error` — explicit, else the documented `false`.
//!   * `job.permissions` — job-level, else inherited from the workflow-level
//!     `permissions:` (the provenance chain records the inheritance), else
//!     UNRESOLVABLE: the GITHUB_TOKEN default is an org/repo setting no
//!     committed file can see.
//!   * `workflow.concurrency` — explicit, else the documented "none".
//!   * `step.uses.ref` — the version reference of every external
//!     `owner/repo@ref` action (the pinning control's evidence). Local
//!     (`./...`) and `docker://` steps carry no GitHub ref and emit nothing.
//!
//! Anything else in a workflow file is not inventoried: the key list is
//! spec-driven, exactly as the typed retrievers only inventory client calls.

use crate::{render_value, ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};
use serde_yaml::Value;

pub struct GithubActions;

/// The documented default for `jobs.<id>.timeout-minutes` (6 hours).
const DEFAULT_TIMEOUT_MINUTES: &str = "360";

impl ConfigRetriever for GithubActions {
    fn format_id(&self) -> &'static str {
        "github-actions"
    }

    /// Workflows live ONLY at `.github/workflows/*.yml|yaml` relative to the
    /// repo root — one directory deep, so a vendored or fixture copy under
    /// some other tree never parses as this repo's CI.
    fn matches(&self, rel_path: &str) -> bool {
        if let Some(name) = rel_path.strip_prefix(".github/workflows/") {
            return !name.contains('/') && (name.ends_with(".yml") || name.ends_with(".yaml"));
        }
        // COMPOSITE ACTION DEFINITIONS (po-av01j round 11). An agent lens found
        // two unpinned third-party actions in .github/actions/*/action.yaml that
        // this retriever could not see at all: the workflows/ prefix excluded
        // every composite action in existence, and those files pull the same
        // third-party code into the same jobs with the same credentials.
        //
        // Matched by BASENAME, which is GitHub's own rule -- an action is
        // defined by an action.yml at the root of its directory -- so it also
        // covers a repository that IS an action and defines one at its root.
        let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
        base == "action.yml" || base == "action.yaml"
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        retrieve(rel_path, contents, snapshot_id)
    }
}

/// Split a `uses:` value into (action, ref), or None when it is not a
/// third-party reference worth pinning.
///
/// Local actions are repo-pinned by construction and docker images are a
/// different pinning story (digest), both out of family (1). No `@` at all
/// means entirely unpinned: the ref fact is the empty string, an authored
/// absence rather than a missing packet.
fn split_uses(uses: &str) -> Option<(&str, String)> {
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return None;
    }
    Some(match uses.rsplit_once('@') {
        Some((a, r)) => (a, r.to_string()),
        None => (uses, String::new()),
    })
}

fn retrieve(rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let Ok(doc) = serde_yaml::from_str::<Value>(contents) else {
        out.unparseable = 1;
        return out;
    };
    let Some(root) = doc.as_mapping() else {
        out.unparseable = 1;
        return out;
    };
    // A composite action has no `jobs`; its steps live under `runs.steps`. It
    // is the same supply-chain question in a different shape, so it gets the
    // same key rather than a parallel one -- a spec should not have to be
    // authored twice for `uses:` depending on which file it appears in.
    if get(root, "jobs").is_none() {
        if let Some(steps) = get(root, "runs")
            .and_then(Value::as_mapping)
            .and_then(|r| get(r, "steps"))
            .and_then(Value::as_sequence)
        {
            for (idx, step) in steps.iter().enumerate() {
                let Some(step) = step.as_mapping() else {
                    continue;
                };
                let Some(uses) = get(step, "uses").and_then(Value::as_str) else {
                    continue;
                };
                let Some((action, reference)) = split_uses(uses) else {
                    continue;
                };
                out.packets.push(ConfigPacket {
                    snapshot_id: snapshot_id.to_string(),
                    format: "github-actions".to_string(),
                    file_path: rel_path.to_string(),
                    line: 0,
                    unit: format!("step:runs/{idx}"),
                    key: "step.uses.ref".to_string(),
                    resolved_value: Some(reference),
                    resolution: Resolution::AsAuthored,
                    provenance: vec![ProvenanceStep::new(
                        rel_path,
                        &format!("runs.steps[{idx}].uses = {action}"),
                        "explicit",
                    )],
                });
            }
            return out;
        }
    }
    let Some(jobs) = get(root, "jobs").and_then(Value::as_mapping) else {
        // Parses as YAML but is neither a workflow nor a composite action:
        // counted so coverage says the lane saw and skipped it.
        out.unparseable = 1;
        return out;
    };

    let packet = |unit: &str,
                  key: &str,
                  value: Option<String>,
                  resolution: Resolution,
                  provenance: Vec<ProvenanceStep>| ConfigPacket {
        snapshot_id: snapshot_id.to_string(),
        format: "github-actions".to_string(),
        file_path: rel_path.to_string(),
        line: 0,
        unit: unit.to_string(),
        key: key.to_string(),
        resolved_value: value,
        resolution,
        provenance,
    };

    // Workflow-level facts consulted by the per-job resolution below.
    let wf_permissions = get(root, "permissions");
    let wf_concurrency = get(root, "concurrency");

    // workflow.concurrency: explicit, else the documented default (no
    // concurrency group; every push runs concurrently).
    match wf_concurrency {
        Some(v) => out.packets.push(packet(
            "workflow",
            "workflow.concurrency",
            Some(render_value(v)),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(rel_path, "concurrency", "explicit")],
        )),
        None => out.packets.push(packet(
            "workflow",
            "workflow.concurrency",
            Some("none".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(rel_path, "concurrency", "absent"),
                ProvenanceStep::new("", "concurrency", "platform-default"),
            ],
        )),
    }

    for (job_key, job_val) in jobs {
        let Some(job_id) = job_key.as_str() else {
            continue;
        };
        let Some(job) = job_val.as_mapping() else {
            continue;
        };
        let unit = format!("job:{job_id}");
        let jpath = |k: &str| format!("jobs.{job_id}.{k}");

        // job.timeout-minutes: explicit, else the documented 6h default.
        match get(job, "timeout-minutes") {
            Some(v) => out.packets.push(packet(
                &unit,
                "job.timeout-minutes",
                Some(render_value(v)),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    rel_path,
                    &jpath("timeout-minutes"),
                    "explicit",
                )],
            )),
            None => out.packets.push(packet(
                &unit,
                "job.timeout-minutes",
                Some(DEFAULT_TIMEOUT_MINUTES.to_string()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(rel_path, &jpath("timeout-minutes"), "absent"),
                    ProvenanceStep::new("", "timeout-minutes", "platform-default"),
                ],
            )),
        }

        // job.continue-on-error: explicit, else the documented false.
        match get(job, "continue-on-error") {
            Some(v) => out.packets.push(packet(
                &unit,
                "job.continue-on-error",
                Some(render_value(v)),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    rel_path,
                    &jpath("continue-on-error"),
                    "explicit",
                )],
            )),
            None => out.packets.push(packet(
                &unit,
                "job.continue-on-error",
                Some("false".to_string()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(rel_path, &jpath("continue-on-error"), "absent"),
                    ProvenanceStep::new("", "continue-on-error", "platform-default"),
                ],
            )),
        }

        // job.permissions: job-level overrides workflow-level; with neither,
        // the GITHUB_TOKEN default is an org/repo setting — unresolvable from
        // the repo, and said so rather than guessed.
        match (get(job, "permissions"), wf_permissions) {
            (Some(v), _) => out.packets.push(packet(
                &unit,
                "job.permissions",
                Some(render_value(v)),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    rel_path,
                    &jpath("permissions"),
                    "explicit",
                )],
            )),
            (None, Some(v)) => out.packets.push(packet(
                &unit,
                "job.permissions",
                Some(render_value(v)),
                Resolution::AsAuthored,
                vec![
                    ProvenanceStep::new(rel_path, &jpath("permissions"), "absent"),
                    ProvenanceStep::new(rel_path, "permissions", "inherited"),
                ],
            )),
            (None, None) => out.packets.push(packet(
                &unit,
                "job.permissions",
                None,
                Resolution::Unresolvable,
                vec![
                    ProvenanceStep::new(rel_path, &jpath("permissions"), "absent"),
                    ProvenanceStep::new(rel_path, "permissions", "absent"),
                    ProvenanceStep::new("", "GITHUB_TOKEN default permissions", "repo-setting"),
                ],
            )),
        }

        // job.uses.ref: a job that CALLS A REUSABLE WORKFLOW has `uses:` at
        // job level and no steps at all (po-av01j round 11). This was invisible
        // -- the retriever only ever looked inside `steps` -- and it is the more
        // dangerous of the two, because a reusable workflow executes with the
        // CALLING repository's secrets. The instance found by the agent lens
        // passes a Claude OAuth token and a GitHub App private key to a
        // workflow pinned to a mutable tag.
        //
        // Its own key rather than step.uses.ref: the unit is a job, the
        // provenance path is different, and a spec may reasonably judge a
        // reusable workflow more strictly than a step action.
        if let Some(uses) = get(job, "uses").and_then(Value::as_str) {
            if let Some((called, reference)) = split_uses(uses) {
                out.packets.push(packet(
                    &unit,
                    "job.uses.ref",
                    Some(reference),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(
                        rel_path,
                        &format!("jobs.{job_id}.uses = {called}"),
                        "explicit",
                    )],
                ));
            }
        }

        // step.uses.ref: the version reference of each external action.
        let steps = get(job, "steps").and_then(Value::as_sequence);
        for (idx, step) in steps.into_iter().flatten().enumerate() {
            let Some(step) = step.as_mapping() else {
                continue;
            };
            let Some(uses) = get(step, "uses").and_then(Value::as_str) else {
                continue;
            };
            let Some((action, reference)) = split_uses(uses) else {
                continue;
            };
            out.packets.push(packet(
                &format!("step:{job_id}/{idx}"),
                "step.uses.ref",
                Some(reference),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    rel_path,
                    &format!("jobs.{job_id}.steps[{idx}].uses = {action}"),
                    "explicit",
                )],
            ));
        }
    }
    out
}

/// Mapping lookup by string key. Workflow YAML keys are plain strings; the
/// YAML-1.1 `on:`→bool quirk affects only keys this retriever never reads.
fn get<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(yaml: &str) -> Retrieved {
        GithubActions.retrieve(".github/workflows/ci.yml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    // po-av01j round 11, found by the agent-lens diff. Both shapes below were
    // invisible to this retriever, and both pull third-party code into the same
    // jobs with the same credentials as a step action.
    #[test]
    fn composite_action_definitions_are_claimed_and_their_steps_pinned() {
        let r = GithubActions;
        assert!(r.matches(".github/actions/nightly-release/action.yaml"));
        assert!(r.matches(".github/actions/foo/action.yml"));
        // A repository that IS an action defines one at its root.
        assert!(r.matches("action.yml"));
        // Still not a workflow file in a subdirectory.
        assert!(!r.matches(".github/workflows/nested/ci.yml"));
        assert!(!r.matches("docs/action.md"));

        let got = retrieve(
            ".github/actions/nightly-release/action.yaml",
            "name: nightly\nruns:\n  using: composite\n  steps:\n    - uses: docker/setup-buildx-action@v3\n    - uses: ./local\n    - run: echo hi\n",
            "s",
        );
        assert_eq!(got.unparseable, 0, "a composite action is not unparseable");
        let refs: Vec<_> = got
            .packets
            .iter()
            .filter(|p| p.key == "step.uses.ref")
            .collect();
        assert_eq!(refs.len(), 1, "one third-party step: {:?}", got.packets);
        assert_eq!(refs[0].resolved_value.as_deref(), Some("v3"));
        assert_eq!(refs[0].unit, "step:runs/0");
    }

    // A reusable-workflow call is the MORE dangerous shape: it runs with the
    // calling repository's secrets. It has `uses:` at job level and no steps.
    #[test]
    fn a_job_calling_a_reusable_workflow_emits_its_ref() {
        let got = retrieve(
            ".github/workflows/claude.yml",
            "on: [push]\njobs:\n  claude:\n    uses: org/repo/.github/workflows/w.yml@v2\n    secrets: inherit\n",
            "s",
        );
        let refs: Vec<_> = got
            .packets
            .iter()
            .filter(|p| p.key == "job.uses.ref")
            .collect();
        assert_eq!(refs.len(), 1, "{:?}", got.packets);
        assert_eq!(refs[0].resolved_value.as_deref(), Some("v2"));
        assert_eq!(refs[0].unit, "job:claude");
        // It must NOT be conflated with step.uses.ref: the unit is a job and a
        // spec may reasonably judge it more strictly.
        assert!(got.packets.iter().all(|p| p.key != "step.uses.ref"));
    }

    // An ordinary step-bearing job must be unaffected by the job-level branch.
    #[test]
    fn a_normal_job_still_emits_only_step_refs() {
        let got = retrieve(
            ".github/workflows/ci.yml",
            "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n",
            "s",
        );
        assert!(got.packets.iter().any(|p| p.key == "step.uses.ref"));
        assert!(got.packets.iter().all(|p| p.key != "job.uses.ref"));
    }

    #[test]
    fn matches_only_root_workflow_files() {
        let r = GithubActions;
        assert!(r.matches(".github/workflows/ci.yml"));
        assert!(r.matches(".github/workflows/release.yaml"));
        assert!(!r.matches("sub/.github/workflows/ci.yml"), "not at root");
        assert!(!r.matches(".github/workflows/nested/ci.yml"));
        assert!(!r.matches(".github/workflows/README.md"));
        assert!(!r.matches(".gitlab-ci.yml"));
    }

    #[test]
    fn explicit_timeout_resolves_as_authored_with_explicit_provenance() {
        let got = packets(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n",
        );
        let p = find(&got, "job:build", "job.timeout-minutes");
        assert_eq!(p.resolved_value.as_deref(), Some("15"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(p.provenance[0].key_path, "jobs.build.timeout-minutes");
        assert_eq!(p.provenance[0].role, "explicit");
    }

    #[test]
    fn absent_timeout_resolves_the_documented_platform_default() {
        let got = packets("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
        let p = find(&got, "job:build", "job.timeout-minutes");
        assert_eq!(p.resolved_value.as_deref(), Some("360"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        // The chain says WHY: the job key was consulted and absent, then the
        // platform default supplied the value.
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
        assert_eq!(p.provenance[1].file, "", "a platform default names no file");
    }

    #[test]
    fn job_permissions_inherit_from_workflow_with_a_two_step_chain() {
        let got = packets(
            "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n",
        );
        let p = find(&got, "job:build", "job.permissions");
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.resolved_value.as_deref(), Some(r#"{"contents":"read"}"#));
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[0].role, "absent", "job level consulted first");
        assert_eq!(p.provenance[1].key_path, "permissions");
        assert_eq!(p.provenance[1].role, "inherited");
    }

    #[test]
    fn job_level_permissions_override_workflow_level() {
        let got = packets(
            "on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: write-all\n",
        );
        let p = find(&got, "job:build", "job.permissions");
        assert_eq!(p.resolved_value.as_deref(), Some("write-all"));
        assert_eq!(p.provenance.len(), 1, "job level decided; no chain");
    }

    #[test]
    fn absent_permissions_everywhere_is_unresolvable_not_guessed() {
        // The GITHUB_TOKEN default is an org/repo setting. Nothing in the
        // repo can resolve it, so the packet says so and the lane abstains.
        let got = packets("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
        let p = find(&got, "job:build", "job.permissions");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance.last().unwrap().role, "repo-setting");
    }

    #[test]
    fn workflow_concurrency_defaults_to_none() {
        let got = packets("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n");
        let p = find(&got, "workflow", "workflow.concurrency");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn step_uses_ref_carries_the_pin_fact_for_external_actions() {
        let sha = "8f4b7f84864484a7bf31766abe9204da3cbe65b3";
        let yaml = format!(
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{sha}\n      - uses: actions/setup-go@v5\n      - uses: ./.github/actions/local-thing\n      - uses: docker://alpine:3.20\n      - run: make test\n"
        );
        let got = packets(&yaml);
        let pinned = find(&got, "step:build/0", "step.uses.ref");
        assert_eq!(pinned.resolved_value.as_deref(), Some(sha));
        assert!(pinned.provenance[0].key_path.contains("actions/checkout"));
        let tag = find(&got, "step:build/1", "step.uses.ref");
        assert_eq!(tag.resolved_value.as_deref(), Some("v5"));
        // Local and docker steps carry no GitHub ref: no packet.
        assert!(
            !got.packets
                .iter()
                .any(|p| p.unit.starts_with("step:build/2") || p.unit.starts_with("step:build/3")),
            "local/docker steps emit nothing: {:?}",
            got.packets
        );
    }

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("jobs: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    #[test]
    fn yaml_without_jobs_is_an_unrecognized_workflow_file() {
        // Parses fine, but is not a workflow. The lane must ABSTAIN from
        // judging it (no packets) and count it so coverage is honest.
        let got = packets("some: config\nother: keys\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }
}
