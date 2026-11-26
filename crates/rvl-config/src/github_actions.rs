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
//! Alongside the packets it states the PREDICATES a conditional spec's guard
//! is judged against (po-av01j.133.10). These are facts about what a unit is,
//! not settings, so they are never packets:
//!
//!   * `workflow.triggers` — the event names under `on:`, for the whole file.
//!   * `job.publishes_image` — whether the job's own steps push a container
//!     image. Withheld when the steps are out of sight (a reusable-workflow
//!     call), so a guard on it abstains rather than closing on a guess.
//!   * `workflow.publishes_image` — any job does; withheld if any is unknown.
//!
//! A unit that hands a static cloud key from `secrets` to its tools gets
//! `credential.static-cloud-key` (RC-072): the provider, or `undecided:`
//! and why (see `static_key`).
//!
//! A job that publishes also gets `job.release_supply_chain`: which RC-079
//! rule the file proves about its SBOM, provenance and pins (see `release`).
//!
//! A job that deploys gets `job.post-deploy-check` (RC-058): `none`, or
//! `undecided:` and why, with the guard predicate `job.deploy-class` (see
//! `post_deploy`).
//!
//! Anything else in a workflow file is not inventoried: the key list is
//! spec-driven, exactly as the typed retrievers only inventory client calls.

use crate::{
    render_value, ConfigPacket, ConfigPredicate, ConfigRetriever, ProvenanceStep, Resolution,
    Retrieved, FILE_SCOPE,
};
use serde_yaml::Value;

mod post_deploy;
mod release;
mod static_key;

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

    /// The scanned root's name says whether the repository is sample
    /// material, which the static cloud key fact abstains on.
    fn retrieve_with_root(
        &self,
        root: &std::path::Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        retrieve_in(
            crate::non_production::root_token(root),
            rel_path,
            contents,
            snapshot_id,
            &post_deploy::FollowUps::read([(rel_path, contents)]),
        )
    }

    /// Every workflow of the scan is read once for the follow-up workflows
    /// a deploy job's fact asks about.
    fn retrieve_all(
        &self,
        root: &std::path::Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let follow_ups =
            post_deploy::FollowUps::read(files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
        let repo = crate::non_production::root_token(root);
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            let got = retrieve_in(repo, rel, contents, snapshot_id, &follow_ups);
            out.packets.extend(got.packets);
            out.predicates.extend(got.predicates);
            out.unparseable += got.unparseable;
            out.sightings.extend(got.sightings);
        }
        out
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

/// The event names under `on:`, sorted, or None when the key is missing or in
/// a shape that names no event.
fn triggers(root: &serde_yaml::Mapping) -> Option<Vec<String>> {
    // YAML 1.1 reads a bare `on` key as the boolean true; accept either so the
    // fact does not depend on which YAML version the parser implements.
    let on = get(root, "on").or_else(|| root.get(Value::Bool(true)))?;
    let mut events: Vec<String> = match on {
        Value::String(s) => vec![s.clone()],
        Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        Value::Mapping(m) => m
            .keys()
            .filter_map(|k| k.as_str().map(str::to_string))
            .collect(),
        _ => return None,
    };
    events.sort();
    events.dedup();
    (!events.is_empty()).then_some(events)
}

/// Whether one step pushes a container image: the evidence is the PUSH, so a
/// build-only step does not count.
fn step_publishes_image(step: &serde_yaml::Mapping) -> bool {
    if let Some(uses) = get(step, "uses").and_then(Value::as_str) {
        if uses.split('@').next() == Some("docker/build-push-action") {
            // `push` defaults to false. Anything but a literal false is an
            // expression that pushes on some event, which is what a guard asks.
            return match get(step, "with")
                .and_then(Value::as_mapping)
                .and_then(|w| get(w, "push"))
            {
                None | Some(Value::Bool(false)) | Some(Value::Null) => false,
                Some(Value::String(s)) => s != "false",
                Some(_) => true,
            };
        }
    }
    get(step, "run").and_then(Value::as_str).is_some_and(|run| {
        run.lines().any(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            words.windows(2).any(|w| w == ["docker", "push"])
                || (words.contains(&"docker") && words.contains(&"--push"))
        })
    })
}

fn retrieve(rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
    let follow_ups = post_deploy::FollowUps::read([(rel_path, contents)]);
    retrieve_in(None, rel_path, contents, snapshot_id, &follow_ups)
}

/// Retrieve one file; `repo` is the scanned root's sample token, if any,
/// and `follow_ups` what the scan's workflows say runs after another.
fn retrieve_in(
    repo: Option<&'static str>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
    follow_ups: &post_deploy::FollowUps,
) -> Retrieved {
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
                    key: crate::key_ledger::declared("github-actions", "step.uses.ref"),
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
        key: crate::key_ledger::declared("github-actions", key),
        resolved_value: value,
        resolution,
        provenance,
    };

    let predicate = |unit: &str, key: &str, values: Vec<String>| ConfigPredicate {
        file_path: rel_path.to_string(),
        unit: unit.to_string(),
        key: crate::key_ledger::declared("github-actions", key),
        values,
    };
    if let Some(events) = triggers(root) {
        out.predicates
            .push(predicate(FILE_SCOPE, "workflow.triggers", events));
    }
    // Some(any job publishes), or None once any job's steps are out of sight.
    let mut wf_publishes = Some(false);

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

    // credential.static-cloud-key: the provider of a static key the unit
    // reads from `secrets`, emitted only where there is one.
    let stem = rel_path.rsplit('/').next().unwrap_or(rel_path);
    let stem = stem.rsplit_once('.').map_or(stem, |(s, _)| s);
    let static_key_packet = |unit: &str, at: &str, k: &static_key::StaticKey, job_id| {
        let cx = static_key::Context {
            repo,
            stem,
            job_id,
            contents,
        };
        packet(
            unit,
            "credential.static-cloud-key",
            Some(static_key::value(k, &cx)),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(
                rel_path,
                &format!("{at}.{} = secrets.{}", k.key, k.secret),
                "explicit",
            )],
        )
    };
    if let Some(k) = static_key::in_env(root) {
        out.packets
            .push(static_key_packet("workflow", "env", &k, None));
    }
    let deploy_wf =
        post_deploy::Workflow::new(repo, rel_path, stem, contents, root, jobs, follow_ups);

    for (job_key, job_val) in jobs {
        let Some(job_id) = job_key.as_str() else {
            continue;
        };
        let Some(job) = job_val.as_mapping() else {
            continue;
        };
        let unit = format!("job:{job_id}");
        let jpath = |k: &str| format!("jobs.{job_id}.{k}");

        // job.publishes_image: decidable only from the job's OWN steps. A job
        // that calls a reusable workflow runs steps this file does not hold.
        match get(job, "steps").and_then(Value::as_sequence) {
            Some(steps) if get(job, "uses").is_none() => {
                let publishes = steps
                    .iter()
                    .filter_map(Value::as_mapping)
                    .any(step_publishes_image);
                out.predicates.push(predicate(
                    &unit,
                    "job.publishes_image",
                    vec![publishes.to_string()],
                ));
                wf_publishes = wf_publishes.map(|any| any || publishes);
            }
            _ => wf_publishes = None,
        }

        // job.release_supply_chain: only a job that publishes is judged.
        if let Some(r) = release::judge(jobs, job_id, job) {
            out.packets.push(packet(
                &unit,
                "job.release_supply_chain",
                Some(r.value),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(rel_path, &r.publish_path, "explicit")],
            ));
        }

        // job.post-deploy-check: only a job that deploys is judged.
        if let Some(site) = post_deploy::judge(&deploy_wf, job_id, job) {
            out.packets.push(packet(
                &unit,
                crate::deploy_check::KEY,
                Some(site.value),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(rel_path, &site.path, "explicit")],
            ));
            out.predicates.push(predicate(
                &unit,
                crate::deploy_check::CLASS_KEY,
                vec![site.class.to_string()],
            ));
        }

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

        if let Some(k) = static_key::in_env(job) {
            out.packets
                .push(static_key_packet(&unit, &jpath("env"), &k, Some(job_id)));
        }
        let steps = get(job, "steps").and_then(Value::as_sequence);
        for (idx, step) in steps.into_iter().flatten().enumerate() {
            if let Some((k, field)) = step.as_mapping().and_then(static_key::in_step) {
                out.packets.push(static_key_packet(
                    &format!("step:{job_id}/{idx}"),
                    &jpath(&format!("steps[{idx}].{field}")),
                    &k,
                    Some(job_id),
                ));
            }
        }

        // step.uses.ref: the version reference of each external action.
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
    if let Some(publishes) = wf_publishes {
        out.predicates.push(predicate(
            FILE_SCOPE,
            "workflow.publishes_image",
            vec![publishes.to_string()],
        ));
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

    /// `credential.static-cloud-key` per unit of one workflow file.
    fn static_keys(path: &str, yaml: &str) -> Vec<(String, String)> {
        retrieve(path, yaml, "s")
            .packets
            .into_iter()
            .filter(|p| p.key == "credential.static-cloud-key")
            .map(|p| (p.unit, p.resolved_value.unwrap_or_default()))
            .collect()
    }

    fn one_step(with: &str) -> String {
        format!("on: push\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n{with}")
    }

    #[test]
    fn a_static_cloud_key_from_secrets_is_flagged_per_provider() {
        let wf = ".github/workflows/deploy.yml";
        for (step, provider) in [
            (
                "      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n          aws-region: us-east-1\n",
                "aws",
            ),
            (
                "      - uses: google-github-actions/auth@v2\n        with:\n          credentials_json: ${{ secrets.GCP_SA_KEY }}\n",
                "gcp",
            ),
            (
                "      - uses: azure/login@v2\n        with:\n          creds: ${{ secrets.AZURE_CREDENTIALS }}\n",
                "azure",
            ),
            (
                "      - run: terraform apply\n        env:\n          ARM_CLIENT_SECRET: ${{ secrets.ARM_CLIENT_SECRET }}\n",
                "azure",
            ),
        ] {
            assert_eq!(
                static_keys(wf, &one_step(step)),
                vec![("step:deploy/0".to_string(), provider.to_string())],
                "{step}"
            );
        }
    }

    // The twins: a federated login, a key that is not from `secrets`, and a
    // `creds` input of an action other than azure/login (a GitHub App's).
    #[test]
    fn federated_logins_and_other_credentials_carry_no_static_cloud_key() {
        let wf = ".github/workflows/deploy.yml";
        for step in [
            "      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/example\n          aws-region: us-east-1\n",
            "      - uses: google-github-actions/auth@v2\n        with:\n          workload_identity_provider: ${{ vars.WIF_PROVIDER }}\n          service_account: example@example.iam.gserviceaccount.com\n",
            "      - uses: azure/login@v2\n        with:\n          client-id: ${{ secrets.AZURE_CLIENT_ID }}\n          tenant-id: ${{ secrets.AZURE_TENANT_ID }}\n",
            "      - uses: some-org/deploy-pages@v1\n        with:\n          creds: ${{ secrets.GH_APP_CREDS }}\n",
            "      - run: aws s3 ls\n        env:\n          AWS_ACCESS_KEY_ID: example\n          AWS_SECRET_ACCESS_KEY: ${{ vars.EXAMPLE }}\n",
        ] {
            assert_eq!(static_keys(wf, &one_step(step)), vec![], "{step}");
        }
    }

    #[test]
    fn job_and_workflow_env_keys_are_their_own_units() {
        let got = static_keys(
            ".github/workflows/release.yml",
            "on: push\nenv:\n  GOOGLE_CREDENTIALS: ${{ secrets.GOOGLE_CREDENTIALS }}\njobs:\n  publish:\n    env:\n      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n    steps:\n      - run: make publish\n",
        );
        assert_eq!(
            got,
            vec![
                ("workflow".to_string(), "gcp".to_string()),
                ("job:publish".to_string(), "aws".to_string()),
            ]
        );
        let p = retrieve(
            ".github/workflows/release.yml",
            "on: push\njobs:\n  publish:\n    env:\n      AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}\n",
            "s",
        )
        .packets
        .into_iter()
        .find(|p| p.key == "credential.static-cloud-key")
        .unwrap();
        assert_eq!(
            p.provenance[0].key_path,
            "jobs.publish.env.AWS_ACCESS_KEY_ID = secrets.AWS_ACCESS_KEY_ID",
            "the provenance names the secret, never a value"
        );
    }

    #[test]
    fn a_static_cloud_key_abstains_where_the_frame_says_it_may() {
        let undecided = |path: &str, yaml: &str| {
            let got = static_keys(path, yaml);
            assert_eq!(got.len(), 1, "{path}: {got:?}");
            got[0]
                .1
                .strip_prefix(crate::UNDECIDED_PREFIX)
                .map(str::to_string)
        };
        let aws = |secret: &str, extra: &str| {
            one_step(&format!(
                "      - run: aws s3 sync . s3://example\n        env:\n          AWS_ACCESS_KEY_ID: ${{{{ secrets.{secret} }}}}\n{extra}"
            ))
        };
        let wf = ".github/workflows/deploy.yml";
        assert_eq!(undecided(wf, &aws("AWS_ACCESS_KEY_ID", "")), None);
        assert_eq!(
            undecided(
                wf,
                &aws(
                    "AWS_ACCESS_KEY_ID",
                    "          AWS_SESSION_TOKEN: ${{ secrets.AWS_SESSION_TOKEN }}\n"
                )
            )
            .as_deref(),
            Some("a federation or session input is beside the key")
        );
        assert_eq!(
            undecided(wf, &aws("R2_ACCESS_KEY_ID", "")).as_deref(),
            Some("S3-compatible third party: R2")
        );
        assert_eq!(
            undecided(
                wf,
                &aws(
                    "AWS_ACCESS_KEY_ID",
                    "          AWS_ENDPOINT_URL: https://example.r2.cloudflarestorage.com\n"
                )
            )
            .as_deref(),
            Some("S3-compatible third party: ENDPOINT")
        );
        assert_eq!(
            undecided(
                ".github/workflows/deploy-backend-dev.yml",
                &aws("AWS_ACCESS_KEY_ID", "")
            )
            .as_deref(),
            Some("non-production workflow: dev")
        );
        assert_eq!(
            undecided(
                ".github/workflows/ci-deploy.yml",
                &aws("AWS_ACCESS_KEY_ID", "")
            ),
            None,
            "a ci workflow deploys"
        );
        assert_eq!(
            undecided(
                wf,
                &aws("AWS_ACCESS_KEY_ID", "").replace("  deploy:", "  e2e_tests:")
            )
            .as_deref(),
            Some("non-production job: e2e")
        );

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cloud-samples");
        let got = GithubActions.retrieve_with_root(&root, wf, &aws("AWS_ACCESS_KEY_ID", ""), "s");
        let p = got
            .packets
            .iter()
            .find(|p| p.key == "credential.static-cloud-key")
            .unwrap();
        assert_eq!(
            p.resolved_value.as_deref(),
            Some("undecided: non-production repository: samples")
        );
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

    // ---- po-av01j.133.10: guard predicates for conditional specs ----

    fn fact<'a>(got: &'a Retrieved, unit: &str, key: &str) -> Option<&'a [String]> {
        got.predicates
            .iter()
            .find(|f| f.unit == unit && f.key == key)
            .map(|f| f.values.as_slice())
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // `on:` has three authored shapes and all three name the same set.
    #[test]
    fn workflow_triggers_are_read_from_every_shape_of_on() {
        let jobs = "jobs:\n  build:\n    runs-on: x\n";
        for on in [
            "on: [push, pull_request]\n",
            "on:\n  pull_request:\n  push:\n    branches: [main]\n",
        ] {
            let got = packets(&format!("{on}{jobs}"));
            assert_eq!(
                fact(&got, crate::FILE_SCOPE, "workflow.triggers"),
                Some(strs(&["pull_request", "push"]).as_slice()),
                "{on}"
            );
        }
        let got = packets(&format!("on: push\n{jobs}"));
        assert_eq!(
            fact(&got, crate::FILE_SCOPE, "workflow.triggers"),
            Some(strs(&["push"]).as_slice())
        );
    }

    // A fact is not a setting: it must not join the packets, where a key with
    // no spec is queued for the spec factory as unjudged.
    #[test]
    fn predicates_are_not_packets() {
        let got = packets("on: push\njobs:\n  build:\n    runs-on: x\n");
        assert!(!got.predicates.is_empty());
        assert!(
            got.packets
                .iter()
                .all(|p| p.key != "workflow.triggers" && !p.key.ends_with("publishes_image")),
            "{:?}",
            got.packets
        );
    }

    #[test]
    fn a_job_that_pushes_an_image_says_so_and_the_workflow_inherits_it() {
        let got = packets(
            "on: push\njobs:\n  test:\n    steps:\n      - run: make test\n  image:\n    steps:\n      - uses: docker/build-push-action@v6\n        with:\n          push: true\n",
        );
        assert_eq!(
            fact(&got, "job:test", "job.publishes_image"),
            Some(strs(&["false"]).as_slice())
        );
        assert_eq!(
            fact(&got, "job:image", "job.publishes_image"),
            Some(strs(&["true"]).as_slice())
        );
        assert_eq!(
            fact(&got, crate::FILE_SCOPE, "workflow.publishes_image"),
            Some(strs(&["true"]).as_slice())
        );
    }

    #[test]
    fn the_publish_evidence_is_the_push_not_the_build() {
        let publishes = |steps: &str| {
            let got = packets(&format!("on: push\njobs:\n  j:\n    steps:\n{steps}"));
            fact(&got, "job:j", "job.publishes_image").map(|v| v.to_vec())
        };
        // build-push-action defaults to push: false: a build-only job.
        assert_eq!(
            publishes("      - uses: docker/build-push-action@v6\n"),
            Some(strs(&["false"]))
        );
        assert_eq!(
            publishes(
                "      - uses: docker/build-push-action@v6\n        with:\n          push: false\n"
            ),
            Some(strs(&["false"]))
        );
        // An expression pushes on SOME event, which is what the guard asks.
        assert_eq!(
            publishes(
                "      - uses: docker/build-push-action@v6\n        with:\n          push: ${{ github.event_name != 'pull_request' }}\n"
            ),
            Some(strs(&["true"]))
        );
        assert_eq!(
            publishes(
                "      - run: |\n          docker build -t app .\n          docker push app\n"
            ),
            Some(strs(&["true"]))
        );
        assert_eq!(
            publishes("      - run: docker build -t app .\n"),
            Some(strs(&["false"]))
        );
    }

    // A reusable-workflow call hides its steps in another file, possibly
    // another repo. Whether it publishes is unknown, and "false" would close a
    // guard on a guess, so the fact is withheld and the guard abstains.
    #[test]
    fn a_job_whose_steps_are_out_of_sight_emits_no_publish_fact() {
        let got = packets(
            "on: push\njobs:\n  test:\n    steps:\n      - run: make test\n  release:\n    uses: org/repo/.github/workflows/release.yml@v2\n",
        );
        assert_eq!(fact(&got, "job:release", "job.publishes_image"), None);
        assert_eq!(
            fact(&got, crate::FILE_SCOPE, "workflow.publishes_image"),
            None,
            "one unknown job makes the workflow unknown"
        );
        assert_eq!(
            fact(&got, "job:test", "job.publishes_image"),
            Some(strs(&["false"]).as_slice())
        );
    }

    // ---- RC-079: the release job's supply chain ----

    const SHA: &str = "11bd71901bbe5b1630ceea73d27597364c9af683";

    /// The `job.release_supply_chain` verdict of each job, judged by the
    /// pattern a spec maps to RC-079.
    fn release_verdicts(yaml: &str) -> Vec<(String, rvl_core::Verdict, String)> {
        let specs = rvl_spec::SpecCache::load(
            r#"{"config_keys":[{"format":"github-actions","key":"job.release_supply_chain",
                "expect":{"kind":"pattern","name":"release_supply_chain"},"confidence":0.9,
                "control":"RC-079","severity":"medium","fix":"attest and pin the release"}]}"#,
        )
        .expect("the spec file parses");
        let got = packets(yaml);
        got.packets
            .iter()
            .filter(|p| p.key == "job.release_supply_chain")
            .map(|p| {
                let f = crate::eval::evaluate(p, &got.predicates, &specs);
                (p.unit.clone(), f.verdict, f.reason)
            })
            .collect()
    }

    fn one(yaml: &str) -> (rvl_core::Verdict, String) {
        let v = release_verdicts(yaml);
        assert_eq!(v.len(), 1, "one release job: {v:?}");
        let (unit, verdict, reason) = v.into_iter().next().unwrap();
        assert_eq!(unit, "job:release");
        (verdict, reason)
    }

    #[test]
    fn a_publishing_job_with_neither_sbom_nor_provenance_violates_m1() {
        let (verdict, reason) = one(&format!(
            "on: push\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@{SHA}\n      - run: npm publish\n"
        ));
        assert_eq!(verdict, rvl_core::Verdict::Violates, "{reason}");
        assert!(
            reason.contains("M1: no SBOM step and no provenance step"),
            "{reason}"
        );
        assert!(!reason.contains("M2b"), "{reason}");
    }

    #[test]
    fn sbom_provenance_and_commit_pins_satisfy_s1() {
        let (verdict, reason) = one(&format!(
            "on: push\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@{SHA}\n      - uses: docker/build-push-action@{SHA}\n        with:\n          push: true\n          sbom: true\n          provenance: mode=max\n"
        ));
        assert_eq!(verdict, rvl_core::Verdict::Satisfies, "{reason}");
        assert!(reason.contains("S1:"), "{reason}");
        // The attestation may be its own job, one that needs the release job.
        let (verdict, reason) = one(&format!(
            "on: push\njobs:\n  release:\n    steps:\n      - uses: softprops/action-gh-release@{SHA}\n      - uses: anchore/sbom-action@{SHA}\n  provenance:\n    needs: [release]\n    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0\n"
        ));
        assert_eq!(verdict, rvl_core::Verdict::Satisfies, "{reason}");
    }

    #[test]
    fn an_action_pinned_by_tag_violates_m2b_and_is_named() {
        let (verdict, reason) = one(&format!(
            "on: push\njobs:\n  release:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: pypa/gh-action-pypi-publish@release/v1\n      - uses: anchore/sbom-action@{SHA}\n      - uses: actions/attest-build-provenance@{SHA}\n"
        ));
        assert_eq!(verdict, rvl_core::Verdict::Violates, "{reason}");
        assert!(
            reason.contains("M2b: actions/checkout@v4, pypa/gh-action-pypi-publish@release/v1"),
            "{reason}"
        );
        assert!(!reason.contains("M1"), "{reason}");
    }

    #[test]
    fn a_job_that_does_not_publish_gets_no_entry() {
        assert!(release_verdicts(
            "on: push\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm publish --dry-run\n      - uses: docker/build-push-action@v6\n      - uses: goreleaser/goreleaser-action@v6\n        with:\n          args: release --snapshot\n"
        )
        .is_empty());
    }

    // M1 asks about what the file shows. Each of these may make an SBOM or a
    // provenance attestation out of its sight, so the job abstains.
    #[test]
    fn m1_abstains_when_an_attestation_may_be_out_of_sight() {
        for steps in [
            "      - uses: goreleaser/goreleaser-action@SHA\n        with:\n          args: release --clean\n",
            "      - uses: docker/build-push-action@SHA\n        with:\n          push: true\n",
            "      - uses: ./.github/actions/sign\n      - run: twine upload dist/*\n",
        ] {
            let (verdict, reason) = one(&format!(
                "on: push\njobs:\n  release:\n    steps:\n{}",
                steps.replace("SHA", SHA)
            ));
            assert_eq!(verdict, rvl_core::Verdict::Abstain, "{steps}: {reason}");
        }
        let (verdict, reason) = one(
            "on: push\njobs:\n  release:\n    steps:\n      - run: gh release upload v1 dist/*\n  notes:\n    uses: org/repo/.github/workflows/notes.yml@main\n",
        );
        assert_eq!(verdict, rvl_core::Verdict::Abstain, "{reason}");
    }

    // One of the two is not S1 and not M1.
    #[test]
    fn an_sbom_without_provenance_abstains() {
        let (verdict, reason) = one(&format!(
            "on: push\njobs:\n  release:\n    steps:\n      - run: ko build ./cmd/app\n      - uses: actions/checkout@{SHA}\n"
        ));
        assert_eq!(verdict, rvl_core::Verdict::Abstain, "{reason}");
        assert!(
            reason.contains("an SBOM step and no provenance step"),
            "{reason}"
        );
    }
}
