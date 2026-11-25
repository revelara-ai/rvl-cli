//! A GitHub Actions job that deploys, and whether anything checks the
//! deploy after it (RC-058): `job.post-deploy-check` and
//! `job.deploy-class` (see [`crate::deploy_check`]).
//!
//! The deploy step is the job's last step that deploys. Something may check
//! it when a check word ([`deploy_check::check_word`]) is in a later step of
//! the job, in the deploy step's own text beyond its action name, or in the
//! id, name or any step of a job that needs this job, directly or through
//! other jobs; or when a follow-up workflow runs after it (one that names
//! this workflow under `workflow_run`, or any that listens on
//! `deployment_status` or `page_build`).
//!
//! The job abstains, before any of that, when the scanned repository is
//! sample material, the workflow shows a test cluster or a rehearsal, every
//! trigger is a pull-request event, a token of the job id, job name,
//! environment name or workflow file stem names a non-production
//! environment, or the job's `if` or deploy step names a pull request or a
//! preview.

use super::{get, triggers};
use crate::deploy_check::{self, Deploy};
use serde_yaml::{Mapping, Value};
use std::collections::BTreeSet;

/// Pull-request events: a workflow that runs on nothing else deploys no
/// production environment.
const PULL_REQUEST_EVENTS: &[&str] = &[
    "pull_request",
    "pull_request_target",
    "pull_request_review",
    "pull_request_review_comment",
];

/// Events a follow-up workflow listens on to run after any deploy.
const FOLLOW_UP_EVENTS: &[&str] = &["deployment_status", "page_build"];

/// What the repository's workflows say runs after a workflow.
#[derive(Debug, Default)]
pub(super) struct FollowUps {
    /// The workflows other workflows name under `workflow_run`.
    named: BTreeSet<String>,
    /// A [`FOLLOW_UP_EVENTS`] event some workflow listens on.
    listener: Option<&'static str>,
}

impl FollowUps {
    /// Read the workflows among `files` (path and text).
    pub(super) fn read<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut out = FollowUps::default();
        for (path, text) in files {
            if !path.starts_with(".github/workflows/") {
                continue;
            }
            let Ok(Value::Mapping(root)) = serde_yaml::from_str::<Value>(text) else {
                continue;
            };
            let events = triggers(&root).unwrap_or_default();
            if out.listener.is_none() {
                out.listener = FOLLOW_UP_EVENTS
                    .iter()
                    .copied()
                    .find(|e| events.iter().any(|t| t == e));
            }
            let on = get(&root, "on").or_else(|| root.get(Value::Bool(true)));
            let names = on
                .and_then(Value::as_mapping)
                .and_then(|m| get(m, "workflow_run"))
                .and_then(Value::as_mapping)
                .and_then(|m| get(m, "workflows"));
            match names {
                Some(Value::String(s)) => {
                    out.named.insert(s.clone());
                }
                Some(Value::Sequence(seq)) => out
                    .named
                    .extend(seq.iter().filter_map(Value::as_str).map(str::to_string)),
                _ => {}
            }
        }
        out
    }

    /// Why a follow-up workflow may check the workflow at `rel_path`.
    fn of(&self, rel_path: &str, root: &Mapping) -> Option<String> {
        let base = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let name = get(root, "name").and_then(Value::as_str);
        if [Some(rel_path), Some(base), name]
            .into_iter()
            .flatten()
            .any(|n| self.named.contains(n))
        {
            return Some("a workflow_run workflow follows this workflow".into());
        }
        self.listener.map(|e| format!("a workflow listens on {e}"))
    }
}

/// What the whole workflow file says about each of its deploy jobs.
pub(super) struct Workflow<'a> {
    /// Why every deploy job of the file abstains, if anything does.
    why: Option<String>,
    jobs: &'a Mapping,
}

impl<'a> Workflow<'a> {
    /// `repo` is the scanned root's sample token; `stem` the file's stem.
    pub(super) fn new(
        repo: Option<&str>,
        rel_path: &str,
        stem: &str,
        contents: &str,
        root: &'a Mapping,
        jobs: &'a Mapping,
        follow_ups: &FollowUps,
    ) -> Self {
        let pull_requests_only = triggers(root).is_some_and(|events| {
            events
                .iter()
                .all(|e| PULL_REQUEST_EVENTS.contains(&e.as_str()))
        });
        let why = if let Some(t) = repo {
            Some(format!("non-production repository: {t}"))
        } else if let Some(m) = deploy_check::test_cluster(contents) {
            Some(format!("test cluster or rehearsal in the workflow: {m}"))
        } else if pull_requests_only {
            Some("the workflow runs only on pull requests".into())
        } else if let Some(t) = deploy_check::non_production_token(stem) {
            Some(format!("non-production workflow: {t}"))
        } else {
            follow_ups
                .of(rel_path, root)
                .map(|f| format!("a check may follow the deploy: {f}"))
        };
        Workflow { why, jobs }
    }
}

/// One deploy job's facts.
pub(super) struct Site {
    /// The [`deploy_check::KEY`] value.
    pub value: String,
    /// The [`deploy_check::CLASS_KEY`] value.
    pub class: &'static str,
    /// `jobs.<id>.steps[<i>] deploys: <kind>`.
    pub path: String,
}

/// The job's steps that are mappings, with their indexes.
fn steps(job: &Mapping) -> impl Iterator<Item = (usize, &Mapping)> {
    get(job, "steps")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(i, s)| s.as_mapping().map(|s| (i, s)))
}

/// What one step deploys, if anything.
fn deploys(step: &Mapping) -> Option<Deploy> {
    if let Some(uses) = get(step, "uses").and_then(Value::as_str) {
        return deploy_check::in_uses(uses, get(step, "with").and_then(Value::as_mapping));
    }
    deploy_check::in_run(get(step, "run").and_then(Value::as_str)?)
}

/// A step's text: its name, id, inputs and script, and its action unless
/// `uses` is false.
fn step_text(step: &Mapping, uses: bool) -> String {
    let fields: &[&str] = if uses {
        &["name", "id", "uses", "with", "run"]
    } else {
        &["name", "id", "with", "run"]
    };
    fields
        .iter()
        .filter_map(|f| get(step, f))
        .map(deploy_check::text_of)
        .collect()
}

/// The ids of the jobs that need `job_id`, directly or through other jobs.
fn dependents<'a>(jobs: &'a Mapping, job_id: &str) -> Vec<&'a str> {
    let needs = |job: &Mapping, id: &str| match get(job, "needs") {
        Some(Value::String(s)) => s == id,
        Some(Value::Sequence(seq)) => seq.iter().any(|v| v.as_str() == Some(id)),
        _ => false,
    };
    let mut found: Vec<&str> = Vec::new();
    let mut queue = vec![job_id.to_string()];
    while let Some(id) = queue.pop() {
        for (k, v) in jobs {
            let (Some(k), Some(job)) = (k.as_str(), v.as_mapping()) else {
                continue;
            };
            if k != job_id && !found.contains(&k) && needs(job, &id) {
                found.push(k);
                queue.push(k.to_string());
            }
        }
    }
    found
}

/// The job's facts, or None when no step of it deploys.
pub(super) fn judge(wf: &Workflow, job_id: &str, job: &Mapping) -> Option<Site> {
    let (idx, step, deploy) = steps(job)
        .filter_map(|(i, s)| deploys(s).map(|d| (i, s, d)))
        .last()?;
    let own = step_text(step, false);
    let why = wf
        .why
        .clone()
        .or_else(|| why_job(wf, job_id, job, idx, &own));
    Some(Site {
        value: deploy_check::value(why),
        class: deploy.class(),
        path: format!("jobs.{job_id}.steps[{idx}] deploys: {}", deploy.kind),
    })
}

/// Why the deploy job abstains, from the job itself and what follows its
/// deploy step `idx`, whose text is `own`.
fn why_job(wf: &Workflow, job_id: &str, job: &Mapping, idx: usize, own: &str) -> Option<String> {
    let name = get(job, "name").and_then(Value::as_str);
    let env = get(job, "environment").and_then(deploy_check::environment_name);
    if let Some(t) = [Some(job_id), name, env]
        .into_iter()
        .flatten()
        .find_map(deploy_check::non_production_token)
    {
        return Some(format!("non-production job: {t}"));
    }
    let condition = get(job, "if")
        .map(deploy_check::text_of)
        .unwrap_or_default();
    if let Some(m) = deploy_check::preview(&condition).or_else(|| deploy_check::preview(own)) {
        return Some(format!("deploys a pull request or a preview: {m}"));
    }
    let checked =
        |w: String, at: String| Some(format!("a check may follow the deploy: {at} ({w})"));
    if let Some(w) = deploy_check::check_word(own) {
        return checked(w, "the deploy step".into());
    }
    for (i, s) in steps(job).filter(|(i, _)| *i > idx) {
        if let Some(w) = deploy_check::check_word(&step_text(s, true)) {
            return checked(w, format!("step {i}"));
        }
    }
    for id in dependents(wf.jobs, job_id) {
        let Some(dep) = get(wf.jobs, id).and_then(Value::as_mapping) else {
            continue;
        };
        let text: String = [id.to_string()]
            .into_iter()
            .chain(
                ["name", "uses"]
                    .iter()
                    .filter_map(|f| get(dep, f))
                    .map(deploy_check::text_of),
            )
            .chain(steps(dep).map(|(_, s)| step_text(s, true)))
            .collect::<Vec<_>>()
            .join(" ");
        if let Some(w) = deploy_check::check_word(&text) {
            return checked(w, format!("job {id}, which needs this job"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::{retrieve, GithubActions};
    use crate::{ConfigRetriever, Retrieved};
    use rvl_core::Verdict;

    const WF: &str = ".github/workflows/deploy.yml";

    /// `job.post-deploy-check` per job, and `job.deploy-class` beside it.
    fn sites(got: &Retrieved) -> Vec<(String, String, String)> {
        got.packets
            .iter()
            .filter(|p| p.key == crate::deploy_check::KEY)
            .map(|p| {
                let class = got
                    .predicates
                    .iter()
                    .find(|f| f.unit == p.unit && f.key == crate::deploy_check::CLASS_KEY)
                    .map(|f| f.values.join(","))
                    .unwrap_or_default();
                (p.unit.clone(), p.resolved_value.clone().unwrap(), class)
            })
            .collect()
    }

    fn one(path: &str, yaml: &str) -> (String, String) {
        let got = sites(&retrieve(path, yaml, "s"));
        assert_eq!(got.len(), 1, "{yaml}: {got:?}");
        let (_, value, class) = got.into_iter().next().unwrap();
        (value, class)
    }

    /// The reason after `undecided: `, or None for a decided value.
    fn why(path: &str, yaml: &str) -> Option<String> {
        let (value, _) = one(path, yaml);
        value
            .strip_prefix(crate::UNDECIDED_PREFIX)
            .map(str::to_string)
    }

    /// A workflow on push with one job `deploy` holding `steps`.
    fn wf(steps: &str) -> String {
        format!(
            "on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - uses: actions/checkout@v4\n{steps}"
        )
    }

    const HELM: &str = "      - run: helm upgrade --install api ./chart\n";
    const TERRAFORM: &str =
        "      - run: terraform init\n      - run: terraform apply -auto-approve\n";

    #[test]
    fn a_service_deploy_with_nothing_after_it_is_none_and_its_twin_is_not() {
        assert_eq!(one(WF, &wf(HELM)), ("none".into(), "deploy".into()));
        let twin = wf(&format!(
            "{HELM}      - name: Smoke test\n        run: ./scripts/smoke.sh\n"
        ));
        assert_eq!(
            why(WF, &twin).as_deref(),
            Some("a check may follow the deploy: step 2 (smoke)")
        );
    }

    #[test]
    fn a_terraform_apply_with_nothing_after_it_is_none_and_its_twin_is_not() {
        assert_eq!(one(WF, &wf(TERRAFORM)), ("none".into(), "terraform".into()));
        let twin = format!(
            "{}  verify:\n    needs: [deploy]\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -fsS https://example.com/healthz\n",
            wf(TERRAFORM)
        );
        assert_eq!(
            why(WF, &twin).as_deref(),
            Some("a check may follow the deploy: job verify, which needs this job (verify)")
        );
    }

    #[test]
    fn a_deploy_action_is_a_site_and_a_pages_deploy_is_not() {
        let ecs = wf(
            "      - uses: aws-actions/amazon-ecs-deploy-task-definition@v2\n        with:\n          task-definition: task.json\n          service: api\n          cluster: prod\n",
        );
        assert_eq!(one(WF, &ecs), ("none".into(), "deploy".into()));
        let pages = wf("      - uses: actions/deploy-pages@v4\n");
        assert!(sites(&retrieve(WF, &pages, "s")).is_empty());
        let script = wf("      - run: ./deploy.sh production\n");
        assert!(sites(&retrieve(WF, &script, "s")).is_empty());
    }

    #[test]
    fn a_check_in_the_deploy_step_or_a_job_further_down_the_chain_abstains() {
        let own = wf("      - run: |\n          kubectl apply -f k8s/\n          kubectl rollout status deploy/api\n");
        assert_eq!(
            why(WF, &own).as_deref(),
            Some("a check may follow the deploy: the deploy step (status)")
        );
        let chain = format!(
            "{}  notify:\n    needs: deploy\n    steps:\n      - run: ./notify.sh\n  e2e:\n    needs: [notify]\n    uses: ./.github/workflows/e2e.yml\n",
            wf(HELM)
        );
        assert!(why(WF, &chain).unwrap().contains("job e2e"), "{chain}");
        // A later checkout is not a check.
        let checkout = wf(&format!("{HELM}      - uses: actions/checkout@v4\n"));
        assert_eq!(why(WF, &checkout), None);
    }

    #[test]
    fn a_follow_up_workflow_abstains_across_files() {
        let smoke = "name: post\non:\n  workflow_run:\n    workflows: [Deploy]\n    types: [completed]\njobs:\n  run:\n    steps:\n      - run: ./run.sh\n";
        let deploy = format!("name: Deploy\n{}", wf(HELM));
        let files = vec![
            (WF.to_string(), deploy.clone()),
            (".github/workflows/post.yml".to_string(), smoke.to_string()),
        ];
        let got = GithubActions.retrieve_all(std::path::Path::new(""), &files, "s");
        let value = &sites(&got)[0].1;
        assert_eq!(
            value,
            "undecided: a check may follow the deploy: a workflow_run workflow follows this workflow"
        );
        // Alone, the deploy workflow has no follow-up.
        assert_eq!(one(WF, &deploy).0, "none");
        let listener = "on: deployment_status\njobs:\n  run:\n    steps:\n      - run: ./run.sh\n";
        let files = vec![
            (WF.to_string(), deploy),
            (
                ".github/workflows/after.yml".to_string(),
                listener.to_string(),
            ),
        ];
        let got = GithubActions.retrieve_all(std::path::Path::new(""), &files, "s");
        assert!(sites(&got)[0]
            .1
            .ends_with("a workflow listens on deployment_status"));
    }

    // Each fixture below would be `none` but for what it names.
    #[test]
    fn non_production_deploys_abstain() {
        let cases = [
            (
                WF,
                wf(HELM).replace("environment: production", "environment: developer"),
                "non-production job: developer",
            ),
            (
                ".github/workflows/api-deploy-developers.yml",
                wf(HELM),
                "non-production workflow: developers",
            ),
            (
                WF,
                wf(HELM).replace("  deploy:\n", "  deploy-preview:\n"),
                "non-production job: preview",
            ),
            (
                WF,
                wf(&format!("      - uses: helm/kind-action@v1\n{HELM}")),
                "test cluster or rehearsal in the workflow: kind-action",
            ),
            (
                WF,
                wf(HELM).replace(
                    "on:\n  push:\n    branches: [main]\n",
                    "on: [pull_request]\n",
                ),
                "the workflow runs only on pull requests",
            ),
            (
                WF,
                wf(HELM).replace(
                    "    environment: production\n",
                    "    environment: production\n    if: github.event_name == 'pull_request'\n",
                ),
                "deploys a pull request or a preview: pull_request",
            ),
            (
                WF,
                wf("      - run: helm upgrade --install api-preview ./chart\n"),
                "deploys a pull request or a preview: preview",
            ),
        ];
        for (path, yaml, want) in cases {
            assert_eq!(why(path, &yaml).as_deref(), Some(want), "{yaml}");
        }
        // `staging` is a named environment that is owed a check.
        let staging = wf(HELM).replace("environment: production", "environment: staging");
        assert_eq!(why(WF, &staging), None);
    }

    // A tool install and a printed deploy command deploy nothing.
    #[test]
    fn a_tool_install_or_a_printed_command_is_no_deploy_site() {
        for steps in [
            "      - run: brew install helm jq oras\n",
            "      - run: |\n          echo \"Placeholder: run \\\n            kubectl apply -f k8s/ when the cluster exists\"\n",
        ] {
            assert!(sites(&retrieve(WF, &wf(steps), "s")).is_empty(), "{steps}");
        }
    }

    #[test]
    fn a_sample_repository_abstains() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("cloud-samples");
        let got = GithubActions.retrieve_with_root(&root, WF, &wf(HELM), "s");
        assert_eq!(
            sites(&got)[0].1,
            "undecided: non-production repository: samples"
        );
    }

    /// ONE expectation decides the fact: `not_equals: none` violates on
    /// `none` and abstains on an undecided value.
    #[test]
    fn the_expectation_not_equals_none_decides() {
        let specs = rvl_spec::SpecCache::load(
            r#"{"config_keys":[{"format":"github-actions","key":"job.post-deploy-check",
                "expect":{"kind":"not_equals","value":"none"},"confidence":0.9,
                "control":"RC-058","severity":"medium","fix":"run a smoke test after the deploy"}]}"#,
        )
        .expect("the spec file parses");
        for (yaml, want) in [
            (wf(HELM), Verdict::Violates),
            (
                wf(&format!("{HELM}      - run: npx playwright test\n")),
                Verdict::Abstain,
            ),
        ] {
            let got = retrieve(WF, &yaml, "s");
            let p = got
                .packets
                .iter()
                .find(|p| p.key == crate::deploy_check::KEY)
                .unwrap();
            let f = crate::eval::evaluate(p, &got.predicates, &specs);
            assert_eq!(f.verdict, want, "{}", f.reason);
        }
    }
}
