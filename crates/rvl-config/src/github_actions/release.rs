//! The release job's supply chain (RC-079): does a job that publishes pin its
//! third-party actions to a commit, and make an SBOM and a builder-made
//! provenance attestation for what it publishes?
//!
//! A RELEASE JOB is a job with a step that publishes: `docker/build-push-action`
//! that pushes, `goreleaser/goreleaser-action` running a release,
//! `pypa/gh-action-pypi-publish`, `softprops/action-gh-release`, or a `run:`
//! line with `npm publish`, `twine upload`, `gh release upload` or `ko
//! publish` / `ko build`. A job that does not publish is not judged.
//!
//! The value names the rule the workflow file proves, by its prefix, and the
//! `release_supply_chain` pattern reads only that prefix:
//!
//!   * `M1:` — no job in the file makes an SBOM or a provenance attestation,
//!     and nothing that could make one is out of sight.
//!   * `M2b:` — a third-party action in the job is referenced by a tag or a
//!     branch. `actions/*` and `docker/*` count. The value names each one.
//!   * `S1:` — the job, or a job that `needs` it, makes an SBOM and a
//!     provenance attestation, and every action in those jobs is pinned to a
//!     commit.
//!   * `undecided:` — anything else, with why. The pattern abstains.
//!
//! Decide only what the file proves. Each of these keeps `M1` from firing,
//! because it may make an SBOM or provenance the file does not show: a local
//! action (its steps are in another file), goreleaser (its `sboms:` are in
//! `.goreleaser.yaml`), `docker/build-push-action` that pushes with no
//! `provenance` input (the action attests provenance by default since v4, at
//! `mode=max` in a public repository), and a reusable-workflow call anywhere
//! in the file.

use super::{get, split_uses, step_publishes_image};
use serde_yaml::{Mapping, Value};

/// One release job's status, and the step that makes it a release job.
pub(super) struct Release {
    pub value: String,
    /// `jobs.<id>.steps[<i>]...`, the first publishing step.
    pub publish_path: String,
}

/// The action a step uses, without its ref, or None for a `run:` step.
fn action(step: &Mapping) -> Option<&str> {
    let uses = get(step, "uses").and_then(Value::as_str)?;
    Some(uses.split('@').next().unwrap_or(uses))
}

/// A `with:` input of a step.
fn input<'a>(step: &'a Mapping, key: &str) -> Option<&'a Value> {
    get(step, "with")
        .and_then(Value::as_mapping)
        .and_then(|w| get(w, key))
}

fn is_true(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "true",
        _ => false,
    }
}

/// The words of each line of a `run:` script.
fn run_lines(step: &Mapping) -> Vec<Vec<&str>> {
    get(step, "run")
        .and_then(Value::as_str)
        .map(|run| {
            run.lines()
                .map(|l| l.split_whitespace().collect())
                .collect()
        })
        .unwrap_or_default()
}

fn has_seq(words: &[&str], seq: &[&str]) -> bool {
    words.windows(seq.len()).any(|w| w == seq)
}

/// `ko publish` or `ko build`, which push unless told to keep the image local.
fn ko_pushes(words: &[&str]) -> bool {
    (has_seq(words, &["ko", "publish"]) || has_seq(words, &["ko", "build"]))
        && !words
            .iter()
            .any(|w| matches!(*w, "-L" | "--local" | "--push=false"))
}

/// goreleaser publishes on `release` (also its default command), unless the
/// run is a snapshot or skips publishing.
fn goreleaser_publishes(step: &Mapping) -> bool {
    let args = input(step, "args").and_then(Value::as_str).unwrap_or("");
    let words: Vec<&str> = args.split_whitespace().collect();
    if words
        .iter()
        .any(|w| w.starts_with("--snapshot") || (w.starts_with("--skip") && w.contains("publish")))
    {
        return false;
    }
    matches!(
        words.iter().find(|w| !w.starts_with('-')),
        None | Some(&"release")
    )
}

fn step_publishes(step: &Mapping) -> bool {
    match action(step) {
        Some("docker/build-push-action") => step_publishes_image(step),
        Some("goreleaser/goreleaser-action") => goreleaser_publishes(step),
        Some("pypa/gh-action-pypi-publish" | "softprops/action-gh-release") => true,
        Some(_) => false,
        None => run_lines(step).iter().any(|w| {
            (has_seq(w, &["npm", "publish"]) && !w.contains(&"--dry-run"))
                || has_seq(w, &["twine", "upload"])
                || has_seq(w, &["gh", "release", "upload"])
                || ko_pushes(w)
        }),
    }
}

fn step_makes_sbom(step: &Mapping) -> bool {
    match action(step) {
        Some("anchore/sbom-action" | "actions/attest-sbom") => true,
        Some("docker/build-push-action") => is_true(input(step, "sbom")),
        Some(a) => a.to_ascii_lowercase().starts_with("cyclonedx/"),
        // ko writes an SPDX SBOM unless told not to.
        None => run_lines(step).iter().any(|w| {
            w.iter().any(|w| {
                *w == "syft" || w.ends_with("/syft") || w.to_ascii_lowercase().contains("cyclonedx")
            }) || (ko_pushes(w) && !w.contains(&"--sbom=none"))
        }),
    }
}

fn step_makes_provenance(step: &Mapping) -> bool {
    match action(step) {
        Some("actions/attest-build-provenance") => true,
        Some("docker/build-push-action") => match input(step, "provenance") {
            Some(Value::String(s)) => s == "true" || s.contains("mode=max"),
            v => is_true(v),
        },
        _ => false,
    }
}

/// A job that calls the SLSA generator's reusable workflow, which makes the
/// provenance of the artifacts its caller hands it.
fn calls_slsa_generator(job: &Mapping) -> bool {
    get(job, "uses")
        .and_then(Value::as_str)
        .is_some_and(|u| u.starts_with("slsa-framework/slsa-github-generator/"))
}

fn steps(job: &Mapping) -> impl Iterator<Item = (usize, &Mapping)> {
    get(job, "steps")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(i, s)| s.as_mapping().map(|s| (i, s)))
}

fn needs(job: &Mapping, id: &str) -> bool {
    match get(job, "needs") {
        Some(Value::String(s)) => s == id,
        Some(Value::Sequence(seq)) => seq.iter().any(|v| v.as_str() == Some(id)),
        _ => false,
    }
}

/// The third-party actions of a job not pinned to a commit, as `action@ref`.
fn unpinned(job: &Mapping) -> Vec<String> {
    steps(job)
        .filter_map(|(_, s)| get(s, "uses").and_then(Value::as_str))
        .filter_map(split_uses)
        .filter(|(_, r)| {
            crate::eval::pattern_matches("sha40", r) != Some(crate::eval::PatternVerdict::Matches)
        })
        .map(|(a, r)| format!("{a}@{r}"))
        .collect()
}

/// Why the steps of a job may make an SBOM or provenance this file does not
/// show, or None when every step is in sight.
fn out_of_sight(job: &Mapping) -> Option<&'static str> {
    steps(job).find_map(|(_, s)| match action(s) {
        Some(a) if a.starts_with("./") => Some("a local action's steps are not in this file"),
        Some("goreleaser/goreleaser-action") => {
            Some("goreleaser's SBOM settings are in its own config file")
        }
        Some("docker/build-push-action")
            if step_publishes_image(s) && input(s, "provenance").is_none() =>
        {
            Some("docker/build-push-action attests provenance by default")
        }
        _ => None,
    })
}

/// Judge one job of a workflow, or None when it does not publish.
pub(super) fn judge(jobs: &Mapping, job_id: &str, job: &Mapping) -> Option<Release> {
    let (idx, _) = steps(job).find(|(_, s)| step_publishes(s))?;
    let publish_path = format!("jobs.{job_id}.steps[{idx}]");

    let all: Vec<&Mapping> = jobs.values().filter_map(Value::as_mapping).collect();
    // The job and the jobs that need it: an attestation is often its own job.
    let related: Vec<&Mapping> = jobs
        .iter()
        .filter(|(k, v)| {
            k.as_str() == Some(job_id) || v.as_mapping().is_some_and(|j| needs(j, job_id))
        })
        .filter_map(|(_, v)| v.as_mapping())
        .collect();
    let any_step =
        |set: &[&Mapping], f: fn(&Mapping) -> bool| set.iter().any(|j| steps(j).any(|(_, s)| f(s)));
    let sbom = any_step(&related, step_makes_sbom);
    let provenance = any_step(&related, step_makes_provenance)
        || related.iter().any(|j| calls_slsa_generator(j));
    let attested_anywhere = any_step(&all, step_makes_sbom)
        || any_step(&all, step_makes_provenance)
        || all.iter().any(|j| calls_slsa_generator(j));
    let hidden = out_of_sight(job).or_else(|| {
        all.iter()
            .any(|j| get(j, "uses").is_some())
            .then_some("a reusable workflow's steps are not in this file")
    });

    let mut violations = Vec::new();
    if !attested_anywhere && hidden.is_none() {
        violations.push("M1: no SBOM step and no provenance step".to_string());
    }
    let tags = unpinned(job);
    if !tags.is_empty() {
        violations.push(format!("M2b: {} not pinned to a commit", tags.join(", ")));
    }
    let value = if !violations.is_empty() {
        violations.join("; ")
    } else {
        let why = match (sbom, provenance) {
            (true, true) => related.iter().find_map(|j| pin_gap(j)),
            _ if hidden.is_some() => hidden,
            _ if !sbom && !provenance => {
                Some("another job in the file makes an SBOM or a provenance attestation")
            }
            (true, false) => Some("an SBOM step and no provenance step"),
            (false, _) => Some("a provenance step and no SBOM step"),
        };
        match why {
            None => "S1: an SBOM step and a provenance step, every action pinned to a commit"
                .to_string(),
            Some(why) => format!("undecided: {why}"),
        }
    };
    Some(Release {
        value,
        publish_path,
    })
}

/// Why a job's actions are not all proven pinned, or None when they are.
fn pin_gap(job: &Mapping) -> Option<&'static str> {
    if !unpinned(job).is_empty() {
        return Some("a job that attests this one uses an action not pinned to a commit");
    }
    steps(job).find_map(|(_, s)| {
        let uses = get(s, "uses").and_then(Value::as_str)?;
        if uses.starts_with("./") {
            Some("a local action's pins are not in this file")
        } else if uses.starts_with("docker://") && !uses.contains("@sha256:") {
            Some("a docker:// step is not pinned to a digest")
        } else {
            None
        }
    })
}
