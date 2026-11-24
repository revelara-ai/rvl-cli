//! RC-058's deploy sites: where a repository deploys, so a smoke test can
//! follow the deploy. RC-058 asks what runs after the deploy at a site; a
//! repository with none (a library, a package published to a registry, a CLI
//! shipped as release artifacts, a collection of examples) has no site to
//! ask it of, and the rule abstains.
//!
//! A site is a CI job with an `environment:` that is not a package registry
//! or a docs page, a CI step that runs a deploy command ([`DEPLOY_COMMANDS`]),
//! or an Argo CD Application, Flux Kustomization or HelmRelease that deploys
//! this repository by its `origin` remote. An image build and push, a
//! package publish and a release upload run no deploy command and are no
//! site.
//!
//! Privacy: a site is a file path and the command or kind that deploys,
//! never the text of a step or an environment's name.

use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::path::Path;

/// The sites kept: one is enough to judge, a few to show.
pub const MAX_SITES: usize = 5;

/// One place the repository deploys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeploySite {
    /// Repo-relative path of the CI file or manifest.
    pub file: String,
    /// "helm upgrade", "a job with an environment", "an Argo CD
    /// Application", ...
    pub deploys: String,
}

/// Commands that deploy to an environment: the tool, then the words of its
/// subcommand, matched in order anywhere after the tool so a flag before
/// the subcommand (`kubectl -n web apply`) still reads.
const DEPLOY_COMMANDS: &[(&str, &[&str])] = &[
    ("kubectl", &["apply"]),
    ("kubectl", &["set", "image"]),
    ("helm", &["upgrade"]),
    ("helm", &["install"]),
    ("argocd", &["app", "sync"]),
    ("terraform", &["apply"]),
    ("gcloud", &["run", "deploy"]),
    ("gcloud", &["app", "deploy"]),
    ("gcloud", &["functions", "deploy"]),
    ("aws", &["ecs", "update-service"]),
    ("aws", &["lambda", "update-function-code"]),
    ("fly", &["deploy"]),
    ("vercel", &["deploy"]),
    ("vercel", &["--prod"]),
    ("serverless", &["deploy"]),
];

/// Words that run the next word as the command.
const WRAPPERS: &[&str] = &["npx", "sudo", "exec", "time", "command"];

/// Tokens of an environment's name that say a job publishes rather than
/// deploys: a package registry, a release, a docs page.
const PUBLISH_ENVIRONMENTS: &[&str] = &[
    "pypi",
    "testpypi",
    "npm",
    "nuget",
    "crates",
    "maven",
    "release",
    "releases",
    "publish",
    "publishing",
    "pages",
    "docs",
];

/// The Flux source a cluster bootstraps from: it syncs the cluster's own
/// config, not a service this repository builds.
const FLUX_BOOTSTRAP: &str = "flux-system";

/// The deploy command one shell line runs, if any. A dry run deploys
/// nothing.
pub(crate) fn deploy_command(line: &str) -> Option<String> {
    if line.trim_start().starts_with('#') {
        return None;
    }
    line.split(['&', '|', ';']).find_map(|segment| {
        if segment.contains("--dry-run") {
            return None;
        }
        let words: Vec<&str> = segment
            .split_whitespace()
            .map(|w| w.trim_matches(['"', '\'']))
            .collect();
        let start = words
            .iter()
            .position(|w| !w.contains('=') && !WRAPPERS.contains(w))?;
        let tool = words[start].rsplit('/').next()?;
        let rest = &words[start + 1..];
        DEPLOY_COMMANDS
            .iter()
            .find(|(t, sub)| *t == tool && rest.windows(sub.len()).any(|w| w == *sub))
            .map(|(t, sub)| format!("{t} {}", sub.join(" ")))
    })
}

/// Whether a job's `environment:` (a name, or a mapping with a `name`) names
/// a registry, a release or a docs page. An expression publishes nothing as
/// far as can be read.
fn publishes(env: &Value) -> bool {
    let name = match env {
        Value::String(s) => s.as_str(),
        Value::Mapping(_) => env.get("name").and_then(Value::as_str).unwrap_or(""),
        _ => "",
    };
    name.split(|c: char| !c.is_alphanumeric())
        .any(|t| PUBLISH_ENVIRONMENTS.contains(&t.to_ascii_lowercase().as_str()))
}

/// The sites of one CI job: its environment, and each step's deploy command.
fn job_sites(file: &str, job: &Value, scripts: &[String], out: &mut Vec<DeploySite>) {
    let site = |deploys: String| DeploySite {
        file: file.to_string(),
        deploys,
    };
    if job.get("environment").is_some_and(|e| !publishes(e)) {
        out.push(site("a job with an environment".into()));
    }
    for script in scripts {
        for line in crate::sast::shell_lines(script) {
            if let Some(command) = deploy_command(&line) {
                out.push(site(command));
            }
        }
    }
}

/// The deploy sites of the parsed GitHub Actions workflows.
pub(crate) fn github(workflows: &[(String, Value)], out: &mut Vec<DeploySite>) {
    for (file, doc) in workflows {
        let jobs = doc.get("jobs").and_then(Value::as_mapping);
        for job in jobs.into_iter().flat_map(|j| j.values()) {
            let runs: Vec<String> = job
                .get("steps")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(|s| s.get("run").and_then(Value::as_str).map(str::to_string))
                .collect();
            job_sites(file, job, &runs, out);
        }
    }
}

/// The deploy sites of one `.gitlab-ci.yml`.
pub(crate) fn gitlab(file: &str, text: &str, out: &mut Vec<DeploySite>) {
    let Ok(Value::Mapping(root)) = serde_yaml::from_str::<Value>(text) else {
        return;
    };
    for (name, job) in &root {
        let Some(name) = name.as_str() else { continue };
        if name.starts_with('.') || crate::sast::GITLAB_GLOBALS.contains(&name) {
            continue;
        }
        let mut scripts = Vec::new();
        for key in ["before_script", "script", "after_script"] {
            match job.get(key) {
                Some(Value::String(s)) => scripts.push(s.clone()),
                Some(Value::Sequence(seq)) => {
                    scripts.extend(seq.iter().filter_map(|l| l.as_str().map(str::to_string)))
                }
                _ => {}
            }
        }
        job_sites(file, job, &scripts, out);
    }
}

/// The GitOps documents the walk saw, resolved against the repository's
/// `origin` once the walk is done.
#[derive(Default)]
pub(crate) struct GitOps {
    /// Argo CD Applications: file and the repository URLs they deploy from.
    argo: Vec<(String, Vec<String>)>,
    /// Flux GitRepository sources: name and URL.
    sources: Vec<(String, String)>,
    /// Flux Kustomizations and HelmReleases: file, kind and the name of the
    /// GitRepository they deploy from.
    consumers: Vec<(String, &'static str, String)>,
}

impl GitOps {
    /// Record the Argo CD and Flux documents of the YAML file at `rp`.
    pub(crate) fn observe(&mut self, rp: &str, text: &str) {
        if !text.contains("argoproj.io") && !text.contains("fluxcd.io") {
            return;
        }
        for doc in serde_yaml::Deserializer::from_str(text) {
            let Ok(doc) = Value::deserialize(doc) else {
                return;
            };
            let api = doc.get("apiVersion").and_then(Value::as_str).unwrap_or("");
            let kind = doc.get("kind").and_then(Value::as_str).unwrap_or("");
            let spec = doc.get("spec");
            let str_at = |v: Option<&Value>, key: &str| {
                v.and_then(|v| v.get(key))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            match (api.split('/').next().unwrap_or(""), kind) {
                ("argoproj.io", "Application") => {
                    let one = spec.and_then(|s| s.get("source"));
                    let many = spec
                        .and_then(|s| s.get("sources"))
                        .and_then(Value::as_sequence);
                    let urls = one
                        .into_iter()
                        .chain(many.into_iter().flatten())
                        .filter_map(|s| str_at(Some(s), "repoURL"))
                        .collect();
                    self.argo.push((rp.to_string(), urls));
                }
                ("source.toolkit.fluxcd.io", "GitRepository") => {
                    let name = str_at(doc.get("metadata"), "name").unwrap_or_default();
                    if let Some(url) = str_at(spec, "url") {
                        self.sources.push((name, url));
                    }
                }
                ("kustomize.toolkit.fluxcd.io", "Kustomization") => {
                    self.consume(
                        rp,
                        "a Flux Kustomization",
                        spec.and_then(|s| s.get("sourceRef")),
                    );
                }
                ("helm.toolkit.fluxcd.io", "HelmRelease") => {
                    let source = spec
                        .and_then(|s| s.get("chart"))
                        .and_then(|c| c.get("spec"))
                        .and_then(|c| c.get("sourceRef"));
                    self.consume(rp, "a Flux HelmRelease", source);
                }
                _ => {}
            }
        }
    }

    fn consume(&mut self, rp: &str, kind: &'static str, source: Option<&Value>) {
        let Some(source) = source else { return };
        if source.get("kind").and_then(Value::as_str) != Some("GitRepository") {
            return;
        }
        if let Some(name) = source.get("name").and_then(Value::as_str) {
            self.consumers
                .push((rp.to_string(), kind, name.to_string()));
        }
    }

    /// The sites among the recorded documents that deploy the repository
    /// whose `origin` remote is `origin`.
    pub(crate) fn sites(&self, origin: Option<&str>, out: &mut Vec<DeploySite>) {
        let Some(origin) = origin.map(normalize_url) else {
            return;
        };
        let ours = |url: &str| normalize_url(url) == origin;
        for (file, urls) in &self.argo {
            if urls.iter().any(|u| ours(u)) {
                out.push(DeploySite {
                    file: file.clone(),
                    deploys: "an Argo CD Application".into(),
                });
            }
        }
        let own_sources: Vec<&str> = self
            .sources
            .iter()
            .filter(|(name, url)| name != FLUX_BOOTSTRAP && ours(url))
            .map(|(name, _)| name.as_str())
            .collect();
        for (file, kind, source) in &self.consumers {
            if own_sources.contains(&source.as_str()) {
                out.push(DeploySite {
                    file: file.clone(),
                    deploys: kind.to_string(),
                });
            }
        }
    }
}

/// A git URL as host and path, lowercased, so the https, ssh and scp-like
/// spellings of one repository compare equal.
fn normalize_url(url: &str) -> String {
    let url = url.trim().to_ascii_lowercase();
    let rest = url.split_once("://").map_or(url.as_str(), |(_, r)| r);
    let rest = rest.split_once('@').map_or(rest, |(_, r)| r);
    // scp-like `host:owner/repo`; a `host:port/` keeps its digits out.
    let rest = match rest.split_once(':') {
        Some((host, path)) if !path.starts_with(|c: char| c.is_ascii_digit()) => {
            format!("{host}/{path}")
        }
        Some((host, path)) => format!(
            "{host}/{}",
            path.trim_start_matches(|c: char| c.is_ascii_digit())
                .trim_start_matches('/')
        ),
        None => rest.to_string(),
    };
    rest.trim_end_matches('/')
        .trim_end_matches(".git")
        .to_string()
}

/// The URL of the `origin` remote in the repository's `.git/config`, if
/// there is one.
pub(crate) fn origin(root: &Path) -> Option<String> {
    let config = crate::inventory::read_capped(&root.join(".git/config"));
    let mut in_origin = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((key, value)) = t.split_once('=') {
                if key.trim() == "url" {
                    return Some(value.trim().to_string());
                }
            }
        }
    }
    None
}

/// Sort, de-duplicate and cap the sites.
pub(crate) fn finish(mut sites: Vec<DeploySite>) -> Vec<DeploySite> {
    sites.sort();
    sites.dedup();
    sites.truncate(MAX_SITES);
    sites
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_commands_read_through_flags_and_wrappers() {
        for (line, want) in [
            ("kubectl -n web apply -f k8s/", Some("kubectl apply")),
            ("helm upgrade --install api ./chart", Some("helm upgrade")),
            ("npx vercel deploy --prebuilt", Some("vercel deploy")),
            (
                "TF_IN_AUTOMATION=1 terraform apply -auto-approve",
                Some("terraform apply"),
            ),
            ("gcloud run deploy api --image x", Some("gcloud run deploy")),
            (
                "aws ecs update-service --cluster c",
                Some("aws ecs update-service"),
            ),
            ("kubectl apply --dry-run=client -f k8s/", None),
            ("docker push ghcr.io/o/api:latest", None),
            ("terraform plan", None),
            ("# helm upgrade later", None),
        ] {
            assert_eq!(deploy_command(line).as_deref(), want, "{line}");
        }
    }

    #[test]
    fn one_repository_by_any_url_spelling() {
        let want = "example.com/o/api";
        for url in [
            "https://example.com/o/api.git",
            "git@example.com:o/api.git",
            "ssh://git@example.com:22/o/api",
            "https://example.com/O/api/",
        ] {
            assert_eq!(normalize_url(url), want, "{url}");
        }
    }
}
