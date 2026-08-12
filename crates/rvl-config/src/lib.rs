//! The G6 config/IaC lane: per-FORMAT retrievers plus the config-spec
//! verification lane.
//!
//! Config controls (CI testing, deploy gates, supply-chain pinning, capacity
//! limits, ...) are per-format, not per-language: one GitHub Actions retriever
//! serves a Go repo and a Python repo identically, which is what makes this
//! the highest-leverage retriever in the inventory (~27-29 controls for every
//! language at once — granularity map G6).
//!
//! The architecture mirrors the call-site lane exactly:
//!
//!   * retrievers emit FACTS (config packets), never verdicts. A packet is a
//!     RESOLVED VALUE plus the PROVENANCE CHAIN that produced it — which
//!     file/overlay/default made the setting effective (wayfinder po-ae75b.1
//!     design principle: "ship evidence, don't conclude").
//!   * specs judge (format, key) identities once and apply everywhere
//!     ([`rvl_spec::ConfigKeySpec`]); the verification lane in [`eval`]
//!     combines them mechanically, with the same abstention semantics as
//!     `spec_gate` — no spec, low confidence, or an out-of-repo value never
//!     become a verdict.
//!   * coverage records unsupported-config-format SIGHTINGS: format identity
//!     and a file count, nothing else. Config file CONTENT can carry secrets
//!     and repo structure; per the privacy contract it never leaves the
//!     machine, so a sighting is structurally incapable of carrying it.
//!
//! New formats (Kubernetes, Prometheus/sloth, dependency manifests,
//! Terraform, Argo/Flux — po-av01j.20-.24) plug in by implementing
//! [`ConfigRetriever`] and joining [`registry`].

use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod argo_flux;
pub mod dep_manifests;
pub mod eval;
pub mod github_actions;
pub mod gitlab_ci;
pub mod kubernetes;
pub mod prometheus;
pub mod terraform;

/// The canonical rendering of a decidable authored ABSENCE: a key the
/// committed file decidably lacks, where no platform default fills in
/// (wayfinder po-av01j.24: an Application with automated sync but no retry).
/// Such packets are `Resolution::AsAuthored` with this value, and the
/// `configured` spec pattern judges them.
pub const ABSENT_RENDERING: &str = "absent";

/// How the effective value of a config key was produced, ordered by
/// decreasing evidentiary strength. This is the packet's confidence marker
/// (wayfinder po-ae75b.1 item 4: Helm renders stamp `rendered`; unresolvable
/// settings are an abstention class, never a guess).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    /// Read directly from a committed file, including mechanical merges the
    /// format defines (a kustomize overlay, a GitLab `default:` block, a
    /// workflow-level GitHub Actions `permissions:` inherited by a job).
    AsAuthored,
    /// Produced by rendering with committed inputs only (e.g. Helm with the
    /// repo's committed values files). Trustworthy but one step removed from
    /// the authored text; no cluster and no remote fetch is ever consulted.
    Rendered,
    /// No explicit setting anywhere in the repo; the platform's DOCUMENTED
    /// default governs (e.g. a GitHub Actions job without `timeout-minutes`
    /// runs under the 360-minute default).
    PlatformDefault,
    /// The effective value is set outside the repo (an org/project/cluster
    /// setting). Nothing committed can resolve it, so the verification lane
    /// abstains rather than guessing.
    Unresolvable,
}

/// One step of the provenance chain: which file (or platform default) was
/// consulted for the value, and what it contributed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceStep {
    /// Repo-relative file consulted, or "" for a platform default / external
    /// setting.
    pub file: String,
    /// The key path consulted within that file (or the platform-side name).
    pub key_path: String,
    /// What this step contributed: "explicit" (supplied the value), "absent"
    /// (consulted, had nothing), "inherited" (supplied it from an enclosing
    /// scope), "default-block" (a format-defined defaults section),
    /// "platform-default" (documented default), "project-setting" /
    /// "repo-setting" (lives outside the repo).
    pub role: String,
}

impl ProvenanceStep {
    pub fn new(file: &str, key_path: &str, role: &str) -> Self {
        Self {
            file: file.to_string(),
            key_path: key_path.to_string(),
            role: role.to_string(),
        }
    }
}

/// A config packet: the RESOLVED effective value of one config key for one
/// config unit, plus the provenance chain that produced it. The config-lane
/// analog of a call-site packet: facts only, never a verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigPacket {
    #[serde(default)]
    pub snapshot_id: String,
    /// The config format id, e.g. "github-actions".
    pub format: String,
    /// Repo-relative file the effective setting is anchored to.
    pub file_path: String,
    /// Best-effort line of the anchor; 0 = unknown.
    #[serde(default)]
    pub line: u32,
    /// The config unit the key applies to, e.g. "job:build", "step:build/2",
    /// "workflow".
    pub unit: String,
    /// The canonical key identity within the format, e.g.
    /// "job.timeout-minutes". Matches [`rvl_spec::ConfigKeySpec::key`].
    pub key: String,
    /// The effective value, canonically rendered. `None` only when
    /// `resolution` is [`Resolution::Unresolvable`].
    pub resolved_value: Option<String>,
    pub resolution: Resolution,
    pub provenance: Vec<ProvenanceStep>,
}

impl ConfigPacket {
    /// Unique per packet: `file:unit:key`. One file has many units, one unit
    /// many keys; the triple never collides within a scan.
    pub fn id(&self) -> String {
        format!("{}:{}:{}", self.file_path, self.unit, self.key)
    }
}

/// What one retriever produced from one file.
#[derive(Debug, Default)]
pub struct Retrieved {
    pub packets: Vec<ConfigPacket>,
    /// Documents that matched this format's path shape but could not be
    /// parsed or recognized. A retriever bug or a malformed file degrades
    /// coverage, never aborts a scan (same contract as `parse_stream`).
    pub unparseable: usize,
    /// Identity-only sightings the retriever itself emits for VARIANTS of
    /// its format it recognizes but cannot resolve honestly (an unvendored
    /// helm chart, an unsupported kustomize patch). Same privacy contract as
    /// the walk's sightings: format identity + count, nothing else.
    pub sightings: Vec<FormatSighting>,
}

/// A per-format config retriever. Implementations parse ONE format and emit
/// facts; families 2-6 (Kubernetes, Prometheus, dependency manifests,
/// Terraform, Argo/Flux) plug in here without touching the lane.
pub trait ConfigRetriever {
    /// Stable format id, e.g. "github-actions". Also the spec-side `format`.
    fn format_id(&self) -> &'static str;
    /// Whether a repo-relative (forward-slashed) path belongs to this format.
    fn matches(&self, rel_path: &str) -> bool;
    /// Content-aware claim for formats with NO canonical path (Prometheus
    /// rule files, Kubernetes manifests): consulted with a bounded head of
    /// each bare YAML file no path-based [`Self::matches`] claimed, before
    /// sighting. Detection must be conservative — a declined file degrades
    /// to an identity-only sighting, never a wrong parse. Default: never
    /// claims, so path-anchored formats are unaffected.
    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        let _ = (rel_path, head);
        false
    }
    /// Parse one matching file into packets.
    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved;
    /// Parse ALL files this format claimed in one scan, path-sorted `(rel,
    /// contents)` pairs. The default forwards file-by-file to
    /// [`ConfigRetriever::retrieve_with_root`]; a format whose effective
    /// values span committed files (a tfvars assignment overriding a
    /// Terraform variable default, a kustomize overlay) overrides this single
    /// entry point instead, so cross-file resolution stays inside the
    /// format's module.
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            let got = self.retrieve_with_root(root, rel, contents, snapshot_id);
            out.packets.extend(got.packets);
            out.unparseable += got.unparseable;
            out.sightings.extend(got.sightings);
        }
        out
    }

    /// Root-aware retrieval for formats that must consult SIBLING files to
    /// resolve honestly (kustomize bases and patches, helm values). Every
    /// read stays under `root`; the default delegates to [`Self::retrieve`]
    /// so single-file formats never notice the difference.
    fn retrieve_with_root(
        &self,
        _root: &Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        self.retrieve(rel_path, contents, snapshot_id)
    }
}

/// Every supported config-format retriever, in deterministic order.
pub fn registry() -> Vec<Box<dyn ConfigRetriever>> {
    vec![
        Box::new(github_actions::GithubActions),
        Box::new(gitlab_ci::GitlabCi),
        Box::new(dep_manifests::DepManifests),
        Box::new(prometheus::PrometheusRules),
        Box::new(argo_flux::ArgoFlux),
        Box::new(terraform::Terraform),
        // Kubernetes stays LAST: its content claim (bare apiVersion+kind
        // YAML) is the broadest, so narrower families (sloth CRDs, Argo/Flux
        // CRs, rule files) must get first refusal.
        Box::new(kubernetes::Kubernetes),
    ]
}

/// An identity-only sighting of a config format no retriever supports yet.
/// Deliberately STRUCTURALLY INCAPABLE of carrying content, paths, or values:
/// the two fields below are the whole record (audited by test). Prevalence
/// data drives post-cutover format ordering; nothing else is needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatSighting {
    pub format: String,
    pub file_count: usize,
    /// Whether a retriever for this format EXISTS. Both cases are "no retriever
    /// claimed these files", and they are very different statements to a reader
    /// (po-av01j.136 defect 2).
    ///
    /// false: nothing here handles the format at all. This is the AUTHORING
    /// QUEUE, prevalence-ranked -- the number means missing coverage.
    ///
    /// true: the format is supported and the retriever declined these
    /// particular files, normally because they carry nothing any spec asks
    /// about. A Kubernetes CRD with no containers is the common case, and
    /// reporting it as an unsupported format made a repo look uncovered when it
    /// was fully covered -- 109 Gatekeeper policies on one Terraform repo, in a
    /// run where the same format resolved 288 settings.
    pub retriever_exists: bool,
}

impl FormatSighting {
    /// A sighting emitted BY a retriever: it recognized the file and declined
    /// it, so a retriever for the format exists by construction. This is the
    /// one classification that needs no lookup and cannot be wrong.
    pub fn declined(format: impl Into<String>, file_count: usize) -> Self {
        Self {
            format: format.into(),
            file_count,
            retriever_exists: true,
        }
    }
}

/// Walk-sighted identities that name a VARIANT of a format a registered
/// retriever handles, rather than a format nothing handles.
///
/// Kept explicit and short because every entry is a claim that something else
/// in this crate can parse the family, and an entry added on a guess would put
/// a real coverage gap in the wrong column. Each of these is emitted by
/// `sight_format` itself, so the set is closed and verifiable by reading it.
const VARIANTS_OF_SUPPORTED: &[&str] = &[
    // sight_format's own templated-variant of prometheus-rules, whose literal
    // form the PrometheusRules retriever claims.
    "prometheus-rules-templated",
    // The Kubernetes retriever carries helm and kustomize submodules; a bare
    // Chart.yaml/kustomization.yaml sighting is one it declined, not a format
    // with no support.
    "helm",
    "kustomize",
];

/// Directory names never worth descending into (mirrors the code lane).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    "testdata",
    // `terraform init`'s cache: vendored third-party modules/providers whose
    // .tf files are not this repo's configuration.
    ".terraform",
];

/// Everything the config lane retrieved from a repo.
#[derive(Debug, Default)]
pub struct LaneRetrieval {
    pub packets: Vec<ConfigPacket>,
    /// Files a retriever claimed but could not parse (coverage, not failure).
    pub unparseable_files: usize,
    /// Identity-only sightings of unsupported config formats, sorted by
    /// format id for deterministic output.
    pub sightings: Vec<FormatSighting>,
}

/// Kubernetes API groups that are NOT DNS subdomains: the historical set that
/// predates the convention. Every other real group is dotted (`*.k8s.io`, or a
/// vendor domain like `networking.istio.io`), so these have to be enumerated.
const CORE_ADJACENT_GROUPS: &[&str] = &["apps", "batch", "autoscaling", "extensions", "policy"];

/// Tools that borrowed Kubernetes' `apiVersion:` + `kind:` convention without
/// being Kubernetes. Keyed by API group, which is the part that identifies the
/// tool. Deliberately short: it holds what has actually been OBSERVED, and a
/// tool nobody has seen is not added on speculation.
const NON_KUBERNETES_API_GROUPS: &[(&str, &str)] = &[("skaffold", "skaffold")];

/// The value of the first column-0 `apiVersion:` line, comment-stripped and
/// unquoted.
///
/// The inline comment matters: real manifests carry them (a licence header on
/// the apiVersion line is common in Google's Gatekeeper policy corpus, which is
/// where this was found). Classification happens to survive an unstripped
/// comment today, because only the group and the first two characters of the
/// version are ever examined -- that is accidental, and it stops being true the
/// moment anything compares the whole version string.
fn api_version_value(head: &str) -> &str {
    head.lines()
        .find(|l| l.starts_with("apiVersion:"))
        .map(|l| {
            let v = &l["apiVersion:".len()..];
            // A YAML comment opens at a '#' preceded by whitespace (or at the
            // start), so a '#' inside the value itself is left alone.
            let v = match v
                .char_indices()
                .find(|&(i, c)| c == '#' && (i == 0 || v[..i].ends_with(char::is_whitespace)))
            {
                Some((i, _)) => &v[..i],
                None => v,
            };
            v.trim().trim_matches(|c| c == '"' || c == '\'')
        })
        .unwrap_or("")
}

/// A version token: `v1`, `v1beta1`, `v2alpha1`.
fn is_version_token(v: &str) -> bool {
    let mut c = v.chars();
    c.next() == Some('v') && c.next().is_some_and(|d| d.is_ascii_digit())
}

/// Does this apiVersion name a KUBERNETES group/version?
///
/// Either a bare core version (`v1`) or `group/version` where the group is a
/// DNS subdomain. The dot test alone would reject `apps/v1`, which is why the
/// historical dotless groups are enumerated above rather than inferred.
fn is_kubernetes_api_version(v: &str) -> bool {
    match v.split_once('/') {
        None => is_version_token(v),
        Some((group, version)) => {
            !group.is_empty()
                && is_version_token(version)
                && (group.contains('.') || CORE_ADJACENT_GROUPS.contains(&group))
        }
    }
}

/// The tool identity for an apiVersion belonging to a known non-Kubernetes
/// tool, or None.
fn non_kubernetes_api_group(v: &str) -> Option<&'static str> {
    let group = v.split_once('/').map(|(g, _)| g).unwrap_or(v);
    NON_KUBERNETES_API_GROUPS
        .iter()
        .find(|(g, _)| *g == group)
        .map(|(_, fmt)| *fmt)
}

/// Classify an unsupported config format by path shape (and, for bare YAML, a
/// bounded content sniff). Returns the format identity only.
fn sight_format(rel: &str, head: &str) -> Option<&'static str> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let is_yaml = rel.ends_with(".yml") || rel.ends_with(".yaml");
    if name == "alertmanager.yml" || name == "alertmanager.yaml" {
        return Some("alertmanager");
    }
    if rel == ".circleci/config.yml" || rel == ".circleci/config.yaml" {
        return Some("circleci");
    }
    if rel == ".travis.yml" {
        return Some("travis-ci");
    }
    if rel == "azure-pipelines.yml" || rel == "azure-pipelines.yaml" {
        return Some("azure-pipelines");
    }
    if rel == "bitbucket-pipelines.yml" || rel == "bitbucket-pipelines.yaml" {
        return Some("bitbucket-pipelines");
    }
    if rel.starts_with(".buildkite/") && is_yaml {
        return Some("buildkite");
    }
    if name == "Chart.yaml" || name == "Chart.yml" {
        return Some("helm");
    }
    if name == "kustomization.yaml" || name == "kustomization.yml" {
        return Some("kustomize");
    }
    // Dependency-manifest variants the dep-manifests retriever does not parse
    // yet (family po-av01j.22): identity-only, pure basename, no read.
    match name {
        "pom.xml" => return Some("maven"),
        "build.gradle" | "build.gradle.kts" => return Some("gradle"),
        "Gemfile" => return Some("bundler"),
        "composer.json" => return Some("composer"),
        "Pipfile" => return Some("pipfile"),
        "mix.exs" => return Some("mix"),
        "build.sbt" => return Some("sbt"),
        _ => {}
    }
    if is_yaml {
        // Bounded sniffs over the head of the file. Only the IDENTITY of the
        // format is recorded; the content is read locally and discarded.
        // Argo/Flux CRs first: the recognized kinds route to the ArgoFlux
        // retriever via matches_head before sighting is ever consulted; the
        // rest classify by product here so the generic-kubernetes sniff
        // below never absorbs them (the po-av01j.20 family boundary).
        if let Some(fmt) = argo_flux::sight_unrecognized(head) {
            return Some(fmt);
        }
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        if col0("apiVersion:") && col0("kind:") {
            // apiVersion + kind is NOT enough to call a file Kubernetes. Other
            // tools borrowed the convention wholesale, and on the dogfood repo
            // this labelled skaffold.yaml (apiVersion: skaffold/v3) as a
            // Kubernetes manifest (po-av01j.136). Sightings are the authoring
            // queue -- prevalence ranks which format to build vocabulary for
            // next -- so a miscounted identity misdirects real work.
            let api = api_version_value(head);
            if let Some(fmt) = non_kubernetes_api_group(api) {
                return Some(fmt);
            }
            if is_kubernetes_api_version(api) {
                return Some("kubernetes");
            }
            // apiVersion/kind-shaped but from a group we cannot name. Falls
            // through to None, the same as any other unrecognized YAML; naming
            // it would be inventing an identity the evidence does not support.
            return None;
        }
        if col0("groups:") && head.contains("expr:") {
            // The literal-YAML variants are claimed by the retriever before
            // sighting; what reaches here is a variant it declined. Helm/Go
            // templating is the known one (no rendering on the scan path —
            // wayfinder po-ae75b.1), sighted under its own identity so
            // prevalence can rank a future render lane.
            if prometheus::helm_templated(head) {
                return Some("prometheus-rules-templated");
            }
            return Some("prometheus-rules");
        }
        if col0("route:") && col0("receivers:") {
            return Some("alertmanager");
        }
    }
    None
}

/// Walk `root` for config files: run every matching [`registry`] retriever
/// and record identity-only sightings for formats none of them support.
pub fn retrieve_repo(root: &Path, snapshot_id: &str) -> LaneRetrieval {
    let retrievers = registry();
    let mut out = LaneRetrieval::default();
    let mut sightings: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    // Identities a retriever itself declined; see absorb().
    let mut declined: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Files each retriever claimed, retrieved in ONE batch after the walk so
    // formats whose resolution spans files see their whole claim at once
    // (see [`ConfigRetriever::retrieve_all`]).
    let mut claimed: Vec<Vec<(String, String)>> = retrievers.iter().map(|_| Vec::new()).collect();

    /// Fold one retriever result into the lane totals, merging any
    /// retriever-emitted sightings into the walk's identity+count map.
    fn absorb(
        out: &mut LaneRetrieval,
        sightings: &mut std::collections::BTreeMap<String, usize>,
        declined: &mut std::collections::BTreeSet<String>,
        got: Retrieved,
    ) {
        out.packets.extend(got.packets);
        out.unparseable_files += got.unparseable;
        for s in got.sightings {
            // Emitted by a retriever, so the format is handled by construction.
            // Recorded here because the two sighting sources merge into one map
            // and provenance cannot be recovered afterwards from the name.
            declined.insert(s.format.clone());
            *sightings.entry(s.format).or_insert(0) += s.file_count;
        }
    }

    // Honor .gitignore (po-90lwe): the config lane was walking the whole tree
    // and reporting findings from a gitignored nested worktree in a backend repo's
    // pre-commit output. The `ignore` walker applies .gitignore /
    // .git/info/exclude / parent ignores and treats a nested .git as its own
    // boundary. hidden(false) keeps .github and other non-ignored dotdirs in
    // scope; git_global(false) keeps output independent of whose machine ran
    // it. SKIP_DIRS stays as a belt-and-suspenders filter (vendor/.terraform
    // are not always gitignored). Mirrors rvl-content::scan_root (po-lqbh2).
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_exclude(true)
        .git_global(false)
        .parents(true)
        .require_git(false)
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            !SKIP_DIRS.contains(&name.as_ref())
        })
        .build();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        let rel = repo_relative(root, path);
        if let Some(idx) = retrievers.iter().position(|r| r.matches(&rel)) {
            let Ok(contents) = std::fs::read_to_string(path) else {
                out.unparseable_files += 1;
                continue;
            };
            claimed[idx].push((rel, contents));
            continue;
        }
        // Path shapes need no read; bare YAML gets a bounded head read
        // for content-identified formats and sighting (content is read
        // locally and dropped either way).
        let needs_head = rel.ends_with(".yml") || rel.ends_with(".yaml");
        let head = if needs_head {
            read_head(path, 4096)
        } else {
            String::new()
        };
        // Content-identified formats (no canonical path) get a bounded
        // head consult before the file degrades to a sighting.
        if needs_head {
            if let Some(r) = retrievers.iter().find(|r| r.matches_head(&rel, &head)) {
                let Ok(contents) = std::fs::read_to_string(path) else {
                    out.unparseable_files += 1;
                    continue;
                };
                absorb(
                    &mut out,
                    &mut sightings,
                    &mut declined,
                    r.retrieve_with_root(root, &rel, &contents, snapshot_id),
                );
                continue;
            }
        }
        // No retriever claimed this file. Whether that means the format is
        // unsupported or merely that this file carries nothing to retrieve
        // is decided once, below, where the registry is in scope.
        if let Some(fmt) = sight_format(&rel, &head) {
            *sightings.entry(fmt.to_string()).or_insert(0) += 1;
        }
    }

    for (idx, files) in claimed.iter_mut().enumerate() {
        if files.is_empty() {
            continue;
        }
        files.sort();
        absorb(
            &mut out,
            &mut sightings,
            &mut declined,
            retrievers[idx].retrieve_all(root, files, snapshot_id),
        );
    }

    // Which sighted identities have a retriever behind them (po-av01j.136
    // defect 2). Three sources, in decreasing order of certainty: emitted BY a
    // retriever (recorded above, cannot be wrong), names a registered
    // format_id exactly, or is a known variant of a registered family.
    let registered: std::collections::BTreeSet<&str> =
        retrievers.iter().map(|r| r.format_id()).collect();
    out.sightings = sightings
        .into_iter()
        .map(|(format, file_count)| {
            let retriever_exists = declined.contains(&format)
                || registered.contains(format.as_str())
                || VARIANTS_OF_SUPPORTED.contains(&format.as_str());
            FormatSighting {
                format,
                file_count,
                retriever_exists,
            }
        })
        .collect();
    // Deterministic packet order regardless of directory-walk order.
    out.packets.sort_by_key(|p| p.id());
    out
}

/// First `cap` bytes of a file as lossy UTF-8 (sniffing only).
fn read_head(path: &Path, cap: usize) -> String {
    use std::io::Read as _;
    let Ok(f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::with_capacity(cap);
    let _ = f.take(cap as u64).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// The repo-relative, forward-slashed spelling of `file` under `root`
/// (matches the code lane's spelling so waivers and reports line up).
fn repo_relative(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Canonical rendering of a YAML value for `resolved_value`: scalars render
/// bare, structures render as compact JSON so a value compares stably.
pub(crate) fn render_value(v: &serde_yaml::Value) -> String {
    match v {
        serde_yaml::Value::Null => "null".to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "<unrenderable>".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_id_is_unique_per_file_unit_key() {
        let p = ConfigPacket {
            snapshot_id: "s".into(),
            format: "github-actions".into(),
            file_path: ".github/workflows/ci.yml".into(),
            line: 0,
            unit: "job:build".into(),
            key: "job.timeout-minutes".into(),
            resolved_value: Some("15".into()),
            resolution: Resolution::AsAuthored,
            provenance: vec![],
        };
        assert_eq!(
            p.id(),
            ".github/workflows/ci.yml:job:build:job.timeout-minutes"
        );
    }

    #[test]
    fn sighting_serializes_only_identity_keys() {
        // The privacy audit: a sighting is the WHOLE record for a format no
        // retriever claimed. Adding a path/content-bearing field breaks this
        // test on purpose (same contract as ReportSurface).
        //
        // `retriever_exists` was added by po-av01j.136 and is deliberately
        // allowed: it is a boolean derived from THIS BINARY's retriever
        // registry, not from the scanned repo, so it cannot carry a path, a
        // file name, or any content. Anything carrying repo-derived text still
        // fails here.
        let s = FormatSighting::declined("terraform", 3);
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["file_count", "format", "retriever_exists"],
            "a sighting must carry ONLY format identity, count, and whether we support it"
        );
        assert!(
            obj["retriever_exists"].is_boolean(),
            "the added field must stay a bare boolean: a string could carry repo text"
        );
    }

    #[test]
    fn api_version_value_strips_inline_comments_and_quotes() {
        // Found on Google's Gatekeeper policy corpus, where the licence header
        // sits on the apiVersion line itself.
        assert_eq!(
            api_version_value(
                "apiVersion: constraints.gatekeeper.sh/v1alpha1 # Copyright 2019\nkind: X\n"
            ),
            "constraints.gatekeeper.sh/v1alpha1"
        );
        assert_eq!(
            api_version_value("apiVersion: skaffold/v3 # a comment\nkind: Config\n"),
            "skaffold/v3",
            "an impostor must stay identifiable through a comment"
        );
        assert_eq!(api_version_value("apiVersion: \"v1\"\n"), "v1");
        assert_eq!(api_version_value("apiVersion: 'apps/v1'\n"), "apps/v1");
        assert_eq!(api_version_value("kind: Config\n"), "");
        // A '#' with no leading whitespace is part of the value, not a comment.
        assert_eq!(api_version_value("apiVersion: we#rd/v1\n"), "we#rd/v1");
    }

    #[test]
    fn kubernetes_api_version_admits_real_groups_and_rejects_impostors() {
        // Core group, bare version.
        for v in ["v1", "v1beta1", "v2alpha1"] {
            assert!(is_kubernetes_api_version(v), "{v} is a core apiVersion");
        }
        // Dotless historical groups. A plain "the group must contain a dot"
        // rule would reject all of these, which is why they are enumerated.
        for v in ["apps/v1", "batch/v1", "autoscaling/v2", "policy/v1"] {
            assert!(is_kubernetes_api_version(v), "{v} is a Kubernetes group");
        }
        // Dotted groups: CRDs, cloud vendors, service meshes.
        for v in [
            "networking.k8s.io/v1",
            "networking.istio.io/v1alpha3",
            "cloud.google.com/v1",
            "networking.gke.io/v1",
        ] {
            assert!(
                is_kubernetes_api_version(v),
                "{v} is a Kubernetes CRD group"
            );
        }
        // The impostors. skaffold/v3 is the one observed in the wild.
        for v in ["skaffold/v3", "skaffold/v4beta6", "tekton/v1", ""] {
            assert!(
                !is_kubernetes_api_version(v),
                "{v} is not a Kubernetes apiVersion"
            );
        }
    }

    #[test]
    fn sight_format_classifies_by_path_and_bounded_sniff() {
        assert_eq!(sight_format(".circleci/config.yml", ""), Some("circleci"));
        assert_eq!(sight_format(".travis.yml", ""), Some("travis-ci"));
        // Terraform graduated from a sighting to a supported format
        // (po-av01j.23): .tf files route to the retriever, never here.
        assert_eq!(sight_format("infra/main.tf", ""), None);
        assert_eq!(sight_format("deploy/chart/Chart.yaml", ""), Some("helm"));
        assert_eq!(
            sight_format("k8s/base/kustomization.yaml", ""),
            Some("kustomize")
        );
        assert_eq!(
            sight_format("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"),
            Some("kubernetes")
        );
        assert_eq!(
            sight_format(
                "alerts/rules.yml",
                "groups:\n- name: x\n  rules:\n  - alert: A\n    expr: up == 0\n"
            ),
            Some("prometheus-rules")
        );
        assert_eq!(
            sight_format("monitoring/alertmanager.yml", ""),
            Some("alertmanager"),
            "the canonical file name identifies alertmanager"
        );
        assert_eq!(
            sight_format(
                "config/am.yaml",
                "route:\n  receiver: default\nreceivers:\n- name: default\n"
            ),
            Some("alertmanager"),
            "route+receivers shape identifies alertmanager"
        );
        assert_eq!(
            sight_format(
                "chart/templates/rules.yml",
                "groups:\n- name: x\n  rules:\n  - alert: A\n    expr: up == 0\n    for: {{ .Values.d }}\n"
            ),
            Some("prometheus-rules-templated"),
            "a templated rules variant sights under its own identity"
        );
        assert_eq!(sight_format("docs/notes.yaml", "a: b\n"), None);
        assert_eq!(sight_format("src/main.go", ""), None);
        // po-av01j.136: apiVersion + kind is not enough. skaffold.yaml carries
        // both and is not a Kubernetes manifest; on the dogfood repo it was
        // counted as one, and sightings are the authoring queue.
        assert_eq!(
            sight_format("skaffold.yaml", "apiVersion: skaffold/v3\nkind: Config\n"),
            Some("skaffold"),
            "a tool that borrows the convention sights under its own identity"
        );
        // Dependency-manifest variants the dep-manifests retriever does not
        // parse yet: identity-only, basename-shaped.
        assert_eq!(sight_format("svc/pom.xml", ""), Some("maven"));
        assert_eq!(sight_format("app/build.gradle.kts", ""), Some("gradle"));
        assert_eq!(sight_format("Gemfile", ""), Some("bundler"));
        assert_eq!(sight_format("composer.json", ""), Some("composer"));
        assert_eq!(sight_format("Pipfile", ""), Some("pipfile"));
        assert_eq!(sight_format("mix.exs", ""), Some("mix"));
        assert_eq!(sight_format("build.sbt", ""), Some("sbt"));
    }

    #[test]
    fn retrieve_repo_skips_gitignored_config_files() {
        // po-90lwe: the config lane walked the whole tree and reported findings
        // from a gitignored nested worktree (.claude/worktrees/…) in a backend repo's
        // pre-commit hook output. It must honor .gitignore like the content
        // lane (po-lqbh2), while still scanning non-ignored dotdirs (.github).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), ".claude/\nlocal.tf\n").unwrap();
        // Tracked config — must be retrieved.
        std::fs::write(root.join("main.tf"), "resource \"x\" \"y\" {}\n").unwrap();
        // Gitignored config — must be SKIPPED.
        std::fs::write(root.join("local.tf"), "resource \"secret\" \"z\" {}\n").unwrap();
        std::fs::create_dir_all(root.join(".claude/worktrees/w")).unwrap();
        std::fs::write(
            root.join(".claude/worktrees/w/infra.tf"),
            "resource \"nested\" \"q\" {}\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets.iter().any(|p| p.unit == "resource:x.y"),
            "tracked main.tf must be retrieved: {:?}",
            got.packets
        );
        assert!(
            got.packets
                .iter()
                .all(|p| !p.file_path.contains(".claude/") && p.file_path != "local.tf"),
            "gitignored config must not be retrieved: {:?}",
            got.packets
        );
    }

    #[test]
    fn retrieve_repo_walks_sights_and_skips_vendored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".circleci")).unwrap();
        std::fs::write(root.join(".circleci/config.yml"), "version: 2\n").unwrap();
        std::fs::write(root.join("main.tf"), "resource \"x\" \"y\" {}\n").unwrap();
        std::fs::write(root.join("infra.tf"), "").unwrap();
        // Vendored terraform files must NOT be claimed or sighted — neither a
        // `vendor/` copy nor `terraform init`'s own `.terraform/` cache.
        std::fs::create_dir_all(root.join("vendor")).unwrap();
        std::fs::write(root.join("vendor/v.tf"), "resource \"a\" \"b\" {}\n").unwrap();
        std::fs::create_dir_all(root.join(".terraform/modules/m")).unwrap();
        std::fs::write(
            root.join(".terraform/modules/m/main.tf"),
            "resource \"c\" \"d\" {}\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert_eq!(
            got.sightings,
            vec![FormatSighting {
                format: "circleci".into(),
                file_count: 1,
                retriever_exists: false,
            }],
            "terraform is a supported format now, never a sighting"
        );
        // The root .tf files route to the Terraform retriever...
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "terraform" && p.unit == "resource:x.y"),
            "root .tf files route to the terraform retriever: {:?}",
            got.packets
        );
        // ...and no packet comes from a vendored tree.
        assert!(
            got.packets
                .iter()
                .all(|p| !p.file_path.starts_with("vendor/")
                    && !p.file_path.starts_with(".terraform/")),
            "vendored .tf files must not be retrieved: {:?}",
            got.packets
        );
    }

    #[test]
    fn retrieve_repo_routes_bare_manifests_by_content_sniff() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("k8s")).unwrap();
        std::fs::write(
            root.join("k8s/deploy.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers: []\n",
        )
        .unwrap();
        // A non-k8s YAML with no distinctive path stays unclaimed.
        std::fs::write(root.join("k8s/notes.yaml"), "a: b\n").unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "kubernetes" && p.key == "workload.replicas"),
            "content-matched manifests route to the kubernetes retriever: {:?}",
            got.packets
        );
        assert!(
            got.sightings.is_empty(),
            "a supported format is not sighted: {:?}",
            got.sightings
        );
    }

    #[test]
    fn retriever_emitted_sightings_surface_in_the_lane_retrieval() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("k8s")).unwrap();
        // A templated manifest outside any chart: the kubernetes retriever
        // claims it by content, then abstains with its own sighting — which
        // must merge into the walk's identity+count map.
        std::fs::write(
            root.join("k8s/tpl.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ .Values.name }}\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert_eq!(
            got.sightings,
            vec![FormatSighting {
                format: "kubernetes-templated".into(),
                file_count: 1,
                retriever_exists: true,
            }]
        );
        assert!(got.packets.is_empty());
    }

    #[test]
    fn retrieve_repo_routes_argo_flux_crs_by_content_and_sights_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("deploy")).unwrap();
        // An Argo CD Application: no canonical path, claimed by content.
        std::fs::write(
            root.join("deploy/app.yaml"),
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  syncPolicy:\n    automated: {}\n",
        )
        .unwrap();
        // An argoproj.io CR the family does not parse: a product sighting,
        // never absorbed into the kubernetes bucket.
        std::fs::write(
            root.join("deploy/rollout.yaml"),
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\n",
        )
        .unwrap();
        // A generic Kubernetes manifest: claimed by the kubernetes family
        // (po-av01j.20) — packets, not a sighting.
        std::fs::write(
            root.join("deploy/web.yaml"),
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 2\n  template:\n    spec:\n      containers: []\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "argo-cd" && p.key == "application.syncPolicy.automated"),
            "content routing must reach the ArgoFlux retriever: {:?}",
            got.packets
        );
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "kubernetes" && p.key == "workload.replicas"),
            "a generic manifest is claimed by the kubernetes family: {:?}",
            got.packets
        );
        // The argo-rollouts CR is declined by BOTH families (argo_flux does
        // not parse Rollout; kubernetes refuses foreign apiVersion groups)
        // and sights by product.
        assert_eq!(
            got.sightings,
            vec![FormatSighting {
                format: "argo-rollouts".into(),
                file_count: 1,
                retriever_exists: false,
            }]
        );
    }

    #[test]
    fn retrieve_repo_routes_workflow_files_to_the_gha_retriever() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(
            root.join(".github/workflows/ci.yml"),
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    timeout-minutes: 15\n    steps: []\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "github-actions" && p.key == "job.timeout-minutes"),
            "workflow files route to the GitHub Actions retriever: {:?}",
            got.packets
        );
        assert!(
            got.sightings.is_empty(),
            "a supported format is not sighted"
        );
    }

    #[test]
    fn retrieve_repo_routes_dep_manifests_to_the_dep_manifests_retriever() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("package.json"), r#"{"name":"x"}"#).unwrap();
        std::fs::write(root.join("Dockerfile"), "FROM alpine:latest\n").unwrap();
        // A vendored manifest must NOT be retrieved.
        std::fs::create_dir_all(root.join("node_modules/dep")).unwrap();
        std::fs::write(root.join("node_modules/dep/package.json"), "{}").unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "dep-manifests" && p.key == "package_json.engines.node"),
            "package.json routes to the dep-manifests retriever: {:?}",
            got.packets
        );
        assert!(
            got.packets
                .iter()
                .any(|p| p.key == "dockerfile.base_image_pin"),
            "Dockerfile routes to the dep-manifests retriever: {:?}",
            got.packets
        );
        assert!(
            !got.packets
                .iter()
                .any(|p| p.file_path.starts_with("node_modules/")),
            "vendored manifests are never retrieved: {:?}",
            got.packets
        );
        assert!(
            got.sightings.is_empty(),
            "a supported format is not sighted"
        );
    }

    #[test]
    fn retrieve_repo_routes_rule_files_to_the_prometheus_retriever() {
        // Rule files have no canonical path: the walk identifies them by a
        // bounded head consult (matches_head), anywhere in the tree.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("deploy/alerts")).unwrap();
        std::fs::write(
            root.join("deploy/alerts/api.yml"),
            "groups:\n- name: api\n  rules:\n  - alert: Down\n    expr: up == 0\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(
            got.packets
                .iter()
                .any(|p| p.format == "prometheus-rules" && p.key == "rule.for"),
            "rule files route to the Prometheus retriever: {:?}",
            got.packets
        );
        assert!(
            got.sightings.is_empty(),
            "a supported format is not sighted"
        );
    }

    #[test]
    fn retrieve_repo_sights_templated_rules_and_alertmanager() {
        // A Helm-templated rule file is declined by the retriever (no
        // rendering on the scan path) and degrades to an identity-only
        // sighting; alertmanager config is identified but not inventoried.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("chart/templates")).unwrap();
        std::fs::write(
            root.join("chart/templates/rules.yml"),
            "groups:\n- name: api\n  rules:\n  - alert: A\n    expr: up == 0\n    for: {{ .Values.forDuration }}\n",
        )
        .unwrap();
        std::fs::write(
            root.join("alertmanager.yml"),
            "route:\n  receiver: default\nreceivers:\n- name: default\n",
        )
        .unwrap();
        let got = retrieve_repo(root, "snap");
        assert!(got.packets.is_empty(), "nothing literal to parse");
        assert_eq!(
            got.sightings,
            vec![
                FormatSighting {
                    format: "alertmanager".into(),
                    file_count: 1,
                    retriever_exists: false,
                },
                FormatSighting {
                    format: "prometheus-rules-templated".into(),
                    file_count: 1,
                    retriever_exists: true,
                },
            ]
        );
    }
}
