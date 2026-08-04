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

pub mod dep_manifests;
pub mod eval;
pub mod github_actions;
pub mod gitlab_ci;
pub mod prometheus;

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
}

/// Every supported config-format retriever, in deterministic order.
pub fn registry() -> Vec<Box<dyn ConfigRetriever>> {
    vec![
        Box::new(github_actions::GithubActions),
        Box::new(gitlab_ci::GitlabCi),
        Box::new(dep_manifests::DepManifests),
        Box::new(prometheus::PrometheusRules),
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
}

/// Directory names never worth descending into (mirrors the code lane).
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "vendor",
    "__pycache__",
    "testdata",
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
    if rel.ends_with(".tf") {
        return Some("terraform");
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
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        if col0("apiVersion:") && col0("kind:") {
            return Some("kubernetes");
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
    let mut sightings: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            let rel = repo_relative(root, &path);
            if let Some(r) = retrievers.iter().find(|r| r.matches(&rel)) {
                let Ok(contents) = std::fs::read_to_string(&path) else {
                    out.unparseable_files += 1;
                    continue;
                };
                let got = r.retrieve(&rel, &contents, snapshot_id);
                out.packets.extend(got.packets);
                out.unparseable_files += got.unparseable;
                continue;
            }
            // Path shapes need no read; bare YAML gets a bounded head read
            // for content-identified formats and sighting (content is read
            // locally and dropped either way).
            let needs_head = rel.ends_with(".yml") || rel.ends_with(".yaml");
            let head = if needs_head {
                read_head(&path, 4096)
            } else {
                String::new()
            };
            // Content-identified formats (no canonical path) get a bounded
            // head consult before the file degrades to a sighting.
            if needs_head {
                if let Some(r) = retrievers.iter().find(|r| r.matches_head(&rel, &head)) {
                    let Ok(contents) = std::fs::read_to_string(&path) else {
                        out.unparseable_files += 1;
                        continue;
                    };
                    let got = r.retrieve(&rel, &contents, snapshot_id);
                    out.packets.extend(got.packets);
                    out.unparseable_files += got.unparseable;
                    continue;
                }
            }
            // Unsupported-format sighting.
            if let Some(fmt) = sight_format(&rel, &head) {
                *sightings.entry(fmt).or_insert(0) += 1;
            }
        }
    }

    out.sightings = sightings
        .into_iter()
        .map(|(format, file_count)| FormatSighting {
            format: format.to_string(),
            file_count,
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
    fn sighting_serializes_exactly_two_identity_keys() {
        // The privacy audit: a sighting is the WHOLE record for an
        // unsupported format. Adding a path/content-bearing field breaks this
        // test on purpose (same contract as ReportSurface).
        let s = FormatSighting {
            format: "terraform".into(),
            file_count: 3,
        };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["file_count", "format"],
            "a sighting must carry ONLY format identity + count"
        );
    }

    #[test]
    fn sight_format_classifies_by_path_and_bounded_sniff() {
        assert_eq!(sight_format(".circleci/config.yml", ""), Some("circleci"));
        assert_eq!(sight_format(".travis.yml", ""), Some("travis-ci"));
        assert_eq!(sight_format("infra/main.tf", ""), Some("terraform"));
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
    fn retrieve_repo_walks_sights_and_skips_vendored_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".circleci")).unwrap();
        std::fs::write(root.join(".circleci/config.yml"), "version: 2\n").unwrap();
        std::fs::write(root.join("main.tf"), "resource \"x\" \"y\" {}\n").unwrap();
        std::fs::write(root.join("infra.tf"), "").unwrap();
        // A vendored terraform file must NOT be sighted.
        std::fs::create_dir_all(root.join("vendor")).unwrap();
        std::fs::write(root.join("vendor/v.tf"), "").unwrap();
        let got = retrieve_repo(root, "snap");
        assert_eq!(
            got.sightings,
            vec![
                FormatSighting {
                    format: "circleci".into(),
                    file_count: 1
                },
                FormatSighting {
                    format: "terraform".into(),
                    file_count: 2
                },
            ]
        );
        assert!(got.packets.is_empty());
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
                    file_count: 1
                },
                FormatSighting {
                    format: "prometheus-rules-templated".into(),
                    file_count: 1
                },
            ]
        );
    }
}
