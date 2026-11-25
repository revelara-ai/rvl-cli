//! Kubernetes manifests retriever: family (2) of the G6 config lane
//! (wayfinder po-ae75b.1 format order, split out as po-av01j.20).
//!
//! Three variants of one format, dispatched by what the walk hands us:
//!
//!   * **Plain manifests** ([`manifest`]) — any YAML document (multi-doc
//!     included) with `apiVersion:` + `kind:` at column 0, claimed by
//!     content because a bare manifest carries no distinctive path. Values
//!     resolve `as_authored`; decidably-absent keys resolve to the DOCUMENTED
//!     Kubernetes default (`platform_default`). Cluster-side mutators
//!     (LimitRange, a globalDefault PriorityClass, admission webhooks) are
//!     deliberately out of scope: the packet records what the repo says and
//!     what the platform documents absent any cluster override — the same
//!     line the GitHub Actions retriever draws for org settings it CAN
//!     detect as governing (there, the token default always governs, so it
//!     is `unresolvable`; here, the documented default governs unless a
//!     cluster object someone must author says otherwise).
//!     One fact spans files: `workload.pdb-coverage` asks whether a
//!     PodDisruptionBudget selects the workload, and for a bare manifest the
//!     set it is asked of is the file's own directory.
//!   * **Kustomize** ([`kustomize`]) — a `kustomization.yaml` resolves its
//!     resource tree (bases, overlays) with strategic-merge patches and the
//!     images/replicas transformers applied, bounded and deterministic. The
//!     overlay chain is the packet's provenance; identity is namePrefix-
//!     agnostic (resources merge by their AUTHORED kind + name). Anything
//!     the bounded merge cannot resolve honestly (JSON6902 ops, `$patch`
//!     directives) emits NO packets for the touched resource, only an
//!     identity sighting — never a guess.
//!     A kustomization another one references is a base: it emits nothing
//!     itself, and its units are asked through each overlay that renders it.
//!   * **Helm** ([`helm`]) — a `Chart.yaml` renders the chart's own
//!     templates with COMMITTED values only (`values.yaml`); packets stamp
//!     `rendered`. No cluster and no remote fetch, ever. Charts declaring
//!     dependencies not vendored under `charts/` abstain with a sighting;
//!     templates using constructs the bounded renderer does not support
//!     abstain per-file with a sighting.
//!
//! Privacy: packets carry key identities and resolved values only — the
//! image PIN SHAPE (`digest`/`tag`/`latest`), never the image reference;
//! sightings are identity + count, structurally (audited in lib.rs tests).

pub mod helm;
pub mod kustomize;
pub mod manifest;

use crate::{ConfigRetriever, Retrieved};
use std::collections::BTreeSet;
use std::path::Path;

pub struct Kubernetes;

fn basename(rel_path: &str) -> &str {
    rel_path.rsplit('/').next().unwrap_or(rel_path)
}

impl ConfigRetriever for Kubernetes {
    fn format_id(&self) -> &'static str {
        "kubernetes"
    }

    /// Path-shaped members of the family: kustomization roots and helm
    /// charts. Bare manifests are claimed by content instead.
    fn matches(&self, rel_path: &str) -> bool {
        matches!(
            basename(rel_path),
            "kustomization.yaml" | "kustomization.yml" | "Chart.yaml" | "Chart.yml"
        )
    }

    /// The sighting classifier's sniff (`apiVersion:` + `kind:` at column
    /// 0), NARROWED to well-known Kubernetes API groups. Third-party CR
    /// groups are deliberately declined — argo/flux CRs belong to the
    /// argo-flux retriever ahead of this one in the registry, and everything
    /// else falls back to `sight_format`, which classifies argo/flux
    /// products by group and the rest as a "kubernetes" sighting (the
    /// po-av01j.24 family boundary, seen from this side).
    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        let is_yaml = rel_path.ends_with(".yml") || rel_path.ends_with(".yaml");
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        if !(is_yaml && col0("apiVersion:") && col0("kind:")) {
            return false;
        }
        // Every apiVersion in the head must be a group this family owns; a
        // file mixing in ANY foreign CR is declined whole, so its product
        // sighting is never absorbed.
        head.lines()
            .filter_map(|l| l.strip_prefix("apiVersion:"))
            .all(|v| core_group(v.trim()))
    }

    /// Rootless retrieval: only bare manifests are resolvable (kustomize and
    /// helm need sibling files); a kustomization/Chart file without a root
    /// emits nothing rather than a partial guess.
    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        dispatch(None, &BTreeSet::new(), rel_path, contents, snapshot_id)
    }

    /// Root-aware single-file entry: the walk hands content-claimed bare
    /// manifests here; `root` keeps the chart-template / kustomize-sibling
    /// double-count suppression in [`dispatch`] working for them.
    fn retrieve_with_root(
        &self,
        root: &Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        dispatch(
            Some(root),
            &BTreeSet::new(),
            rel_path,
            contents,
            snapshot_id,
        )
    }

    /// The batch entry point: kustomization roots, charts, and bare
    /// manifests arrive together; each file dispatches independently (the
    /// cross-FILE resolution lives in kustomize/helm, which read their own
    /// committed inputs under `root`). The batch holds every kustomization
    /// of the repository, so it alone knows which are bases another one
    /// references ([`kustomize::referenced_bases`]); those emit nothing
    /// themselves.
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let mut out = Retrieved::default();
        let bases = kustomize::referenced_bases(files);
        for (rel, contents) in files {
            let got = dispatch(Some(root), &bases, rel, contents, snapshot_id);
            out.packets.extend(got.packets);
            out.unparseable += got.unparseable;
            out.sightings.extend(got.sightings);
        }
        out
    }
}

/// Whether an `apiVersion` value belongs to the API surface this family
/// inventories: the core group and the built-in `<name>` / `*.k8s.io`
/// groups. `kustomize.config.k8s.io` rides in via the path claim, never
/// this sniff.
fn core_group(api_version: &str) -> bool {
    let group = match api_version.split_once('/') {
        Some((g, _)) => g,
        // Bare "v1" style: the core group.
        None => return true,
    };
    matches!(group, "apps" | "batch" | "policy" | "autoscaling") || group.ends_with(".k8s.io")
}

/// Retrieve one file of the family. A manifest that is not deployed to
/// production ([`crate::non_production`]: its anchor's path, or a sample
/// repository's root) emits no packets at all, for every workload, pod,
/// container, PodDisruptionBudget and autoscaler key: the family's one
/// behavior for test material. Sightings and parse failures still count.
/// A kustomization in `bases` is rendered by the overlays that reference
/// it, and emits nothing as it stands.
fn dispatch(
    root: Option<&Path>,
    bases: &BTreeSet<String>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    if bases.contains(rel_path) {
        return Retrieved::default();
    }
    let mut got = retrieve_file(root, rel_path, contents, snapshot_id);
    if root.and_then(crate::non_production::root_token).is_some() {
        got.packets.clear();
    }
    got.packets
        .retain(|p| crate::non_production::path_token(&p.file_path).is_none());
    got
}

fn retrieve_file(
    root: Option<&Path>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    match basename(rel_path) {
        "kustomization.yaml" | "kustomization.yml" => match root {
            Some(root) => kustomize::retrieve(root, rel_path, contents, snapshot_id),
            None => Retrieved::default(),
        },
        "Chart.yaml" | "Chart.yml" => match root {
            Some(root) => helm::retrieve(root, rel_path, contents, snapshot_id),
            None => Retrieved::default(),
        },
        _ => {
            if let Some(root) = root {
                // A chart template is rendered when its Chart.yaml is
                // visited; a manifest a same-dir kustomization references is
                // resolved when that kustomization is visited. Emitting them
                // standalone too would double-count the same authored facts.
                if helm::under_chart_templates(root, rel_path)
                    || kustomize::claimed_by_sibling(root, rel_path)
                {
                    return Retrieved::default();
                }
            }
            manifest::retrieve_plain(root, rel_path, contents, snapshot_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_kustomization_and_chart_by_path() {
        let r = Kubernetes;
        assert!(r.matches("k8s/base/kustomization.yaml"));
        assert!(r.matches("kustomization.yml"));
        assert!(r.matches("deploy/chart/Chart.yaml"));
        assert!(
            !r.matches("k8s/deployment.yaml"),
            "bare manifests are content-matched"
        );
        assert!(!r.matches(".github/workflows/ci.yml"));
    }

    #[test]
    fn matches_head_wants_apiversion_and_kind_at_col0() {
        let r = Kubernetes;
        assert!(r.matches_head("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"));
        assert!(r.matches_head(
            "k8s/pdb.yaml",
            "apiVersion: policy/v1\nkind: PodDisruptionBudget\n"
        ));
        assert!(r.matches_head("k8s/svc.yaml", "apiVersion: v1\nkind: Service\n"));
        assert!(!r.matches_head("k8s/deploy.yaml", "a: b\n"));
        assert!(
            !r.matches_head("notes.txt", "apiVersion: apps/v1\nkind: Deployment\n"),
            "only YAML files"
        );
        assert!(
            !r.matches_head("k8s/deploy.yaml", "  apiVersion: apps/v1\n  kind: X\n"),
            "indented keys are some other document"
        );
    }

    #[test]
    fn matches_head_declines_foreign_cr_groups_whole_file() {
        // The po-av01j.24 boundary: argo/flux (and any third-party) CRs are
        // never absorbed by the generic manifest sniff — declined files fall
        // to the walk's sight_format, which classifies them by product.
        let r = Kubernetes;
        assert!(!r.matches_head(
            "argo/rollout.yaml",
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\n"
        ));
        assert!(!r.matches_head(
            "flux/sync.yaml",
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n"
        ));
        assert!(
            !r.matches_head(
                "mixed.yaml",
                "apiVersion: v1\nkind: Service\n---\napiVersion: argoproj.io/v1alpha1\nkind: Rollout\n"
            ),
            "one foreign CR declines the whole file"
        );
        assert!(!r.matches_head(
            "istio.yaml",
            "apiVersion: networking.istio.io/v1beta1\nkind: VirtualService\n"
        ));
    }

    const DEPLOY: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n      containers:\n        - name: app\n          image: web:v1\n";

    #[test]
    fn a_manifest_under_a_non_production_path_emits_nothing() {
        for path in [
            "keda-example/rabbitmq/deploy.yaml",
            "deploy/test-apps/unhealthy-app.yaml",
            "deploy/helm/ci/backing-services.yaml",
            "development/kind/dex.yaml",
            "kubernetes/snippets/define-command-in-deployment.yml",
            "cnpg/cluster-dev.yaml",
            "docs/content/reference/deploy.yml",
            "hack/dev-env/web.yaml",
            ".bootstrap/localstack/manifests/deployment.yaml",
            "k8s/single-node/agent.yml",
            ".github/db-client.yaml",
            "archive/network/echo.yaml",
            "deploy/wiremock/wiremock-deployment.yaml",
            "k8s/apps/stress-cpu.yaml",
            "cluster/canary/merger.yaml",
        ] {
            let got = Kubernetes.retrieve(path, DEPLOY, "snap");
            assert!(got.packets.is_empty(), "{path}: {:?}", got.packets);
        }
        for path in [
            "deploy/production/app.yaml",
            "deploy/production/api.yaml",
            "devops/k8s/app.yaml",
            "clusters/live/apps/api.yaml",
        ] {
            let got = Kubernetes.retrieve(path, DEPLOY, "snap");
            for key in [
                "workload.replicas",
                "container.liveness-probe",
                "container.resources.requests.cpu",
                "container.image.pin",
            ] {
                assert!(got.packets.iter().any(|p| p.key == key), "{path}: {key}");
            }
        }
    }

    #[test]
    fn every_manifest_of_a_sample_repository_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("kubernetes-training");
        std::fs::create_dir_all(root.join("k8s")).unwrap();
        std::fs::write(root.join("k8s/deploy.yaml"), DEPLOY).unwrap();
        let got = Kubernetes.retrieve_with_root(&root, "k8s/deploy.yaml", DEPLOY, "snap");
        assert!(got.packets.is_empty(), "{:?}", got.packets);
        // The same manifest in a repository not named for samples deploys.
        let root = dir.path().join("platform");
        std::fs::create_dir_all(root.join("k8s")).unwrap();
        std::fs::write(root.join("k8s/deploy.yaml"), DEPLOY).unwrap();
        let got = Kubernetes.retrieve_with_root(&root, "k8s/deploy.yaml", DEPLOY, "snap");
        assert!(got.packets.iter().any(|p| p.key == "workload.pdb-coverage"));
    }

    #[test]
    fn a_bare_workload_is_matched_against_the_pdbs_of_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        let k8s = dir.path().join("k8s");
        std::fs::create_dir_all(&k8s).unwrap();
        let deploy = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    metadata:\n      labels:\n        app: web\n    spec:\n      containers: []\n";
        std::fs::write(k8s.join("deploy.yaml"), deploy).unwrap();
        std::fs::write(
            k8s.join("pdb.yaml"),
            "apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: web\nspec:\n  minAvailable: 1\n  selector:\n    matchLabels:\n      app: web\n",
        )
        .unwrap();
        let value = |got: Retrieved| {
            got.packets
                .into_iter()
                .find(|p| p.key == "workload.pdb-coverage")
                .map(|p| p.resolved_value)
        };
        let rooted = Kubernetes.retrieve_with_root(dir.path(), "k8s/deploy.yaml", deploy, "snap");
        assert_eq!(value(rooted), Some(Some("covered".to_string())));
        // Rootless, the directory is out of reach: no claim either way.
        let rootless = Kubernetes.retrieve("k8s/deploy.yaml", deploy, "snap");
        assert_eq!(value(rootless), None);
    }

    /// Write `files` under `root` and retrieve the batch the walk hands
    /// over: every kustomization of the repository.
    fn batch(root: &Path, files: &[(&str, &str)]) -> Retrieved {
        let mut claimed = Vec::new();
        for (rel, contents) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
            if Kubernetes.matches(rel) {
                claimed.push((rel.to_string(), contents.to_string()));
            }
        }
        Kubernetes.retrieve_all(root, &claimed, "snap")
    }

    fn statefulset(name: &str) -> String {
        format!("apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: {name}\nspec:\n  replicas: 1\n  template:\n    spec:\n      containers:\n        - name: {name}\n          image: {name}:1\n")
    }

    /// Two app bases, and overlays named `overlays` that reference both.
    fn apps_referenced_by(overlays: &[&str]) -> Retrieved {
        let dir = tempfile::tempdir().unwrap();
        let (testapi, moto) = (statefulset("testapi"), statefulset("moto"));
        let mut files = vec![
            ("config/apps/testapi/testapi.yaml", testapi.as_str()),
            (
                "config/apps/testapi/kustomization.yaml",
                "resources:\n  - testapi.yaml\n",
            ),
            ("config/apps/moto/moto.yaml", moto.as_str()),
            (
                "config/apps/moto/kustomization.yaml",
                "resources:\n  - moto.yaml\n",
            ),
        ];
        let paths: Vec<String> = overlays
            .iter()
            .map(|o| format!("config/{o}/kustomization.yaml"))
            .collect();
        for path in &paths {
            files.push((path, "resources:\n  - ../apps/testapi\n  - ../apps/moto\n"));
        }
        batch(dir.path(), &files)
    }

    #[test]
    fn a_base_only_non_production_overlays_reference_emits_nothing() {
        let got = apps_referenced_by(&["ci", "dev"]);
        assert!(got.packets.is_empty(), "{:?}", got.packets);
        // A production overlay renders the same bases, under its own path.
        let got = apps_referenced_by(&["ci", "production"]);
        for unit in ["statefulset:testapi", "statefulset:moto"] {
            let rows: Vec<_> = got.packets.iter().filter(|p| p.unit == unit).collect();
            assert!(!rows.is_empty(), "{unit}: {:?}", got.packets);
            assert!(
                rows.iter()
                    .all(|p| p.file_path == "config/production/kustomization.yaml"),
                "{unit}: {rows:?}"
            );
        }
    }

    #[test]
    fn a_base_behind_a_non_production_overlay_emits_nothing_at_any_depth() {
        let dir = tempfile::tempdir().unwrap();
        let api = statefulset("api");
        let got = batch(
            dir.path(),
            &[
                ("deploy/base/api.yaml", &api),
                (
                    "deploy/base/kustomization.yaml",
                    "resources:\n  - api.yaml\n",
                ),
                (
                    "deploy/shared/kustomization.yaml",
                    "resources:\n  - ../base\n",
                ),
                (
                    "deploy/dev/kustomization.yaml",
                    "resources:\n  - ../shared\n",
                ),
            ],
        );
        assert!(got.packets.is_empty(), "{:?}", got.packets);
    }

    const PDB: &str = "apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: web\nspec:\n  minAvailable: 1\n  selector:\n    matchLabels:\n      app: web\n";

    #[test]
    fn a_base_emits_nothing_itself_and_its_overlay_renders_it() {
        let dir = tempfile::tempdir().unwrap();
        let got = batch(
            dir.path(),
            &[
                ("deploy/kubernetes/base/web.yaml", DEPLOY),
                (
                    "deploy/kubernetes/base/kustomization.yaml",
                    "resources:\n  - web.yaml\n",
                ),
                ("deploy/kubernetes/production/pdb.yaml", PDB),
                (
                    "deploy/kubernetes/production/kustomization.yaml",
                    "resources:\n  - ../base\n  - pdb.yaml\nreplicas:\n  - name: web\n    count: 2\n",
                ),
            ],
        );
        assert!(
            got.packets
                .iter()
                .all(|p| p.file_path == "deploy/kubernetes/production/kustomization.yaml"),
            "{:?}",
            got.packets
        );
        let value = |key: &str| {
            got.packets
                .iter()
                .find(|p| p.unit == "deployment:web" && p.key == key)
                .and_then(|p| p.resolved_value.clone())
        };
        assert_eq!(value("workload.replicas").as_deref(), Some("2"));
        assert_eq!(value("workload.pdb-coverage").as_deref(), Some("covered"));
    }

    #[test]
    fn a_unit_the_production_overlay_deletes_is_not_emitted_from_its_base() {
        let dir = tempfile::tempdir().unwrap();
        let redis = statefulset("redis");
        let got = batch(
            dir.path(),
            &[
                ("k8s/web.yaml", DEPLOY),
                ("k8s/redis.yaml", &redis),
                (
                    "k8s/kustomization.yaml",
                    "resources:\n  - web.yaml\n  - redis.yaml\n",
                ),
                (
                    "k8s/overlays/production/drop-redis.yaml",
                    "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: redis\n$patch: delete\n",
                ),
                (
                    "k8s/overlays/production/kustomization.yaml",
                    "resources:\n  - ../..\npatches:\n  - path: drop-redis.yaml\n",
                ),
            ],
        );
        assert!(
            !got.packets.iter().any(|p| p.unit.contains("redis")),
            "{:?}",
            got.packets
        );
        assert!(got.packets.iter().any(|p| p.unit == "deployment:web"));
    }

    #[test]
    fn a_root_kustomization_nothing_references_keeps_its_units() {
        let dir = tempfile::tempdir().unwrap();
        let got = batch(
            dir.path(),
            &[
                ("deploy/kubernetes/base/web.yaml", DEPLOY),
                (
                    "deploy/kubernetes/base/kustomization.yaml",
                    "resources:\n  - web.yaml\n",
                ),
                // A self-reference does not make a kustomization a base.
                ("k8s/kustomization.yaml", "resources:\n  - .\n"),
            ],
        );
        let p = got
            .packets
            .iter()
            .find(|p| p.unit == "deployment:web" && p.key == "workload.replicas")
            .expect("the root emits");
        assert_eq!(p.resolved_value.as_deref(), Some("1"));
        assert_eq!(p.file_path, "deploy/kubernetes/base/kustomization.yaml");
    }

    #[test]
    fn every_manifest_of_a_lab_repository_emits_nothing() {
        let dir = tempfile::tempdir().unwrap();
        for (repo, emits) in [("aks-landing-zone-lab", false), ("platform", true)] {
            let root = dir.path().join(repo);
            std::fs::create_dir_all(root.join("k8s/apps")).unwrap();
            std::fs::write(root.join("k8s/apps/log-generator.yaml"), DEPLOY).unwrap();
            let got =
                Kubernetes.retrieve_with_root(&root, "k8s/apps/log-generator.yaml", DEPLOY, "snap");
            assert_eq!(!got.packets.is_empty(), emits, "{repo}: {:?}", got.packets);
        }
    }

    #[test]
    fn performance_test_tooling_emits_nothing_and_a_performance_service_does() {
        for path in [
            "perf/dashboards/exporters/redis_exporter.yaml",
            "k8s/loadtest/web.yaml",
            "benchmarks/web.yaml",
        ] {
            let got = Kubernetes.retrieve(path, DEPLOY, "snap");
            assert!(got.packets.is_empty(), "{path}: {:?}", got.packets);
        }
        let got = Kubernetes.retrieve("deploy/performance-api.yaml", DEPLOY, "snap");
        assert!(got.packets.iter().any(|p| p.key == "workload.replicas"));
    }
}
