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
//!   * **Kustomize** ([`kustomize`]) — a `kustomization.yaml` resolves its
//!     resource tree (bases, overlays) with strategic-merge patches and the
//!     images/replicas transformers applied, bounded and deterministic. The
//!     overlay chain is the packet's provenance; identity is namePrefix-
//!     agnostic (resources merge by their AUTHORED kind + name). Anything
//!     the bounded merge cannot resolve honestly (JSON6902 ops, `$patch`
//!     directives) emits NO packets for the touched resource, only an
//!     identity sighting — never a guess.
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
        dispatch(None, rel_path, contents, snapshot_id)
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
        dispatch(Some(root), rel_path, contents, snapshot_id)
    }

    /// The batch entry point: kustomization roots, charts, and bare
    /// manifests arrive together; each file dispatches independently (the
    /// cross-FILE resolution lives in kustomize/helm, which read their own
    /// committed inputs under `root`).
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            let got = dispatch(Some(root), rel, contents, snapshot_id);
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

fn dispatch(root: Option<&Path>, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
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
            manifest::retrieve_plain(rel_path, contents, snapshot_id)
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
}
