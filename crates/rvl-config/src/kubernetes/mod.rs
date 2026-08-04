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

    /// The same conservative sniff the sighting classifier uses: YAML with
    /// `apiVersion:` and `kind:` at column 0. Variants this retriever then
    /// declines fall back to the walk's "kubernetes" sighting.
    fn matches_content(&self, rel_path: &str, head: &str) -> bool {
        let is_yaml = rel_path.ends_with(".yml") || rel_path.ends_with(".yaml");
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        is_yaml && col0("apiVersion:") && col0("kind:")
    }

    /// Rootless retrieval: only bare manifests are resolvable (kustomize and
    /// helm need sibling files); a kustomization/Chart file without a root
    /// emits nothing rather than a partial guess.
    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        dispatch(None, rel_path, contents, snapshot_id)
    }

    fn retrieve_with_root(
        &self,
        root: &Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        dispatch(Some(root), rel_path, contents, snapshot_id)
    }
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
    fn matches_content_wants_apiversion_and_kind_at_col0() {
        let r = Kubernetes;
        assert!(r.matches_content("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"));
        assert!(!r.matches_content("k8s/deploy.yaml", "a: b\n"));
        assert!(
            !r.matches_content("notes.txt", "apiVersion: apps/v1\nkind: Deployment\n"),
            "only YAML files"
        );
        assert!(
            !r.matches_content("k8s/deploy.yaml", "  apiVersion: apps/v1\n  kind: X\n"),
            "indented keys are some other document"
        );
    }
}
