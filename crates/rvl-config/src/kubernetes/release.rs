//! The repository-scope facts the release keys of a workload ask (RC-014):
//! can a rollback return to what ran before?
//!
//! A container on a mutable tag (`:latest`, `:main`) cannot be rolled back
//! to its old image, because the old build no longer has the name. That is
//! only true of the committed tag when nothing replaces it before it is
//! applied, so one walk of the repository answers two questions once per
//! scan:
//!
//!   * which image names a kustomization's `images:` sets (an overlay
//!     gives them their tag);
//!   * whether a CI file, Makefile or script sets images at deploy time
//!     ([`crate::non_production::image_rewrite`]), a build tool such as
//!     skaffold or tilt is configured, or an in-cluster image updater is
//!     declared.
//!
//! Nothing read here rides in a packet: image names and script text stay in
//! this module, and only the reason an image fact is not judged leaves it.

use crate::non_production;
use serde_yaml::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The key: whether a container's image tag is one a registry moves.
pub const TAG_MUTABLE_KEY: &str = "container.image.tag-mutable";

/// The key: a Deployment's `spec.revisionHistoryLimit`.
pub const REVISION_HISTORY_KEY: &str = "workload.revision-history-limit";

/// Files larger than this are not read: a generated bundle, never a
/// kustomization or a deploy script.
const MAX_FILE_BYTES: u64 = 4 << 20;

/// How a rendered workload's release facts are scoped.
#[derive(Clone, Copy)]
pub(crate) enum Release<'a> {
    /// No scan root: the repository cannot be read.
    Rootless,
    /// Rendered from a Helm chart, whose values decide what deploys.
    Chart,
    /// A repository whose facts were read.
    Repo(&'a RepoRelease),
}

/// The answers one walk of the repository gives.
#[derive(Debug, Default)]
pub(crate) struct RepoRelease {
    root: PathBuf,
    /// Every `images[].name` of every kustomization.
    kustomize_images: BTreeSet<String>,
    /// The marker of the first deploy-time image rewrite found, if any.
    rewrite: Option<&'static str>,
}

impl RepoRelease {
    /// Read the facts from every file the config lane walks under `root`.
    pub(crate) fn read(root: &Path) -> Self {
        let mut facts = RepoRelease {
            root: root.to_path_buf(),
            ..Default::default()
        };
        for entry in crate::walk(root).flatten() {
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let rel = crate::repo_relative(root, entry.path());
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            if non_production::IMAGE_REWRITE_FILES.contains(&name) {
                facts.rewrite.get_or_insert(name_marker(name));
                continue;
            }
            let kustomization = matches!(
                name,
                "kustomization.yaml" | "kustomization.yml" | "Kustomization"
            );
            let script = non_production::deploy_script(&rel);
            let yaml = name.ends_with(".yaml") || name.ends_with(".yml");
            if !(kustomization || script || yaml) {
                continue;
            }
            if entry.metadata().is_ok_and(|m| m.len() > MAX_FILE_BYTES) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            if kustomization {
                facts.kustomize_images.extend(kustomize_images(&text));
            } else if script {
                if let Some(m) = non_production::image_rewrite(&text) {
                    facts.rewrite.get_or_insert(m);
                }
            } else if let Some(m) = non_production::IMAGE_UPDATER_MARKERS
                .iter()
                .find(|m| text.contains(*m))
            {
                facts.rewrite.get_or_insert(m);
            }
        }
        facts
    }

    /// Why the release facts of the unit `name` (in `namespace`) at
    /// `rel_path` are not judged, if any.
    pub(crate) fn unit_reason(
        &self,
        rel_path: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> Option<String> {
        non_production::release_reason(Some(&self.root), rel_path, name, namespace)
    }
}

/// The marker a build tool's own config file stands for.
fn name_marker(name: &str) -> &'static str {
    match name {
        "Tiltfile" => "Tiltfile",
        _ => "skaffold",
    }
}

/// The `images[].name` entries of one kustomization.
fn kustomize_images(text: &str) -> Vec<String> {
    let Ok(doc) = serde_yaml::from_str::<Value>(text) else {
        return Vec::new();
    };
    doc.get("images")
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|i| i.get("name").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// An image reference without its digest and tag.
fn image_name(image: &str) -> &str {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    // The tag follows the last ':' of the last path segment; a registry
    // port (host:5000/app) is not one.
    let seg_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[seg_start..].rfind(':') {
        Some(i) => &image[..seg_start + i],
        None => image,
    }
}

/// The tag of an image reference, if it has one.
fn image_tag(image: &str) -> Option<&str> {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    let name = image_name(image);
    image.get(name.len() + 1..).filter(|t| !t.is_empty())
}

/// The value of `container.image.tag-mutable` for `image`: `Ok("true")` for
/// a mutable tag (or none, which pulls `latest`) and no digest,
/// `Ok("false")` otherwise; `Err(reason)` when the image is not judged.
pub(super) fn tag_mutable(release: Release, image: &str) -> Result<&'static str, String> {
    let name = image_name(image);
    if non_production::placeholder_image(image) {
        return Err("placeholder image or registry".into());
    }
    if !name.contains('/') {
        return Err("image name has no registry or owner: a placeholder or library image".into());
    }
    let repo = match release {
        Release::Repo(repo) => repo,
        Release::Chart => return Err("inside a Helm chart: its values decide what deploys".into()),
        Release::Rootless => {
            return Err("no scan root: a deploy step that sets the image is not ruled out".into())
        }
    };
    if repo.kustomize_images.contains(name) {
        return Err("a kustomization sets this image's tag".into());
    }
    if let Some(marker) = repo.rewrite {
        return Err(format!(
            "the repository sets images at deploy time ({marker})"
        ));
    }
    if image.contains('@') {
        return Ok("false");
    }
    let mutable = image_tag(image).is_none_or(|t| {
        non_production::MUTABLE_IMAGE_TAGS.contains(&t.to_ascii_lowercase().as_str())
    });
    Ok(if mutable { "true" } else { "false" })
}

/// Why the release facts of the workload `name` are not judged, if any.
pub(super) fn unit_reason(
    release: Release,
    rel_path: &str,
    name: &str,
    namespace: Option<&str>,
) -> Option<String> {
    match release {
        Release::Repo(repo) => repo.unit_reason(rel_path, name, namespace),
        Release::Chart => Some("inside a Helm chart: its values decide what deploys".into()),
        Release::Rootless => non_production::release_reason(None, rel_path, name, namespace),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_name_and_tag_split_on_the_last_segment() {
        assert_eq!(image_name("ghcr.io/acme/web:main"), "ghcr.io/acme/web");
        assert_eq!(image_tag("ghcr.io/acme/web:main"), Some("main"));
        assert_eq!(
            image_name("registry:5000/acme/web"),
            "registry:5000/acme/web"
        );
        assert_eq!(image_tag("registry:5000/acme/web"), None);
        assert_eq!(image_name("acme/web:v1@sha256:ab"), "acme/web");
        assert_eq!(image_tag("acme/web:v1@sha256:ab"), Some("v1"));
    }

    fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, RepoRelease) {
        let dir = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let facts = RepoRelease::read(dir.path());
        (dir, facts)
    }

    #[test]
    fn mutable_tags_and_untagged_images_are_mutable_and_pins_are_not() {
        let (_dir, facts) = repo(&[]);
        let r = Release::Repo(&facts);
        for image in [
            "ghcr.io/acme/web:latest",
            "ghcr.io/acme/web",
            "acme/web:Main",
        ] {
            assert_eq!(tag_mutable(r, image), Ok("true"), "{image}");
        }
        for image in [
            "ghcr.io/acme/web:v1.2.3",
            "ghcr.io/acme/web:latest@sha256:ab",
            "acme/web:mainline",
        ] {
            assert_eq!(tag_mutable(r, image), Ok("false"), "{image}");
        }
    }

    #[test]
    fn library_and_placeholder_images_are_not_judged() {
        let (_dir, facts) = repo(&[]);
        let r = Release::Repo(&facts);
        for image in [
            "controller:latest",
            "nginx",
            "example.com/web:latest",
            "localhost:5000/web:latest",
            "acme/<image>:latest",
            "acme/Placeholder:latest",
            "YOUR_REGISTRY/web:latest",
        ] {
            assert!(tag_mutable(r, image).is_err(), "{image}");
        }
    }

    #[test]
    fn a_kustomization_image_or_a_deploy_rewrite_leaves_the_tag_unjudged() {
        let (_dir, facts) = repo(&[(
            "k8s/prod/kustomization.yaml",
            "resources: [../base]\nimages:\n  - name: ghcr.io/acme/web\n    newTag: v2\n",
        )]);
        let r = Release::Repo(&facts);
        assert!(tag_mutable(r, "ghcr.io/acme/web:latest").is_err());
        assert_eq!(tag_mutable(r, "ghcr.io/acme/api:latest"), Ok("true"));

        for (rel, text) in [
            (
                ".github/workflows/deploy.yml",
                "jobs:\n  d:\n    steps:\n      - run: kubectl set image deploy/web web=$REF\n",
            ),
            (
                "Makefile",
                "deploy:\n\tsed -i 's|image: .*|image: $(REF)|' k8s/web.yaml\n",
            ),
            (
                "scripts/release.sh",
                "yq -i '.spec.image = env(REF)' k8s/web.yaml\n",
            ),
            ("skaffold.yaml", "apiVersion: skaffold/v4beta6\n"),
            (
                "clusters/prod/policy.yaml",
                "apiVersion: image.toolkit.fluxcd.io/v1beta2\nkind: ImagePolicy\n",
            ),
        ] {
            let (_dir, facts) = repo(&[(rel, text)]);
            let got = tag_mutable(Release::Repo(&facts), "ghcr.io/acme/web:latest");
            assert!(got.is_err(), "{rel}: {got:?}");
        }
        // A script that never touches an image leaves the tag judged.
        let (_dir, facts) = repo(&[("Makefile", "test:\n\tcargo test\n")]);
        assert_eq!(
            tag_mutable(Release::Repo(&facts), "ghcr.io/acme/web:latest"),
            Ok("true")
        );
    }

    #[test]
    fn rootless_and_chart_images_are_not_judged() {
        assert!(tag_mutable(Release::Rootless, "ghcr.io/acme/web:latest").is_err());
        assert!(tag_mutable(Release::Chart, "ghcr.io/acme/web:latest").is_err());
    }
}
