//! The one classifier every config retriever asks two questions of: is this
//! unit deployed to production at all, and is it a whole unit or a fragment
//! another file completes?
//!
//! A spec judges what is deployed. A manifest, module or rule file under a
//! test, example, dev or teaching tree, or in a repository that is sample
//! material as a whole, is not, so its facts must not become findings
//! (frame cells C1, test or fixture, and C2, dev-only or experimental). A
//! kustomize patch is a fragment of a workload: a key it does not author is
//! carried by the base it patches, so its absence is no fact about the
//! workload.
//!
//! Each retriever applies the answers in one way, stated in its own module:
//! the Kubernetes retriever emits nothing for a non-production unit (what it
//! already did for test material); the operator, Argo/Flux, Prometheus,
//! Alertmanager and Terraform retrievers emit the unit's facts valued
//! [`crate::UNDECIDED_PREFIX`] and the reason ([`undecide_unit`]), so the
//! verification lane abstains and says why.

use crate::{ConfigPacket, Resolution, Retrieved};
use serde_yaml::Value;
use std::path::Path;

/// Path tokens that mark a config unit as not deployed to production. A
/// path is split on every non-alphanumeric character, directory segments
/// and the file stem alike, and lower-cased; a unit is non-production when
/// any WHOLE token, or two adjacent tokens of one segment joined by `-`, is
/// listed here, so `devops/`, `latest/`, `contest/` and `production/`
/// deploy. Every unit under a `.github/` directory is non-production too
/// ([`GITHUB_DIR`]).
///
/// Evidence: a blind check of flagged units against the rule frames (two
/// independent judges with repository access, a row counted where both
/// agree) found nearly every flag under these names test or fixture
/// material (C1) or dev-only and experimental config (C2): `tests/`, `e2e/`,
/// `_testdata/`, `test-apps/`, `test-resources/`, `__mocks__/`, the fake and
/// `golden/` trees a chart test compares rendered output against; `docs/`,
/// `book/`, tutorial, course, lab, workshop, snippet and cheatsheet trees,
/// whose units illustrate a page; example, sample, demo, quickstart,
/// scenario, playground, sandbox and proof-of-concept trees (`keda-example/`,
/// Higress `samples/`, Chaos Mesh `examples/`, git-sync `demo/`); `hack/`;
/// the CI-only values a chart is linted with (`helm/ci/`); and dev, local,
/// kind and temporary environments (`dev-env/`, `development/kind/`,
/// `cluster-dev.yaml`, `environments/temp/`). Exact segments alone missed
/// most of these: the stem and the hyphenated parts carry the signal.
///
/// A second check after that classifier found the rest of the wrong flags
/// under a local cluster bootstrap (`.bootstrap/`, a `localstack` emulator),
/// a `single-node` dev setup, `archive/` trees, mock servers (`wiremock/`),
/// load generators (`stress-cpu.yaml`), and preview, canary, staging,
/// proof-of-concept and prototype environments. The test is on path tokens
/// only: a rollout strategy named `canary` in a document is a key, not a
/// path, and stays a fact.
pub const NON_PRODUCTION_TOKENS: &[&str] = &[
    "test",
    "tests",
    "testing",
    "testdata",
    "e2e",
    "fixture",
    "fixtures",
    "mocks",
    "fake",
    "fakedata",
    "golden",
    "example",
    "examples",
    "sample",
    "samples",
    "demo",
    "demos",
    "tutorial",
    "tutorials",
    "training",
    "course",
    "courses",
    "lab",
    "labs",
    "workshop",
    "workshops",
    "snippet",
    "snippets",
    "cheatsheet",
    "cheatsheets",
    "ci",
    "dev",
    "development",
    "local",
    "kind",
    "temp",
    "tmp",
    "playground",
    "sandbox",
    "scenarios",
    "quickstart",
    "hack",
    "docs",
    "doc",
    "book",
    "poc",
    "prototype",
    "bootstrap",
    "localstack",
    "single-node",
    "singlenode",
    "archive",
    "archived",
    "wiremock",
    "mock",
    "stress",
    "preview",
    "canary",
    "staging",
    "stage",
];

/// A directory segment whose units are not deployed: the manifests under
/// `.github/` are applied by CI jobs (the e2e clients a workflow installs),
/// and the workflow files there have a retriever of their own that does not
/// ask this classifier.
pub const GITHUB_DIR: &str = ".github";

/// Tokens of the scanned root directory's own name that mark the whole
/// repository as sample or teaching material, so every unit in it is
/// non-production: the same check found every flag in repositories named
/// for training, cheatsheets, blog code, docs examples and samples not
/// applicable, wherever in the tree the unit sat.
pub const SAMPLE_REPOSITORY_TOKENS: &[&str] = &[
    "samples",
    "sample",
    "examples",
    "example",
    "training",
    "tutorial",
    "tutorials",
    "workshop",
    "course",
    "cheatsheets",
    "blog",
    "blogcode",
    "demo",
    "demos",
    "learning",
    "playground",
    "talks",
    "codelab",
    "codelabs",
];

/// Tokens of a workflow file's stem or a job id that mark a GitHub Actions
/// unit as reaching a non-production environment (frame cell C5), for the
/// static cloud key fact (RC-072). Narrower than [`NON_PRODUCTION_TOKENS`]:
/// every workflow sits under `.github/`, and a `ci-*.yaml` workflow that
/// holds a cloud key was judged a violation, so `ci` is not listed, nor are
/// `staging` and `canary`, which deploy.
pub const NON_PRODUCTION_WORKFLOW_TOKENS: &[&str] = &[
    "dev",
    "development",
    "test",
    "tests",
    "testing",
    "e2e",
    "sandbox",
    "demo",
    "preview",
    "playground",
    "local",
];

/// Upper-case substrings of a secret's name that mark an AWS-shaped key as
/// one for an S3-compatible third party (Cloudflare R2, DigitalOcean
/// Spaces, MinIO, Backblaze B2 and the like), which no cloud federation
/// replaces (frame cell C6).
pub const S3_COMPATIBLE_SECRET_TOKENS: &[&str] = &[
    "R2",
    "CLOUDFLARE",
    "CF_",
    "SPACES",
    "DIGITALOCEAN",
    "DO_",
    "MINIO",
    "B2_",
    "BACKBLAZE",
    "WASABI",
    "SCALEWAY",
    "SCW",
    "OSS",
    "ALIYUN",
    "LINODE",
    "HETZNER",
    "TIGRIS",
    "STORJ",
    "GARAGE",
    "CEPH",
    "OVH",
    "YANDEX",
    "IDRIVE",
    "SUPABASE",
];

/// Text in a workflow file that points its AWS-shaped keys at an
/// S3-compatible endpoint: an endpoint input or variable, or one of those
/// providers' host names. Matched case-sensitively, as written.
pub const S3_COMPATIBLE_FILE_MARKERS: &[&str] = &[
    "endpoint-url",
    "endpoint_url",
    "ENDPOINT",
    "r2.cloudflarestorage.com",
    "digitaloceanspaces.com",
    "backblazeb2.com",
    "wasabisys.com",
    "scw.cloud",
    "aliyuncs.com",
    "linodeobjects.com",
    "your-objectstorage.com",
    "storage.dev",
    "tigris.dev",
    "storjshare.io",
    "cloud.ovh.net",
    "yandexcloud.net",
    "idrivee2",
    "supabase.co",
];

/// Directory tokens under which a Terraform static credential is not one a
/// deployment holds: a retired tree, or library and asset code another
/// module embeds. Asked of the static credential fact (RC-072) only, on top
/// of [`path_token`] (which already holds `archive` and `archived`): `pkg`
/// and `internal` hold deployed code in general.
pub const STATIC_CREDENTIAL_DIR_TOKENS: &[&str] = &["deprecated", "pkg", "internal", "assets"];

/// Directories whose documents are kustomize fragments: patches, and the
/// components an overlay mixes in.
const FRAGMENT_DIRS: &[&str] = &["patches", "components"];

/// File-stem tokens that name a patch (`manager_webhook_patch.yaml`).
const FRAGMENT_STEM_TOKENS: &[&str] = &["patch", "patches"];

/// The reason an absent key of a patch fragment carries.
pub const FRAGMENT_REASON: &str = "patch fragment: the base carries this key";

/// The first token of `s` that `list` holds: a token, or two adjacent
/// tokens of one `/`-segment joined by `-` (`single_node` is `single-node`).
fn listed(s: &str, list: &[&'static str]) -> Option<&'static str> {
    s.split('/').find_map(|segment| {
        let tokens: Vec<String> = segment
            .split(|c: char| !c.is_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase)
            .collect();
        tokens.iter().enumerate().find_map(|(i, t)| {
            let pair = tokens.get(i + 1).map(|next| format!("{t}-{next}"));
            list.iter()
                .copied()
                .find(|w| *w == t || pair.as_deref() == Some(*w))
        })
    })
}

/// The [`NON_PRODUCTION_WORKFLOW_TOKENS`] token of a workflow file stem or
/// a job id, if any.
pub fn workflow_token(name: &str) -> Option<&'static str> {
    listed(name, NON_PRODUCTION_WORKFLOW_TOKENS)
}

/// The [`S3_COMPATIBLE_SECRET_TOKENS`] token a secret's name holds, if any.
pub fn s3_compatible_secret(name: &str) -> Option<&'static str> {
    let upper = name.to_uppercase();
    S3_COMPATIBLE_SECRET_TOKENS
        .iter()
        .copied()
        .find(|t| upper.contains(t))
}

/// The [`S3_COMPATIBLE_FILE_MARKERS`] entry a file's text holds, if any.
pub fn s3_compatible_file(contents: &str) -> Option<&'static str> {
    S3_COMPATIBLE_FILE_MARKERS
        .iter()
        .copied()
        .find(|m| contents.contains(m))
}

/// The [`STATIC_CREDENTIAL_DIR_TOKENS`] token of `rel_path`'s directory, if
/// any.
pub fn static_credential_dir_token(rel_path: &str) -> Option<&'static str> {
    listed(dir_and_stem(rel_path).0, STATIC_CREDENTIAL_DIR_TOKENS)
}

/// A repo-relative path split into its directory and its file stem (the
/// name without its last extension).
fn dir_and_stem(rel_path: &str) -> (&str, &str) {
    let (dir, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
    (dir, name.rsplit_once('.').map_or(name, |(stem, _)| stem))
}

/// The token that marks `rel_path` non-production, if any.
pub fn path_token(rel_path: &str) -> Option<&'static str> {
    let (dir, stem) = dir_and_stem(rel_path);
    if dir.split('/').any(|seg| seg == GITHUB_DIR) {
        return Some(GITHUB_DIR);
    }
    listed(dir, NON_PRODUCTION_TOKENS).or_else(|| listed(stem, NON_PRODUCTION_TOKENS))
}

/// Whether a resource name is a template awaiting substitution rather than
/// a name the API accepts: it holds `$NAME`, `${...}`, `{{ ... }}` or an
/// upper-case `PR_NUMBER`. A Kubernetes object name is lower-case letters,
/// digits, `-` and `.`, so any other character means the file is applied
/// only after a script fills it in (a per-pull-request preview, an e2e
/// template), and is a fragment of what deploys. A chart template is
/// rendered before its name is read, so its rendered name is what is asked.
pub fn placeholder_name(name: &str) -> bool {
    name.chars()
        .any(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.'))
}

/// The reason a unit with a [`placeholder_name`] carries.
pub const PLACEHOLDER_REASON: &str = "unexpanded placeholder in the resource name";

/// The token of the scanned root's own directory name that marks the whole
/// repository as sample material, if any. The name is the last component
/// of the path the scan was given (made absolute when it is `.` or ends in
/// `..`); a root with no name, such as `/` or the empty path a rootless
/// retrieval passes, has no token.
pub fn root_token(root: &Path) -> Option<&'static str> {
    let name = match root.file_name() {
        Some(name) => name.to_os_string(),
        None => root.canonicalize().ok()?.file_name()?.to_os_string(),
    };
    listed(&name.to_string_lossy(), SAMPLE_REPOSITORY_TOKENS)
}

/// Why the unit at `rel_path` is not deployed to production, or `None`
/// when nothing says so. `repo` is the scanned root's [`root_token`], read
/// once per scan by a caller that asks of many units.
pub fn reason(repo: Option<&str>, rel_path: &str) -> Option<String> {
    if let Some(token) = path_token(rel_path) {
        return Some(format!("non-production path: {token}"));
    }
    repo.map(|token| format!("non-production repository: {token}"))
}

/// Carry `p` as [`crate::UNDECIDED_PREFIX`] and `why`. A packet already
/// undecided keeps its own reason, and an unresolvable one stays as it is:
/// the lane abstains on both already.
pub fn undecide(p: &mut ConfigPacket, why: &str) {
    let undecided = p
        .resolved_value
        .as_deref()
        .is_some_and(|v| v.starts_with(crate::UNDECIDED_PREFIX));
    if p.resolution == Resolution::Unresolvable || undecided {
        return;
    }
    p.resolved_value = Some(format!("{}{why}", crate::UNDECIDED_PREFIX));
}

/// Undecide every packet of a file at `rel_path` that is not deployed to
/// production. The behavior of every retriever but Kubernetes.
pub fn undecide_unit(root: Option<&Path>, rel_path: &str, out: &mut Retrieved) {
    if let Some(why) = reason(root.and_then(root_token), rel_path) {
        for p in &mut out.packets {
            undecide(p, &why);
        }
    }
}

/// Whether the Kubernetes document file at `rel_path` is a kustomize patch
/// fragment: it lies under a `patches/` or `components/` directory, its
/// stem holds the token `patch`, or (given `root`) a `kustomization.yaml`
/// in its own directory lists it under `patches`, `patchesStrategicMerge`
/// or `patchesJson6902`.
pub fn patch_fragment(root: Option<&Path>, rel_path: &str) -> bool {
    let (dir, stem) = dir_and_stem(rel_path);
    dir.split('/').any(|seg| FRAGMENT_DIRS.contains(&seg))
        || listed(stem, FRAGMENT_STEM_TOKENS).is_some()
        || root.is_some_and(|root| listed_as_patch(root, dir, rel_path))
}

/// Whether a kustomization in `dir` names the file at `rel_path` as a patch.
fn listed_as_patch(root: &Path, dir: &str, rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    ["kustomization.yaml", "kustomization.yml", "Kustomization"]
        .into_iter()
        .filter_map(|k| std::fs::read_to_string(root.join(dir).join(k)).ok())
        .filter_map(|text| serde_yaml::from_str::<Value>(&text).ok())
        .any(|doc| {
            ["patches", "patchesStrategicMerge", "patchesJson6902"]
                .into_iter()
                .filter_map(|field| doc.get(field).and_then(Value::as_sequence))
                .flatten()
                .filter_map(|entry| match entry {
                    Value::String(path) => Some(path.as_str()),
                    Value::Mapping(m) => m.get("path").and_then(Value::as_str),
                    _ => None,
                })
                .any(|path| path.trim_start_matches("./") == name)
        })
}

/// Undecide the packets of a patch fragment whose key the fragment does not
/// author (a provenance step reads it `absent`); the keys it authors stay
/// facts.
pub fn undecide_fragment_absences(packets: &mut [ConfigPacket]) {
    for p in packets {
        if p.provenance.iter().any(|s| s.role == "absent") {
            undecide(p, FRAGMENT_REASON);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_the_frame_check_found_not_deployed_are_non_production() {
        for (path, token) in [
            ("keda-example/rabbitmq/kustomization.yaml", "example"),
            ("deploy/test-apps/unhealthy-app.yaml", "test"),
            ("test-resources/deployment-for-list-items.yaml", "test"),
            (
                "cmd/cli/kubectl-kyverno/_testdata/apply/test-2/resources.yaml",
                "testdata",
            ),
            ("deploy/helm/ci/backing-services.yaml", "ci"),
            ("infra/helm/aisoc/ci/datastores.yaml", "ci"),
            ("development/kind/dex.yaml", "development"),
            (
                "kubernetes/snippets/define-command-in-deployment.yml",
                "snippets",
            ),
            ("scenarios/ciso/app/manifests/application.yaml", "scenarios"),
            (
                "namespaces/live.cluster/hmpps-manage-people-on-probation-dev/deploy.yaml",
                "dev",
            ),
            ("cnpg/cluster-dev.yaml", "dev"),
            ("course/infra/labs/gcp/02-wordpress/main.tf", "course"),
            ("deployment/terraform/environments/temp/main.tf", "temp"),
            ("tests/fixtures/deploy.yaml", "tests"),
            ("src/__mocks__/deploy.yaml", "mocks"),
            ("hack/dev-env/metallb.yaml", "hack"),
            ("k8s/app.test.yaml", "test"),
            (
                ".bootstrap/localstack/manifests/deployment.yaml",
                "bootstrap",
            ),
            (".bootstrap/portal/manifests/deployment.yaml", "bootstrap"),
            ("k8s/single-node/agent.yml", "single-node"),
            ("k8s/single_node/agent.yml", "single-node"),
            (".github/db-client.yaml", ".github"),
            ("ci/.github/kind/store-client.yaml", ".github"),
            ("archive/network/echo.yaml", "archive"),
            ("deploy/wiremock/wiremock-deployment.yaml", "wiremock"),
            ("deploy/mock/api.yaml", "mock"),
            ("k8s/apps/stress-cpu.yaml", "stress"),
            ("cluster/canary/merger.yaml", "canary"),
            ("deploy/staging/api.yaml", "staging"),
            ("envs/stage/main.tf", "stage"),
            ("deploy/preview/api.yaml", "preview"),
            ("prototype/api.yaml", "prototype"),
        ] {
            assert_eq!(path_token(path), Some(token), "{path}");
        }
    }

    #[test]
    fn deployed_paths_are_not_non_production() {
        for path in [
            "deploy/production/app.yaml",
            "devops/k8s/app.yaml",
            "charts/api/templates/deployment.yaml",
            "clusters/live/apps/api.yaml",
            "infra/prod/db.tf",
            "contest/latest/app.yaml",
            "deploy/production/api.yaml",
            "k8s/node/single.yaml",
            "k8s/single/node/app.yaml",
            "github/k8s/app.yaml",
            "k8s/rollouts/api.yaml",
            "deploy.yaml",
        ] {
            assert_eq!(path_token(path), None, "{path}");
        }
    }

    #[test]
    fn workflow_tokens_leave_ci_and_staging_deployed() {
        for (name, token) in [
            ("deploy-python-backend-dev", Some("dev")),
            ("e2e_tests", Some("e2e")),
            ("deploy_sandbox", Some("sandbox")),
            ("ci-deploy", None),
            ("deploy-staging", None),
            ("release", None),
        ] {
            assert_eq!(workflow_token(name), token, "{name}");
        }
    }

    #[test]
    fn s3_compatible_secrets_and_endpoints_are_named() {
        assert_eq!(s3_compatible_secret("R2_ACCESS_KEY_ID"), Some("R2"));
        assert_eq!(s3_compatible_secret("do_spaces_key"), Some("SPACES"));
        assert_eq!(s3_compatible_secret("AWS_ACCESS_KEY_ID"), None);
        assert_eq!(
            s3_compatible_file("run: aws s3 sync . s3://b --endpoint-url $E"),
            Some("endpoint-url")
        );
        assert_eq!(s3_compatible_file("run: aws s3 sync . s3://b"), None);
    }

    #[test]
    fn static_credential_dir_tokens_read_the_directory_only() {
        assert_eq!(
            static_credential_dir_token("infra/deprecated/iam.tf"),
            Some("deprecated")
        );
        assert_eq!(static_credential_dir_token("pkg/keys/main.tf"), Some("pkg"));
        assert_eq!(static_credential_dir_token("infra/internal.tf"), None);
        assert_eq!(static_credential_dir_token("infra/prod/iam.tf"), None);
    }

    #[test]
    fn a_name_the_api_would_refuse_is_a_placeholder() {
        for name in [
            "board-deployment-PR_NUMBER",
            "db-$NAME",
            "api-${SUFFIX}",
            "{{ .name }}",
        ] {
            assert!(placeholder_name(name), "{name}");
        }
        for name in ["board-deployment", "db", "api-v2.internal"] {
            assert!(!placeholder_name(name), "{name}");
        }
    }

    #[test]
    fn a_sample_repository_is_named_by_its_root_directory() {
        for (root, token) in [
            ("/scans/kubernetes-training", Some("training")),
            ("/scans/cheatsheets", Some("cheatsheets")),
            ("/scans/blogcode", Some("blogcode")),
            ("/scans/docs-examples", Some("examples")),
            ("/scans/terraform-docs-samples", Some("samples")),
            ("/scans/localstack-terraform-samples", Some("samples")),
            ("/scans/devfest-codelabs", Some("codelabs")),
            ("/scans/conference-talks", Some("talks")),
            ("/scans/platform", None),
            ("", None),
        ] {
            assert_eq!(root_token(Path::new(root)), token, "{root}");
        }
        assert_eq!(
            reason(Some("cheatsheets"), "k8s/app.yaml").as_deref(),
            Some("non-production repository: cheatsheets")
        );
        assert_eq!(
            reason(Some("cheatsheets"), "tests/app.yaml").as_deref(),
            Some("non-production path: tests"),
            "the path names its own token first"
        );
        assert_eq!(reason(None, "k8s/app.yaml"), None);
    }

    #[test]
    fn patches_by_directory_stem_or_kustomization_listing_are_fragments() {
        for path in [
            "config/default/manager_webhook_patch.yaml",
            "config/default/manager_prometheus_metrics_patch.yaml",
            "components/image-controller/production/base/manager_resources_patch.yaml",
            "kubernetes/clusters/home/apps/media/immich/app/patches/cnpg.yaml",
        ] {
            assert!(patch_fragment(None, path), "{path}");
        }
        assert!(!patch_fragment(None, "config/manager/manager.yaml"));
        assert!(!patch_fragment(None, "k8s/dispatcher.yaml"));

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("overlay")).unwrap();
        std::fs::write(
            dir.path().join("overlay/kustomization.yaml"),
            "resources: [../base]\npatchesJson6902:\n- path: ./replicas.yaml\n  target: {kind: Deployment, name: web}\n",
        )
        .unwrap();
        assert!(patch_fragment(Some(dir.path()), "overlay/replicas.yaml"));
        assert!(!patch_fragment(Some(dir.path()), "overlay/service.yaml"));
    }
}
