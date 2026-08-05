//! Argo CD / Flux retriever: the GitOps family (6) of the G6 config lane
//! (po-av01j.24), covering the deployment-excellence / GitOps-rollback slice
//! of the G6 control set (RC-014/015/036/050 — granularity map §2 G6).
//!
//! Custom resources have no canonical path — an Application or HelmRelease
//! can live anywhere in a repo — so this family claims files by CONTENT: the
//! [`ConfigRetriever::matches_head`] hook routes a YAML file here iff its
//! head shows an apiVersion in the `argoproj.io` or `*.fluxcd.io` groups AND
//! a kind this retriever parses. Generic Kubernetes manifests are NEVER
//! claimed (they belong to the Kubernetes family, po-av01j.20); argo/flux
//! CRs of other kinds (Rollouts, Workflows, image automation, ...) are
//! sighted identity-only by [`sight_unrecognized`] instead.
//!
//! Kinds parsed, and the facts emitted (packet formats are per-product,
//! `argo-cd` and `flux`, so spec identities and waiver class rules read
//! naturally):
//!
//!   * Application / ApplicationSet (`argoproj.io`, format `argo-cd`) —
//!     `application.syncPolicy.automated` (presence), `.prune` / `.selfHeal`
//!     (documented `false` defaults), `application.syncPolicy.retry`
//!     (automated apps only: an unattended sync loop with no bounded retry
//!     is the risk a spec judges), `application.targetRevision.shape`
//!     (`pinned` | `floating`; HEAD/branch float, tag/SHA pin — the value is
//!     the SHAPE, never the ref itself), `application.project`,
//!     `application.ignoreDifferences`. An ApplicationSet's
//!     `spec.template.spec` IS an Application spec: it emits the same
//!     `application.*` keys under an `applicationset:` unit, so one spec
//!     identity judges both.
//!   * Kustomization (`kustomize.toolkit.fluxcd.io`) —
//!     `kustomization.interval` / `.prune` (required fields), `.wait`
//!     (documented `false`), `.timeout` (documented: defaults to the
//!     interval).
//!   * HelmRelease (`helm.toolkit.fluxcd.io`) — `helmrelease.interval`,
//!     `.timeout` (documented `300s`),
//!     `helmrelease.install.remediation.retries` /
//!     `helmrelease.upgrade.remediation.retries` (documented `0`: a failed
//!     install/upgrade is NOT remediated unless asked — the rollback
//!     control's evidence).
//!   * GitRepository / HelmRepository (`source.toolkit.fluxcd.io`) —
//!     `.interval`, and `gitrepository.ref.shape` (`commit` | `semver` |
//!     `tag` | `branch` | `other`; an absent ref is the documented
//!     master-branch default). Shape only: no branch, tag, or URL value is
//!     ever emitted.
//!
//! Absence policy (this family's reading of the lane contract):
//!
//!   * absent key with a platform-DOCUMENTED default value →
//!     [`Resolution::PlatformDefault`] with that value (the GitHub Actions
//!     precedent);
//!   * decidable absence with no default value — the feature is simply not
//!     configured, or a required field is missing — → an AS-AUTHORED-ABSENT
//!     packet: [`Resolution::AsAuthored`], value [`crate::ABSENT_RENDERING`],
//!     provenance role "absent". The committed CR is the entire authored
//!     intent, so its absences are authored facts, judgeable by specs (the
//!     `configured` pattern) — never platform-side unknowns.
//!
//! Seed-grade bounds, recorded for the corpus follow-up bead: only
//! `spec.source` of an Application is read (multi-source apps emit no
//! targetRevision packet), content claiming reads the walk's bounded head,
//! and ref-shape precedence is checked commit > semver > tag > branch.

use crate::{
    render_value, ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved,
    ABSENT_RENDERING,
};
use serde::Deserialize as _;
use serde_yaml::Value;

pub struct ArgoFlux;

/// Packet format for Argo CD resources.
const FORMAT_ARGO: &str = "argo-cd";
/// Packet format for Flux resources.
const FORMAT_FLUX: &str = "flux";

impl ConfigRetriever for ArgoFlux {
    fn format_id(&self) -> &'static str {
        "argo-flux"
    }

    /// No canonical path: CRs live anywhere. Path-based matching never
    /// claims; [`Self::matches_head`] does the claiming by content.
    fn matches(&self, _rel_path: &str) -> bool {
        false
    }

    /// Claim a YAML file iff its head shows an argo/flux apiVersion group
    /// paired with a kind this retriever parses. Generic Kubernetes
    /// manifests (any other group) are never claimed — the family boundary
    /// with po-av01j.20.
    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        if !(rel_path.ends_with(".yml") || rel_path.ends_with(".yaml")) {
            return false;
        }
        head_scan(head)
            .iter()
            .any(|(api, kind)| recognized(group_of(api), kind))
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        retrieve(rel_path, contents, snapshot_id)
    }
}

/// The apiVersion group: everything before the first `/`.
fn group_of(api_version: &str) -> &str {
    api_version.split('/').next().unwrap_or(api_version)
}

fn is_argo_group(group: &str) -> bool {
    group == "argoproj.io"
}

fn is_flux_group(group: &str) -> bool {
    group == "fluxcd.io" || group.ends_with(".fluxcd.io")
}

/// The (group, kind) pairs this retriever parses. Group-qualified on
/// purpose: a `kustomize.config.k8s.io` Kustomization is a kustomize
/// overlay, not a Flux CR, and must never be claimed.
fn recognized(group: &str, kind: &str) -> bool {
    match kind {
        "Application" | "ApplicationSet" => is_argo_group(group),
        "Kustomization" => group == "kustomize.toolkit.fluxcd.io",
        "HelmRelease" => group == "helm.toolkit.fluxcd.io",
        "GitRepository" | "HelmRepository" => group == "source.toolkit.fluxcd.io",
        _ => false,
    }
}

/// Per-document (apiVersion, kind) pairs found in a bounded head window.
/// Column-0 scanning only — the same discipline as `sight_format`'s sniffs;
/// the content is read locally and discarded.
fn head_scan(head: &str) -> Vec<(String, String)> {
    let clean = |v: &str| v.trim().trim_matches('"').trim_matches('\'').to_string();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut api = String::new();
    let mut kind = String::new();
    for line in head.lines() {
        if line.trim_end() == "---" {
            if !api.is_empty() || !kind.is_empty() {
                out.push((std::mem::take(&mut api), std::mem::take(&mut kind)));
            }
            continue;
        }
        if let Some(v) = line.strip_prefix("apiVersion:") {
            api = clean(v);
        } else if let Some(v) = line.strip_prefix("kind:") {
            kind = clean(v);
        }
    }
    if !api.is_empty() || !kind.is_empty() {
        out.push((api, kind));
    }
    out
}

/// Classify an argo/flux CR head as a product-identity sighting. Called by
/// the walk's `sight_format` BEFORE the generic-kubernetes sniff, so an
/// unrecognized Rollout or ImagePolicy is recorded under its product, never
/// absorbed into the `kubernetes` bucket (the po-av01j.20 boundary works in
/// both directions). Returns `None` for anything outside the argo/flux
/// apiVersion groups.
pub(crate) fn sight_unrecognized(head: &str) -> Option<&'static str> {
    for (api, kind) in head_scan(head) {
        let group = group_of(&api);
        if is_argo_group(group) {
            return Some(match kind.as_str() {
                "Rollout"
                | "AnalysisTemplate"
                | "ClusterAnalysisTemplate"
                | "AnalysisRun"
                | "Experiment" => "argo-rollouts",
                "Workflow"
                | "CronWorkflow"
                | "WorkflowTemplate"
                | "ClusterWorkflowTemplate"
                | "WorkflowEventBinding" => "argo-workflows",
                "EventSource" | "Sensor" | "EventBus" => "argo-events",
                // Application/ApplicationSet route to the retriever before
                // sighting; anything else argoproj.io (AppProject, ...) is
                // Argo CD surface this family does not parse yet.
                _ => "argo-cd",
            });
        }
        if is_flux_group(group) {
            return Some("flux");
        }
    }
    None
}

/// Pin shape of an Argo CD targetRevision: HEAD, an empty value, or a branch
/// name float; a full 40-hex commit SHA or a semver-ish tag (`v1`, `1.2.3`,
/// `v1.2.3-rc.1`) pins. Anything unclassifiable floats — conservative for a
/// pin-shape spec, and documented for the corpus follow-up.
fn pin_shape(reference: &str) -> &'static str {
    let r = reference.trim();
    if r.is_empty() || r == "HEAD" {
        return "floating";
    }
    if r.len() == 40 && r.bytes().all(|b| b.is_ascii_hexdigit()) {
        return "pinned";
    }
    let core = r.strip_prefix('v').unwrap_or(r);
    let core = core.split(['-', '+']).next().unwrap_or(core);
    if !core.is_empty()
        && core
            .split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()))
    {
        return "pinned";
    }
    "floating"
}

/// One config unit's packet sink: carries the constants every packet of the
/// unit repeats so the emitters below read as key lists.
struct Emitter<'a> {
    out: &'a mut Retrieved,
    file: &'a str,
    snapshot: &'a str,
    format: &'static str,
    unit: String,
}

impl Emitter<'_> {
    fn push(
        &mut self,
        key: &str,
        value: Option<String>,
        resolution: Resolution,
        provenance: Vec<ProvenanceStep>,
    ) {
        self.out.packets.push(ConfigPacket {
            snapshot_id: self.snapshot.to_string(),
            format: self.format.to_string(),
            file_path: self.file.to_string(),
            line: 0,
            unit: self.unit.clone(),
            key: key.to_string(),
            resolved_value: value,
            resolution,
            provenance,
        });
    }

    /// An explicitly authored value.
    fn authored(&mut self, key: &str, key_path: &str, v: &Value) {
        let p = vec![ProvenanceStep::new(self.file, key_path, "explicit")];
        self.push(key, Some(render_value(v)), Resolution::AsAuthored, p);
    }

    /// A decidable authored absence: the CR is the whole authored intent, so
    /// a missing key is an authored fact, not a platform-side unknown.
    fn absent(&mut self, key: &str, key_path: &str) {
        let p = vec![ProvenanceStep::new(self.file, key_path, "absent")];
        self.push(
            key,
            Some(ABSENT_RENDERING.to_string()),
            Resolution::AsAuthored,
            p,
        );
    }

    /// An absent key governed by a platform-DOCUMENTED default value.
    fn platform_default(&mut self, key: &str, key_path: &str, default_note: &str, value: &str) {
        let p = vec![
            ProvenanceStep::new(self.file, key_path, "absent"),
            ProvenanceStep::new("", default_note, "platform-default"),
        ];
        self.push(key, Some(value.to_string()), Resolution::PlatformDefault, p);
    }
}

fn retrieve(rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let mut recognized_docs = 0usize;
    for doc in serde_yaml::Deserializer::from_str(contents) {
        let Ok(v) = Value::deserialize(doc) else {
            out.unparseable = 1;
            break;
        };
        let Some(m) = v.as_mapping() else { continue };
        let Some(api) = get(m, "apiVersion").and_then(Value::as_str) else {
            continue;
        };
        let Some(kind) = get(m, "kind").and_then(Value::as_str) else {
            continue;
        };
        let group = group_of(api);
        if !recognized(group, kind) {
            // Foreign documents in a claimed file (a ConfigMap between two
            // Applications) are not ours to judge; whole-file unrecognized
            // kinds never get here — matches_head does not claim them.
            continue;
        }
        recognized_docs += 1;
        let name = get(m, "metadata")
            .and_then(Value::as_mapping)
            .and_then(|md| get(md, "name"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let spec = get(m, "spec").and_then(Value::as_mapping);
        fn emitter<'a>(
            out: &'a mut Retrieved,
            file: &'a str,
            snapshot: &'a str,
            format: &'static str,
            unit: String,
        ) -> Emitter<'a> {
            Emitter {
                out,
                file,
                snapshot,
                format,
                unit,
            }
        }
        match kind {
            "Application" => {
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_ARGO,
                    format!("application:{name}"),
                );
                emit_application(&mut e, spec, "spec");
            }
            "ApplicationSet" => {
                let tmpl = spec
                    .and_then(|s| get(s, "template"))
                    .and_then(Value::as_mapping)
                    .and_then(|t| get(t, "spec"))
                    .and_then(Value::as_mapping);
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_ARGO,
                    format!("applicationset:{name}"),
                );
                emit_application(&mut e, tmpl, "spec.template.spec");
            }
            "Kustomization" => {
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("kustomization:{name}"),
                );
                emit_kustomization(&mut e, spec);
            }
            "HelmRelease" => {
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("helmrelease:{name}"),
                );
                emit_helmrelease(&mut e, spec);
            }
            "GitRepository" => {
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("gitrepository:{name}"),
                );
                emit_gitrepository(&mut e, spec);
            }
            "HelmRepository" => {
                let mut e = emitter(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("helmrepository:{name}"),
                );
                emit_helmrepository(&mut e, spec);
            }
            _ => unreachable!("recognized() only admits the kinds above"),
        }
    }
    if recognized_docs == 0 && out.unparseable == 0 {
        // Claimed by head shape, but nothing recognized parsed out (the head
        // sniff was optimistic): coverage says the lane saw and skipped it —
        // the same contract as the CI retrievers.
        out.unparseable = 1;
    }
    out
}

/// The Application spec keys, shared by Application and ApplicationSet
/// (whose `spec.template.spec` is an Application spec). `base` prefixes the
/// provenance key paths so the chain names the real location.
fn emit_application(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>, base: &str) {
    let jp = |k: &str| format!("{base}.{k}");
    let sget = |k: &str| spec.and_then(|s| get(s, k));

    let sync = sget("syncPolicy").and_then(Value::as_mapping);
    match sync.and_then(|s| get(s, "automated")) {
        Some(v) => {
            e.authored(
                "application.syncPolicy.automated",
                &jp("syncPolicy.automated"),
                v,
            );
            // The automated block's knobs have documented `false` defaults.
            let am = v.as_mapping();
            for knob in ["prune", "selfHeal"] {
                let key = format!("application.syncPolicy.automated.{knob}");
                let key_path = jp(&format!("syncPolicy.automated.{knob}"));
                match am.and_then(|a| get(a, knob)) {
                    Some(v) => e.authored(&key, &key_path, v),
                    None => e.platform_default(&key, &key_path, knob, "false"),
                }
            }
            // Retry is judged where sync is automated: an unattended failure
            // loop with no bounded retry is the risk. Manual-sync apps emit
            // no retry packet.
            match sync.and_then(|s| get(s, "retry")) {
                Some(v) => e.authored("application.syncPolicy.retry", &jp("syncPolicy.retry"), v),
                None => e.absent("application.syncPolicy.retry", &jp("syncPolicy.retry")),
            }
        }
        None => e.absent(
            "application.syncPolicy.automated",
            &jp("syncPolicy.automated"),
        ),
    }

    // Pin shape of the tracked revision. The value is the SHAPE, never the
    // ref: `pinned`/`floating` is all a spec needs and all a report shows.
    if let Some(source) = sget("source").and_then(Value::as_mapping) {
        let key_path = jp("source.targetRevision");
        match get(source, "targetRevision") {
            Some(v) => {
                let shape = pin_shape(&render_value(v));
                let p = vec![ProvenanceStep::new(e.file, &key_path, "explicit")];
                e.push(
                    "application.targetRevision.shape",
                    Some(shape.to_string()),
                    Resolution::AsAuthored,
                    p,
                );
            }
            None => e.platform_default(
                "application.targetRevision.shape",
                &key_path,
                "targetRevision (defaults to HEAD)",
                "floating",
            ),
        }
    }

    match sget("project") {
        Some(v) => e.authored("application.project", &jp("project"), v),
        None => e.platform_default(
            "application.project",
            &jp("project"),
            "project (defaults to the default project)",
            "default",
        ),
    }

    match sget("ignoreDifferences") {
        Some(v) => e.authored("application.ignoreDifferences", &jp("ignoreDifferences"), v),
        None => e.absent("application.ignoreDifferences", &jp("ignoreDifferences")),
    }
}

fn emit_kustomization(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    let sget = |k: &str| spec.and_then(|s| get(s, k));
    let interval = sget("interval");
    match interval {
        Some(v) => e.authored("kustomization.interval", "spec.interval", v),
        None => e.absent("kustomization.interval", "spec.interval"),
    }
    match sget("prune") {
        Some(v) => e.authored("kustomization.prune", "spec.prune", v),
        None => e.absent("kustomization.prune", "spec.prune"),
    }
    match sget("wait") {
        Some(v) => e.authored("kustomization.wait", "spec.wait", v),
        None => e.platform_default("kustomization.wait", "spec.wait", "wait", "false"),
    }
    match (sget("timeout"), interval) {
        (Some(v), _) => e.authored("kustomization.timeout", "spec.timeout", v),
        (None, Some(iv)) => {
            // Documented: the timeout defaults to the interval, so the
            // resolved value is derivable from the committed file.
            let iv = render_value(iv);
            e.platform_default(
                "kustomization.timeout",
                "spec.timeout",
                "timeout (defaults to the interval)",
                &iv,
            );
        }
        (None, None) => e.absent("kustomization.timeout", "spec.timeout"),
    }
}

fn emit_helmrelease(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    let sget = |k: &str| spec.and_then(|s| get(s, k));
    match sget("interval") {
        Some(v) => e.authored("helmrelease.interval", "spec.interval", v),
        None => e.absent("helmrelease.interval", "spec.interval"),
    }
    match sget("timeout") {
        Some(v) => e.authored("helmrelease.timeout", "spec.timeout", v),
        None => e.platform_default(
            "helmrelease.timeout",
            "spec.timeout",
            "timeout (the documented 300s Helm-action default)",
            "300s",
        ),
    }
    // Remediation retries: documented default 0 — a failed install/upgrade
    // is NOT remediated unless asked. This is the rollback control's fact.
    for action in ["install", "upgrade"] {
        let key = format!("helmrelease.{action}.remediation.retries");
        let key_path = format!("spec.{action}.remediation.retries");
        let retries = sget(action)
            .and_then(Value::as_mapping)
            .and_then(|a| get(a, "remediation"))
            .and_then(Value::as_mapping)
            .and_then(|r| get(r, "retries"));
        match retries {
            Some(v) => e.authored(&key, &key_path, v),
            None => e.platform_default(
                &key,
                &key_path,
                &format!("{action}.remediation.retries"),
                "0",
            ),
        }
    }
}

fn emit_gitrepository(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    let sget = |k: &str| spec.and_then(|s| get(s, k));
    match sget("interval") {
        Some(v) => e.authored("gitrepository.interval", "spec.interval", v),
        None => e.absent("gitrepository.interval", "spec.interval"),
    }
    match sget("ref").and_then(Value::as_mapping) {
        None => e.platform_default(
            "gitrepository.ref.shape",
            "spec.ref",
            "ref (defaults to the master branch)",
            "branch",
        ),
        Some(r) => {
            // Shape by field precedence (commit > semver > tag > branch);
            // `name` and future forms classify as `other`. The value is the
            // SHAPE only — no branch, tag, or commit value is emitted.
            let (field, shape) = if get(r, "commit").is_some() {
                ("commit", "commit")
            } else if get(r, "semver").is_some() {
                ("semver", "semver")
            } else if get(r, "tag").is_some() {
                ("tag", "tag")
            } else if get(r, "branch").is_some() {
                ("branch", "branch")
            } else {
                ("", "other")
            };
            let key_path = if field.is_empty() {
                "spec.ref".to_string()
            } else {
                format!("spec.ref.{field}")
            };
            let p = vec![ProvenanceStep::new(e.file, &key_path, "explicit")];
            e.push(
                "gitrepository.ref.shape",
                Some(shape.to_string()),
                Resolution::AsAuthored,
                p,
            );
        }
    }
}

fn emit_helmrepository(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    match spec.and_then(|s| get(s, "interval")) {
        Some(v) => e.authored("helmrepository.interval", "spec.interval", v),
        None => e.absent("helmrepository.interval", "spec.interval"),
    }
}

fn get<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(yaml: &str) -> Retrieved {
        ArgoFlux.retrieve("deploy/app.yaml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    const APP_HEAD: &str = "apiVersion: argoproj.io/v1alpha1\nkind: Application\n";
    const FLUX_KS_HEAD: &str = "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\n";

    #[test]
    fn matches_head_claims_only_argo_flux_groups_with_recognized_kinds() {
        let r = ArgoFlux;
        assert!(r.matches_head("deploy/app.yaml", APP_HEAD));
        assert!(r.matches_head("clusters/prod/apps.yml", FLUX_KS_HEAD));
        // The po-av01j.20 boundary: a generic Kubernetes manifest is NEVER
        // claimed, whatever its kind is called.
        assert!(!r.matches_head("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"));
        // A kustomize overlay is not a Flux Kustomization.
        assert!(!r.matches_head(
            "k8s/base/kustomization.yaml",
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\n"
        ));
        // An argo group with an unrecognized kind is sighted, not claimed.
        assert!(!r.matches_head(
            "deploy/rollout.yaml",
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\n"
        ));
        // Only YAML paths are ever claimed.
        assert!(!r.matches_head("deploy/app.json", APP_HEAD));
        // Path-based matching never claims: content is the router.
        assert!(!r.matches("deploy/app.yaml"));
    }

    #[test]
    fn quoted_and_multi_doc_heads_still_claim() {
        let r = ArgoFlux;
        assert!(r.matches_head(
            "a.yaml",
            "apiVersion: \"argoproj.io/v1alpha1\"\nkind: 'Application'\n"
        ));
        // A recognized doc after an unrecognized one still claims the file.
        assert!(r.matches_head(
            "a.yaml",
            "apiVersion: v1\nkind: ConfigMap\n---\napiVersion: argoproj.io/v1alpha1\nkind: Application\n"
        ));
        // Pairing is per-document: an argo apiVersion in one doc and a
        // recognized kind in ANOTHER doc must not combine into a claim.
        assert!(!r.matches_head(
            "a.yaml",
            "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\n---\napiVersion: apps/v1\nkind: Application\n"
        ));
    }

    #[test]
    fn automated_app_without_retry_emits_an_as_authored_absent_packet() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  syncPolicy:\n    automated: {}\n",
        );
        let auto = find(
            &got,
            "application:guestbook",
            "application.syncPolicy.automated",
        );
        assert_eq!(auto.resolution, Resolution::AsAuthored);
        assert_eq!(auto.format, "argo-cd");

        // The issue's canonical example: automated sync, no retry. The
        // absence is authored — the CR is the whole intent — so the packet
        // is AsAuthored("absent"), decidable by a `configured` spec.
        let retry = find(
            &got,
            "application:guestbook",
            "application.syncPolicy.retry",
        );
        assert_eq!(retry.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        assert_eq!(retry.resolution, Resolution::AsAuthored);
        assert_eq!(retry.provenance.len(), 1);
        assert_eq!(retry.provenance[0].key_path, "spec.syncPolicy.retry");
        assert_eq!(retry.provenance[0].role, "absent");

        // The automated block's knobs default to the documented false.
        let self_heal = find(
            &got,
            "application:guestbook",
            "application.syncPolicy.automated.selfHeal",
        );
        assert_eq!(self_heal.resolved_value.as_deref(), Some("false"));
        assert_eq!(self_heal.resolution, Resolution::PlatformDefault);
        assert_eq!(self_heal.provenance[0].role, "absent");
        assert_eq!(self_heal.provenance[1].role, "platform-default");
        let prune = find(
            &got,
            "application:guestbook",
            "application.syncPolicy.automated.prune",
        );
        assert_eq!(prune.resolved_value.as_deref(), Some("false"));
    }

    #[test]
    fn explicit_automated_knobs_and_retry_resolve_as_authored() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  syncPolicy:\n    automated:\n      prune: true\n      selfHeal: true\n    retry:\n      limit: 5\n",
        );
        assert_eq!(
            find(
                &got,
                "application:g",
                "application.syncPolicy.automated.selfHeal"
            )
            .resolved_value
            .as_deref(),
            Some("true")
        );
        let retry = find(&got, "application:g", "application.syncPolicy.retry");
        assert_eq!(retry.resolved_value.as_deref(), Some(r#"{"limit":5}"#));
        assert_eq!(retry.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn manual_sync_app_is_absent_automated_and_emits_no_retry_packet() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  project: team-a\n",
        );
        let auto = find(&got, "application:g", "application.syncPolicy.automated");
        assert_eq!(auto.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        assert_eq!(auto.resolution, Resolution::AsAuthored);
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == "application.syncPolicy.retry"),
            "retry is judged only where sync is automated: {:?}",
            got.packets
        );
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == "application.syncPolicy.automated.selfHeal"),
            "automated knobs need an automated block: {:?}",
            got.packets
        );
    }

    #[test]
    fn target_revision_emits_the_shape_never_the_ref() {
        let sha = "8f4b7f84864484a7bf31766abe9204da3cbe65b3";
        for (rev, shape) in [
            ("main", "floating"),
            ("HEAD", "floating"),
            ("release-1.2", "floating"),
            ("v1.2.3", "pinned"),
            ("1.2.3", "pinned"),
            ("v1.2.3-rc.1", "pinned"),
            (sha, "pinned"),
        ] {
            let got = packets(&format!(
                "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  source:\n    targetRevision: {rev}\n"
            ));
            let p = find(&got, "application:g", "application.targetRevision.shape");
            assert_eq!(p.resolved_value.as_deref(), Some(shape), "rev {rev}");
            assert_eq!(p.resolution, Resolution::AsAuthored);
            assert!(
                p.resolved_value.as_deref() != Some(rev) || rev == shape,
                "the value must be the shape, not the ref"
            );
        }
    }

    #[test]
    fn absent_target_revision_defaults_to_floating_head() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  source:\n    path: k8s\n",
        );
        let p = find(&got, "application:g", "application.targetRevision.shape");
        assert_eq!(p.resolved_value.as_deref(), Some("floating"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
    }

    #[test]
    fn project_defaults_to_the_default_project() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec: {}\n",
        );
        let p = find(&got, "application:g", "application.project");
        assert_eq!(p.resolved_value.as_deref(), Some("default"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn applicationset_template_emits_application_keys_under_its_own_unit() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: fleet\nspec:\n  template:\n    spec:\n      source:\n        targetRevision: main\n      syncPolicy:\n        automated: {}\n",
        );
        let p = find(
            &got,
            "applicationset:fleet",
            "application.targetRevision.shape",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("floating"));
        // Provenance names the real location inside the template.
        assert_eq!(
            p.provenance[0].key_path,
            "spec.template.spec.source.targetRevision"
        );
        let retry = find(&got, "applicationset:fleet", "application.syncPolicy.retry");
        assert_eq!(
            retry.provenance[0].key_path,
            "spec.template.spec.syncPolicy.retry"
        );
    }

    #[test]
    fn kustomization_required_fields_absent_are_as_authored_absent() {
        let got = packets(
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\nspec:\n  path: ./k8s\n",
        );
        for key in ["kustomization.interval", "kustomization.prune"] {
            let p = find(&got, "kustomization:apps", key);
            assert_eq!(p.resolved_value.as_deref(), Some(ABSENT_RENDERING), "{key}");
            assert_eq!(p.resolution, Resolution::AsAuthored, "{key}");
            assert_eq!(p.provenance[0].role, "absent", "{key}");
        }
        // No interval to derive from: the timeout is absent too.
        let t = find(&got, "kustomization:apps", "kustomization.timeout");
        assert_eq!(t.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        // Wait has a documented false default.
        let w = find(&got, "kustomization:apps", "kustomization.wait");
        assert_eq!(w.resolved_value.as_deref(), Some("false"));
        assert_eq!(w.resolution, Resolution::PlatformDefault);
        assert_eq!(w.format, "flux");
    }

    #[test]
    fn kustomization_timeout_derives_from_the_interval() {
        let got = packets(
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\nspec:\n  interval: 10m\n  prune: true\n  wait: true\n",
        );
        let t = find(&got, "kustomization:apps", "kustomization.timeout");
        assert_eq!(t.resolved_value.as_deref(), Some("10m"));
        assert_eq!(t.resolution, Resolution::PlatformDefault);
        assert!(t.provenance[1]
            .key_path
            .contains("defaults to the interval"));
        assert_eq!(
            find(&got, "kustomization:apps", "kustomization.prune")
                .resolved_value
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            find(&got, "kustomization:apps", "kustomization.wait")
                .resolved_value
                .as_deref(),
            Some("true")
        );
    }

    #[test]
    fn helmrelease_remediation_retries_default_to_zero() {
        let got = packets(
            "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: podinfo\nspec:\n  interval: 5m\n  install:\n    remediation:\n      retries: 3\n",
        );
        let install = find(
            &got,
            "helmrelease:podinfo",
            "helmrelease.install.remediation.retries",
        );
        assert_eq!(install.resolved_value.as_deref(), Some("3"));
        assert_eq!(install.resolution, Resolution::AsAuthored);
        let upgrade = find(
            &got,
            "helmrelease:podinfo",
            "helmrelease.upgrade.remediation.retries",
        );
        assert_eq!(upgrade.resolved_value.as_deref(), Some("0"));
        assert_eq!(upgrade.resolution, Resolution::PlatformDefault);
        let t = find(&got, "helmrelease:podinfo", "helmrelease.timeout");
        assert_eq!(t.resolved_value.as_deref(), Some("300s"));
        assert_eq!(t.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn gitrepository_ref_shape_is_the_shape_only() {
        for (refyaml, shape, field) in [
            ("    branch: main\n", "branch", "spec.ref.branch"),
            ("    tag: v6.0.0\n", "tag", "spec.ref.tag"),
            ("    semver: \">=6.0.0\"\n", "semver", "spec.ref.semver"),
            (
                "    commit: 8f4b7f84864484a7bf31766abe9204da3cbe65b3\n",
                "commit",
                "spec.ref.commit",
            ),
            ("    name: refs/heads/main\n", "other", "spec.ref"),
        ] {
            let got = packets(&format!(
                "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: podinfo\nspec:\n  interval: 1m\n  ref:\n{refyaml}"
            ));
            let p = find(&got, "gitrepository:podinfo", "gitrepository.ref.shape");
            assert_eq!(p.resolved_value.as_deref(), Some(shape), "{refyaml}");
            assert_eq!(p.provenance[0].key_path, field, "{refyaml}");
            // Privacy: the branch/tag/commit VALUE never rides the packet.
            assert!(
                !p.resolved_value.as_deref().unwrap_or("").contains("main")
                    && !p.resolved_value.as_deref().unwrap_or("").contains("6.0.0"),
                "shape only: {:?}",
                p.resolved_value
            );
        }
    }

    #[test]
    fn gitrepository_without_ref_defaults_to_the_master_branch_shape() {
        let got = packets(
            "apiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: podinfo\nspec:\n  interval: 1m\n",
        );
        let p = find(&got, "gitrepository:podinfo", "gitrepository.ref.shape");
        assert_eq!(p.resolved_value.as_deref(), Some("branch"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn helmrepository_emits_its_interval() {
        let got = packets(
            "apiVersion: source.toolkit.fluxcd.io/v1\nkind: HelmRepository\nmetadata:\n  name: bitnami\nspec:\n  interval: 10m\n",
        );
        let p = find(&got, "helmrepository:bitnami", "helmrepository.interval");
        assert_eq!(p.resolved_value.as_deref(), Some("10m"));
    }

    #[test]
    fn multi_doc_files_emit_per_doc_units_and_skip_foreign_docs() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: a\nspec: {}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n---\napiVersion: source.toolkit.fluxcd.io/v1\nkind: GitRepository\nmetadata:\n  name: g\nspec:\n  interval: 1m\n",
        );
        assert!(got.packets.iter().any(|p| p.unit == "application:a"));
        assert!(got.packets.iter().any(|p| p.unit == "gitrepository:g"));
        assert!(
            !got.packets.iter().any(|p| p.unit.contains("cm")),
            "a foreign doc in a claimed file emits nothing: {:?}",
            got.packets
        );
        assert_eq!(got.unparseable, 0);
    }

    #[test]
    fn claimed_file_with_nothing_recognized_counts_unparseable() {
        // A head-sniff false positive must degrade to coverage, not vanish.
        let got = packets("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("spec: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    #[test]
    fn sight_unrecognized_classifies_argo_flux_products_only() {
        let head = |api: &str, kind: &str| format!("apiVersion: {api}\nkind: {kind}\n");
        assert_eq!(
            sight_unrecognized(&head("argoproj.io/v1alpha1", "Rollout")),
            Some("argo-rollouts")
        );
        assert_eq!(
            sight_unrecognized(&head("argoproj.io/v1alpha1", "Workflow")),
            Some("argo-workflows")
        );
        assert_eq!(
            sight_unrecognized(&head("argoproj.io/v1alpha1", "EventSource")),
            Some("argo-events")
        );
        assert_eq!(
            sight_unrecognized(&head("argoproj.io/v1alpha1", "AppProject")),
            Some("argo-cd")
        );
        assert_eq!(
            sight_unrecognized(&head("image.toolkit.fluxcd.io/v1beta2", "ImagePolicy")),
            Some("flux")
        );
        // Legacy Flux v1 groups still classify as flux.
        assert_eq!(
            sight_unrecognized(&head("helm.fluxcd.io/v1", "HelmRelease")),
            Some("flux")
        );
        // The boundary: generic Kubernetes and kustomize overlays are not
        // this family's to sight.
        assert_eq!(sight_unrecognized(&head("apps/v1", "Deployment")), None);
        assert_eq!(
            sight_unrecognized(&head("kustomize.config.k8s.io/v1beta1", "Kustomization")),
            None
        );
        assert_eq!(sight_unrecognized(""), None);
    }
}
