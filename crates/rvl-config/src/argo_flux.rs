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
//! CRs of other kinds (Experiments, Workflows, image automation, ...) are
//! sighted identity-only by [`sight_unrecognized`] instead.
//!
//! Kinds parsed, and the facts emitted (packet formats are per-product,
//! `argo-cd` and `flux`, so spec identities and waiver class rules read
//! naturally):
//!
//!   * Rollout (`argoproj.io`, format `argo-rollouts`, po-pk3fp.13) —
//!     `rollout.strategy` (`canary` | `blueGreen`, else absent),
//!     `rollout.canary.steps.count` (canary only; no steps is `0`), and
//!     `rollout.analysis`: WHERE an analysis can abort the rollout
//!     (`background`, `step`, `prePromotion`, `postPromotion`, joined with
//!     `+`), else absent. A rollout with no analysis cannot roll itself back.
//!   * AnalysisTemplate / ClusterAnalysisTemplate (format `argo-rollouts`) —
//!     `analysistemplate.metrics.count` and
//!     `analysistemplate.metrics.without-condition`: metrics with neither a
//!     success nor a failure condition, which are measured and never judged.
//!   * Application / ApplicationSet (`argoproj.io`, format `argo-cd`) —
//!     `application.syncPolicy.automated` (presence), `.prune` / `.selfHeal`
//!     (documented `false` defaults), `.enabled` (documented `true`: an
//!     automated block switched off), `application.syncPolicy.retry`
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
//!     `.timeout` (documented `300s`), `helmrelease.driftDetection.mode`
//!     (absent with no `driftDetection` block; a block without a mode is
//!     the documented `disabled`),
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
//! Application, ApplicationSet, Kustomization and HelmRelease units are
//! judged only where they are whole and reconciled into production: the
//! conditions of [`Repo`] carry a unit's facts undecided with the reason
//! otherwise (a non-production path, repository or target, a chart
//! template, a fragment, an object declared twice, a templated value, an
//! interval that is not a Go duration).
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
use std::cell::OnceCell;
use std::collections::BTreeMap;
use std::path::Path;

pub struct ArgoFlux;

/// Packet format for Argo CD resources.
const FORMAT_ARGO: &str = "argo-cd";
/// Packet format for Argo Rollouts resources: a separate product from Argo
/// CD that shares its apiVersion group.
const FORMAT_ROLLOUTS: &str = "argo-rollouts";
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
        let files = [(rel_path.to_string(), contents.to_string())];
        let mut out = retrieve(rel_path, contents, snapshot_id, &Repo::new(None, &files));
        crate::non_production::undecide_unit(None, rel_path, &mut out);
        out
    }

    /// One file under a root: the root names a sample repository
    /// ([`crate::non_production::undecide_unit`]).
    fn retrieve_with_root(
        &self,
        root: &Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        let files = [(rel_path.to_string(), contents.to_string())];
        self.retrieve_all(root, &files, snapshot_id)
    }

    /// The walk's entry: every claimed file at once, so an object another
    /// file restates is seen as declared twice ([`Repo`]).
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let repo = Repo::new(Some(root), files);
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            let mut got = retrieve(rel, contents, snapshot_id, &repo);
            crate::non_production::undecide_unit(Some(root), rel, &mut got);
            out.packets.extend(got.packets);
            out.predicates.extend(got.predicates);
            out.unparseable += got.unparseable;
            out.sightings.extend(got.sightings);
        }
        out
    }
}

/// The apiVersion group: everything before the first `/`.
pub(crate) fn group_of(api_version: &str) -> &str {
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
        "Rollout" | "AnalysisTemplate" | "ClusterAnalysisTemplate" => is_argo_group(group),
        "Kustomization" => group == "kustomize.toolkit.fluxcd.io",
        "HelmRelease" => group == "helm.toolkit.fluxcd.io",
        "GitRepository" | "HelmRepository" => group == "source.toolkit.fluxcd.io",
        _ => false,
    }
}

/// Per-document (apiVersion, kind) pairs found in a bounded head window.
/// Column-0 scanning only — the same discipline as `sight_format`'s sniffs;
/// the content is read locally and discarded.
pub(crate) fn head_scan(head: &str) -> Vec<(String, String)> {
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
pub(crate) struct Emitter<'a> {
    out: &'a mut Retrieved,
    pub(crate) file: &'a str,
    snapshot: &'a str,
    format: &'static str,
    unit: String,
}

impl<'a> Emitter<'a> {
    pub(crate) fn new(
        out: &'a mut Retrieved,
        file: &'a str,
        snapshot: &'a str,
        format: &'static str,
        unit: String,
    ) -> Self {
        Self {
            out,
            file,
            snapshot,
            format,
            unit,
        }
    }

    pub(crate) fn push(
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
            key: crate::key_ledger::declared(self.format, key),
            resolved_value: value,
            resolution,
            provenance,
        });
    }

    /// An explicitly authored value.
    pub(crate) fn authored(&mut self, key: &str, key_path: &str, v: &Value) {
        let p = vec![ProvenanceStep::new(self.file, key_path, "explicit")];
        self.push(key, Some(render_value(v)), Resolution::AsAuthored, p);
    }

    /// A decidable authored absence: the CR is the whole authored intent, so
    /// a missing key is an authored fact, not a platform-side unknown.
    pub(crate) fn absent(&mut self, key: &str, key_path: &str) {
        let p = vec![ProvenanceStep::new(self.file, key_path, "absent")];
        self.push(
            key,
            Some(ABSENT_RENDERING.to_string()),
            Resolution::AsAuthored,
            p,
        );
    }

    /// An absent key governed by a platform-DOCUMENTED default value.
    pub(crate) fn platform_default(
        &mut self,
        key: &str,
        key_path: &str,
        default_note: &str,
        value: &str,
    ) {
        let p = vec![
            ProvenanceStep::new(self.file, key_path, "absent"),
            ProvenanceStep::new("", default_note, "platform-default"),
        ];
        self.push(key, Some(value.to_string()), Resolution::PlatformDefault, p);
    }
}

fn retrieve(rel_path: &str, contents: &str, snapshot_id: &str, repo: &Repo) -> Retrieved {
    let mut out = Retrieved::default();
    let mut recognized_docs = 0usize;
    for doc in serde_yaml::Deserializer::from_str(contents) {
        let Ok(v) = Value::deserialize(doc) else {
            out.unparseable = 1;
            break;
        };
        let first = out.packets.len();
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
        match kind {
            "Application" => {
                let mut e = Emitter::new(
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
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_ARGO,
                    format!("applicationset:{name}"),
                );
                emit_application(&mut e, tmpl, "spec.template.spec");
            }
            "Rollout" => {
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_ROLLOUTS,
                    format!("rollout:{name}"),
                );
                emit_rollout(&mut e, spec);
            }
            "AnalysisTemplate" | "ClusterAnalysisTemplate" => {
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_ROLLOUTS,
                    format!("{}:{name}", kind.to_ascii_lowercase()),
                );
                emit_analysis_template(&mut e, spec);
            }
            "Kustomization" => {
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("kustomization:{name}"),
                );
                emit_kustomization(&mut e, spec);
            }
            "HelmRelease" => {
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("helmrelease:{name}"),
                );
                emit_helmrelease(&mut e, spec);
            }
            "GitRepository" => {
                let mut e = Emitter::new(
                    &mut out,
                    rel_path,
                    snapshot_id,
                    FORMAT_FLUX,
                    format!("gitrepository:{name}"),
                );
                emit_gitrepository(&mut e, spec);
            }
            "HelmRepository" => {
                let mut e = Emitter::new(
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
        if let Some(why) = repo.abstain(rel_path, contents, kind, &v) {
            for p in &mut out.packets[first..] {
                crate::non_production::undecide(p, &why);
            }
        }
        if kind == "HelmRelease" && !drift_detection_on(spec) && repo.drift_patched() {
            for p in &mut out.packets[first..] {
                if p.key == "helmrelease.driftDetection.mode" {
                    crate::non_production::undecide(p, DRIFT_PATCH_REASON);
                }
            }
        }
    }
    if out.unparseable == 1 {
        // A file that does not parse (a chart template, a file a script
        // fills in) says nothing whole about the reconciled objects before
        // the break.
        let reconciled = |unit: &str| {
            unit.split_once(':')
                .is_some_and(|(kind, _)| RECONCILED.iter().any(|k| k.eq_ignore_ascii_case(kind)))
        };
        for p in out.packets.iter_mut().filter(|p| reconciled(&p.unit)) {
            crate::non_production::undecide(p, "the file does not parse as YAML");
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
            // `enabled` turns the block off without removing it, and
            // defaults to `true`.
            for (knob, key, default) in [
                ("prune", "application.syncPolicy.automated.prune", "false"),
                (
                    "selfHeal",
                    "application.syncPolicy.automated.selfHeal",
                    "false",
                ),
                (
                    "enabled",
                    "application.syncPolicy.automated.enabled",
                    "true",
                ),
            ] {
                let key_path = jp(&format!("syncPolicy.automated.{knob}"));
                match am.and_then(|a| get(a, knob)) {
                    Some(v) => e.authored(key, &key_path, v),
                    None => e.platform_default(key, &key_path, knob, default),
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
    // Drift detection: with no block, Flux never corrects a change made in
    // the cluster; a block without a mode is the documented `disabled`.
    match sget("driftDetection") {
        None => e.absent("helmrelease.driftDetection.mode", "spec.driftDetection"),
        Some(block) => match block.as_mapping().and_then(|b| get(b, "mode")) {
            Some(v) => e.authored(
                "helmrelease.driftDetection.mode",
                "spec.driftDetection.mode",
                v,
            ),
            None => e.platform_default(
                "helmrelease.driftDetection.mode",
                "spec.driftDetection.mode",
                "driftDetection.mode",
                "disabled",
            ),
        },
    }
    // Remediation retries: documented default 0 — a failed install/upgrade
    // is NOT remediated unless asked. This is the rollback control's fact.
    for (action, key) in [
        ("install", "helmrelease.install.remediation.retries"),
        ("upgrade", "helmrelease.upgrade.remediation.retries"),
    ] {
        let key_path = format!("spec.{action}.remediation.retries");
        let retries = sget(action)
            .and_then(Value::as_mapping)
            .and_then(|a| get(a, "remediation"))
            .and_then(Value::as_mapping)
            .and_then(|r| get(r, "retries"));
        match retries {
            Some(v) => e.authored(key, &key_path, v),
            None => e.platform_default(
                key,
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

/// A Rollout's progressive-delivery shape (RC-036): which strategy it uses,
/// how many canary steps it takes, and where an analysis can abort it. The
/// values are shapes and counts; template names, weights and services are
/// never emitted.
fn emit_rollout(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    let strategy = spec
        .and_then(|s| get(s, "strategy"))
        .and_then(Value::as_mapping);
    let Some((name, body)) = ["canary", "blueGreen"]
        .into_iter()
        .find_map(|n| strategy.and_then(|s| get(s, n)).map(|v| (n, v)))
    else {
        // A Rollout requires one of the two; without it there is no rollout
        // shape to describe.
        e.absent("rollout.strategy", "spec.strategy");
        return;
    };
    let base = format!("spec.strategy.{name}");
    let provenance =
        |file: &str, key_path: String, role: &str| vec![ProvenanceStep::new(file, &key_path, role)];
    let p = provenance(e.file, base.clone(), "explicit");
    e.push(
        "rollout.strategy",
        Some(name.to_string()),
        Resolution::AsAuthored,
        p,
    );
    let body = body.as_mapping();
    let has = |k: &str| body.is_some_and(|b| get(b, k).is_some_and(|v| !v.is_null()));

    // Where an analysis can stop this rollout, in a fixed order so the value
    // compares stably.
    let mut analysis: Vec<&str> = Vec::new();
    if name == "canary" {
        let steps = body
            .and_then(|b| get(b, "steps"))
            .and_then(Value::as_sequence);
        // No steps means the canary goes straight to full weight: a count of
        // 0 is the authored fact, and a numeric bound can judge it.
        let role = if steps.is_some() {
            "explicit"
        } else {
            "absent"
        };
        let p = provenance(e.file, format!("{base}.steps"), role);
        e.push(
            "rollout.canary.steps.count",
            Some(steps.map_or(0, Vec::len).to_string()),
            Resolution::AsAuthored,
            p,
        );
        if has("analysis") {
            analysis.push("background");
        }
        let step_analysis = steps.is_some_and(|steps| {
            steps
                .iter()
                .filter_map(Value::as_mapping)
                .any(|step| get(step, "analysis").is_some())
        });
        if step_analysis {
            analysis.push("step");
        }
    } else {
        for (field, label) in [
            ("prePromotionAnalysis", "prePromotion"),
            ("postPromotionAnalysis", "postPromotion"),
        ] {
            if has(field) {
                analysis.push(label);
            }
        }
    }
    if analysis.is_empty() {
        e.absent("rollout.analysis", &base);
    } else {
        let p = provenance(e.file, base, "explicit");
        e.push(
            "rollout.analysis",
            Some(analysis.join("+")),
            Resolution::AsAuthored,
            p,
        );
    }
}

/// An AnalysisTemplate's metrics, as counts: how many there are, and how many
/// carry neither a successCondition nor a failureCondition. Such a metric is
/// measured and never judged, so it cannot fail an analysis run. The
/// conditions and queries themselves are never emitted.
fn emit_analysis_template(e: &mut Emitter, spec: Option<&serde_yaml::Mapping>) {
    let metrics = spec
        .and_then(|s| get(s, "metrics"))
        .and_then(Value::as_sequence);
    let role = if metrics.is_some() {
        "explicit"
    } else {
        "absent"
    };
    let unconditioned = metrics.map_or(0, |ms| {
        ms.iter()
            .filter(|m| {
                !m.as_mapping().is_some_and(|m| {
                    get(m, "successCondition").is_some() || get(m, "failureCondition").is_some()
                })
            })
            .count()
    });
    for (key, count) in [
        (
            "analysistemplate.metrics.count",
            metrics.map_or(0, Vec::len),
        ),
        ("analysistemplate.metrics.without-condition", unconditioned),
    ] {
        let p = vec![ProvenanceStep::new(e.file, "spec.metrics", role)];
        e.push(key, Some(count.to_string()), Resolution::AsAuthored, p);
    }
}

/// The kinds whose reconciliation a GitOps spec judges: the abstain
/// conditions of [`Repo::abstain`] were measured on these, and only these.
const RECONCILED: &[&str] = &[
    "Application",
    "ApplicationSet",
    "Kustomization",
    "HelmRelease",
];

/// The reason a HelmRelease's drift-detection fact carries when a patch in
/// the repository may set it.
const DRIFT_PATCH_REASON: &str =
    "a patch in the repository may set driftDetection (a YAML file holds both)";

/// Text that marks a value as filled in before it is applied: a Helm or
/// ApplicationSet template, a Flux post-build substitution, a placeholder.
const TEMPLATE_MARKERS: &[&str] = &["{{", "${", "<"];

/// What the abstain conditions of the reconciled kinds read beyond one
/// document: the scanned root, and every file the scan claimed for this
/// retriever. A unit these conditions catch carries its facts undecided
/// with the reason, so the lane abstains and says why:
///
///   * a chart template (`<chart>/templates/`, rendered before it is
///     applied);
///   * a non-production path or repository
///     ([`crate::non_production::gitops_reason`]);
///   * a fragment: a patch or component file, a file holding `$patch`, an
///     Application with no destination or no source, a Kustomization with
///     no `sourceRef`, a HelmRelease with no `chart` and no `chartRef`;
///   * a non-production target: its name, its namespace, or where it
///     deploys holds a token ([`crate::non_production::gitops_value_token`]);
///   * an object declared in more than one file (an overlay or a second
///     cluster restates it, so no one file is its whole intent);
///   * a templated value in a judged field, or an ApplicationSet with a
///     `templatePatch`;
///   * an `interval` that is not a Go duration.
///
/// A HelmRelease's `helmrelease.driftDetection.mode` alone is undecided
/// when a YAML file of the repository holds both `driftDetection` and
/// `patch`: a parent Kustomization usually patches it into every release.
struct Repo<'a> {
    root: Option<&'a Path>,
    token: Option<&'static str>,
    files: &'a [(String, String)],
    /// The number of files declaring each reconciled (kind, name).
    declared: BTreeMap<(String, String), usize>,
    drift_patched: OnceCell<bool>,
}

impl<'a> Repo<'a> {
    fn new(root: Option<&'a Path>, files: &'a [(String, String)]) -> Self {
        let mut declared = BTreeMap::new();
        for (_, contents) in files {
            let mut seen = std::collections::BTreeSet::new();
            for doc in serde_yaml::Deserializer::from_str(contents) {
                let Ok(v) = Value::deserialize(doc) else {
                    break;
                };
                if let Some(key) = reconciled_identity(&v) {
                    seen.insert(key);
                }
            }
            for key in seen {
                *declared.entry(key).or_insert(0) += 1;
            }
        }
        Self {
            root,
            token: root.and_then(crate::non_production::gitops_root_token),
            files,
            declared,
            drift_patched: OnceCell::new(),
        }
    }

    /// Whether a YAML file of the repository holds both `driftDetection`
    /// and `patch`. Walked once, on the first HelmRelease that asks; with
    /// no root, the claimed files are the repository.
    fn drift_patched(&self) -> bool {
        let patches = |text: &str| text.contains("driftDetection") && text.contains("patch");
        *self.drift_patched.get_or_init(|| match self.root {
            None => self.files.iter().any(|(_, text)| patches(text)),
            Some(root) => crate::walk(root).flatten().any(|entry| {
                let path = entry.path();
                entry.file_type().is_some_and(|t| t.is_file())
                    && path.extension().is_some_and(|x| x == "yaml" || x == "yml")
                    && std::fs::read_to_string(path).is_ok_and(|text| patches(&text))
            }),
        })
    }

    /// Why the object `doc` of kind `kind` in the file at `rel_path` is not
    /// judged, or `None` when it is (or is not a reconciled kind).
    fn abstain(&self, rel_path: &str, contents: &str, kind: &str, doc: &Value) -> Option<String> {
        use crate::non_production as np;
        if !RECONCILED.contains(&kind) {
            return None;
        }
        if self
            .root
            .is_some_and(|root| crate::kubernetes::helm::under_chart_templates(root, rel_path))
        {
            return Some("chart template: rendered before it is applied".into());
        }
        if let Some(why) = np::gitops_reason(self.token, rel_path) {
            return Some(why);
        }
        if np::patch_fragment(self.root, rel_path) || contents.contains("$patch") {
            return Some("fragment: a patch or component another file completes".into());
        }
        let spec = at(doc, &["spec"]);
        // An ApplicationSet is judged by the Application spec it stamps out.
        let app = match kind {
            "ApplicationSet" => spec.and_then(|s| at(s, &["template", "spec"])),
            _ => spec,
        };
        if let Some(field) = missing_whole_field(kind, spec, app) {
            return Some(format!("fragment: no {field}, another file completes it"));
        }
        if let Some((field, token)) = target_fields(kind, doc, spec, app)
            .into_iter()
            .find_map(|(field, v)| np::gitops_value_token(&v).map(|t| (field, t)))
        {
            return Some(format!("non-production target: {field} names {token}"));
        }
        if let Some(n) = reconciled_identity(doc)
            .and_then(|key| self.declared.get(&key))
            .filter(|n| **n > 1)
        {
            return Some(format!(
                "declared in {n} files: an overlay or a second cluster restates it"
            ));
        }
        if kind == "ApplicationSet" && spec.and_then(|s| at(s, &["templatePatch"])).is_some() {
            return Some("templated value: templatePatch".into());
        }
        for (field, v) in judged_fields(kind, spec, app) {
            let text = v.as_str().map_or_else(|| render_value(v), str::to_string);
            if v.is_string() && TEMPLATE_MARKERS.iter().any(|m| text.contains(m)) {
                return Some(format!("templated value: {field}"));
            }
            if field == "interval" && !go_duration(&text) {
                return Some(format!("interval {text:?} is not a Go duration"));
            }
        }
        None
    }
}

/// The (kind, name) of a reconciled object, for [`Repo::declared`].
fn reconciled_identity(doc: &Value) -> Option<(String, String)> {
    let api = at(doc, &["apiVersion"]).and_then(Value::as_str)?;
    let kind = at(doc, &["kind"]).and_then(Value::as_str)?;
    if !(RECONCILED.contains(&kind) && recognized(group_of(api), kind)) {
        return None;
    }
    let name = at(doc, &["metadata", "name"]).and_then(Value::as_str);
    Some((kind.to_string(), name.unwrap_or("unnamed").to_string()))
}

/// The field a whole object of `kind` has and a fragment lacks, if it is
/// missing: what it deploys and where.
fn missing_whole_field(
    kind: &str,
    spec: Option<&Value>,
    app: Option<&Value>,
) -> Option<&'static str> {
    let has = |v: Option<&Value>, key: &str| v.and_then(|v| at(v, &[key])).is_some();
    match kind {
        "Application" | "ApplicationSet" if !has(app, "destination") => Some("destination"),
        "Application" | "ApplicationSet" if !has(app, "source") && !has(app, "sources") => {
            Some("source")
        }
        "Kustomization" if !has(spec, "sourceRef") => Some("sourceRef"),
        "HelmRelease" if !has(spec, "chart") && !has(spec, "chartRef") => Some("chart or chartRef"),
        _ => None,
    }
}

/// The string values that name what an object is and where it deploys,
/// each with its field: the object's name and namespace; an Argo CD
/// destination, project, source path and value files; a Flux path and
/// target namespace.
fn target_fields<'v>(
    kind: &str,
    doc: &'v Value,
    spec: Option<&'v Value>,
    app: Option<&'v Value>,
) -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, Option<&'v Value>)> = vec![
        ("metadata.name", at(doc, &["metadata", "name"])),
        ("metadata.namespace", at(doc, &["metadata", "namespace"])),
    ];
    let under = |v: Option<&'v Value>, path: &[&str]| v.and_then(|v| at(v, path));
    match kind {
        "Application" | "ApplicationSet" => {
            found.extend([
                (
                    "destination.namespace",
                    under(app, &["destination", "namespace"]),
                ),
                ("destination.name", under(app, &["destination", "name"])),
                ("destination.server", under(app, &["destination", "server"])),
                ("project", under(app, &["project"])),
            ]);
            let sources = under(app, &["sources"])
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .chain(under(app, &["source"]));
            for source in sources {
                found.push(("source.path", at(source, &["path"])));
                found.push((
                    "source.helm.valueFiles",
                    at(source, &["helm", "valueFiles"]),
                ));
            }
        }
        "Kustomization" => found.extend([
            ("spec.path", under(spec, &["path"])),
            ("spec.targetNamespace", under(spec, &["targetNamespace"])),
        ]),
        _ => found.push(("spec.targetNamespace", under(spec, &["targetNamespace"]))),
    }
    let mut out = Vec::new();
    for (field, v) in found {
        match v {
            Some(Value::String(s)) => out.push((field, s.clone())),
            Some(Value::Sequence(items)) => out.extend(
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|s| (field, s.to_string())),
            ),
            _ => {}
        }
    }
    out
}

/// The fields a GitOps spec judges, as authored, each named by its last
/// key: Argo CD's sync policy and its automated knobs, a Kustomization's
/// prune and interval, a HelmRelease's interval and drift detection.
fn judged_fields<'v>(
    kind: &str,
    spec: Option<&'v Value>,
    app: Option<&'v Value>,
) -> Vec<(&'static str, &'v Value)> {
    let under = |v: Option<&'v Value>, path: &[&str]| v.and_then(|v| at(v, path));
    let fields: Vec<(&'static str, Option<&'v Value>)> = match kind {
        "Application" | "ApplicationSet" => {
            let automated = under(app, &["syncPolicy", "automated"]);
            vec![
                ("syncPolicy", under(app, &["syncPolicy"])),
                ("automated", automated),
                ("selfHeal", under(automated, &["selfHeal"])),
                ("prune", under(automated, &["prune"])),
                ("enabled", under(automated, &["enabled"])),
            ]
        }
        "Kustomization" => vec![
            ("prune", under(spec, &["prune"])),
            ("interval", under(spec, &["interval"])),
        ],
        _ => vec![
            ("interval", under(spec, &["interval"])),
            ("driftDetection", under(spec, &["driftDetection"])),
            ("mode", under(spec, &["driftDetection", "mode"])),
        ],
    };
    fields
        .into_iter()
        .filter_map(|(field, v)| v.map(|v| (field, v)))
        .collect()
}

/// Whether a HelmRelease's own `driftDetection.mode` turns detection on
/// (`enabled`, or `warn`, which detects and reports).
fn drift_detection_on(spec: Option<&serde_yaml::Mapping>) -> bool {
    spec.and_then(|s| get(s, "driftDetection"))
        .and_then(|d| at(d, &["mode"]))
        .and_then(Value::as_str)
        .is_some_and(|mode| matches!(mode, "enabled" | "warn"))
}

/// Whether `text` is a Go duration (`time.ParseDuration`): an optional
/// sign, then `0` or one or more decimal numbers each with a unit of `ns`,
/// `us`, `µs`, `ms`, `s`, `m` or `h`. Flux parses every interval this way.
fn go_duration(text: &str) -> bool {
    let body = text.strip_prefix(['+', '-']).unwrap_or(text);
    if body == "0" {
        return true;
    }
    let mut rest = body;
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let number = &rest[..digits];
        if !number.bytes().any(|b| b.is_ascii_digit()) || number.matches('.').count() > 1 {
            return false;
        }
        rest = &rest[digits..];
        let unit = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        if !matches!(
            &rest[..unit],
            "ns" | "us" | "\u{b5}s" | "\u{3bc}s" | "ms" | "s" | "m" | "h"
        ) {
            return false;
        }
        rest = &rest[unit..];
    }
    true
}

/// The value at `path` under `v`, through mappings.
fn at<'v>(v: &'v Value, path: &[&str]) -> Option<&'v Value> {
    path.iter()
        .try_fold(v, |v, key| v.as_mapping().and_then(|m| get(m, key)))
}

pub(crate) fn get<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
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
            "deploy/experiment.yaml",
            "apiVersion: argoproj.io/v1alpha1\nkind: Experiment\n"
        ));
        // Rollouts and their analysis templates are parsed (po-pk3fp.13).
        for kind in ["Rollout", "AnalysisTemplate", "ClusterAnalysisTemplate"] {
            assert!(r.matches_head(
                "deploy/rollout.yaml",
                &format!("apiVersion: argoproj.io/v1alpha1\nkind: {kind}\n")
            ));
        }
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
            "apiVersion: argoproj.io/v1alpha1\nkind: Experiment\n---\napiVersion: apps/v1\nkind: Application\n"
        ));
    }

    #[test]
    fn an_application_under_a_non_production_path_carries_every_fact_undecided() {
        let yaml = "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    repoURL: https://example.com/deploy.git\n  syncPolicy:\n    automated: {}\n";
        let got = ArgoFlux.retrieve("examples/argocd/app.yaml", yaml, "snap");
        assert!(!got.packets.is_empty());
        for p in &got.packets {
            assert_eq!(
                p.resolved_value.as_deref(),
                Some("undecided: non-production path: examples"),
                "{}",
                p.key
            );
        }
        let got = packets(yaml);
        assert!(got.packets.iter().all(|p| !p
            .resolved_value
            .as_deref()
            .unwrap_or("")
            .starts_with("undecided")));
    }

    #[test]
    fn automated_app_without_retry_emits_an_as_authored_absent_packet() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: guestbook\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    repoURL: https://example.com/deploy.git\n  syncPolicy:\n    automated: {}\n",
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
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    repoURL: https://example.com/deploy.git\n  syncPolicy:\n    automated:\n      prune: true\n      selfHeal: true\n    retry:\n      limit: 5\n",
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
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    repoURL: https://example.com/deploy.git\n  project: team-a\n",
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
                "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    targetRevision: {rev}\n"
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
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    path: k8s\n",
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
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: g\nspec:\n  destination:\n    server: https://kubernetes.default.svc\n  source:\n    repoURL: https://example.com/deploy.git\n",
        );
        let p = find(&got, "application:g", "application.project");
        assert_eq!(p.resolved_value.as_deref(), Some("default"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn applicationset_template_emits_application_keys_under_its_own_unit() {
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: fleet\nspec:\n  template:\n    spec:\n      destination:\n        server: https://kubernetes.default.svc\n      source:\n        targetRevision: main\n      syncPolicy:\n        automated: {}\n",
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
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\nspec:\n  sourceRef:\n    kind: GitRepository\n    name: flux-system\n  path: ./k8s\n",
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
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\nspec:\n  sourceRef:\n    kind: GitRepository\n    name: flux-system\n  interval: 10m\n  prune: true\n  wait: true\n",
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
            "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: podinfo\nspec:\n  chart:\n    spec:\n      chart: podinfo\n  interval: 5m\n  install:\n    remediation:\n      retries: 3\n",
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

    const ROLLOUT_HEAD: &str =
        "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\n";

    #[test]
    fn canary_rollout_emits_step_count_and_where_analysis_runs() {
        let got = packets(&format!(
            "{ROLLOUT_HEAD}spec:\n  strategy:\n    canary:\n      analysis:\n        templates:\n        - templateName: success-rate\n      steps:\n      - setWeight: 20\n      - pause: {{duration: 10m}}\n      - analysis:\n          templates:\n          - templateName: latency\n      - setWeight: 100\n"
        ));
        let strategy = find(&got, "rollout:web", "rollout.strategy");
        assert_eq!(strategy.format, "argo-rollouts");
        assert_eq!(strategy.resolved_value.as_deref(), Some("canary"));
        let steps = find(&got, "rollout:web", "rollout.canary.steps.count");
        assert_eq!(steps.resolved_value.as_deref(), Some("4"));
        assert_eq!(steps.provenance[0].key_path, "spec.strategy.canary.steps");
        let analysis = find(&got, "rollout:web", "rollout.analysis");
        assert_eq!(analysis.resolved_value.as_deref(), Some("background+step"));
        assert_eq!(analysis.resolution, Resolution::AsAuthored);
        assert_eq!(got.unparseable, 0);
    }

    #[test]
    fn canary_rollout_without_steps_or_analysis_is_decidably_bare() {
        // No steps means the canary goes straight to 100%, and no analysis
        // means nothing can abort it: both are authored facts of this CR.
        let got = packets(&format!(
            "{ROLLOUT_HEAD}spec:\n  strategy:\n    canary: {{}}\n"
        ));
        let steps = find(&got, "rollout:web", "rollout.canary.steps.count");
        assert_eq!(steps.resolved_value.as_deref(), Some("0"));
        assert_eq!(steps.provenance[0].role, "absent");
        let analysis = find(&got, "rollout:web", "rollout.analysis");
        assert_eq!(analysis.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        assert_eq!(analysis.provenance[0].role, "absent");
    }

    #[test]
    fn blue_green_rollout_names_its_promotion_analysis_and_has_no_step_count() {
        let got = packets(&format!(
            "{ROLLOUT_HEAD}spec:\n  strategy:\n    blueGreen:\n      activeService: web\n      prePromotionAnalysis:\n        templates:\n        - templateName: smoke\n"
        ));
        assert_eq!(
            find(&got, "rollout:web", "rollout.strategy")
                .resolved_value
                .as_deref(),
            Some("blueGreen")
        );
        assert_eq!(
            find(&got, "rollout:web", "rollout.analysis")
                .resolved_value
                .as_deref(),
            Some("prePromotion")
        );
        assert!(!got
            .packets
            .iter()
            .any(|p| p.key == "rollout.canary.steps.count"));
    }

    #[test]
    fn rollout_without_a_strategy_is_absent_and_emits_nothing_else() {
        let got = packets(&format!("{ROLLOUT_HEAD}spec:\n  replicas: 2\n"));
        assert_eq!(
            find(&got, "rollout:web", "rollout.strategy")
                .resolved_value
                .as_deref(),
            Some(ABSENT_RENDERING)
        );
        assert_eq!(got.packets.len(), 1, "{:?}", got.packets);
    }

    #[test]
    fn analysis_template_counts_metrics_that_can_never_fail() {
        // A metric with neither successCondition nor failureCondition is
        // measured and never judged, so it cannot abort a rollout.
        let got = packets(
            "apiVersion: argoproj.io/v1alpha1\nkind: AnalysisTemplate\nmetadata:\n  name: success-rate\nspec:\n  metrics:\n  - name: ok\n    successCondition: result[0] >= 0.95\n  - name: errors\n    failureCondition: result[0] > 0.05\n  - name: watched-only\n    interval: 1m\n---\napiVersion: argoproj.io/v1alpha1\nkind: ClusterAnalysisTemplate\nmetadata:\n  name: shared\nspec: {}\n",
        );
        let unit = "analysistemplate:success-rate";
        assert_eq!(
            find(&got, unit, "analysistemplate.metrics.count")
                .resolved_value
                .as_deref(),
            Some("3")
        );
        let bare = find(&got, unit, "analysistemplate.metrics.without-condition");
        assert_eq!(bare.resolved_value.as_deref(), Some("1"));
        assert_eq!(bare.format, "argo-rollouts");
        // Conditions are counted, never emitted: they can name internal metrics.
        assert!(got.packets.iter().all(|p| !p
            .resolved_value
            .as_deref()
            .unwrap_or("")
            .contains("result")));
        assert_eq!(
            find(
                &got,
                "clusteranalysistemplate:shared",
                "analysistemplate.metrics.count"
            )
            .resolved_value
            .as_deref(),
            Some("0")
        );
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

    /// A whole Application: it names where it deploys and what.
    fn whole_app(name: &str, spec: &str) -> String {
        format!(
            "apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: {name}\n  namespace: argocd\nspec:\n  project: platform\n  destination:\n    server: https://kubernetes.default.svc\n    namespace: {name}\n  source:\n    repoURL: https://example.com/deploy.git\n    path: apps/{name}\n{spec}"
        )
    }

    /// A whole Flux Kustomization.
    fn whole_ks(name: &str, spec: &str) -> String {
        format!(
            "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: {name}\n  namespace: flux-system\nspec:\n  sourceRef:\n    kind: GitRepository\n    name: flux-system\n  path: ./apps/{name}\n{spec}"
        )
    }

    /// A whole HelmRelease.
    fn whole_hr(name: &str, spec: &str) -> String {
        format!(
            "apiVersion: helm.toolkit.fluxcd.io/v2\nkind: HelmRelease\nmetadata:\n  name: {name}\n  namespace: {name}\nspec:\n  chart:\n    spec:\n      chart: {name}\n{spec}"
        )
    }

    /// The reason a packet carries when undecided, else `None`.
    fn undecided<'a>(got: &'a Retrieved, unit: &str, key: &str) -> Option<&'a str> {
        find(got, unit, key)
            .resolved_value
            .as_deref()
            .and_then(|v| v.strip_prefix(crate::UNDECIDED_PREFIX))
    }

    /// Retrieve `files` as one scan of a repository written under `root`.
    fn scan(root: &Path, files: &[(&str, &str)]) -> Retrieved {
        for (rel, text) in files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let claimed: Vec<(String, String)> = files
            .iter()
            .filter(|(rel, text)| ArgoFlux.matches_head(rel, text))
            .map(|(rel, text)| (rel.to_string(), text.to_string()))
            .collect();
        ArgoFlux.retrieve_all(root, &claimed, "snap")
    }

    #[test]
    fn automated_enabled_defaults_to_true_and_reads_an_authored_false() {
        let got = packets(&whole_app("api", "  syncPolicy:\n    automated: {}\n"));
        let on = find(
            &got,
            "application:api",
            "application.syncPolicy.automated.enabled",
        );
        assert_eq!(on.resolved_value.as_deref(), Some("true"));
        assert_eq!(on.resolution, Resolution::PlatformDefault);
        let got = packets(&whole_app(
            "api",
            "  syncPolicy:\n    automated:\n      enabled: false\n",
        ));
        let off = find(
            &got,
            "application:api",
            "application.syncPolicy.automated.enabled",
        );
        assert_eq!(off.resolved_value.as_deref(), Some("false"));
        assert_eq!(off.resolution, Resolution::AsAuthored);
        assert_eq!(
            off.provenance[0].key_path,
            "spec.syncPolicy.automated.enabled"
        );
        // No automated block: no enabled fact, as for prune and selfHeal.
        let got = packets(&whole_app("api", ""));
        assert!(!got
            .packets
            .iter()
            .any(|p| p.key == "application.syncPolicy.automated.enabled"));
    }

    #[test]
    fn drift_detection_mode_is_absent_without_a_block_and_disabled_by_default() {
        let key = "helmrelease.driftDetection.mode";
        let got = packets(&whole_hr("podinfo", "  interval: 5m\n"));
        let p = find(&got, "helmrelease:podinfo", key);
        assert_eq!(p.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance[0].role, "absent");

        let got = packets(&whole_hr("podinfo", "  driftDetection: {}\n"));
        let p = find(&got, "helmrelease:podinfo", key);
        assert_eq!(p.resolved_value.as_deref(), Some("disabled"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);

        for mode in ["enabled", "warn", "disabled"] {
            let got = packets(&whole_hr(
                "podinfo",
                &format!("  driftDetection:\n    mode: {mode}\n"),
            ));
            let p = find(&got, "helmrelease:podinfo", key);
            assert_eq!(p.resolved_value.as_deref(), Some(mode));
            assert_eq!(p.resolution, Resolution::AsAuthored);
        }
    }

    #[test]
    fn a_gitops_non_production_path_is_undecided_and_its_production_twin_is_not() {
        let ks = whole_ks("apps", "  interval: 30m\n  prune: true\n");
        for (path, token) in [
            ("clusters/qa/apps.yaml", "qa"),
            ("clusters/staging/apps.yaml", "staging"),
            ("legacy/apps.yaml", "legacy"),
            ("clusters/prod/apps-old.yaml", "old"),
        ] {
            let got = ArgoFlux.retrieve(path, &ks, "snap");
            assert_eq!(
                undecided(&got, "kustomization:apps", "kustomization.interval"),
                Some(format!("non-production path: {token}").as_str()),
                "{path}"
            );
        }
        let got = ArgoFlux.retrieve("clusters/production/apps.yaml", &ks, "snap");
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
        // A kind the measurement did not cover keeps the shared list only.
        let rollout = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\nspec:\n  strategy:\n    canary: {}\n";
        let got = ArgoFlux.retrieve("legacy/rollout.yaml", rollout, "snap");
        assert_eq!(undecided(&got, "rollout:web", "rollout.strategy"), None);
    }

    #[test]
    fn a_non_production_target_is_undecided_and_its_production_twin_is_not() {
        let key = "application.syncPolicy.automated.selfHeal";
        let auto = "  syncPolicy:\n    automated: {}\n";
        for (yaml, field, token) in [
            (
                whole_app("api", auto).replace("name: api\n", "name: api-staging\n"),
                "metadata.name",
                "staging",
            ),
            (
                whole_app("api", auto).replace("namespace: argocd", "namespace: dev"),
                "metadata.namespace",
                "dev",
            ),
            (
                whole_app("api", auto).replace("    namespace: api", "    namespace: qa"),
                "destination.namespace",
                "qa",
            ),
            (
                whole_app("api", auto).replace(
                    "    server: https://kubernetes.default.svc",
                    "    name: uat-cluster",
                ),
                "destination.name",
                "uat",
            ),
            (
                whole_app("api", auto).replace(
                    "https://kubernetes.default.svc",
                    "https://stg.k8s.internal",
                ),
                "destination.server",
                "stg",
            ),
            (
                whole_app("api", auto).replace("path: apps/api", "path: envs/preview/api"),
                "source.path",
                "preview",
            ),
            (
                whole_app("api", auto).replace("project: platform", "project: sandbox"),
                "project",
                "sandbox",
            ),
            (
                whole_app(
                    "api",
                    &format!("{auto}  sources:\n  - repoURL: https://example.com/c.git\n    helm:\n      valueFiles: [values-int.yaml]\n"),
                ),
                "source.helm.valueFiles",
                "int",
            ),
        ] {
            let got = packets(&yaml);
            let unit = got.packets[0].unit.clone();
            assert_eq!(
                undecided(&got, &unit, key),
                Some(format!("non-production target: {field} names {token}").as_str()),
                "{yaml}"
            );
        }
        let ks = whole_ks("apps", "  interval: 30m\n").replace("./apps/apps", "./clusters/staging");
        let got = packets(&ks);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("non-production target: spec.path names staging")
        );
        let ks = whole_ks("apps", "  targetNamespace: qa\n  interval: 30m\n");
        let got = packets(&ks);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("non-production target: spec.targetNamespace names qa")
        );
        let hr = whole_hr(
            "podinfo",
            "  targetNamespace: podinfo-dev\n  interval: 5m\n",
        );
        let got = packets(&hr);
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
            Some("non-production target: spec.targetNamespace names dev")
        );

        // The production twins.
        let got = packets(&whole_app("api", auto));
        assert_eq!(undecided(&got, "application:api", key), None);
        let got = packets(&whole_ks(
            "apps",
            "  targetNamespace: apps\n  interval: 30m\n",
        ));
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
        let got = packets(&whole_hr(
            "podinfo",
            "  targetNamespace: podinfo\n  interval: 5m\n",
        ));
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
            None
        );
    }

    #[test]
    fn a_lab_repository_is_undecided_and_a_fleet_repository_is_not() {
        let ks = whole_ks("apps", "  interval: 30m\n");
        let dir = tempfile::tempdir().unwrap();
        let got = scan(&dir.path().join("k8s-lab"), &[("clusters/apps.yaml", &ks)]);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("non-production repository: lab")
        );
        let got = scan(&dir.path().join("fleet"), &[("clusters/apps.yaml", &ks)]);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
    }

    #[test]
    fn a_chart_template_is_undecided_and_a_file_beside_the_chart_is_not() {
        let ks = whole_ks("apps", "  interval: 30m\n");
        let dir = tempfile::tempdir().unwrap();
        let got = scan(
            dir.path(),
            &[
                (
                    "chart/Chart.yaml",
                    "apiVersion: v2\nname: fleet\nversion: 1.0.0\n",
                ),
                ("chart/templates/apps.yaml", &ks),
            ],
        );
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("chart template: rendered before it is applied")
        );
        let dir = tempfile::tempdir().unwrap();
        let got = scan(
            dir.path(),
            &[
                (
                    "chart/Chart.yaml",
                    "apiVersion: v2\nname: fleet\nversion: 1.0.0\n",
                ),
                ("chart/apps.yaml", &ks),
            ],
        );
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
    }

    #[test]
    fn a_file_that_does_not_parse_undecides_the_documents_before_the_break() {
        let ks = whole_ks("apps", "  interval: 30m\n");
        let rollout = "apiVersion: argoproj.io/v1alpha1\nkind: Rollout\nmetadata:\n  name: web\nspec:\n  strategy:\n    canary: {}\n";
        let got = packets(&format!("{ks}---\n{rollout}---\nkey: [unclosed\n"));
        assert_eq!(got.unparseable, 1);
        // A kind the measurement did not cover keeps its facts.
        assert_eq!(undecided(&got, "rollout:web", "rollout.strategy"), None);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("the file does not parse as YAML")
        );
        let got = packets(&ks);
        assert_eq!(got.unparseable, 0);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
    }

    #[test]
    fn a_fragment_is_undecided_and_its_whole_twin_is_not() {
        let ks = whole_ks("apps", "  interval: 30m\n");
        let file_fragment = "fragment: a patch or component another file completes";
        for path in [
            "clusters/prod/patches/apps.yaml",
            "clusters/prod/components/apps.yaml",
            "clusters/prod/apps-patch.yaml",
        ] {
            let got = ArgoFlux.retrieve(path, &ks, "snap");
            assert_eq!(
                undecided(&got, "kustomization:apps", "kustomization.interval"),
                Some(file_fragment),
                "{path}"
            );
        }
        let got = packets(&format!("{ks}  $patch: replace\n"));
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some(file_fragment)
        );

        let auto = "  syncPolicy:\n    automated: {}\n";
        let key = "application.syncPolicy.automated.prune";
        let no_destination = whole_app("api", auto).replace(
            "  destination:\n    server: https://kubernetes.default.svc\n    namespace: api\n",
            "",
        );
        let got = packets(&no_destination);
        assert_eq!(
            undecided(&got, "application:api", key),
            Some("fragment: no destination, another file completes it")
        );
        let no_source = whole_app("api", auto).replace(
            "  source:\n    repoURL: https://example.com/deploy.git\n    path: apps/api\n",
            "",
        );
        let got = packets(&no_source);
        assert_eq!(
            undecided(&got, "application:api", key),
            Some("fragment: no source, another file completes it")
        );
        let multi = no_source.replace(
            "  syncPolicy:",
            "  sources:\n  - repoURL: https://example.com/deploy.git\n  syncPolicy:",
        );
        assert_eq!(undecided(&packets(&multi), "application:api", key), None);

        let no_ref = ks.replace(
            "  sourceRef:\n    kind: GitRepository\n    name: flux-system\n",
            "",
        );
        let got = packets(&no_ref);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            Some("fragment: no sourceRef, another file completes it")
        );

        let hr = whole_hr("podinfo", "  interval: 5m\n");
        let no_chart = hr.replace("  chart:\n    spec:\n      chart: podinfo\n", "");
        let got = packets(&no_chart);
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
            Some("fragment: no chart or chartRef, another file completes it")
        );
        let chart_ref = no_chart.replace(
            "  interval:",
            "  chartRef:\n    kind: OCIRepository\n    name: podinfo\n  interval:",
        );
        let got = packets(&chart_ref);
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
            None
        );
        let got = packets(&ks);
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.interval"),
            None
        );
    }

    #[test]
    fn an_object_declared_in_two_files_is_undecided_and_a_single_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let got = scan(
            dir.path(),
            &[
                (
                    "clusters/eu/apps.yaml",
                    &whole_ks("apps", "  interval: 30m\n"),
                ),
                (
                    "clusters/us/apps.yaml",
                    &whole_ks("apps", "  interval: 5m\n"),
                ),
                (
                    "clusters/us/infra.yaml",
                    &whole_ks("infra", "  interval: 30m\n"),
                ),
            ],
        );
        let reasons: Vec<_> = got
            .packets
            .iter()
            .filter(|p| p.key == "kustomization.interval")
            .map(|p| (p.file_path.as_str(), p.resolved_value.as_deref()))
            .collect();
        let twice =
            Some("undecided: declared in 2 files: an overlay or a second cluster restates it");
        assert_eq!(
            reasons,
            vec![
                ("clusters/eu/apps.yaml", twice),
                ("clusters/us/apps.yaml", twice),
                ("clusters/us/infra.yaml", Some("30m")),
            ]
        );
    }

    #[test]
    fn a_templated_value_is_undecided_and_its_literal_twin_is_not() {
        for (yaml, unit, key, field) in [
            (
                whole_ks("apps", "  interval: ${RECONCILE_INTERVAL}\n"),
                "kustomization:apps",
                "kustomization.interval",
                "interval",
            ),
            (
                whole_ks(
                    "apps",
                    "  interval: 30m\n  prune: \"{{ .Values.prune }}\"\n",
                ),
                "kustomization:apps",
                "kustomization.prune",
                "prune",
            ),
            (
                whole_app(
                    "api",
                    "  syncPolicy:\n    automated:\n      selfHeal: <self-heal>\n",
                ),
                "application:api",
                "application.syncPolicy.automated.prune",
                "selfHeal",
            ),
            (
                whole_app("api", "  syncPolicy: \"{{ .syncPolicy }}\"\n"),
                "application:api",
                "application.syncPolicy.automated",
                "syncPolicy",
            ),
            (
                whole_hr(
                    "podinfo",
                    "  interval: 5m\n  driftDetection:\n    mode: ${DRIFT}\n",
                ),
                "helmrelease:podinfo",
                "helmrelease.driftDetection.mode",
                "mode",
            ),
        ] {
            let got = packets(&yaml);
            assert_eq!(
                undecided(&got, unit, key),
                Some(format!("templated value: {field}").as_str()),
                "{yaml}"
            );
        }
        let set = "apiVersion: argoproj.io/v1alpha1\nkind: ApplicationSet\nmetadata:\n  name: fleet\nspec:\n  template:\n    spec:\n      destination:\n        server: https://kubernetes.default.svc\n      source:\n        repoURL: https://example.com/deploy.git\n      syncPolicy:\n        automated: {}\n";
        let key = "application.syncPolicy.automated.selfHeal";
        let got = packets(&format!("{set}  templatePatch: |\n    spec: {{}}\n"));
        assert_eq!(
            undecided(&got, "applicationset:fleet", key),
            Some("templated value: templatePatch")
        );
        assert_eq!(undecided(&packets(set), "applicationset:fleet", key), None);
        let got = packets(&whole_ks("apps", "  interval: 30m\n  prune: false\n"));
        assert_eq!(
            undecided(&got, "kustomization:apps", "kustomization.prune"),
            None
        );
    }

    #[test]
    fn an_interval_that_is_not_a_go_duration_is_undecided() {
        for interval in ["1d", "five minutes", "10", "1.2.3m"] {
            let got = packets(&whole_ks("apps", &format!("  interval: {interval}\n")));
            assert_eq!(
                undecided(&got, "kustomization:apps", "kustomization.prune"),
                Some(format!("interval {interval:?} is not a Go duration").as_str()),
                "{interval}"
            );
        }
        for interval in ["1h30m", "30m", "0", "1.5h", "500ms"] {
            let got = packets(&whole_hr("podinfo", &format!("  interval: {interval}\n")));
            assert_eq!(
                undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
                None,
                "{interval}"
            );
        }
    }

    #[test]
    fn drift_detection_patched_elsewhere_undecides_only_the_drift_fact() {
        let key = "helmrelease.driftDetection.mode";
        let hr = whole_hr("podinfo", "  interval: 5m\n");
        let parent = "apiVersion: kustomize.toolkit.fluxcd.io/v1\nkind: Kustomization\nmetadata:\n  name: apps\nspec:\n  patches:\n  - patch: |\n      - op: add\n        path: /spec/driftDetection\n        value: {mode: enabled}\n    target:\n      kind: HelmRelease\n";
        let dir = tempfile::tempdir().unwrap();
        let got = scan(
            dir.path(),
            &[
                ("apps/podinfo.yaml", &hr),
                ("clusters/prod/kustomization.yaml", parent),
            ],
        );
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", key),
            Some(DRIFT_PATCH_REASON)
        );
        assert_eq!(
            undecided(&got, "helmrelease:podinfo", "helmrelease.interval"),
            None
        );
        // A release that turns detection on itself keeps its fact.
        let on = whole_hr("podinfo", "  driftDetection:\n    mode: enabled\n");
        let dir = tempfile::tempdir().unwrap();
        let got = scan(
            dir.path(),
            &[
                ("apps/podinfo.yaml", &on),
                ("clusters/prod/kustomization.yaml", parent),
            ],
        );
        assert_eq!(undecided(&got, "helmrelease:podinfo", key), None);
        // No patch anywhere: the absence is the fact.
        let dir = tempfile::tempdir().unwrap();
        let got = scan(dir.path(), &[("apps/podinfo.yaml", &hr)]);
        let p = find(&got, "helmrelease:podinfo", key);
        assert_eq!(p.resolved_value.as_deref(), Some(ABSENT_RENDERING));
    }

    #[test]
    fn go_duration_follows_parse_duration() {
        for ok in ["0", "5m", "1h30m", "1.5h", "300ms", "10us", "-1s", "+2h"] {
            assert!(go_duration(ok), "{ok}");
        }
        for bad in ["", "5", "1d", "1w", "m", "1..5s", ".s", "5 m", "5M"] {
            assert!(!go_duration(bad), "{bad}");
        }
    }
}
