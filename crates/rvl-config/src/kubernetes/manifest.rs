//! Plain-manifest extraction: one parsed Kubernetes document (from a bare
//! file, a kustomize-resolved resource, or a helm render) becomes packets
//! for the G6 control-set keys.
//!
//! The key inventory (granularity map G6: capacity RC-024, fault tolerance
//! RC-017, progressive deploy RC-015, health checks, supply-chain pinning
//! RC-045, least privilege RC-044):
//!
//!   * `workload.replicas` (Deployment/StatefulSet; documented default 1)
//!   * `workload.strategy.type` (Deployment; default RollingUpdate) and,
//!     when the effective type is RollingUpdate, `workload.strategy.max-surge`
//!     / `workload.strategy.max-unavailable` (documented defaults 25%/25%)
//!   * `pod.termination-grace-period-seconds` (default 30),
//!     `pod.priority-class-name` (default none),
//!     `pod.security-context` (default none)
//!   * per container: `container.resources.{requests,limits}.{cpu,memory}`
//!     (default none), `container.{liveness,readiness,startup}-probe`
//!     (default none), `container.liveness-probe.http-get.path` (authored
//!     only, vocabulary: the manifest half of the probe-to-handler join),
//!     `container.security-context` (default none),
//!     `container.image.pin` (derived shape: digest | tag | latest — never
//!     the image reference itself), `container.image-pull-policy`
//!     (documented conditional default: Always for latest/untagged,
//!     IfNotPresent otherwise)
//!   * `pdb.min-available` / `pdb.max-unavailable` (authored only: the API
//!     requires exactly one, so the pair's absence is invalid config, not a
//!     decidable default)
//!   * `hpa.min-replicas` (documented default 1) / `hpa.max-replicas`
//!     (required field, authored only)
//!   * `workload.pdb-coverage` (Deployment/StatefulSet; derived: `covered`
//!     when a PodDisruptionBudget of the same RENDERED SET selects the pod
//!     template labels, `none` — the documented default, evictions are
//!     unbudgeted — when the whole set was read and none does; no packet
//!     when the set or a selector cannot be resolved, see [`RenderedSet`])
//!   * `pod.anti-affinity` / `pod.topology-spread-constraints`
//!     (Deployment/StatefulSet; default none)
//!
//! Absence resolves to the DOCUMENTED Kubernetes default. Cluster-side
//! mutators (LimitRange, globalDefault PriorityClass, admission webhooks)
//! are authored cluster objects, not always-present platform settings, so
//! they do not demote these defaults to `unresolvable` (contrast the
//! GITHUB_TOKEN default, which always exists org-side).

use crate::{render_value, ConfigPacket, FormatSighting, ProvenanceStep, Resolution, Retrieved};
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::path::Path;

/// The key that carries a liveness probe's `httpGet` path: the manifest half
/// of the probe-to-handler join (`rvl_propagate::probe_handler`).
pub const LIVENESS_HTTP_GET_PATH_KEY: &str = "container.liveness-probe.http-get.path";

pub(super) fn get<'a>(m: &'a Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

/// Walk a mapping chain by field names.
pub(super) fn dig<'a>(v: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = v;
    for k in path {
        cur = get(cur.as_mapping()?, k)?;
    }
    Some(cur)
}

/// Resolve a dotted lookup path against a document. A `field[name]` segment
/// selects the element of a sequence whose `name:` equals `name` — the
/// strategic-merge identity for containers.
pub(super) fn lookup<'a>(doc: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = doc;
    for seg in path.split('.') {
        if let Some((field, rest)) = seg.split_once('[') {
            let name = rest.strip_suffix(']')?;
            let seq = get(cur.as_mapping()?, field)?.as_sequence()?;
            cur = seq.iter().find(|e| {
                e.as_mapping()
                    .and_then(|m| get(m, "name"))
                    .and_then(Value::as_str)
                    == Some(name)
            })?;
        } else {
            cur = get(cur.as_mapping()?, seg)?;
        }
    }
    Some(cur)
}

/// How a variant explains one resolved key: the plain file says "explicit",
/// a kustomize chain lists the layers that touched it, a helm render cites
/// the template and its committed inputs.
pub(super) trait ProvenanceOracle {
    /// Resolution + chain for a key present in the final document.
    /// `lookup_path` addresses the value (for layer comparison);
    /// `display_path` is what the chain shows.
    fn present(&self, lookup_path: &str, display_path: &str) -> (Resolution, Vec<ProvenanceStep>);
    /// Chain for a decidably-absent key resolved by the documented default.
    fn absent(&self, display_path: &str, platform_key: &str) -> Vec<ProvenanceStep>;
}

/// The bare-file oracle: whatever the document says was authored right there.
pub(super) struct PlainOracle<'a> {
    pub file: &'a str,
}

impl ProvenanceOracle for PlainOracle<'_> {
    fn present(&self, _lookup_path: &str, display_path: &str) -> (Resolution, Vec<ProvenanceStep>) {
        (
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(self.file, display_path, "explicit")],
        )
    }
    fn absent(&self, display_path: &str, platform_key: &str) -> Vec<ProvenanceStep> {
        vec![
            ProvenanceStep::new(self.file, display_path, "absent"),
            ProvenanceStep::new("", platform_key, "platform-default"),
        ]
    }
}

/// Shared packet assembly for every variant of the family.
pub(super) struct Emitter<'a> {
    pub file_anchor: &'a str,
    pub snapshot_id: &'a str,
    pub oracle: &'a dyn ProvenanceOracle,
    pub out: Vec<ConfigPacket>,
}

impl Emitter<'_> {
    fn push(
        &mut self,
        unit: &str,
        key: &str,
        value: String,
        resolution: Resolution,
        provenance: Vec<ProvenanceStep>,
    ) {
        self.out.push(ConfigPacket {
            snapshot_id: self.snapshot_id.to_string(),
            format: "kubernetes".to_string(),
            file_path: self.file_anchor.to_string(),
            line: 0,
            unit: unit.to_string(),
            key: crate::key_ledger::declared("kubernetes", key),
            resolved_value: Some(value),
            resolution,
            provenance,
        });
    }

    /// A key present in the document, valued by its canonical rendering.
    fn present(&mut self, unit: &str, key: &str, path: &str, v: &Value) {
        let (resolution, provenance) = self.oracle.present(path, path);
        self.push(unit, key, render_value(v), resolution, provenance);
    }

    /// A key DERIVED from a document value (the image pin shape): the packet
    /// carries the derived string, the chain the display path.
    fn derived(&mut self, unit: &str, key: &str, lookup_path: &str, display: &str, value: &str) {
        let (resolution, provenance) = self.oracle.present(lookup_path, display);
        self.push(unit, key, value.to_string(), resolution, provenance);
    }

    /// A decidably-absent key: the documented platform default governs.
    fn absent(&mut self, unit: &str, key: &str, path: &str, platform_key: &str, default: &str) {
        self.push(
            unit,
            key,
            default.to_string(),
            Resolution::PlatformDefault,
            self.oracle.absent(path, platform_key),
        );
    }

    /// Present-or-default for a placement rule, where an authored but empty
    /// value (`podAntiAffinity: {}`, `topologySpreadConstraints: []`) places
    /// nothing and so resolves like an absent one.
    fn placement(&mut self, unit: &str, key: &str, doc: &Value, path: &str, platform_key: &str) {
        let empty = |v: &Value| match v {
            Value::Null => true,
            Value::Mapping(m) => m.is_empty(),
            Value::Sequence(s) => s.is_empty(),
            _ => false,
        };
        match lookup(doc, path).filter(|v| !empty(v)) {
            Some(v) => self.present(unit, key, path, v),
            None => self.absent(unit, key, path, platform_key, "none"),
        }
    }

    /// Present-or-default in one move.
    fn setting(
        &mut self,
        unit: &str,
        key: &str,
        doc: &Value,
        path: &str,
        platform_key: &str,
        default: &str,
    ) {
        match lookup(doc, path) {
            Some(v) => self.present(unit, key, path, v),
            None => self.absent(unit, key, path, platform_key, default),
        }
    }
}

/// The pin shape of an image reference: `digest` (immutable), `tag`
/// (mutable but named), `latest` (an explicit `:latest` or no tag at all —
/// the docs default an untagged image to `latest`).
pub(super) fn image_pin(image: &str) -> &'static str {
    if image.contains("@sha256:") || image.contains("@sha512:") {
        return "digest";
    }
    // The tag lives after the last ':' of the last path segment; splitting
    // on the whole string would misread a registry port (host:5000/app).
    let last_seg = image.rsplit('/').next().unwrap_or(image);
    match last_seg.rsplit_once(':') {
        Some((_, "latest")) => "latest",
        Some(_) => "tag",
        None => "latest",
    }
}

/// One PodDisruptionBudget of a rendered set.
struct Pdb {
    /// Repo-relative file that authored it.
    file: String,
    name: String,
    namespace: Option<String>,
    /// `policy/v1` reads an empty selector as every pod of the namespace;
    /// `policy/v1beta1` reads it as none.
    empty_selects_all: bool,
    selector: Option<Value>,
}

/// Whether one selector picks one pod template.
enum Selects {
    Yes,
    No,
    /// The repo does not decide it: an operator outside the label-selector
    /// grammar, a non-scalar label, a namespace only one side states.
    Unknown,
}

/// PDB coverage of one workload within its rendered set.
enum Coverage<'a> {
    Covered(&'a Pdb),
    Uncovered,
    Unknown,
}

/// The PodDisruptionBudgets that are applied together with a workload: the
/// documents of one kustomization, one chart render, or one directory of bare
/// manifests (the `kubectl apply -f <dir>` unit).
///
/// `workload.pdb-coverage` is a statement about the whole set, so the set
/// also records whether it was read in full. A set with a hole in it (an
/// unrendered template, a dropped kustomize resource, an unparseable sibling)
/// can still prove `covered`; it can never prove `none`, and the workload
/// then gets no coverage packet at all, which is how this family abstains.
pub(super) struct RenderedSet {
    pdbs: Vec<Pdb>,
    complete: bool,
}

impl RenderedSet {
    pub(super) fn new() -> Self {
        Self {
            pdbs: Vec::new(),
            complete: true,
        }
    }

    /// Part of the set could not be read: absence of a PDB is not provable.
    pub(super) fn mark_incomplete(&mut self) {
        self.complete = false;
    }

    /// Record `doc` when it is a PodDisruptionBudget; every other kind is
    /// not part of the coverage question.
    pub(super) fn add(&mut self, file: &str, doc: &Value) {
        if dig(doc, &["kind"]).and_then(Value::as_str) != Some("PodDisruptionBudget") {
            return;
        }
        let Some(name) = dig(doc, &["metadata", "name"]).and_then(Value::as_str) else {
            return;
        };
        self.pdbs.push(Pdb {
            file: file.to_string(),
            name: name.to_string(),
            namespace: namespace_of(doc),
            empty_selects_all: dig(doc, &["apiVersion"]).and_then(Value::as_str)
                == Some("policy/v1"),
            selector: dig(doc, &["spec", "selector"])
                .filter(|v| !v.is_null())
                .cloned(),
        });
    }

    fn coverage(&self, namespace: Option<&str>, labels: Option<&Mapping>) -> Coverage<'_> {
        let mut unknown = !self.complete;
        for pdb in &self.pdbs {
            match pdb.selects(namespace, labels) {
                Selects::Yes => return Coverage::Covered(pdb),
                Selects::Unknown => unknown = true,
                Selects::No => {}
            }
        }
        if unknown {
            Coverage::Unknown
        } else {
            Coverage::Uncovered
        }
    }
}

fn namespace_of(doc: &Value) -> Option<String> {
    dig(doc, &["metadata", "namespace"])
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// A label key or value as the API compares it: a string. YAML authors write
/// `version: 2` and `canary: true` unquoted, so scalars are rendered.
fn label_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn label(labels: Option<&Mapping>, key: &str) -> Option<String> {
    labels.and_then(|m| get(m, key)).and_then(label_str)
}

/// One `matchExpressions` requirement against the pod labels.
fn expression_selects(expr: &Value, labels: Option<&Mapping>) -> Selects {
    let field = |name: &str| dig(expr, &[name]);
    let (Some(key), Some(operator)) = (
        field("key").and_then(Value::as_str),
        field("operator").and_then(Value::as_str),
    ) else {
        return Selects::Unknown;
    };
    let got = label(labels, key);
    let decided = |yes: bool| if yes { Selects::Yes } else { Selects::No };
    match operator {
        "Exists" => decided(got.is_some()),
        "DoesNotExist" => decided(got.is_none()),
        "In" | "NotIn" => {
            let Some(values) = field("values")
                .and_then(Value::as_sequence)
                .and_then(|s| s.iter().map(label_str).collect::<Option<Vec<_>>>())
            else {
                return Selects::Unknown;
            };
            let within = got.is_some_and(|g| values.contains(&g));
            decided(within == (operator == "In"))
        }
        _ => Selects::Unknown,
    }
}

impl Pdb {
    /// Whether this budget selects a pod template with `labels` in
    /// `namespace`. Requirements are ANDed, so one that fails decides `No`
    /// whatever the others are.
    fn selects(&self, namespace: Option<&str>, labels: Option<&Mapping>) -> Selects {
        let namespace_known = match (self.namespace.as_deref(), namespace) {
            (a, b) if a == b => true,
            (Some(_), Some(_)) => return Selects::No,
            // One side leaves the namespace to `kubectl apply -n` or to a
            // transformer: the repo does not say whether they meet.
            _ => false,
        };
        // No selector at all selects no pod.
        let Some(selector) = self.selector.as_ref() else {
            return Selects::No;
        };
        let Some(selector) = selector.as_mapping() else {
            return Selects::Unknown;
        };
        let mut unknown = false;
        let mut requirements = 0;
        for (field, v) in selector {
            match (field.as_str(), v) {
                (Some("matchLabels"), Value::Mapping(want)) => {
                    for (k, v) in want {
                        requirements += 1;
                        match (k.as_str(), label_str(v)) {
                            (Some(k), Some(v)) if label(labels, k).as_ref() != Some(&v) => {
                                return Selects::No
                            }
                            (Some(_), Some(_)) => {}
                            _ => unknown = true,
                        }
                    }
                }
                (Some("matchExpressions"), Value::Sequence(exprs)) => {
                    for expr in exprs {
                        requirements += 1;
                        match expression_selects(expr, labels) {
                            Selects::No => return Selects::No,
                            Selects::Unknown => unknown = true,
                            Selects::Yes => {}
                        }
                    }
                }
                (Some("matchLabels" | "matchExpressions"), Value::Null) => {}
                _ => unknown = true,
            }
        }
        if unknown {
            Selects::Unknown
        } else if requirements == 0 && !self.empty_selects_all {
            Selects::No
        } else if namespace_known {
            Selects::Yes
        } else {
            Selects::Unknown
        }
    }
}

/// Kinds that run replicas a disruption budget and a placement rule protect.
fn replicated(kind: &str) -> bool {
    matches!(kind, "Deployment" | "StatefulSet")
}

/// The rendered set of a bare manifest file: its own documents plus the
/// PodDisruptionBudgets of the other YAML files of its directory. Without a
/// `root` the directory cannot be listed and the set is incomplete.
fn directory_set(root: Option<&Path>, rel_path: &str, own: &[Value], failed: bool) -> RenderedSet {
    let mut set = RenderedSet::new();
    for doc in own {
        set.add(rel_path, doc);
    }
    if failed {
        set.mark_incomplete();
    }
    // Only a replicated workload asks the question; a file without one never
    // pays for the directory listing.
    let asks = own.iter().any(|d| {
        dig(d, &["kind"])
            .and_then(Value::as_str)
            .is_some_and(replicated)
    });
    if !asks {
        return set;
    }
    let Some(root) = root else {
        set.mark_incomplete();
        return set;
    };
    let (dir, own_name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
    let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
        set.mark_incomplete();
        return set;
    };
    let mut siblings: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != own_name && (n.ends_with(".yaml") || n.ends_with(".yml")))
        .collect();
    // Directory order is the filesystem's; the PDB a packet names must not be.
    siblings.sort();
    for name in siblings {
        let rel = if dir.is_empty() {
            name
        } else {
            format!("{dir}/{name}")
        };
        let Ok(text) = std::fs::read_to_string(root.join(&rel)) else {
            set.mark_incomplete();
            continue;
        };
        if !text.contains("PodDisruptionBudget") {
            continue;
        }
        // A templated budget has a selector no committed input renders here.
        if text.contains("{{") {
            set.mark_incomplete();
            continue;
        }
        let (docs, failed) = parse_docs(&text);
        if failed {
            set.mark_incomplete();
        }
        for doc in &docs {
            set.add(&rel, doc);
        }
    }
    set
}

/// Kinds whose pod template we inventory, with the unit prefix and the path
/// from `spec` to the pod spec.
pub(super) fn workload_shape(kind: &str) -> Option<(&'static str, &'static [&'static str])> {
    match kind {
        "Deployment" => Some(("deployment", &["template", "spec"])),
        "StatefulSet" => Some(("statefulset", &["template", "spec"])),
        "DaemonSet" => Some(("daemonset", &["template", "spec"])),
        "Job" => Some(("job", &["template", "spec"])),
        "CronJob" => Some(("cronjob", &["jobTemplate", "spec", "template", "spec"])),
        _ => None,
    }
}

/// Extract packets from one parsed document into the emitter. Documents of
/// kinds outside the inventory emit nothing (valid Kubernetes, no facts the
/// G6 control set asks about). `set` is the rendered set `doc` belongs to,
/// which answers the one fact a document cannot answer about itself.
pub(super) fn packets_from_doc(doc: &Value, set: &RenderedSet, em: &mut Emitter) {
    let Some(root) = doc.as_mapping() else { return };
    let Some(kind) = get(root, "kind").and_then(Value::as_str) else {
        return;
    };
    let Some(name) = dig(doc, &["metadata", "name"]).and_then(Value::as_str) else {
        return;
    };
    let Some(spec) = get(root, "spec").and_then(Value::as_mapping) else {
        return;
    };

    match kind {
        "PodDisruptionBudget" => {
            let unit = format!("pdb:{name}");
            // The API requires exactly one of the pair: only authored
            // values are facts; the pair's absence is invalid, not a default.
            if let Some(v) = get(spec, "minAvailable") {
                em.present(&unit, "pdb.min-available", "spec.minAvailable", v);
            }
            if let Some(v) = get(spec, "maxUnavailable") {
                em.present(&unit, "pdb.max-unavailable", "spec.maxUnavailable", v);
            }
            return;
        }
        "HorizontalPodAutoscaler" => {
            let unit = format!("hpa:{name}");
            em.setting(
                &unit,
                "hpa.min-replicas",
                doc,
                "spec.minReplicas",
                "minReplicas",
                "1",
            );
            // maxReplicas is required; an absent one is invalid config, not
            // a platform default.
            if let Some(v) = get(spec, "maxReplicas") {
                em.present(&unit, "hpa.max-replicas", "spec.maxReplicas", v);
            }
            return;
        }
        _ => {}
    }

    let Some((kind_lower, pod_path)) = workload_shape(kind) else {
        return;
    };
    let unit = format!("{kind_lower}:{name}");

    if matches!(kind, "Deployment" | "StatefulSet") {
        em.setting(
            &unit,
            "workload.replicas",
            doc,
            "spec.replicas",
            "replicas",
            "1",
        );
    }

    if replicated(kind) {
        const LABELS: &str = "spec.template.metadata.labels";
        let labels = lookup(doc, LABELS).and_then(Value::as_mapping);
        match set.coverage(namespace_of(doc).as_deref(), labels) {
            Coverage::Covered(pdb) => {
                // The fact is as strong as the labels it was matched on.
                let (resolution, _) = em.oracle.present(LABELS, LABELS);
                let role = match resolution {
                    Resolution::Rendered => "rendered",
                    _ => "explicit",
                };
                let selector = format!("PodDisruptionBudget/{} spec.selector", pdb.name);
                em.push(
                    &unit,
                    "workload.pdb-coverage",
                    "covered".to_string(),
                    resolution,
                    vec![ProvenanceStep::new(&pdb.file, &selector, role)],
                );
            }
            Coverage::Uncovered => em.absent(
                &unit,
                "workload.pdb-coverage",
                &format!("PodDisruptionBudget selecting {LABELS}"),
                "no disruption budget: voluntary evictions are unlimited",
                "none",
            ),
            Coverage::Unknown => {}
        }
    }

    if kind == "Deployment" {
        let stype = dig(doc, &["spec", "strategy", "type"]).and_then(Value::as_str);
        em.setting(
            &unit,
            "workload.strategy.type",
            doc,
            "spec.strategy.type",
            "strategy.type",
            "RollingUpdate",
        );
        // Surge/unavailable govern only a RollingUpdate (authored or
        // defaulted); a Recreate deployment has neither.
        if stype.unwrap_or("RollingUpdate") == "RollingUpdate" {
            em.setting(
                &unit,
                "workload.strategy.max-surge",
                doc,
                "spec.strategy.rollingUpdate.maxSurge",
                "strategy.rollingUpdate.maxSurge",
                "25%",
            );
            em.setting(
                &unit,
                "workload.strategy.max-unavailable",
                doc,
                "spec.strategy.rollingUpdate.maxUnavailable",
                "strategy.rollingUpdate.maxUnavailable",
                "25%",
            );
        }
    }

    // Pod-level and container-level facts hang off the pod template; a
    // workload without one is invalid config and emits nothing further.
    let mut prefix = String::from("spec");
    for seg in pod_path {
        prefix.push('.');
        prefix.push_str(seg);
    }
    let Some(pod) = lookup(doc, &prefix) else {
        return;
    };
    if pod.as_mapping().is_none() {
        return;
    }

    em.setting(
        &unit,
        "pod.termination-grace-period-seconds",
        doc,
        &format!("{prefix}.terminationGracePeriodSeconds"),
        "terminationGracePeriodSeconds",
        "30",
    );
    em.setting(
        &unit,
        "pod.priority-class-name",
        doc,
        &format!("{prefix}.priorityClassName"),
        "priorityClassName",
        "none",
    );
    em.setting(
        &unit,
        "pod.security-context",
        doc,
        &format!("{prefix}.securityContext"),
        "securityContext",
        "none",
    );

    if replicated(kind) {
        em.placement(
            &unit,
            "pod.anti-affinity",
            doc,
            &format!("{prefix}.affinity.podAntiAffinity"),
            "affinity.podAntiAffinity",
        );
        em.placement(
            &unit,
            "pod.topology-spread-constraints",
            doc,
            &format!("{prefix}.topologySpreadConstraints"),
            "topologySpreadConstraints",
        );
    }

    let containers = lookup(doc, &format!("{prefix}.containers")).and_then(Value::as_sequence);
    for c in containers.into_iter().flatten() {
        let Some(cm) = c.as_mapping() else { continue };
        let Some(cname) = get(cm, "name").and_then(Value::as_str) else {
            continue;
        };
        let cunit = format!("container:{kind_lower}/{name}/{cname}");
        let cpath = format!("{prefix}.containers[{cname}]");

        for (key, section, resource) in [
            ("container.resources.requests.cpu", "requests", "cpu"),
            ("container.resources.requests.memory", "requests", "memory"),
            ("container.resources.limits.cpu", "limits", "cpu"),
            ("container.resources.limits.memory", "limits", "memory"),
        ] {
            em.setting(
                &cunit,
                key,
                doc,
                &format!("{cpath}.resources.{section}.{resource}"),
                &format!("resources.{section}.{resource}"),
                "none",
            );
        }

        for (field, key) in [
            ("livenessProbe", "container.liveness-probe"),
            ("readinessProbe", "container.readiness-probe"),
            ("startupProbe", "container.startup-probe"),
        ] {
            em.setting(&cunit, key, doc, &format!("{cpath}.{field}"), field, "none");
        }

        // The path the kubelet requests, for the join to the handler that
        // serves it. Carried only when the probe is an httpGet with a path:
        // an exec, tcpSocket or grpc probe has no route to join to.
        let live_path = format!("{cpath}.livenessProbe.httpGet.path");
        if let Some(v @ Value::String(_)) = lookup(doc, &live_path) {
            em.present(&cunit, LIVENESS_HTTP_GET_PATH_KEY, &live_path, v);
        }

        em.setting(
            &cunit,
            "container.security-context",
            doc,
            &format!("{cpath}.securityContext"),
            "securityContext",
            "none",
        );

        if let Some(image) = get(cm, "image").and_then(Value::as_str) {
            let pin = image_pin(image);
            // The pin SHAPE is the fact; the image reference itself never
            // enters a packet (privacy: key identities and shapes only).
            em.derived(
                &cunit,
                "container.image.pin",
                &format!("{cpath}.image"),
                &format!("{cpath}.image (pin shape)"),
                pin,
            );
            match get(cm, "imagePullPolicy") {
                Some(v) => em.present(
                    &cunit,
                    "container.image-pull-policy",
                    &format!("{cpath}.imagePullPolicy"),
                    v,
                ),
                None => {
                    // Documented conditional default: latest/untagged images
                    // pull Always, everything else IfNotPresent — a format
                    // fact, exactly like GitLab's manual-job allow_failure.
                    let (default, platform_key) = if pin == "latest" {
                        ("Always", "imagePullPolicy (latest tag)")
                    } else {
                        ("IfNotPresent", "imagePullPolicy")
                    };
                    em.absent(
                        &cunit,
                        "container.image-pull-policy",
                        &format!("{cpath}.imagePullPolicy"),
                        platform_key,
                        default,
                    );
                }
            }
        }
    }
}

/// Parse a manifest file into documents. Docs parsed before a syntax error
/// are kept; the error marks the file unparseable (coverage, not failure).
pub(super) fn parse_docs(contents: &str) -> (Vec<Value>, bool) {
    let mut docs = Vec::new();
    for de in serde_yaml::Deserializer::from_str(contents) {
        match Value::deserialize(de) {
            Ok(v) => {
                if v.as_mapping().is_some() {
                    docs.push(v);
                }
            }
            Err(_) => return (docs, true),
        }
    }
    (docs, false)
}

/// Extract packets from a bare manifest file (possibly multi-doc). Values
/// resolve `as_authored`; decidably-absent keys resolve to the documented
/// platform default. `root` lets PDB coverage see the file's directory.
pub(super) fn retrieve_plain(
    root: Option<&Path>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    let mut out = Retrieved::default();
    // Template markers mean this is source for SOME renderer, not an
    // effective manifest — and templated text can still parse as YAML into
    // garbage values. Outside a chart no committed input can render it
    // honestly: an unsupported variant, sighted by identity only.
    if contents.contains("{{") {
        out.sightings.push(FormatSighting::declined(
            "kubernetes-templated".to_string(),
            1,
        ));
        return out;
    }
    let (docs, failed) = parse_docs(contents);
    if failed {
        out.unparseable = 1;
        if docs.is_empty() {
            return out;
        }
    }
    let set = directory_set(root, rel_path, &docs, failed);
    let oracle = PlainOracle { file: rel_path };
    let mut em = Emitter {
        file_anchor: rel_path,
        snapshot_id,
        oracle: &oracle,
        out: Vec::new(),
    };
    for doc in &docs {
        packets_from_doc(doc, &set, &mut em);
    }
    out.packets = em.out;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigPacket, Resolution};

    fn packets(yaml: &str) -> Retrieved {
        retrieve_plain(None, "k8s/deploy.yaml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    const DEPLOY: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: app
          image: registry.example.com/web:v1.2.3
          resources:
            limits:
              cpu: 500m
              memory: 256Mi
";

    #[test]
    fn explicit_replicas_resolve_as_authored_with_explicit_provenance() {
        let got = packets(DEPLOY);
        let p = find(&got, "deployment:web", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("3"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(p.provenance[0].file, "k8s/deploy.yaml");
        assert_eq!(p.provenance[0].key_path, "spec.replicas");
        assert_eq!(p.provenance[0].role, "explicit");
        assert_eq!(p.format, "kubernetes");
    }

    #[test]
    fn absent_replicas_resolve_the_documented_default_of_one() {
        let got = packets(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers: []\n",
        );
        let p = find(&got, "deployment:web", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("1"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
        assert_eq!(p.provenance[1].file, "");
    }

    #[test]
    fn limits_present_and_requests_decidably_absent() {
        let got = packets(DEPLOY);
        let cpu = find(
            &got,
            "container:deployment/web/app",
            "container.resources.limits.cpu",
        );
        assert_eq!(cpu.resolved_value.as_deref(), Some("500m"));
        assert_eq!(cpu.resolution, Resolution::AsAuthored);
        assert!(cpu.provenance[0]
            .key_path
            .contains("containers[app].resources.limits.cpu"));

        let req = find(
            &got,
            "container:deployment/web/app",
            "container.resources.requests.cpu",
        );
        assert_eq!(req.resolved_value.as_deref(), Some("none"));
        assert_eq!(req.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn probes_render_as_json_when_present_and_none_when_absent() {
        let yaml = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: web:v1
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
";
        let got = packets(yaml);
        let live = find(
            &got,
            "container:deployment/web/app",
            "container.liveness-probe",
        );
        assert_eq!(live.resolution, Resolution::AsAuthored);
        assert!(
            live.resolved_value.as_deref().unwrap().contains("/healthz"),
            "structured probes render compactly: {:?}",
            live.resolved_value
        );
        let ready = find(
            &got,
            "container:deployment/web/app",
            "container.readiness-probe",
        );
        assert_eq!(ready.resolved_value.as_deref(), Some("none"));
        assert_eq!(ready.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn a_liveness_http_get_path_is_carried_as_its_own_key() {
        let yaml = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: app
          image: web:v1
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
          readinessProbe:
            httpGet:
              path: /readyz
              port: 8080
        - name: sidecar
          image: proxy:v1
          livenessProbe:
            exec:
              command: [\"true\"]
";
        let got = packets(yaml);
        let path = find(
            &got,
            "container:deployment/web/app",
            LIVENESS_HTTP_GET_PATH_KEY,
        );
        assert_eq!(path.resolved_value.as_deref(), Some("/healthz"));
        assert_eq!(path.resolution, Resolution::AsAuthored);
        // Only the liveness probe's path, and only when the probe is an
        // httpGet: an exec probe has no handler to join to.
        let carried: Vec<&str> = got
            .packets
            .iter()
            .filter(|p| p.key == LIVENESS_HTTP_GET_PATH_KEY)
            .map(|p| p.unit.as_str())
            .collect();
        assert_eq!(carried, vec!["container:deployment/web/app"]);
    }

    #[test]
    fn image_pin_shapes_classify_digest_tag_and_latest() {
        assert_eq!(image_pin("web@sha256:abcd"), "digest");
        assert_eq!(image_pin("registry.io/team/web:v1.2.3"), "tag");
        assert_eq!(image_pin("web:latest"), "latest");
        assert_eq!(image_pin("web"), "latest");
        assert_eq!(
            image_pin("registry.io:5000/team/web"),
            "latest",
            "a registry port is not a tag"
        );
        assert_eq!(image_pin("registry.io:5000/team/web:v2"), "tag");
    }

    #[test]
    fn image_pin_packet_carries_the_shape_never_the_reference() {
        let got = packets(DEPLOY);
        let p = find(&got, "container:deployment/web/app", "container.image.pin");
        assert_eq!(p.resolved_value.as_deref(), Some("tag"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        for packet in &got.packets {
            assert!(
                !format!("{packet:?}").contains("registry.example.com"),
                "the image reference must never enter a packet: {packet:?}"
            );
        }
    }

    #[test]
    fn pull_policy_defaults_follow_the_documented_latest_rule() {
        let yaml = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: pinned
          image: web:v1
        - name: floating
          image: web:latest
        - name: forced
          image: web:latest
          imagePullPolicy: Never
";
        let got = packets(yaml);
        let pinned = find(
            &got,
            "container:deployment/web/pinned",
            "container.image-pull-policy",
        );
        assert_eq!(pinned.resolved_value.as_deref(), Some("IfNotPresent"));
        assert_eq!(pinned.resolution, Resolution::PlatformDefault);
        let floating = find(
            &got,
            "container:deployment/web/floating",
            "container.image-pull-policy",
        );
        assert_eq!(floating.resolved_value.as_deref(), Some("Always"));
        assert!(floating.provenance[1].key_path.contains("latest"));
        let forced = find(
            &got,
            "container:deployment/web/forced",
            "container.image-pull-policy",
        );
        assert_eq!(forced.resolved_value.as_deref(), Some("Never"));
        assert_eq!(forced.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn strategy_defaults_to_rolling_update_with_25_percent_bounds() {
        let got = packets(DEPLOY);
        let t = find(&got, "deployment:web", "workload.strategy.type");
        assert_eq!(t.resolved_value.as_deref(), Some("RollingUpdate"));
        assert_eq!(t.resolution, Resolution::PlatformDefault);
        let surge = find(&got, "deployment:web", "workload.strategy.max-surge");
        assert_eq!(surge.resolved_value.as_deref(), Some("25%"));
        let unavail = find(&got, "deployment:web", "workload.strategy.max-unavailable");
        assert_eq!(unavail.resolved_value.as_deref(), Some("25%"));
    }

    #[test]
    fn recreate_strategy_emits_no_rolling_update_bounds() {
        let yaml = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  strategy:
    type: Recreate
  template:
    spec:
      containers: []
";
        let got = packets(yaml);
        let t = find(&got, "deployment:web", "workload.strategy.type");
        assert_eq!(t.resolved_value.as_deref(), Some("Recreate"));
        assert_eq!(t.resolution, Resolution::AsAuthored);
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key.starts_with("workload.strategy.max")),
            "Recreate has no surge/unavailable: {:?}",
            got.packets
        );
    }

    #[test]
    fn pod_level_defaults_are_documented_values() {
        let got = packets(DEPLOY);
        let tgps = find(
            &got,
            "deployment:web",
            "pod.termination-grace-period-seconds",
        );
        assert_eq!(tgps.resolved_value.as_deref(), Some("30"));
        assert_eq!(tgps.resolution, Resolution::PlatformDefault);
        let prio = find(&got, "deployment:web", "pod.priority-class-name");
        assert_eq!(prio.resolved_value.as_deref(), Some("none"));
        let sec = find(&got, "deployment:web", "pod.security-context");
        assert_eq!(sec.resolved_value.as_deref(), Some("none"));
    }

    #[test]
    fn pdb_emits_authored_bounds_only() {
        let yaml = "\
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: web
spec:
  minAvailable: 2
  selector: {}
";
        let got = packets(yaml);
        let p = find(&got, "pdb:web", "pdb.min-available");
        assert_eq!(p.resolved_value.as_deref(), Some("2"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert!(
            !got.packets.iter().any(|p| p.key == "pdb.max-unavailable"),
            "exactly-one semantics: the other bound is not a default"
        );
    }

    #[test]
    fn hpa_min_defaults_to_one_and_max_is_authored() {
        let yaml = "\
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: web
spec:
  maxReplicas: 10
";
        let got = packets(yaml);
        let min = find(&got, "hpa:web", "hpa.min-replicas");
        assert_eq!(min.resolved_value.as_deref(), Some("1"));
        assert_eq!(min.resolution, Resolution::PlatformDefault);
        let max = find(&got, "hpa:web", "hpa.max-replicas");
        assert_eq!(max.resolved_value.as_deref(), Some("10"));
        assert_eq!(max.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn cronjob_pod_facts_resolve_through_the_job_template() {
        let yaml = "\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  schedule: '0 3 * * *'
  jobTemplate:
    spec:
      template:
        spec:
          terminationGracePeriodSeconds: 120
          containers:
            - name: worker
              image: backup@sha256:abcd
";
        let got = packets(yaml);
        let tgps = find(
            &got,
            "cronjob:backup",
            "pod.termination-grace-period-seconds",
        );
        assert_eq!(tgps.resolved_value.as_deref(), Some("120"));
        assert!(tgps.provenance[0]
            .key_path
            .starts_with("spec.jobTemplate.spec.template.spec"));
        let pin = find(
            &got,
            "container:cronjob/backup/worker",
            "container.image.pin",
        );
        assert_eq!(pin.resolved_value.as_deref(), Some("digest"));
        assert!(
            !got.packets.iter().any(|p| p.key == "workload.replicas"),
            "a CronJob has no replicas"
        );
    }

    #[test]
    fn multi_doc_files_emit_for_every_document() {
        let yaml = format!(
            "{DEPLOY}---\napiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: web\nspec:\n  minAvailable: 1\n"
        );
        let got = packets(&yaml);
        assert!(got.packets.iter().any(|p| p.unit == "deployment:web"));
        assert!(got.packets.iter().any(|p| p.unit == "pdb:web"));
        assert_eq!(got.unparseable, 0);
    }

    #[test]
    fn non_inventoried_kinds_emit_nothing() {
        let got =
            packets("apiVersion: v1\nkind: Service\nmetadata:\n  name: web\nspec:\n  ports: []\n");
        assert!(got.packets.is_empty(), "{:?}", got.packets);
        assert_eq!(
            got.unparseable, 0,
            "a Service is valid, just not inventoried"
        );
    }

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("kind: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
        assert!(got.sightings.is_empty());
    }

    #[test]
    fn templated_manifests_outside_a_chart_are_sighted_not_guessed() {
        let got = packets(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {{ include \"x\" . }}\nspec: {}\n",
        );
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0);
        assert_eq!(
            got.sightings,
            vec![crate::FormatSighting::declined("kubernetes-templated", 1)]
        );
    }

    // --- workload.pdb-coverage, pod.anti-affinity, pod.topology-spread-constraints ---

    const LABELED: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
        tier: frontend
    spec:
      containers:
        - name: app
          image: registry.example.com/web:v1.2.3
";

    fn pdb(selector: &str) -> String {
        format!(
            "apiVersion: policy/v1\nkind: PodDisruptionBudget\nmetadata:\n  name: web-pdb\nspec:\n  minAvailable: 1\n{selector}"
        )
    }

    const SELECTS_WEB: &str = "  selector:\n    matchLabels:\n      app: web\n";

    /// Write `files` under `k8s/` of a fresh root and retrieve `k8s/deploy.yaml`.
    fn in_dir(files: &[(&str, &str)]) -> Retrieved {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("k8s")).unwrap();
        for (name, contents) in files {
            std::fs::write(dir.path().join("k8s").join(name), contents).unwrap();
        }
        let own = files
            .iter()
            .find(|(name, _)| *name == "deploy.yaml")
            .expect("the fixture names deploy.yaml")
            .1;
        retrieve_plain(Some(dir.path()), "k8s/deploy.yaml", own, "snap")
    }

    fn coverage(got: &Retrieved) -> Option<&ConfigPacket> {
        got.packets
            .iter()
            .find(|p| p.key == "workload.pdb-coverage")
    }

    #[test]
    fn a_pdb_in_the_same_file_that_selects_the_pod_labels_covers_the_workload() {
        let yaml = format!("{LABELED}---\n{}", pdb(SELECTS_WEB));
        let got = in_dir(&[("deploy.yaml", &yaml)]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("covered"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(p.provenance[0].file, "k8s/deploy.yaml");
        assert_eq!(
            p.provenance[0].key_path,
            "PodDisruptionBudget/web-pdb spec.selector"
        );
        assert_eq!(p.provenance[0].role, "explicit");
    }

    #[test]
    fn a_pdb_in_a_sibling_file_covers_the_workload_and_the_chain_names_that_file() {
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yml", &pdb(SELECTS_WEB))]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("covered"));
        assert_eq!(p.provenance[0].file, "k8s/pdb.yml");
    }

    #[test]
    fn a_workload_no_pdb_in_the_directory_selects_resolves_to_none() {
        let got = in_dir(&[("deploy.yaml", LABELED)]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance[0].file, "k8s/deploy.yaml");
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
    }

    #[test]
    fn a_pdb_whose_selector_misses_the_pod_labels_does_not_cover() {
        let other = pdb("  selector:\n    matchLabels:\n      app: api\n");
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &other)]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        // Every label of the selector must match, not any one of them.
        let partial = pdb("  selector:\n    matchLabels:\n      app: web\n      tier: backend\n");
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &partial)]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
    }

    #[test]
    fn match_expressions_are_evaluated_against_the_pod_labels() {
        for (expr, want) in [
            ("{key: app, operator: In, values: [web, api]}", "covered"),
            ("{key: app, operator: In, values: [api]}", "none"),
            ("{key: app, operator: NotIn, values: [api]}", "covered"),
            ("{key: tier, operator: Exists}", "covered"),
            ("{key: canary, operator: Exists}", "none"),
            ("{key: canary, operator: DoesNotExist}", "covered"),
            ("{key: tier, operator: DoesNotExist}", "none"),
        ] {
            let sel = pdb(&format!(
                "  selector:\n    matchExpressions:\n      - {expr}\n"
            ));
            let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &sel)]);
            let p = find(&got, "deployment:web", "workload.pdb-coverage");
            assert_eq!(p.resolved_value.as_deref(), Some(want), "{expr}");
        }
    }

    #[test]
    fn a_selector_the_matcher_cannot_evaluate_abstains() {
        let sel = pdb(
            "  selector:\n    matchExpressions:\n      - {key: app, operator: Gt, values: ['1']}\n",
        );
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &sel)]);
        assert!(coverage(&got).is_none(), "{:?}", coverage(&got));
        // The other facts of the workload are not held back by the abstention.
        find(&got, "deployment:web", "workload.replicas");
    }

    #[test]
    fn an_empty_selector_selects_every_pod_under_policy_v1_only() {
        let got = in_dir(&[
            ("deploy.yaml", LABELED),
            ("pdb.yaml", &pdb("  selector: {}\n")),
        ]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("covered"));
        let beta = pdb("  selector: {}\n").replace("policy/v1", "policy/v1beta1");
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &beta)]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        // No selector at all selects nothing.
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &pdb(""))]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
    }

    #[test]
    fn a_pdb_in_another_namespace_does_not_cover_and_a_half_stated_one_abstains() {
        let namespaced = |ns: &str| {
            pdb(SELECTS_WEB).replace(
                "  name: web-pdb\n",
                &format!("  name: web-pdb\n  namespace: {ns}\n"),
            )
        };
        let deploy_in = |ns: &str| {
            LABELED.replacen(
                "  name: web\n",
                &format!("  name: web\n  namespace: {ns}\n"),
                1,
            )
        };
        let got = in_dir(&[
            ("deploy.yaml", &deploy_in("prod")),
            ("pdb.yaml", &namespaced("prod")),
        ]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("covered"));
        let got = in_dir(&[
            ("deploy.yaml", &deploy_in("prod")),
            ("pdb.yaml", &namespaced("staging")),
        ]);
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        // Only one side names a namespace: `kubectl apply -n` decides, not the repo.
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &namespaced("prod"))]);
        assert!(coverage(&got).is_none(), "{:?}", coverage(&got));
    }

    #[test]
    fn a_sibling_pdb_that_cannot_be_read_abstains_rather_than_reporting_none() {
        let templated = pdb("  selector:\n    matchLabels:\n      app: {{ .Values.app }}\n");
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &templated)]);
        assert!(coverage(&got).is_none(), "templated: {:?}", coverage(&got));
        let broken = format!(
            "{}---\nkind: [unclosed\n  - {{",
            pdb("  selector:\n    matchLabels:\n      app: api\n")
        );
        let got = in_dir(&[("deploy.yaml", LABELED), ("pdb.yaml", &broken)]);
        assert!(
            coverage(&got).is_none(),
            "unparseable: {:?}",
            coverage(&got)
        );
    }

    #[test]
    fn without_a_root_the_directory_is_unknown_so_only_a_same_file_pdb_decides() {
        let got = packets(LABELED);
        assert!(coverage(&got).is_none(), "{:?}", coverage(&got));
        let got = packets(&format!("{LABELED}---\n{}", pdb(SELECTS_WEB)));
        let p = find(&got, "deployment:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("covered"));
    }

    #[test]
    fn anti_affinity_and_topology_spread_resolve_as_authored_or_to_none() {
        let got = packets(LABELED);
        for key in ["pod.anti-affinity", "pod.topology-spread-constraints"] {
            let p = find(&got, "deployment:web", key);
            assert_eq!(p.resolved_value.as_deref(), Some("none"), "{key}");
            assert_eq!(p.resolution, Resolution::PlatformDefault, "{key}");
        }
        let spread = LABELED.replace(
            "    spec:\n      containers:",
            "    spec:\n      affinity:\n        podAntiAffinity:\n          requiredDuringSchedulingIgnoredDuringExecution:\n            - topologyKey: kubernetes.io/hostname\n        nodeAffinity: {}\n      topologySpreadConstraints:\n        - maxSkew: 1\n          topologyKey: topology.kubernetes.io/zone\n          whenUnsatisfiable: ScheduleAnyway\n      containers:",
        );
        let got = packets(&spread);
        let anti = find(&got, "deployment:web", "pod.anti-affinity");
        assert_eq!(anti.resolution, Resolution::AsAuthored);
        assert_eq!(
            anti.provenance[0].key_path,
            "spec.template.spec.affinity.podAntiAffinity"
        );
        let tsc = find(&got, "deployment:web", "pod.topology-spread-constraints");
        assert_eq!(tsc.resolution, Resolution::AsAuthored);
        assert!(
            tsc.resolved_value.as_deref().unwrap().contains("maxSkew"),
            "{:?}",
            tsc.resolved_value
        );
    }

    #[test]
    fn an_empty_spread_or_a_node_affinity_alone_is_not_a_placement_rule() {
        let empty = LABELED.replace(
            "    spec:\n      containers:",
            "    spec:\n      affinity:\n        nodeAffinity: {}\n        podAntiAffinity: {}\n      topologySpreadConstraints: []\n      containers:",
        );
        let got = packets(&empty);
        for key in ["pod.anti-affinity", "pod.topology-spread-constraints"] {
            let p = find(&got, "deployment:web", key);
            assert_eq!(p.resolved_value.as_deref(), Some("none"), "{key}");
            assert_eq!(p.resolution, Resolution::PlatformDefault, "{key}");
        }
    }

    #[test]
    fn only_replicated_workloads_carry_the_disruption_and_placement_keys() {
        let daemon = LABELED
            .replace("kind: Deployment", "kind: DaemonSet")
            .replace("  replicas: 3\n", "");
        let got = in_dir(&[("deploy.yaml", &daemon)]);
        find(&got, "daemonset:web", "pod.security-context");
        for key in [
            "workload.pdb-coverage",
            "pod.anti-affinity",
            "pod.topology-spread-constraints",
        ] {
            assert!(!got.packets.iter().any(|p| p.key == key), "{key}");
        }
        let sts = LABELED.replace("kind: Deployment", "kind: StatefulSet");
        let got = in_dir(&[("deploy.yaml", &sts)]);
        let p = find(&got, "statefulset:web", "workload.pdb-coverage");
        assert_eq!(p.resolved_value.as_deref(), Some("none"));
        find(&got, "statefulset:web", "pod.anti-affinity");
    }
}
