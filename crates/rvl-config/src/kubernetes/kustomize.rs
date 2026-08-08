//! Bounded, deterministic kustomize-style resolution.
//!
//! A `kustomization.yaml` is a config UNIT: its resource tree (files, base
//! directories, nested kustomizations) resolves to effective documents with
//! strategic-merge patches and the `images`/`replicas` transformers applied.
//! Each document carries its LAYER history — origin file, every patch and
//! transformer that touched it — which becomes the packet's provenance
//! chain. Identity is namePrefix-agnostic: resources and patches match by
//! their AUTHORED kind + name, so the same unit keeps the same identity
//! across overlays.
//!
//! Bounded on purpose: depth-capped recursion with cycle detection, no path
//! ever escapes the repo root, no remote bases. What the bounded merge
//! cannot resolve honestly — JSON6902 op lists, `$patch`/`$retainKeys`
//! directives, remote or missing references — drops the affected resource
//! and records a `kubernetes-kustomize-unresolved` sighting: an abstention,
//! never a guess.

use super::manifest::{self, get, lookup, Emitter, ProvenanceOracle};
use crate::{FormatSighting, ProvenanceStep, Resolution, Retrieved};
use serde_yaml::{Mapping, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_DEPTH: usize = 16;
const UNRESOLVED: &str = "kubernetes-kustomize-unresolved";

/// One stage of a resource's resolution history.
struct Layer {
    file: String,
    role: &'static str,
    doc: Value,
}

/// A resolved resource: the last layer's doc is effective.
struct Resource {
    layers: Vec<Layer>,
}

impl Resource {
    fn doc(&self) -> &Value {
        &self.layers.last().expect("at least the origin layer").doc
    }
    fn kind(&self) -> Option<&str> {
        self.doc()
            .as_mapping()
            .and_then(|m| get(m, "kind"))
            .and_then(Value::as_str)
    }
    fn name(&self) -> Option<&str> {
        manifest::dig(self.doc(), &["metadata", "name"]).and_then(Value::as_str)
    }
}

/// Lexically join `entry` onto `dir_rel`, normalizing `.`/`..`; `None` when
/// the result would escape the repo root.
fn norm_join(dir_rel: &str, entry: &str) -> Option<String> {
    let mut parts: Vec<&str> = if dir_rel.is_empty() {
        Vec::new()
    } else {
        dir_rel.split('/').collect()
    };
    for seg in entry.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

fn parent_dir(rel_path: &str) -> &str {
    rel_path.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

fn seq<'a>(m: &'a Mapping, key: &str) -> impl Iterator<Item = &'a Value> {
    get(m, key)
        .and_then(Value::as_sequence)
        .into_iter()
        .flatten()
}

fn str_entries<'a>(m: &'a Mapping, key: &str) -> impl Iterator<Item = &'a str> {
    seq(m, key).filter_map(Value::as_str)
}

/// Any `$`-prefixed key anywhere is a strategic-merge DIRECTIVE (`$patch:
/// delete`, `$retainKeys`, ...) the bounded merge does not implement.
fn has_directive(v: &Value) -> bool {
    match v {
        Value::Mapping(m) => m
            .iter()
            .any(|(k, val)| k.as_str().is_some_and(|s| s.starts_with('$')) || has_directive(val)),
        Value::Sequence(s) => s.iter().any(has_directive),
        _ => false,
    }
}

/// Strategic-merge two values: mappings merge per key (a null patch value
/// deletes), sequences of named mappings merge by `name`, everything else is
/// replaced by the patch.
fn smp_merge(base: &Value, patch: &Value) -> Value {
    match (base, patch) {
        (Value::Mapping(b), Value::Mapping(p)) => {
            let mut out = b.clone();
            for (k, pv) in p {
                if pv.is_null() {
                    out.remove(k);
                } else if let Some(bv) = b.get(k) {
                    *out.get_mut(k).unwrap() = smp_merge(bv, pv);
                } else {
                    out.insert(k.clone(), pv.clone());
                }
            }
            Value::Mapping(out)
        }
        (Value::Sequence(b), Value::Sequence(p)) => {
            let named = |v: &Value| {
                v.as_mapping()
                    .and_then(|m| get(m, "name"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            if !p.iter().all(|e| named(e).is_some()) || !b.iter().all(|e| named(e).is_some()) {
                return patch.clone();
            }
            let mut out = b.clone();
            for pe in p {
                let pname = named(pe).expect("checked above");
                match out
                    .iter_mut()
                    .find(|be| named(be).as_deref() == Some(&pname))
                {
                    Some(be) => *be = smp_merge(be, pe),
                    None => out.push(pe.clone()),
                }
            }
            Value::Sequence(out)
        }
        _ => patch.clone(),
    }
}

/// A patch's target identity: kind + name, from an explicit `target:` block
/// or from the patch document itself. `*` names match every resource of the
/// kind (conservative: what a wildcard touches, a wildcard drops).
struct Target {
    kind: Option<String>,
    name: Option<String>,
}

impl Target {
    fn from_mapping(m: Option<&Mapping>) -> Self {
        let field = |k: &str| {
            m.and_then(|m| get(m, k))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Target {
            kind: field("kind"),
            name: field("name"),
        }
    }
    fn from_doc(doc: &Value) -> Self {
        Target {
            kind: doc
                .as_mapping()
                .and_then(|m| get(m, "kind"))
                .and_then(Value::as_str)
                .map(str::to_string),
            name: manifest::dig(doc, &["metadata", "name"])
                .and_then(Value::as_str)
                .map(str::to_string),
        }
    }
    fn matches(&self, r: &Resource) -> bool {
        let kind_ok = match self.kind.as_deref() {
            None | Some("*") => true,
            Some(k) => r.kind() == Some(k),
        };
        let name_ok = match self.name.as_deref() {
            None | Some("*") => true,
            Some(n) => r.name() == Some(n),
        };
        kind_ok && name_ok
    }
}

struct Resolver<'a> {
    root: &'a Path,
    sightings: BTreeMap<String, usize>,
    unparseable: usize,
    /// Kustomization directories on the current resolution stack.
    visiting: BTreeSet<String>,
}

impl Resolver<'_> {
    fn sight(&mut self, format: &str) {
        *self.sightings.entry(format.to_string()).or_insert(0) += 1;
    }

    /// Resolve one kustomization document rooted at `dir_rel`.
    fn resolve(
        &mut self,
        dir_rel: &str,
        kdoc: &Mapping,
        krel: &str,
        depth: usize,
    ) -> Vec<Resource> {
        if depth == 0 {
            self.sight(UNRESOLVED);
            return Vec::new();
        }
        let mut resources: Vec<Resource> = Vec::new();

        // resources: (and the legacy bases:) — files, or directories holding
        // a nested kustomization.
        let entries = str_entries(kdoc, "resources").chain(str_entries(kdoc, "bases"));
        for entry in entries {
            if entry.contains("://") {
                // Remote bases are a fetch the scan path never performs.
                self.sight(UNRESOLVED);
                continue;
            }
            let Some(target) = norm_join(dir_rel, entry) else {
                self.sight(UNRESOLVED);
                continue;
            };
            let path = self.root.join(&target);
            if path.is_dir() {
                let Some((nested_rel, nested_doc)) = self.load_kustomization(&target) else {
                    self.sight(UNRESOLVED);
                    continue;
                };
                if !self.visiting.insert(target.clone()) {
                    self.sight(UNRESOLVED);
                    continue;
                }
                let nested = self.resolve(&target, &nested_doc, &nested_rel, depth - 1);
                self.visiting.remove(&target);
                resources.extend(nested);
            } else {
                match std::fs::read_to_string(&path) {
                    Ok(contents) => {
                        let (docs, failed) = manifest::parse_docs(&contents);
                        if failed {
                            self.unparseable += 1;
                        }
                        resources.extend(docs.into_iter().map(|doc| Resource {
                            layers: vec![Layer {
                                file: target.clone(),
                                role: "explicit",
                                doc,
                            }],
                        }));
                    }
                    Err(_) => self.sight(UNRESOLVED),
                }
            }
        }

        // patchesStrategicMerge: file paths, or inline multi-line documents.
        for entry in str_entries(kdoc, "patchesStrategicMerge") {
            let (text, pfile) = if entry.contains('\n') {
                (entry.to_string(), krel.to_string())
            } else {
                let Some(target) = norm_join(dir_rel, entry) else {
                    self.sight(UNRESOLVED);
                    continue;
                };
                match std::fs::read_to_string(self.root.join(&target)) {
                    Ok(t) => (t, target),
                    Err(_) => {
                        self.sight(UNRESOLVED);
                        continue;
                    }
                }
            };
            let (docs, failed) = manifest::parse_docs(&text);
            if failed {
                self.unparseable += 1;
            }
            for patch in docs {
                self.apply_smp(&mut resources, &patch, Target::from_doc(&patch), &pfile);
            }
        }

        // patches: strategic-merge (mapping docs) or JSON6902 (op lists).
        // 6902 ops are a grammar the bounded merge does not evaluate: the
        // touched resources drop with a sighting.
        for entry in seq(kdoc, "patches") {
            let Some(em) = entry.as_mapping() else {
                continue;
            };
            let target = Target::from_mapping(get(em, "target").and_then(Value::as_mapping));
            let (text, pfile) = match (get(em, "path").and_then(Value::as_str), get(em, "patch")) {
                (Some(p), _) => {
                    let Some(t) = norm_join(dir_rel, p) else {
                        self.sight(UNRESOLVED);
                        continue;
                    };
                    match std::fs::read_to_string(self.root.join(&t)) {
                        Ok(text) => (text, t),
                        Err(_) => {
                            self.sight(UNRESOLVED);
                            continue;
                        }
                    }
                }
                (None, Some(inline)) => match inline.as_str() {
                    Some(s) => (s.to_string(), krel.to_string()),
                    None => continue,
                },
                (None, None) => continue,
            };
            match serde_yaml::from_str::<Value>(&text) {
                Ok(Value::Sequence(_)) => self.drop_matching(&mut resources, &target),
                Ok(doc @ Value::Mapping(_)) => {
                    // An explicit target wins over the patch doc's identity.
                    let t = if get(em, "target").is_some() {
                        target
                    } else {
                        Target::from_doc(&doc)
                    };
                    self.apply_smp(&mut resources, &doc, t, &pfile);
                }
                _ => self.unparseable += 1,
            }
        }
        for _ in seq(kdoc, "patchesJson6902") {
            // Legacy 6902 field: same abstention. Without evaluating targets
            // we cannot say which resource is still honest — drop them all.
            self.sight(UNRESOLVED);
            resources.clear();
        }

        // Transformers are a layer authored in the kustomization itself.
        self.apply_images(&mut resources, kdoc, krel);
        self.apply_replicas(&mut resources, kdoc, krel);

        resources
    }

    fn load_kustomization(&mut self, dir_rel: &str) -> Option<(String, Mapping)> {
        for name in ["kustomization.yaml", "kustomization.yml"] {
            let rel = if dir_rel.is_empty() {
                name.to_string()
            } else {
                format!("{dir_rel}/{name}")
            };
            if let Ok(contents) = std::fs::read_to_string(self.root.join(&rel)) {
                match serde_yaml::from_str::<Value>(&contents) {
                    Ok(Value::Mapping(m)) => return Some((rel, m)),
                    _ => {
                        self.unparseable += 1;
                        return None;
                    }
                }
            }
        }
        None
    }

    fn drop_matching(&mut self, resources: &mut Vec<Resource>, target: &Target) {
        let before = resources.len();
        resources.retain(|r| !target.matches(r));
        let dropped = before - resources.len();
        for _ in 0..dropped {
            self.sight(UNRESOLVED);
        }
        if dropped == 0 {
            // The patch aims at something we never resolved; say so anyway.
            self.sight(UNRESOLVED);
        }
    }

    fn apply_smp(
        &mut self,
        resources: &mut Vec<Resource>,
        patch: &Value,
        target: Target,
        pfile: &str,
    ) {
        if has_directive(patch) {
            self.drop_matching(resources, &target);
            return;
        }
        for r in resources.iter_mut() {
            if target.matches(r) {
                let merged = smp_merge(r.doc(), patch);
                r.layers.push(Layer {
                    file: pfile.to_string(),
                    role: "patch",
                    doc: merged,
                });
            }
        }
    }

    /// The `images:` transformer: retag/redigest matching container images.
    fn apply_images(&mut self, resources: &mut [Resource], kdoc: &Mapping, krel: &str) {
        let entries: Vec<(&Mapping, &str)> = seq(kdoc, "images")
            .filter_map(Value::as_mapping)
            .filter_map(|m| get(m, "name").and_then(Value::as_str).map(|n| (m, n)))
            .collect();
        if entries.is_empty() {
            return;
        }
        for r in resources.iter_mut() {
            let mut doc = r.doc().clone();
            let mut changed = false;
            for_each_container_image(&mut doc, &mut |image| {
                for (m, name) in &entries {
                    if image_name(image) != *name {
                        continue;
                    }
                    let new_name = get(m, "newName")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| image_name(image));
                    let suffix = if let Some(d) = get(m, "digest").and_then(Value::as_str) {
                        format!("@{d}")
                    } else if let Some(t) = get(m, "newTag").and_then(Value::as_str) {
                        format!(":{t}")
                    } else {
                        image[image_name(image).len()..].to_string()
                    };
                    let new = format!("{new_name}{suffix}");
                    if new != *image {
                        *image = new;
                        changed = true;
                    }
                }
            });
            if changed {
                r.layers.push(Layer {
                    file: krel.to_string(),
                    role: "transformer",
                    doc,
                });
            }
        }
    }

    /// The `replicas:` transformer: set spec.replicas on named workloads.
    fn apply_replicas(&mut self, resources: &mut [Resource], kdoc: &Mapping, krel: &str) {
        for entry in seq(kdoc, "replicas") {
            let Some(m) = entry.as_mapping() else {
                continue;
            };
            let Some(name) = get(m, "name").and_then(Value::as_str) else {
                continue;
            };
            let Some(count) = get(m, "count") else {
                continue;
            };
            for r in resources.iter_mut() {
                if r.name() != Some(name)
                    || !matches!(
                        r.kind(),
                        Some("Deployment") | Some("StatefulSet") | Some("ReplicaSet")
                    )
                {
                    continue;
                }
                let mut doc = r.doc().clone();
                if let Some(spec) = doc
                    .as_mapping_mut()
                    .and_then(|m| m.get_mut(Value::String("spec".into())))
                    .and_then(Value::as_mapping_mut)
                {
                    spec.insert(Value::String("replicas".into()), count.clone());
                    r.layers.push(Layer {
                        file: krel.to_string(),
                        role: "transformer",
                        doc,
                    });
                }
            }
        }
    }
}

/// The name part of an image reference (before any tag or digest).
fn image_name(image: &str) -> &str {
    if let Some((name, _)) = image.split_once('@') {
        return name;
    }
    let cut = image.rfind('/').map(|i| i + 1).unwrap_or(0);
    match image[cut..].rfind(':') {
        Some(i) => &image[..cut + i],
        None => image,
    }
}

/// Visit every `spec...containers[*].image` of a workload doc mutably.
fn for_each_container_image(doc: &mut Value, f: &mut dyn FnMut(&mut String)) {
    let Some(kind) = doc
        .as_mapping()
        .and_then(|m| get(m, "kind"))
        .and_then(Value::as_str)
    else {
        return;
    };
    let Some((_, pod_path)) = manifest::workload_shape(kind) else {
        return;
    };
    let mut cur = match doc
        .as_mapping_mut()
        .and_then(|m| m.get_mut(Value::String("spec".into())))
    {
        Some(v) => v,
        None => return,
    };
    for segment in pod_path {
        cur = match cur
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String((*segment).to_string())))
        {
            Some(v) => v,
            None => return,
        };
    }
    let Some(containers) = cur
        .as_mapping_mut()
        .and_then(|m| m.get_mut(Value::String("containers".into())))
        .and_then(Value::as_sequence_mut)
    else {
        return;
    };
    for c in containers {
        if let Some(Value::String(s)) = c
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String("image".into())))
        {
            f(s);
        }
    }
}

/// The layer-history oracle: one provenance step per layer that first
/// supplied or changed the key's value.
struct KustomizeOracle<'a> {
    layers: &'a [Layer],
}

impl ProvenanceOracle for KustomizeOracle<'_> {
    fn present(&self, lookup_path: &str, display_path: &str) -> (Resolution, Vec<ProvenanceStep>) {
        let mut steps = Vec::new();
        let mut prev: Option<&Value> = None;
        for layer in self.layers {
            let cur = lookup(&layer.doc, lookup_path);
            let touched = match (prev, cur) {
                (None, Some(_)) => true,
                (Some(p), Some(c)) => p != c,
                _ => false,
            };
            if touched {
                steps.push(ProvenanceStep::new(&layer.file, display_path, layer.role));
            }
            if cur.is_some() {
                prev = cur;
            }
        }
        (Resolution::AsAuthored, steps)
    }

    fn absent(&self, display_path: &str, platform_key: &str) -> Vec<ProvenanceStep> {
        let origin = self.layers.first().map(|l| l.file.as_str()).unwrap_or("");
        vec![
            ProvenanceStep::new(origin, display_path, "absent"),
            ProvenanceStep::new("", platform_key, "platform-default"),
        ]
    }
}

/// Resolve one kustomization's resource tree into packets.
pub(crate) fn retrieve(
    root: &Path,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    let mut out = Retrieved::default();
    let kdoc = match serde_yaml::from_str::<Value>(contents) {
        Ok(Value::Mapping(m)) => m,
        _ => {
            out.unparseable = 1;
            return out;
        }
    };
    let dir_rel = parent_dir(rel_path).to_string();
    let mut resolver = Resolver {
        root,
        sightings: BTreeMap::new(),
        unparseable: 0,
        visiting: BTreeSet::from([dir_rel.clone()]),
    };
    let resources = resolver.resolve(&dir_rel, &kdoc, rel_path, MAX_DEPTH);
    for r in &resources {
        let oracle = KustomizeOracle { layers: &r.layers };
        let mut em = Emitter {
            file_anchor: rel_path,
            snapshot_id,
            oracle: &oracle,
            out: Vec::new(),
        };
        manifest::packets_from_doc(r.doc(), &mut em);
        out.packets.extend(em.out);
    }
    out.unparseable = resolver.unparseable;
    out.sightings = resolver
        .sightings
        .into_iter()
        .map(|(format, file_count)| FormatSighting::declined(format, file_count))
        .collect();
    out
}

/// Whether a same-directory kustomization references this manifest file (in
/// which case the kustomization visit owns its facts). Bounded to the same
/// directory: a kustomization elsewhere referencing the file directly leaves
/// the standalone facts in place — duplicate evidence, never lost evidence.
pub(crate) fn claimed_by_sibling(root: &Path, rel_path: &str) -> bool {
    let dir = parent_dir(rel_path);
    let Some(base) = rel_path.rsplit('/').next() else {
        return false;
    };
    for name in ["kustomization.yaml", "kustomization.yml"] {
        let krel = if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        };
        let Ok(contents) = std::fs::read_to_string(root.join(&krel)) else {
            continue;
        };
        let Ok(Value::Mapping(kdoc)) = serde_yaml::from_str::<Value>(&contents) else {
            continue;
        };
        let referenced = str_entries(&kdoc, "resources")
            .chain(str_entries(&kdoc, "bases"))
            .chain(str_entries(&kdoc, "patchesStrategicMerge"))
            .chain(
                seq(&kdoc, "patches")
                    .filter_map(Value::as_mapping)
                    .filter_map(|m| get(m, "path").and_then(Value::as_str)),
            )
            .any(|entry| entry == base);
        if referenced {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigPacket, Resolution};

    const BASE_DEPLOY: &str = "\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: app
          image: web:v1
          resources:
            limits:
              cpu: 100m
";

    fn write(root: &Path, rel: &str, contents: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contents).unwrap();
    }

    fn run(root: &Path, krel: &str) -> Retrieved {
        let contents = std::fs::read_to_string(root.join(krel)).unwrap();
        retrieve(root, krel, &contents, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    #[test]
    fn base_kustomization_resolves_its_resources_with_origin_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "k8s/base/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "k8s/base/kustomization.yaml",
            "resources:\n  - deployment.yaml\n",
        );
        let got = run(root, "k8s/base/kustomization.yaml");
        let p = find(&got, "deployment:web", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("1"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(
            p.file_path, "k8s/base/kustomization.yaml",
            "anchored to the unit"
        );
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(p.provenance[0].file, "k8s/base/deployment.yaml");
        assert_eq!(p.provenance[0].role, "explicit");
    }

    #[test]
    fn overlay_patch_resolves_the_effective_value_with_the_overlay_chain() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "k8s/base/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "k8s/base/kustomization.yaml",
            "resources:\n  - deployment.yaml\n",
        );
        write(
            root,
            "k8s/overlays/prod/patch.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  replicas: 5\n",
        );
        write(
            root,
            "k8s/overlays/prod/kustomization.yaml",
            "namePrefix: prod-\nresources:\n  - ../../base\npatchesStrategicMerge:\n  - patch.yaml\n",
        );
        let got = run(root, "k8s/overlays/prod/kustomization.yaml");
        // namePrefix-agnostic identity: the unit keeps the authored name.
        let p = find(&got, "deployment:web", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("5"), "the patch decides");
        assert_eq!(p.resolution, Resolution::AsAuthored);
        // The overlay chain: base supplied 1, the patch overrode with 5.
        assert_eq!(p.provenance.len(), 2, "chain: {:?}", p.provenance);
        assert_eq!(p.provenance[0].file, "k8s/base/deployment.yaml");
        assert_eq!(p.provenance[0].role, "explicit");
        assert_eq!(p.provenance[1].file, "k8s/overlays/prod/patch.yaml");
        assert_eq!(p.provenance[1].role, "patch");
        // Untouched keys keep single-step base provenance.
        let cpu = find(
            &got,
            "container:deployment/web/app",
            "container.resources.limits.cpu",
        );
        assert_eq!(cpu.resolved_value.as_deref(), Some("100m"));
        assert_eq!(cpu.provenance.len(), 1);
    }

    #[test]
    fn strategic_merge_patches_containers_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "app/patch.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          resources:\n            limits:\n              memory: 512Mi\n",
        );
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\npatchesStrategicMerge:\n  - patch.yaml\n",
        );
        let got = run(root, "app/kustomization.yaml");
        // The patch adds a memory limit; the base cpu limit survives the merge.
        let mem = find(
            &got,
            "container:deployment/web/app",
            "container.resources.limits.memory",
        );
        assert_eq!(mem.resolved_value.as_deref(), Some("512Mi"));
        assert_eq!(mem.provenance.last().unwrap().role, "patch");
        let cpu = find(
            &got,
            "container:deployment/web/app",
            "container.resources.limits.cpu",
        );
        assert_eq!(
            cpu.resolved_value.as_deref(),
            Some("100m"),
            "merge, not replace"
        );
    }

    #[test]
    fn images_transformer_resolves_the_effective_pin_shape() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\nimages:\n  - name: web\n    newTag: latest\n",
        );
        let got = run(root, "app/kustomization.yaml");
        let pin = find(&got, "container:deployment/web/app", "container.image.pin");
        assert_eq!(
            pin.resolved_value.as_deref(),
            Some("latest"),
            "the transformer decides"
        );
        assert_eq!(pin.provenance.last().unwrap().role, "transformer");
        assert_eq!(
            pin.provenance.last().unwrap().file,
            "app/kustomization.yaml"
        );
    }

    #[test]
    fn replicas_transformer_is_a_kustomization_layer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\nreplicas:\n  - name: web\n    count: 7\n",
        );
        let got = run(root, "app/kustomization.yaml");
        let p = find(&got, "deployment:web", "workload.replicas");
        assert_eq!(p.resolved_value.as_deref(), Some("7"));
        assert_eq!(p.provenance.last().unwrap().role, "transformer");
    }

    #[test]
    fn json6902_patches_abstain_with_a_sighting_never_a_guess() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "app/patch.yaml",
            "- op: replace\n  path: /spec/replicas\n  value: 9\n",
        );
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\npatches:\n  - path: patch.yaml\n    target:\n      kind: Deployment\n      name: web\n",
        );
        let got = run(root, "app/kustomization.yaml");
        assert!(
            !got.packets.iter().any(|p| p.unit == "deployment:web"),
            "a 6902-patched resource is not honestly resolvable here: {:?}",
            got.packets
        );
        assert!(
            got.sightings
                .iter()
                .any(|s| s.format == "kubernetes-kustomize-unresolved"),
            "sightings: {:?}",
            got.sightings
        );
    }

    #[test]
    fn dollar_patch_directives_abstain_with_a_sighting() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(
            root,
            "app/patch.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          $patch: delete\n",
        );
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\npatchesStrategicMerge:\n  - patch.yaml\n",
        );
        let got = run(root, "app/kustomization.yaml");
        assert!(!got.packets.iter().any(|p| p.unit.contains("web")));
        assert!(got
            .sightings
            .iter()
            .any(|s| s.format == "kubernetes-kustomize-unresolved"));
    }

    #[test]
    fn cycles_and_root_escapes_terminate_with_sightings() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "a/kustomization.yaml", "resources:\n  - ../b\n");
        write(root, "b/kustomization.yaml", "resources:\n  - ../a\n");
        let got = run(root, "a/kustomization.yaml");
        assert!(got.packets.is_empty());
        write(
            root,
            "c/kustomization.yaml",
            "resources:\n  - ../../outside.yaml\n",
        );
        let got = run(root, "c/kustomization.yaml");
        assert!(
            got.packets.is_empty(),
            "an escape above root resolves nothing"
        );
        assert!(!got.sightings.is_empty(), "the walk says WHY it abstained");
    }

    #[test]
    fn sibling_claims_cover_referenced_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, "app/deployment.yaml", BASE_DEPLOY);
        write(root, "app/unrelated.yaml", BASE_DEPLOY);
        write(
            root,
            "app/kustomization.yaml",
            "resources:\n  - deployment.yaml\n",
        );
        assert!(claimed_by_sibling(root, "app/deployment.yaml"));
        assert!(
            !claimed_by_sibling(root, "app/unrelated.yaml"),
            "unreferenced files keep their standalone facts"
        );
        assert!(!claimed_by_sibling(root, "elsewhere/deployment.yaml"));
    }
}
