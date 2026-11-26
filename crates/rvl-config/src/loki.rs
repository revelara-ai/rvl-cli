//! Loki configuration retriever: the log retention facts (RC-028) of a
//! Grafana Loki config.
//!
//! A Loki config is a YAML mapping that holds `limits_config` or
//! `table_manager`. It is found at any depth: a plain config file, a Helm
//! values block (`loki.limits_config`), or a ConfigMap or Secret string,
//! which is parsed again. Claimed by content ([`ConfigRetriever::matches_head`]):
//! a YAML file whose head has a `limits_config:` or `table_manager:` line.
//! A Kubernetes manifest the Kubernetes retriever would claim is claimed here
//! and handed to it as well, so its Kubernetes facts do not change.
//!
//! Emitted facts, one per section of each Loki config:
//!
//!   * `limits_config.retention_period-effective` — how long the compactor
//!     keeps logs: `limits_config.retention_period` as written when
//!     `compactor.retention_enabled` is `true` in the same mapping, else
//!     `never` (the compactor deletes nothing without the switch, which
//!     defaults to `false`). A period of `0` is `never` too.
//!   * `table_manager.retention_period-effective` — the same for the table
//!     manager: `table_manager.retention_period` when
//!     `table_manager.retention_deletes_enabled` is `true`, else `never`.
//!
//! A section with no `retention_period` emits nothing. A period that is not
//! a duration (`${RETENTION}`, a bare number other than `0`) or a switch that
//! is not a boolean is Unresolvable. The spec `duration_at_least` then
//! decides a period and abstains on `never`.
//!
//! The unit is `<kind>:<metadata.name>` for a Kubernetes object, else
//! `loki-config:<key path>` of the mapping (`loki-config:root` for a plain
//! file). What a spec must not judge is carried as
//! [`crate::UNDECIDED_PREFIX`] and why: every fact of a non-production file
//! or repository ([`crate::non_production`]) or of an eval fixture tree
//! ([`crate::log_retention`]); a Kubernetes object whose name is a
//! placeholder; and a plain config file with a compose file in its directory
//! or above it, which no Kubernetes or Helm file of the repository names and
//! no chart in its directory carries: a compose stack is a developer's
//! stack, not where logs are kept. A Helm-templated file is declined whole.

use crate::kubernetes::Kubernetes;
use crate::prometheus::helm_templated;
use crate::{
    render_value, ConfigPacket, ConfigRetriever, FormatSighting, ProvenanceStep, Resolution,
    Retrieved,
};
use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::collections::BTreeSet;
use std::path::Path;

pub struct Loki;

const FORMAT: &str = "loki";

/// The walk reads this much of a YAML file for a content claim; the same
/// head decides here whether the Kubernetes retriever would have claimed it.
const HEAD_BYTES: usize = 4096;

/// Files larger than this are not read for references: a generated bundle.
const MAX_REFERRER_BYTES: u64 = 4 << 20;

/// File stems of a compose stack (`docker-compose.yml`, `compose.yaml`) and
/// their variants (`docker-compose.dev.yml`, `docker-compose-loki.yaml`).
const COMPOSE_STEMS: &[&str] = &["docker-compose", "compose"];

/// One retention section of a Loki config: the section key, the switch that
/// makes its period delete data (a path from the config mapping), and the
/// packet key.
struct Section {
    section: &'static str,
    switch: [&'static str; 2],
    ledger: &'static str,
}

const SECTIONS: &[Section] = &[
    Section {
        section: "limits_config",
        switch: ["compactor", "retention_enabled"],
        ledger: "limits_config.retention_period-effective",
    },
    Section {
        section: "table_manager",
        switch: ["table_manager", "retention_deletes_enabled"],
        ledger: "table_manager.retention_period-effective",
    },
];

impl ConfigRetriever for Loki {
    fn format_id(&self) -> &'static str {
        FORMAT
    }

    /// Claimed by content only: a Loki config has no canonical name.
    fn matches(&self, _rel_path: &str) -> bool {
        false
    }

    /// A YAML file whose head has a section line at any indentation. A
    /// manifest is claimed only where the Kubernetes retriever would claim
    /// it, so a foreign resource keeps its product sighting.
    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        let is_yaml = rel_path.ends_with(".yml") || rel_path.ends_with(".yaml");
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        let section = head.lines().any(|l| {
            let l = l.trim_start();
            SECTIONS.iter().any(|s| {
                l.strip_prefix(s.section)
                    .is_some_and(|rest| rest.trim_start().starts_with(':'))
            })
        });
        let manifest = col0("apiVersion:") && col0("kind:");
        is_yaml && section && (!manifest || Kubernetes.matches_head(rel_path, head))
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let mut out = Retrieved::default();
        if manifest_head(rel_path, contents) {
            merge(
                &mut out,
                Kubernetes.retrieve(rel_path, contents, snapshot_id),
            );
        }
        let mut got = retrieve(rel_path, contents, snapshot_id);
        gate(None, &Carriers::default(), rel_path, &mut got);
        merge(&mut out, got);
        out
    }

    /// The walk's entry: one walk of the repository finds the compose
    /// stacks and the files that name a config.
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let carriers = Carriers::read(root, files);
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            if manifest_head(rel, contents) {
                merge(
                    &mut out,
                    Kubernetes.retrieve_with_root(root, rel, contents, snapshot_id),
                );
            }
            let mut got = retrieve(rel, contents, snapshot_id);
            gate(Some(root), &carriers, rel, &mut got);
            merge(&mut out, got);
        }
        out
    }
}

/// Whether the Kubernetes retriever claims this file by its head.
fn manifest_head(rel_path: &str, contents: &str) -> bool {
    let mut end = contents.len().min(HEAD_BYTES);
    while !contents.is_char_boundary(end) {
        end -= 1;
    }
    Kubernetes.matches_head(rel_path, &contents[..end])
}

fn merge(out: &mut Retrieved, got: Retrieved) {
    out.packets.extend(got.packets);
    out.predicates.extend(got.predicates);
    out.unparseable += got.unparseable;
    out.sightings.extend(got.sightings);
}

/// Undecide what a spec must not judge in the file at `rel_path`.
fn gate(root: Option<&Path>, carriers: &Carriers, rel_path: &str, out: &mut Retrieved) {
    crate::non_production::undecide_unit(root, rel_path, out);
    let why = if let Some(t) = crate::log_retention::eval_dir_token(rel_path) {
        Some(format!("eval fixture: {t}"))
    } else if carriers.compose_only(rel_path) {
        Some("loaded by a compose stack only".to_string())
    } else {
        None
    };
    for p in &mut out.packets {
        if let Some(why) = &why {
            crate::non_production::undecide(p, why);
        }
        let name = p.unit.split_once(':').map_or("", |(_, name)| name);
        if !p.unit.starts_with("loki-config:") && crate::non_production::placeholder_name(name) {
            crate::non_production::undecide(p, crate::non_production::PLACEHOLDER_REASON);
        }
    }
}

/// What the repository says about who loads a plain config file.
#[derive(Debug, Default)]
struct Carriers {
    /// Directories holding a compose file.
    compose_dirs: BTreeSet<String>,
    /// Directories holding a `Chart.yaml`.
    chart_dirs: BTreeSet<String>,
    /// File names a Kubernetes manifest, a kustomization or a chart template
    /// holds.
    named: BTreeSet<String>,
}

impl Carriers {
    /// One walk of `root`. Only the names of the claimed plain files near a
    /// compose stack are looked for, and only then are files read.
    fn read(root: &Path, files: &[(String, String)]) -> Self {
        let mut carriers = Carriers::default();
        let mut referrers = Vec::new();
        for entry in crate::walk(root).flatten() {
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let rel = crate::repo_relative(root, entry.path());
            let (dir, name) = rel.rsplit_once('/').unwrap_or(("", &rel));
            let (stem, ext) = name.rsplit_once('.').unwrap_or((name, ""));
            let yaml = matches!(ext, "yml" | "yaml");
            if yaml && compose_stem(stem) {
                carriers.compose_dirs.insert(dir.to_string());
            }
            if name == "Chart.yaml" || name == "Chart.yml" {
                carriers.chart_dirs.insert(dir.to_string());
            }
            let template = dir.split('/').any(|seg| seg == "templates");
            if (yaml || template)
                && entry
                    .metadata()
                    .is_ok_and(|m| m.len() <= MAX_REFERRER_BYTES)
            {
                referrers.push((rel.clone(), entry.into_path(), template));
            }
        }
        let wanted: BTreeSet<&str> = files
            .iter()
            .filter(|(rel, contents)| !manifest_head(rel, contents))
            .filter(|(rel, _)| carriers.near_compose(rel))
            .map(|(rel, _)| rel.rsplit('/').next().unwrap_or(rel))
            .collect();
        if wanted.is_empty() {
            return carriers;
        }
        for (rel, path, template) in referrers {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let col0 = |k: &str| text.lines().any(|l| l.starts_with(k));
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            let kustomization = matches!(name, "kustomization.yaml" | "kustomization.yml");
            if !(template || kustomization || (col0("apiVersion:") && col0("kind:"))) {
                continue;
            }
            for w in &wanted {
                if *w != name && text.contains(w) {
                    carriers.named.insert(w.to_string());
                }
            }
        }
        carriers
    }

    /// Whether a compose file sits in the directory of `rel_path` or above.
    fn near_compose(&self, rel_path: &str) -> bool {
        let mut dir = rel_path.rsplit_once('/').map_or("", |(dir, _)| dir);
        loop {
            if self.compose_dirs.contains(dir) {
                return true;
            }
            match dir.rsplit_once('/') {
                Some((up, _)) => dir = up,
                None if !dir.is_empty() => dir = "",
                None => return false,
            }
        }
    }

    /// Whether only a compose stack loads the plain config at `rel_path`.
    fn compose_only(&self, rel_path: &str) -> bool {
        let (dir, name) = rel_path.rsplit_once('/').unwrap_or(("", rel_path));
        self.near_compose(rel_path) && !self.chart_dirs.contains(dir) && !self.named.contains(name)
    }
}

/// Whether a YAML file stem names a compose stack.
fn compose_stem(stem: &str) -> bool {
    let stem = stem.to_ascii_lowercase();
    COMPOSE_STEMS.iter().any(|s| {
        stem == *s
            || stem
                .strip_prefix(s)
                .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('-'))
    })
}

/// The facts of one file, before any gate.
fn retrieve(rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
    let mut out = Retrieved::default();
    if helm_templated(contents) {
        out.sightings
            .push(FormatSighting::declined("loki-templated", 1));
        return out;
    }
    let docs: Result<Vec<Value>, _> = serde_yaml::Deserializer::from_str(contents)
        .map(Value::deserialize)
        .collect();
    let Ok(docs) = docs else {
        out.unparseable = 1;
        return out;
    };
    let mut seen = BTreeSet::new();
    for doc in &docs {
        let object = kubernetes_unit(doc);
        let mut configs = Vec::new();
        find_configs(doc, "", &mut configs);
        for (path, config) in configs {
            let unit = match &object {
                Some(unit) => unit.clone(),
                None if path.is_empty() => "loki-config:root".to_string(),
                None => format!("loki-config:{path}"),
            };
            for s in SECTIONS {
                if !seen.insert((unit.clone(), s.ledger)) {
                    continue;
                }
                if let Some((value, resolution, provenance)) =
                    section_fact(s, &config, &path, rel_path)
                {
                    out.packets.push(ConfigPacket {
                        snapshot_id: snapshot_id.to_string(),
                        format: FORMAT.to_string(),
                        file_path: rel_path.to_string(),
                        line: 0,
                        unit: unit.clone(),
                        key: crate::key_ledger::declared(FORMAT, s.ledger),
                        resolved_value: value,
                        resolution,
                        provenance,
                    });
                }
            }
        }
    }
    out
}

/// `<kind>:<metadata.name>` of a Kubernetes object document.
fn kubernetes_unit(doc: &Value) -> Option<String> {
    doc.get("apiVersion")?.as_str()?;
    let kind = doc.get("kind")?.as_str()?;
    let name = doc.get("metadata")?.get("name")?;
    Some(format!("{kind}:{}", render_value(name)))
}

/// Every Loki config at any depth of `v`, with the dotted key path of its
/// mapping ("" for `v` itself). A string that holds a section name is
/// parsed again (a ConfigMap's `loki.yaml`); a config found is not searched
/// further.
fn find_configs(v: &Value, path: &str, out: &mut Vec<(String, Mapping)>) {
    match v {
        Value::Mapping(m) => {
            if SECTIONS
                .iter()
                .any(|s| m.get(s.section).is_some_and(Value::is_mapping))
            {
                out.push((path.to_string(), m.clone()));
                return;
            }
            for (k, child) in m {
                let k = render_value(k);
                let child_path = if path.is_empty() {
                    k
                } else {
                    format!("{path}.{k}")
                };
                find_configs(child, &child_path, out);
            }
        }
        Value::Sequence(items) => {
            for (i, child) in items.iter().enumerate() {
                find_configs(child, &format!("{path}.{i}"), out);
            }
        }
        Value::String(s) if SECTIONS.iter().any(|sec| s.contains(sec.section)) => {
            if let Ok(inner) = serde_yaml::from_str::<Value>(s) {
                find_configs(&inner, path, out);
            }
        }
        _ => {}
    }
}

/// One packet's (value, resolution, provenance chain).
type Fact = (Option<String>, Resolution, Vec<ProvenanceStep>);

/// The effective retention of one section of `config`, or `None` when the
/// section sets no period.
fn section_fact(s: &Section, config: &Mapping, path: &str, rel_path: &str) -> Option<Fact> {
    let at = |keys: &[&str]| {
        std::iter::once(path)
            .filter(|p| !p.is_empty())
            .chain(keys.iter().copied())
            .collect::<Vec<_>>()
            .join(".")
    };
    let period_path = at(&[s.section, "retention_period"]);
    let period = config.get(s.section)?.get("retention_period")?;
    let mut chain = vec![ProvenanceStep::new(rel_path, &period_path, "explicit")];
    let switch_path = at(&s.switch);
    let switch = config
        .get(s.switch[0])
        .and_then(|section| section.get(s.switch[1]));
    let (on, resolution) = match switch.map(boolean) {
        Some(Some(on)) => {
            chain.push(ProvenanceStep::new(rel_path, &switch_path, "explicit"));
            (on, Resolution::AsAuthored)
        }
        Some(None) => {
            chain.push(ProvenanceStep::new(rel_path, &switch_path, "not-a-boolean"));
            return Some((None, Resolution::Unresolvable, chain));
        }
        None => {
            chain.push(ProvenanceStep::new(rel_path, &switch_path, "absent"));
            chain.push(ProvenanceStep::new("", s.switch[1], "platform-default"));
            (false, Resolution::PlatformDefault)
        }
    };
    let text = render_value(period);
    let value = match duration_secs(&text) {
        None => {
            chain.push(ProvenanceStep::new(
                rel_path,
                &period_path,
                "not-a-duration",
            ));
            return Some((None, Resolution::Unresolvable, chain));
        }
        Some(secs) if secs <= 0.0 => "never".to_string(),
        Some(_) if !on => "never".to_string(),
        Some(_) => text,
    };
    Some((Some(value), resolution, chain))
}

/// A YAML boolean, or the string `true` / `false`.
fn boolean(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Seconds in a Loki duration (`744h`, `31d`, `4w`, `1y`, `1h30m`): one or
/// more `<integer><unit>` terms, or a bare `0`. `None` for anything else.
fn duration_secs(text: &str) -> Option<f64> {
    const UNITS: &[(&str, f64)] = &[
        ("ms", 1e-3),
        ("s", 1.0),
        ("m", 60.0),
        ("h", 3600.0),
        ("d", 86_400.0),
        ("w", 604_800.0),
        ("y", 31_536_000.0),
    ];
    let mut rest = text.trim();
    if rest == "0" {
        return Some(0.0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total = 0.0;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let number: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (_, scale) = UNITS.iter().find(|(u, _)| *u == &rest[..unit_len])?;
        total += number * scale;
        rest = &rest[unit_len..];
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: &str =
        "limits_config:\n  retention_period: 168h\ncompactor:\n  retention_enabled: true\n";

    fn value(got: &Retrieved, unit: &str, key: &str) -> Option<String> {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key && p.format == FORMAT)
            .unwrap_or_else(|| panic!("no {unit} {key} in {:?}", got.packets))
            .resolved_value
            .clone()
    }

    fn some(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    const EFFECTIVE: &str = "limits_config.retention_period-effective";
    const TABLE: &str = "table_manager.retention_period-effective";

    /// The verdict `duration_at_least 720h` gives a packet.
    fn judge(p: &ConfigPacket) -> rvl_core::Verdict {
        let specs = rvl_spec::SpecCache::from_file(rvl_spec::SpecFile {
            config_keys: vec![rvl_spec::ConfigKeySpec {
                format: FORMAT.into(),
                key: p.key.clone(),
                expect: rvl_spec::ConfigExpect::DurationAtLeast {
                    value: "720h".into(),
                },
                confidence: 0.9,
                rationale: String::new(),
                control: String::new(),
                severity: String::new(),
                fix: String::new(),
                gate: String::new(),
            }],
            ..Default::default()
        });
        crate::eval::evaluate(p, &[], &specs).verdict
    }

    #[test]
    fn one_duration_floor_decides_the_effective_retention() {
        use rvl_core::Verdict::{Abstain, Satisfies, Violates};
        for (text, verdict) in [
            (LIMITS.to_string(), Violates),
            (LIMITS.replace("168h", "31d"), Satisfies),
            (
                LIMITS.replace("retention_enabled: true", "retention_enabled: false"),
                Abstain,
            ),
        ] {
            let got = Loki.retrieve("ops/loki.yaml", &text, "s");
            assert_eq!(judge(&got.packets[0]), verdict, "{text}");
        }
    }

    #[test]
    fn a_deleting_period_is_the_fact_and_without_the_switch_it_is_never() {
        let got = Loki.retrieve("ops/loki/loki.yaml", LIMITS, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("168h"));

        let off = LIMITS.replace("retention_enabled: true", "retention_enabled: false");
        let got = Loki.retrieve("ops/loki/loki.yaml", &off, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("never"));

        let absent = "limits_config:\n  retention_period: 168h\n";
        let got = Loki.retrieve("ops/loki/loki.yaml", absent, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("never"));
        assert_eq!(got.packets[0].resolution, Resolution::PlatformDefault);

        let long = LIMITS.replace("168h", "31d");
        let got = Loki.retrieve("ops/loki/loki.yaml", &long, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("31d"));
    }

    #[test]
    fn the_table_manager_has_its_own_switch() {
        let on = "table_manager:\n  retention_deletes_enabled: true\n  retention_period: 2w\n";
        let got = Loki.retrieve("ops/loki.yaml", on, "s");
        assert_eq!(value(&got, "loki-config:root", TABLE), some("2w"));

        let off = "table_manager:\n  retention_period: 2w\ncompactor:\n  retention_enabled: true\n";
        let got = Loki.retrieve("ops/loki.yaml", off, "s");
        assert_eq!(value(&got, "loki-config:root", TABLE), some("never"));
    }

    #[test]
    fn no_period_emits_nothing_and_an_unread_value_is_unresolvable() {
        let none =
            "limits_config:\n  max_streams_per_user: 0\ncompactor:\n  retention_enabled: true\n";
        assert!(Loki.retrieve("ops/loki.yaml", none, "s").packets.is_empty());

        for text in [
            LIMITS.replace("168h", "${RETENTION}"),
            LIMITS.replace("168h", "168"),
            LIMITS.replace("retention_enabled: true", "retention_enabled: maybe"),
        ] {
            let got = Loki.retrieve("ops/loki.yaml", &text, "s");
            assert_eq!(got.packets.len(), 1, "{text}");
            assert_eq!(
                got.packets[0].resolution,
                Resolution::Unresolvable,
                "{text}"
            );
            assert_eq!(got.packets[0].resolved_value, None, "{text}");
        }

        let zero = LIMITS.replace("168h", "0s");
        let got = Loki.retrieve("ops/loki.yaml", &zero, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("never"));
    }

    #[test]
    fn a_configmap_string_and_a_helm_values_block_are_read() {
        let cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: loki\ndata:\n  loki.yaml: |\n    limits_config:\n      retention_period: 72h\n    compactor:\n      retention_enabled: true\n";
        assert!(Loki.matches_head("k8s/loki.yaml", cm));
        let got = Loki.retrieve("k8s/loki.yaml", cm, "s");
        assert_eq!(value(&got, "ConfigMap:loki", EFFECTIVE), some("72h"));

        let values = "loki:\n  limits_config:\n    retention_period: 72h\n  compactor:\n    retention_enabled: true\n";
        let got = Loki.retrieve("charts/values.yaml", values, "s");
        assert_eq!(value(&got, "loki-config:loki", EFFECTIVE), some("72h"));
        assert_eq!(
            got.packets[0].provenance[0].key_path,
            "loki.limits_config.retention_period"
        );
    }

    #[test]
    fn the_head_claim_leaves_foreign_resources_and_other_yaml_alone() {
        assert!(Loki.matches_head("loki.yaml", LIMITS));
        assert!(!Loki.matches_head("loki.json", LIMITS));
        assert!(!Loki.matches_head("app.yaml", "server:\n  http_listen_port: 3100\n"));
        assert!(!Loki.matches_head(
            "x.yaml",
            "apiVersion: example.com/v1\nkind: Thing\nspec:\n  limits_config: {}\n"
        ));
    }

    #[test]
    fn a_manifest_keeps_its_kubernetes_facts() {
        let manifest = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: loki\nspec:\n  replicas: 1\n  template:\n    spec:\n      containers:\n        - name: loki\n          image: grafana/loki:3.0.0\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: loki\ndata:\n  loki.yaml: |\n    limits_config:\n      retention_period: 72h\n";
        let got = Loki.retrieve("k8s/loki.yaml", manifest, "s");
        let direct = Kubernetes.retrieve("k8s/loki.yaml", manifest, "s");
        assert!(!direct.packets.is_empty());
        for p in &direct.packets {
            assert!(got.packets.contains(p), "{} is kept", p.id());
        }
        assert_eq!(value(&got, "ConfigMap:loki", EFFECTIVE), some("never"));
    }

    #[test]
    fn a_templated_file_is_declined_and_a_placeholder_name_undecided() {
        let tpl = "loki:\n  limits_config:\n    retention_period: {{ .Values.retention }}\n";
        let got = Loki.retrieve("chart/values.yaml", tpl, "s");
        assert!(got.packets.is_empty());
        assert_eq!(got.sightings[0].format, "loki-templated");

        let cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: loki-$ENV\ndata:\n  loki.yaml: |\n    limits_config:\n      retention_period: 72h\n    compactor:\n      retention_enabled: true\n";
        let got = Loki.retrieve("k8s/loki.yaml", cm, "s");
        assert_eq!(
            value(&got, "ConfigMap:loki-$ENV", EFFECTIVE),
            some("undecided: unexpanded placeholder in the resource name")
        );
    }

    #[test]
    fn non_production_and_eval_paths_are_undecided() {
        let got = Loki.retrieve("examples/loki.yaml", LIMITS, "s");
        assert_eq!(
            value(&got, "loki-config:root", EFFECTIVE),
            some("undecided: non-production path: examples")
        );
        let got = Loki.retrieve("evals/run-2/evidence/loki.yaml", LIMITS, "s");
        assert_eq!(
            value(&got, "loki-config:root", EFFECTIVE),
            some("undecided: eval fixture: evals")
        );
    }

    fn repo(files: &[(&str, &str)]) -> (tempfile::TempDir, Vec<(String, String)>) {
        let dir = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let claimed = files
            .iter()
            .filter(|(rel, text)| Loki.matches_head(rel, text))
            .map(|(rel, text)| (rel.to_string(), text.to_string()))
            .collect();
        (dir, claimed)
    }

    #[test]
    fn a_config_only_a_compose_stack_loads_is_undecided() {
        let compose = "services:\n  loki:\n    image: grafana/loki\n    volumes:\n      - ./loki/loki.yaml:/etc/loki/local-config.yaml\n";
        let (dir, files) = repo(&[
            ("observability/docker-compose.yml", compose),
            ("observability/loki/loki.yaml", LIMITS),
        ]);
        let got = Loki.retrieve_all(dir.path(), &files, "s");
        assert_eq!(
            value(&got, "loki-config:root", EFFECTIVE),
            some("undecided: loaded by a compose stack only")
        );
    }

    #[test]
    fn a_config_a_kubernetes_object_names_is_a_fact_beside_a_compose_file() {
        let compose = "services:\n  loki:\n    image: grafana/loki\n";
        let kustomization = "configMapGenerator:\n  - name: loki\n    files:\n      - loki.yaml\n";
        let (dir, files) = repo(&[
            ("docker-compose.yml", compose),
            ("deploy/loki/loki.yaml", LIMITS),
            ("deploy/loki/kustomization.yaml", kustomization),
        ]);
        let got = Loki.retrieve_all(dir.path(), &files, "s");
        assert_eq!(value(&got, "loki-config:root", EFFECTIVE), some("168h"));
    }

    #[test]
    fn durations_parse_in_the_loki_units() {
        assert_eq!(duration_secs("744h"), Some(744.0 * 3600.0));
        assert_eq!(duration_secs("1h30m"), Some(5400.0));
        assert_eq!(duration_secs("4w"), Some(4.0 * 604_800.0));
        assert_eq!(duration_secs("1y"), Some(31_536_000.0));
        assert_eq!(duration_secs("0"), Some(0.0));
        assert_eq!(duration_secs("30"), None);
        assert_eq!(duration_secs("1.5h"), None);
        assert_eq!(duration_secs("${R}"), None);
    }
}
