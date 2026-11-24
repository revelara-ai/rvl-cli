//! The repository-scope facts the Prometheus rule retriever asks before a
//! paging alert with no runbook annotation becomes a finding (RC-006).
//!
//! An alert rule is one file; whether a missing runbook link matters depends
//! on the rest of the repository:
//!
//!   * an Alertmanager config or a notification template that mentions a
//!     runbook can compose the link from labels, so the rule needs none;
//!   * receivers that only post to chat or email (or to nothing) page nobody,
//!     so there is no pager to open a runbook from;
//!   * a kustomize patch that targets a `PrometheusRule` can change the
//!     severity the rule file states.
//!
//! One walk of the repository answers all three, once per scan. Nothing read
//! here rides in a packet: receiver names, targets and template text stay
//! inside this module, and only the three answers leave it.

use serde::Deserialize;
use serde_yaml::{Mapping, Value};
use std::path::Path;

/// Integration types that can page a person: a receiver with one of these
/// can wake someone, so a runbook link has a reader. Chat and email
/// integrations (`slack`, `msteams`, `email`, ...) are not in the list.
const PAGING_INTEGRATIONS: &[&str] = &[
    "pagerduty",
    "opsgenie",
    "victorops",
    "pushover",
    "webhook",
    "sns",
    "incidentio",
    "rootly",
    "jira",
];

/// Notification-template extensions Alertmanager configs load.
const TEMPLATE_EXTENSIONS: &[&str] = &["tmpl", "tpl", "gotmpl"];

/// Files larger than this are not read for receivers: a generated bundle,
/// never an Alertmanager config.
const MAX_CONFIG_BYTES: u64 = 4 << 20;

/// What the repository's Alertmanager receivers can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Paging {
    /// No receivers list in a production path.
    #[default]
    NoneDeclared,
    /// A receiver has a paging integration ([`PAGING_INTEGRATIONS`]).
    Yes,
    /// Receivers are declared and none has a paging integration.
    No,
}

impl Paging {
    /// The predicate value: `none_declared`, `yes` or `no`.
    pub fn as_str(self) -> &'static str {
        match self {
            Paging::NoneDeclared => "none_declared",
            Paging::Yes => "yes",
            Paging::No => "no",
        }
    }
}

/// The answers one walk of the repository gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoFacts {
    /// An Alertmanager config or a notification template holds the text
    /// `runbook` (any case).
    pub mentions_runbook: bool,
    pub paging: Paging,
    /// The `target.name` of each kustomize patch whose `target.kind` is
    /// `PrometheusRule`; `None` for a target that names no resource, which
    /// patches every one.
    pub patched_rules: Vec<Option<String>>,
}

impl RepoFacts {
    /// Read the facts from every file the config lane walks under `root`.
    pub fn read(root: &Path) -> Self {
        let mut facts = RepoFacts::default();
        for entry in crate::walk(root).flatten() {
            if !entry.file_type().is_some_and(|ft| ft.is_file()) {
                continue;
            }
            let rel = crate::repo_relative(root, entry.path());
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            let ext = name.rsplit_once('.').map_or("", |(_, ext)| ext);
            let yaml = matches!(ext, "yml" | "yaml");
            let kustomization = matches!(
                name,
                "kustomization.yaml" | "kustomization.yml" | "Kustomization"
            );
            if !(yaml || kustomization || TEMPLATE_EXTENSIONS.contains(&ext)) {
                continue;
            }
            if entry.metadata().is_ok_and(|m| m.len() > MAX_CONFIG_BYTES) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            if TEMPLATE_EXTENSIONS.contains(&ext) {
                facts.mentions_runbook |= mentions_runbook(&text);
            } else if kustomization {
                facts.patched_rules.extend(patched_rules(&text));
            } else {
                facts.read_alertmanager(&rel, &text);
            }
        }
        facts
    }

    /// Fold the Alertmanager configs of one YAML file in. A CRD schema
    /// (`openAPIV3Schema`) describes the config and is not one, and a
    /// receivers list in a non-production path pages nobody in production.
    fn read_alertmanager(&mut self, rel_path: &str, text: &str) {
        if !(text.contains("receivers") && text.contains("route"))
            || text.contains("openAPIV3Schema")
        {
            return;
        }
        let mut configs = Vec::new();
        for doc in documents(text) {
            alertmanager_configs(&doc, &mut configs);
        }
        let production = crate::non_production::path_token(rel_path).is_none();
        for config in &configs {
            let text = serde_yaml::to_string(config).unwrap_or_default();
            self.mentions_runbook |= mentions_runbook(&text);
            if !production {
                continue;
            }
            if pages(config) {
                self.paging = Paging::Yes;
            } else if self.paging == Paging::NoneDeclared {
                self.paging = Paging::No;
            }
        }
    }

    /// Whether a kustomize patch targets the `PrometheusRule` named `name`.
    pub fn patches_rule(&self, name: &str) -> bool {
        self.patched_rules
            .iter()
            .any(|target| target.as_deref().is_none_or(|t| t == name))
    }
}

fn mentions_runbook(text: &str) -> bool {
    text.to_lowercase().contains("runbook")
}

/// Every YAML document of `text`; none when any of them does not parse
/// (a Helm template, a file of another language).
fn documents(text: &str) -> Vec<Value> {
    serde_yaml::Deserializer::from_str(text)
        .map(Value::deserialize)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

/// The Alertmanager configs at any depth of `v`: a mapping with a `route`
/// mapping beside a `receivers` list of named mappings. That shape is a plain
/// config, an `AlertmanagerConfig` spec, a Helm values block, or (parsed
/// again) a ConfigMap or Secret string.
fn alertmanager_configs(v: &Value, out: &mut Vec<Mapping>) {
    match v {
        Value::Mapping(m) => {
            let route = m.get("route").is_some_and(Value::is_mapping);
            let receivers = m.get("receivers").and_then(Value::as_sequence);
            let named = receivers.is_some_and(|r| {
                r.iter()
                    .any(|r| r.as_mapping().is_some_and(|r| r.contains_key("name")))
            });
            if route && named {
                out.push(m.clone());
                return;
            }
            for v in m.values() {
                alertmanager_configs(v, out);
            }
        }
        Value::Sequence(s) => s.iter().for_each(|v| alertmanager_configs(v, out)),
        Value::String(s) if s.contains("receivers") && s.contains("route") => {
            for doc in documents(s) {
                alertmanager_configs(&doc, out);
            }
        }
        Value::Tagged(t) => alertmanager_configs(&t.value, out),
        _ => {}
    }
}

/// Whether any receiver of `config` has a non-empty integration list of a
/// paging type. The integration type is the key without its `_configs`
/// (plain config) or `Configs` (`AlertmanagerConfig`) suffix, lower-cased and
/// without `_`.
fn pages(config: &Mapping) -> bool {
    let receivers = config.get("receivers").and_then(Value::as_sequence);
    receivers
        .into_iter()
        .flatten()
        .filter_map(Value::as_mapping)
        .flat_map(|r| r.iter())
        .any(|(k, v)| {
            let Some(k) = k.as_str() else { return false };
            let Some(kind) = k
                .strip_suffix("_configs")
                .or_else(|| k.strip_suffix("Configs"))
            else {
                return false;
            };
            let kind = kind.replace('_', "").to_lowercase();
            PAGING_INTEGRATIONS.contains(&kind.as_str())
                && v.as_sequence().is_some_and(|s| !s.is_empty())
        })
}

/// The `PrometheusRule` targets of one kustomization's `patches` and
/// `patchesJson6902` entries.
fn patched_rules(text: &str) -> Vec<Option<String>> {
    let Ok(doc) = serde_yaml::from_str::<Value>(text) else {
        return Vec::new();
    };
    ["patches", "patchesJson6902"]
        .into_iter()
        .filter_map(|field| doc.get(field).and_then(Value::as_sequence))
        .flatten()
        .filter_map(|entry| entry.get("target").and_then(Value::as_mapping))
        .filter(|t| t.get("kind").and_then(Value::as_str) == Some("PrometheusRule"))
        .map(|t| t.get("name").and_then(Value::as_str).map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(files: &[(&str, &str)]) -> RepoFacts {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        RepoFacts::read(dir.path())
    }

    const SLACK_ONLY: &str = "route:\n  receiver: chat\nreceivers:\n- name: chat\n  slack_configs:\n  - channel: '#alerts'\n";
    const PAGER: &str = "route:\n  receiver: pager\nreceivers:\n- name: chat\n  slack_configs:\n  - channel: '#alerts'\n- name: pager\n  pagerduty_configs:\n  - routing_key: KEY\n";

    #[test]
    fn receivers_page_when_one_has_a_paging_integration() {
        assert_eq!(repo(&[]).paging, Paging::NoneDeclared);
        assert_eq!(
            repo(&[("monitoring/alertmanager.yml", SLACK_ONLY)]).paging,
            Paging::No
        );
        assert_eq!(
            repo(&[("monitoring/alertmanager.yml", PAGER)]).paging,
            Paging::Yes
        );
        // A receiver with no integration at all pages nobody.
        let stub = "route:\n  receiver: x\nreceivers:\n- name: x\n";
        assert_eq!(repo(&[("alertmanager.yaml", stub)]).paging, Paging::No);
        // An empty paging list is no integration.
        let empty = "route:\n  receiver: x\nreceivers:\n- name: x\n  webhook_configs: []\n";
        assert_eq!(repo(&[("alertmanager.yaml", empty)]).paging, Paging::No);
    }

    #[test]
    fn receivers_are_found_at_any_depth_and_inside_config_map_strings() {
        // Helm values.
        let values = "alertmanager:\n  config:\n    route:\n      receiver: p\n    receivers:\n    - name: p\n      opsgenie_configs:\n      - api_key: K\n";
        assert_eq!(repo(&[("deploy/values.yaml", values)]).paging, Paging::Yes);
        // An AlertmanagerConfig spec, camel-cased.
        let crd = "apiVersion: monitoring.coreos.com/v1alpha1\nkind: AlertmanagerConfig\nmetadata:\n  name: team\nspec:\n  route:\n    receiver: p\n  receivers:\n  - name: p\n    pagerdutyConfigs:\n    - routingKey: {name: k, key: k}\n";
        assert_eq!(repo(&[("deploy/amc.yaml", crd)]).paging, Paging::Yes);
        // A ConfigMap string.
        let cm = format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: am\ndata:\n  alertmanager.yml: |\n{}",
            SLACK_ONLY
                .lines()
                .map(|l| format!("    {l}\n"))
                .collect::<String>()
        );
        assert_eq!(repo(&[("deploy/am.yaml", &cm)]).paging, Paging::No);
    }

    #[test]
    fn non_production_receivers_and_crd_schemas_are_not_read() {
        assert_eq!(
            repo(&[("examples/alertmanager.yml", SLACK_ONLY)]).paging,
            Paging::NoneDeclared
        );
        let schema = format!("openAPIV3Schema: {{}}\n{SLACK_ONLY}");
        assert_eq!(
            repo(&[("crds/alertmanagerconfigs.yaml", &schema)]).paging,
            Paging::NoneDeclared
        );
    }

    #[test]
    fn a_template_or_an_alertmanager_config_can_mention_a_runbook() {
        assert!(!repo(&[("alertmanager.yml", PAGER)]).mentions_runbook);
        let tmpl = "{{ define \"x\" }}{{ .CommonAnnotations.RunBook }}{{ end }}";
        assert!(repo(&[("templates/pager.tmpl", tmpl)]).mentions_runbook);
        let am = format!("{PAGER}templates: ['/etc/am/runbook.tmpl']\n");
        assert!(repo(&[("alertmanager.yml", &am)]).mentions_runbook);
        // A rule file's runbook annotation is not an Alertmanager config.
        let rules =
            "groups:\n- name: a\n  rules:\n  - alert: A\n    annotations:\n      runbook_url: x\n";
        assert!(!repo(&[("alertmanager.yml", PAGER), ("rules.yml", rules)]).mentions_runbook);
    }

    #[test]
    fn kustomize_patches_name_the_prometheus_rules_they_target() {
        let k = "resources: [../base]\npatches:\n- path: sev.yaml\n  target:\n    kind: PrometheusRule\n    name: etcd\n- path: dep.yaml\n  target:\n    kind: Deployment\n";
        let facts = repo(&[("overlay/kustomization.yaml", k)]);
        assert!(facts.patches_rule("etcd"));
        assert!(!facts.patches_rule("api"));
        let any = "patchesJson6902:\n- path: sev.yaml\n  target:\n    kind: PrometheusRule\n";
        let facts = repo(&[("overlay/kustomization.yml", any)]);
        assert!(
            facts.patches_rule("api"),
            "a target with no name patches all"
        );
        assert!(!repo(&[]).patches_rule("etcd"));
    }
}
