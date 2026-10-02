//! Alertmanager routing-config retriever: the routing half of the G6
//! alerting family (po-av01j.39; rule files are [`crate::prometheus`]).
//!
//! Claims, conservatively and by CONTENT (a bounded head, via
//! [`ConfigRetriever::matches_head`]):
//!
//!   * a file named `alertmanager.yml` / `alertmanager.yaml` that is not
//!     `apiVersion:` + `kind:` shaped (a Deployment or operator CR that is
//!     merely NAMED after Alertmanager stays the Kubernetes family's);
//!   * any YAML with top-level `route:` and `receivers:`.
//!
//! Nothing is rendered on the scan path (wayfinder po-ae75b.1). A file that
//! does not parse and carries Helm markers is DECLINED as an
//! `alertmanager-templated` sighting; a templated VALUE inside otherwise
//! literal YAML becomes an [`Resolution::Unresolvable`] packet. Alertmanager's
//! OWN notification templating (`{{ range .Alerts }}` in a receiver's text) is
//! legitimate in a literal file and lives in fields this retriever never
//! reads.
//!
//! Emitted facts, one set per node of the routing tree. Units name a route by
//! its INDEX path (`route:root`, `route:root/0/2`), never by its matchers:
//!
//!   * `route.group_by` / `route.group_wait` / `route.group_interval` /
//!     `route.repeat_interval` — explicit, else INHERITED from the nearest
//!     ancestor that sets it (Alertmanager's own rule; provenance names that
//!     ancestor), else the DOCUMENTED default at the root: no grouping
//!     labels, `30s`, `5m`, `4h`. `group_by` renders as its label NAMES,
//!     comma-joined.
//!   * `route.receiver` — SHAPE-ONLY state of the effective receiver:
//!     `configured` (defined, with at least one integration), `blackhole`
//!     (defined with no integration: alerts routed there notify nobody),
//!     `undefined` (names a receiver `receivers:` does not define), or the
//!     empty string (no receiver on the route or any ancestor).
//!   * `inhibit_rules` — on the `config` unit, a presence marker: `nonempty`
//!     or the empty string.
//!
//! Privacy: receiver names and targets (webhook URLs, pager and API keys),
//! matcher label values and inhibit-rule content never ride in a packet —
//! states and presence markers only, the `rule.annotations.runbook` contract.

use crate::prometheus::helm_templated;
use crate::{
    render_value, ConfigPacket, ConfigRetriever, FormatSighting, ProvenanceStep, Resolution,
    Retrieved,
};
use serde_yaml::{Mapping, Value};
use std::collections::BTreeMap;

pub struct Alertmanager;

const FORMAT: &str = "alertmanager";

/// One inheritable route setting: its YAML key, its packet key, and the
/// documented default that governs when no route up to the root sets it
/// (`None`: no platform supplies one, so absence is an authored fact).
struct Setting {
    yaml: &'static str,
    ledger: &'static str,
    default: Option<&'static str>,
}

const SETTINGS: &[Setting] = &[
    Setting {
        yaml: "group_by",
        ledger: "route.group_by",
        // No grouping labels: every alert on the route lands in one group.
        default: Some(""),
    },
    Setting {
        yaml: "group_wait",
        ledger: "route.group_wait",
        default: Some("30s"),
    },
    Setting {
        yaml: "group_interval",
        ledger: "route.group_interval",
        default: Some("5m"),
    },
    Setting {
        yaml: "repeat_interval",
        ledger: "route.repeat_interval",
        default: Some("4h"),
    },
    Setting {
        yaml: "receiver",
        ledger: "route.receiver",
        default: None,
    },
];

impl ConfigRetriever for Alertmanager {
    fn format_id(&self) -> &'static str {
        FORMAT
    }

    /// Claimed by content only: the canonical basename is shared with
    /// Kubernetes manifests that deploy Alertmanager.
    fn matches(&self, _rel_path: &str) -> bool {
        false
    }

    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        if !(rel_path.ends_with(".yml") || rel_path.ends_with(".yaml")) {
            return false;
        }
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        // A manifest named after Alertmanager is the Kubernetes family's.
        if col0("apiVersion:") && col0("kind:") {
            return false;
        }
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        if name == "alertmanager.yml" || name == "alertmanager.yaml" {
            return true;
        }
        col0("route:") && col0("receivers:")
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let mut out = Retrieved::default();
        let Ok(Value::Mapping(root)) = serde_yaml::from_str::<Value>(contents) else {
            // No rendering on the scan path: a Helm template is not broken
            // YAML, it is a variant this retriever declines.
            if helm_templated(contents) {
                out.sightings
                    .push(FormatSighting::declined("alertmanager-templated", 1));
            } else {
                out.unparseable = 1;
            }
            return out;
        };
        let Some(route) = get(&root, "route").and_then(Value::as_mapping) else {
            out.unparseable = 1;
            return out;
        };
        let em = Emitter {
            rel_path,
            snapshot_id,
            receivers: receivers(&root),
        };
        em.route(route, "route:root", "route", None, &mut out);

        // inhibit_rules: shape-only presence; the matchers never leave.
        let inhibits = get(&root, "inhibit_rules")
            .and_then(Value::as_sequence)
            .is_some_and(|s| !s.is_empty());
        let (value, role) = if inhibits {
            ("nonempty", "explicit")
        } else {
            ("", "absent")
        };
        out.packets.push(em.packet(
            "config",
            "inhibit_rules",
            Some(value.to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(rel_path, "inhibit_rules", role)],
        ));
        out
    }
}

/// Defined receiver names, each mapped to whether it carries at least one
/// integration (a non-empty `*_configs` list). Names stay inside this
/// module: they key the lookup and never reach a packet.
fn receivers(root: &Mapping) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    let defined = get(root, "receivers").and_then(Value::as_sequence);
    for r in defined.into_iter().flatten() {
        let Some(r) = r.as_mapping() else { continue };
        let Some(name) = get(r, "name").and_then(Value::as_str) else {
            continue;
        };
        let integrated = r.iter().any(|(k, v)| {
            k.as_str().is_some_and(|k| k.ends_with("_configs"))
                && v.as_sequence().is_some_and(|s| !s.is_empty())
        });
        out.insert(name.to_string(), integrated);
    }
    out
}

/// The effective value of one setting on one route, and the provenance step
/// that established it (handed down to the routes that inherit it).
#[derive(Clone)]
struct Effective {
    value: Option<String>,
    resolution: Resolution,
    origin: ProvenanceStep,
}

/// Shared packet plumbing for one file.
struct Emitter<'a> {
    rel_path: &'a str,
    snapshot_id: &'a str,
    receivers: BTreeMap<String, bool>,
}

impl Emitter<'_> {
    fn packet(
        &self,
        unit: &str,
        key: &str,
        value: Option<String>,
        resolution: Resolution,
        provenance: Vec<ProvenanceStep>,
    ) -> ConfigPacket {
        ConfigPacket {
            snapshot_id: self.snapshot_id.to_string(),
            format: FORMAT.to_string(),
            file_path: self.rel_path.to_string(),
            line: 0,
            unit: unit.to_string(),
            key: crate::key_ledger::declared(FORMAT, key),
            resolved_value: value,
            resolution,
            provenance,
        }
    }

    /// One node of the routing tree, then its children. `parent` is the
    /// effective value of every [`SETTINGS`] entry on the enclosing route.
    fn route(
        &self,
        route: &Mapping,
        unit: &str,
        path: &str,
        parent: Option<&[Effective]>,
        out: &mut Retrieved,
    ) {
        let mut effective = Vec::with_capacity(SETTINGS.len());
        for (idx, setting) in SETTINGS.iter().enumerate() {
            let key_path = format!("{path}.{}", setting.yaml);
            // An empty `key:` is YAML null: nothing authored.
            let own = get(route, setting.yaml).filter(|v| !v.is_null());
            let (eff, provenance) = match own {
                Some(v) => {
                    let eff = self.authored(setting, &key_path, v);
                    let provenance = vec![eff.origin.clone()];
                    (eff, provenance)
                }
                None => {
                    let absent = ProvenanceStep::new(self.rel_path, &key_path, "absent");
                    match (parent, setting.default) {
                        // Alertmanager's own rule: an unset route setting
                        // is the enclosing route's.
                        (Some(parent), _) => {
                            let eff = parent[idx].clone();
                            let mut from = eff.origin.clone();
                            if from.role == "explicit" {
                                from.role = "inherited".to_string();
                            }
                            (eff, vec![absent, from])
                        }
                        (None, Some(default)) => {
                            let eff = Effective {
                                value: Some(default.to_string()),
                                resolution: Resolution::PlatformDefault,
                                origin: ProvenanceStep::new("", setting.yaml, "platform-default"),
                            };
                            let provenance = vec![absent, eff.origin.clone()];
                            (eff, provenance)
                        }
                        // No platform supplies it: an authored absence.
                        (None, None) => {
                            let eff = Effective {
                                value: Some(String::new()),
                                resolution: Resolution::AsAuthored,
                                origin: absent.clone(),
                            };
                            (eff, vec![absent])
                        }
                    }
                }
            };
            out.packets.push(self.packet(
                unit,
                setting.ledger,
                eff.value.clone(),
                eff.resolution,
                provenance,
            ));
            effective.push(eff);
        }

        let children = get(route, "routes").and_then(Value::as_sequence);
        for (idx, child) in children.into_iter().flatten().enumerate() {
            let Some(child) = child.as_mapping() else {
                continue;
            };
            self.route(
                child,
                &format!("{unit}/{idx}"),
                &format!("{path}.routes[{idx}]"),
                Some(&effective),
                out,
            );
        }
    }

    /// A setting a route sets itself. Anything that is not a plain literal
    /// (a template, a value of the wrong shape) is unresolvable: nothing is
    /// rendered on the scan path, so it can only be abstained on.
    fn authored(&self, setting: &Setting, key_path: &str, v: &Value) -> Effective {
        let literal = match setting.yaml {
            "group_by" => v.as_sequence().and_then(|labels| {
                let names: Option<Vec<&str>> = labels.iter().map(Value::as_str).collect();
                names.map(|n| n.join(","))
            }),
            _ => match v {
                Value::String(_) | Value::Number(_) => Some(render_value(v)),
                _ => None,
            },
        }
        .filter(|s| !s.contains("{{"));
        let Some(literal) = literal else {
            let role = if render_value(v).contains("{{") {
                "templated"
            } else {
                "non-literal"
            };
            return Effective {
                value: None,
                resolution: Resolution::Unresolvable,
                origin: ProvenanceStep::new(self.rel_path, key_path, role),
            };
        };
        // The receiver NAME never rides in a packet, only what it resolves to.
        let value = if setting.yaml == "receiver" {
            match self.receivers.get(&literal) {
                Some(true) => "configured",
                Some(false) => "blackhole",
                None => "undefined",
            }
            .to_string()
        } else {
            literal
        };
        Effective {
            value: Some(value),
            resolution: Resolution::AsAuthored,
            origin: ProvenanceStep::new(self.rel_path, key_path, "explicit"),
        }
    }
}

fn get<'a>(m: &'a Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATH: &str = "monitoring/alertmanager.yml";

    fn packets(yaml: &str) -> Retrieved {
        Alertmanager.retrieve(PATH, yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    /// A root route that sets everything, one child that overrides only
    /// `group_wait` and names a blackhole receiver, one grandchild that sets
    /// nothing, and a child naming a receiver nothing defines.
    const TREE: &str = "global:\n  slack_api_url: https://hooks.slack.example/T000/B000/secret\nroute:\n  receiver: team-payments-pager\n  group_by: [alertname, cluster]\n  group_wait: 10s\n  group_interval: 2m\n  repeat_interval: 1h\n  routes:\n  - matchers:\n    - team=\"payments-core\"\n    receiver: devnull\n    group_wait: 0s\n    routes:\n    - matchers:\n      - severity=\"warning\"\n  - receiver: nobody-defined-this\ninhibit_rules:\n- source_matchers: [severity=\"critical\"]\n  target_matchers: [severity=\"warning\"]\n  equal: [alertname]\nreceivers:\n- name: team-payments-pager\n  pagerduty_configs:\n  - routing_key: PAGERKEY0123456789\n  webhook_configs:\n  - url: https://hooks.internal.example/alert\n  slack_configs:\n  - text: \"{{ range .Alerts -}}{{ .Annotations.summary }}{{- end }}\"\n- name: devnull\n";

    const BARE: &str = "route:\n  receiver: default\nreceivers:\n- name: default\n  webhook_configs:\n  - url: https://hooks.internal.example/alert\n";

    // --- matches_head: conservative content identification ---

    #[test]
    fn matches_head_claims_the_canonical_name_and_the_route_receivers_shape() {
        let r = Alertmanager;
        assert!(r.matches_head("monitoring/alertmanager.yml", BARE));
        assert!(r.matches_head("alertmanager.yaml", "global: {}\n"));
        assert!(
            r.matches_head("config/am.yaml", BARE),
            "route+receivers shape identifies alertmanager under any name"
        );
    }

    #[test]
    fn matches_head_declines_what_is_not_conservatively_ours() {
        let r = Alertmanager;
        // A manifest that DEPLOYS Alertmanager is the Kubernetes family's.
        assert!(!r.matches_head(
            "k8s/alertmanager.yaml",
            "apiVersion: apps/v1\nkind: StatefulSet\nmetadata:\n  name: alertmanager\n"
        ));
        // route: alone is not identifiable as ours.
        assert!(!r.matches_head("cfg.yml", "route:\n  path: /x\n"));
        // Nested route/receivers keys are some other tool's.
        assert!(!r.matches_head(
            "cfg.yml",
            "spec:\n  route:\n    receiver: x\n  receivers: []\n"
        ));
        assert!(!r.matches_head("docs/notes.yaml", "a: b\n"));
        // Non-YAML extensions are never consulted.
        assert!(!r.matches_head("alertmanager.txt", BARE));
    }

    // --- route grouping: explicit, inherited, platform default ---

    #[test]
    fn explicit_root_grouping_resolves_as_authored() {
        let got = packets(TREE);
        for (key, want, path) in [
            ("route.group_by", "alertname,cluster", "route.group_by"),
            ("route.group_wait", "10s", "route.group_wait"),
            ("route.group_interval", "2m", "route.group_interval"),
            ("route.repeat_interval", "1h", "route.repeat_interval"),
        ] {
            let p = find(&got, "route:root", key);
            assert_eq!(p.format, "alertmanager");
            assert_eq!(p.resolved_value.as_deref(), Some(want), "{key}");
            assert_eq!(p.resolution, Resolution::AsAuthored, "{key}");
            assert_eq!(p.provenance.len(), 1, "{key}");
            assert_eq!(p.provenance[0].file, PATH);
            assert_eq!(p.provenance[0].key_path, path);
            assert_eq!(p.provenance[0].role, "explicit");
        }
    }

    #[test]
    fn absent_root_grouping_resolves_the_documented_defaults() {
        let got = packets(BARE);
        for (key, want) in [
            ("route.group_by", ""),
            ("route.group_wait", "30s"),
            ("route.group_interval", "5m"),
            ("route.repeat_interval", "4h"),
        ] {
            let p = find(&got, "route:root", key);
            assert_eq!(p.resolved_value.as_deref(), Some(want), "{key}");
            assert_eq!(p.resolution, Resolution::PlatformDefault, "{key}");
            assert_eq!(p.provenance[0].role, "absent");
            assert_eq!(p.provenance[1].role, "platform-default");
            assert_eq!(p.provenance[1].file, "", "a platform default names no file");
        }
    }

    #[test]
    fn a_child_route_inherits_what_it_does_not_set_and_names_the_ancestor() {
        let got = packets(TREE);
        // The child overrides group_wait and inherits the rest from the root.
        let own = find(&got, "route:root/0", "route.group_wait");
        assert_eq!(own.resolved_value.as_deref(), Some("0s"));
        assert_eq!(own.provenance[0].key_path, "route.routes[0].group_wait");
        assert_eq!(own.provenance[0].role, "explicit");

        let inherited = find(&got, "route:root/0", "route.repeat_interval");
        assert_eq!(inherited.resolved_value.as_deref(), Some("1h"));
        assert_eq!(inherited.resolution, Resolution::AsAuthored);
        assert_eq!(
            inherited.provenance[0].key_path,
            "route.routes[0].repeat_interval"
        );
        assert_eq!(inherited.provenance[0].role, "absent");
        assert_eq!(inherited.provenance[1].key_path, "route.repeat_interval");
        assert_eq!(inherited.provenance[1].role, "inherited");

        // The grandchild inherits the CHILD's override, not the root's value.
        let deep = find(&got, "route:root/0/0", "route.group_wait");
        assert_eq!(deep.resolved_value.as_deref(), Some("0s"));
        assert_eq!(deep.provenance[1].key_path, "route.routes[0].group_wait");
        assert_eq!(deep.provenance[1].role, "inherited");
    }

    #[test]
    fn a_child_under_a_defaulted_root_inherits_the_platform_default() {
        let got = packets(
            "route:\n  receiver: default\n  routes:\n  - receiver: default\nreceivers:\n- name: default\n  email_configs:\n  - to: oncall@example.com\n",
        );
        let p = find(&got, "route:root/0", "route.group_interval");
        assert_eq!(p.resolved_value.as_deref(), Some("5m"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance[0].key_path, "route.routes[0].group_interval");
        assert_eq!(p.provenance[1].role, "platform-default");
    }

    // --- route.receiver: a shape-only state ---

    #[test]
    fn receiver_state_is_configured_blackhole_undefined_or_absent() {
        let got = packets(TREE);
        let state = |unit: &str| {
            find(&got, unit, "route.receiver")
                .resolved_value
                .clone()
                .unwrap()
        };
        assert_eq!(state("route:root"), "configured");
        assert_eq!(
            state("route:root/0"),
            "blackhole",
            "a defined receiver with no integration notifies nobody"
        );
        assert_eq!(
            state("route:root/1"),
            "undefined",
            "a receiver that receivers: does not define"
        );
        // The grandchild sets no receiver and inherits its parent's blackhole.
        let deep = find(&got, "route:root/0/0", "route.receiver");
        assert_eq!(deep.resolved_value.as_deref(), Some("blackhole"));
        assert_eq!(deep.provenance[0].role, "absent");
        assert_eq!(deep.provenance[1].key_path, "route.routes[0].receiver");
        assert_eq!(deep.provenance[1].role, "inherited");

        let got = packets("route:\n  group_wait: 5s\nreceivers: []\n");
        let p = find(&got, "route:root", "route.receiver");
        assert_eq!(
            p.resolved_value.as_deref(),
            Some(""),
            "no platform supplies a receiver: an authored absence"
        );
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(p.provenance[0].role, "absent");
    }

    #[test]
    fn an_empty_integration_list_is_still_a_blackhole() {
        let got = packets("route:\n  receiver: r\nreceivers:\n- name: r\n  webhook_configs: []\n");
        let p = find(&got, "route:root", "route.receiver");
        assert_eq!(p.resolved_value.as_deref(), Some("blackhole"));
    }

    // --- inhibit_rules: a presence marker ---

    #[test]
    fn inhibit_rules_is_a_presence_marker() {
        let got = packets(TREE);
        let p = find(&got, "config", "inhibit_rules");
        assert_eq!(p.resolved_value.as_deref(), Some("nonempty"));
        assert_eq!(p.provenance[0].role, "explicit");

        for yaml in [BARE.to_string(), format!("{BARE}inhibit_rules: []\n")] {
            let got = packets(&yaml);
            let p = find(&got, "config", "inhibit_rules");
            assert_eq!(p.resolved_value.as_deref(), Some(""));
            assert_eq!(p.resolution, Resolution::AsAuthored);
            assert_eq!(p.provenance[0].role, "absent");
        }
    }

    // --- privacy ---

    #[test]
    fn receiver_names_targets_and_matcher_values_never_ride_in_a_packet() {
        let got = packets(TREE);
        assert!(!got.packets.is_empty());
        let all = serde_json::to_string(&got.packets).unwrap();
        for secret in [
            "hooks.slack.example",
            "hooks.internal.example",
            "PAGERKEY0123456789",
            "team-payments-pager",
            "devnull",
            "nobody-defined-this",
            "payments-core",
            "critical",
            "Annotations",
        ] {
            assert!(!all.contains(secret), "leaked `{secret}`: {all}");
        }
    }

    // --- templating and degradation ---

    #[test]
    fn templated_values_inside_literal_yaml_are_unresolvable_not_guessed() {
        let got = packets(
            "route:\n  receiver: \"{{ .Values.receiver }}\"\n  group_wait: \"{{ .Values.wait }}\"\n  group_by: [\"{{ .Values.label }}\"]\nreceivers:\n- name: default\n",
        );
        for key in ["route.receiver", "route.group_wait", "route.group_by"] {
            let p = find(&got, "route:root", key);
            assert_eq!(p.resolution, Resolution::Unresolvable, "{key}");
            assert_eq!(p.resolved_value, None, "{key}");
            assert_eq!(p.provenance[0].role, "templated", "{key}");
        }
        // A child of a templated ancestor inherits the abstention.
        let got = packets(
            "route:\n  receiver: r\n  group_wait: \"{{ .Values.wait }}\"\n  routes:\n  - receiver: r\nreceivers:\n- name: r\n",
        );
        let p = find(&got, "route:root/0", "route.group_wait");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
    }

    #[test]
    fn a_helm_templated_file_is_declined_as_a_sighting_not_parsed() {
        let got = packets(
            "route:\n  receiver: default\n{{- if .Values.extraRoutes }}\n  routes:\n{{ toYaml .Values.extraRoutes | indent 2 }}\n{{- end }}\nreceivers:\n- name: default\n",
        );
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0, "declined, not broken");
        assert_eq!(
            got.sightings,
            vec![FormatSighting::declined("alertmanager-templated", 1)]
        );
    }

    #[test]
    fn alertmanagers_own_notification_templating_stays_literal() {
        // TREE carries `{{ range .Alerts -}}` in a receiver's text.
        let got = packets(TREE);
        assert!(got.sightings.is_empty());
        assert_eq!(got.unparseable, 0);
        assert_eq!(
            find(&got, "route:root", "route.receiver").resolution,
            Resolution::AsAuthored
        );
    }

    #[test]
    fn malformed_or_routeless_yaml_degrades_to_an_unparseable_count() {
        for yaml in [
            "route: [unclosed\n  - {",
            "",
            "receivers: []\n",
            "- a\n- b\n",
        ] {
            let got = packets(yaml);
            assert!(got.packets.is_empty(), "{yaml:?}");
            assert!(got.sightings.is_empty(), "{yaml:?}");
            assert_eq!(got.unparseable, 1, "{yaml:?}");
        }
    }
}
