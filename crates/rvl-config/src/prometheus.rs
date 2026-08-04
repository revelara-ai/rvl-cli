//! Prometheus alert/recording rules + sloth SLO retriever: family (3) of the
//! G6 config lane, and the first CONTENT-identified format (rule files have
//! no canonical path, so the walk consults [`ConfigRetriever::matches_head`]
//! with a bounded head before a file degrades to a sighting).
//!
//! Claims, conservatively:
//!
//!   * literal Prometheus rule files — top-level `groups:` whose rules carry
//!     `alert:` / `record:`;
//!   * sloth SLO definitions — the native `service:` + `slos:` shape, or the
//!     CRD form (`apiVersion: sloth.slok.dev/...`).
//!
//! Anything Helm/Go-templated is DECLINED (no rendering on the scan path —
//! wayfinder po-ae75b.1): a whole-file template falls through to the
//! `prometheus-rules-templated` sighting; a templated VALUE inside otherwise
//! literal YAML becomes an [`Resolution::Unresolvable`] packet, so the
//! verification lane abstains instead of judging an unrendered string.
//!
//! Emitted facts (the alerting/SLO-coverage control set — granularity map G6:
//! RC-001/RC-002 monitoring, RC-023/026/051/052 SLO coverage):
//!
//!   * `rule.for` — per alert rule; absent resolves the DOCUMENTED `0s`
//!     platform default (the alert fires on first evaluation).
//!   * `rule.labels.severity` — per alert rule; absence is an AUTHORED fact
//!     (no platform supplies a severity), emitted as the empty string.
//!   * `rule.annotations.runbook` — presence of a `runbook_url` / `runbook`
//!     annotation. SHAPE-ONLY: the packet carries the marker `nonempty`,
//!     never the URL (runbook locations are repo-internal content).
//!   * `rule.expr` — non-emptiness of the alert expression. SHAPE-ONLY: the
//!     marker `nonempty`, never the PromQL (metric names, label values and
//!     hostnames live in expressions; per the privacy contract they never
//!     leave the machine).
//!   * `group.interval` — per rule group; absent is UNRESOLVABLE: the global
//!     `evaluation_interval` governs and lives in the Prometheus server
//!     config, not this file.
//!   * `slo.objective` / `slo.time_window` / `slo.alerting.page_alert` /
//!     `slo.alerting.ticket_alert` — per sloth SLO. The window is a
//!     generation-time sloth setting (`--default-slo-period`), so an absent
//!     `time_window` is unresolvable, never guessed at 30d.
//!
//! Recording rules are detected (they make a file claimable) but emit no
//! per-rule packets: `for:` and severity semantics are alert-only, and a
//! record rule's health is promtool's job, not a reliability control's.

use crate::{render_value, ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};
use serde_yaml::Value;

pub struct PrometheusRules;

/// Helm/Go-template markers, distinguished from Prometheus's own alert
/// templating (`{{ $labels.x }}`, `{{ $value }}`), which is legitimate inside
/// literal rule files: Helm control lines carry `{{-` and Helm data comes
/// from `.Values` / `.Release`.
pub(crate) fn helm_templated(text: &str) -> bool {
    text.contains("{{-") || text.contains(".Values") || text.contains(".Release")
}

impl ConfigRetriever for PrometheusRules {
    fn format_id(&self) -> &'static str {
        "prometheus-rules"
    }

    /// No canonical path exists for rule files; identification is
    /// content-based via [`Self::matches_head`].
    fn matches(&self, _rel_path: &str) -> bool {
        false
    }

    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        if !(rel_path.ends_with(".yml") || rel_path.ends_with(".yaml")) {
            return false;
        }
        // No rendering on the scan path: templated files are sighted, not
        // parsed (matching the coverage contract in `sight_format`).
        if helm_templated(head) {
            return false;
        }
        let col0 = |k: &str| head.lines().any(|l| l.starts_with(k));
        // Sloth CRD: ours even though it also looks like a k8s manifest.
        if head
            .lines()
            .any(|l| l.starts_with("apiVersion:") && l.contains("sloth.slok.dev"))
        {
            return true;
        }
        // Any other manifest (including PrometheusRule CRDs) is the
        // Kubernetes family's, not ours.
        if col0("apiVersion:") && col0("kind:") {
            return false;
        }
        // Sloth native shape.
        if col0("service:") && col0("slos:") {
            return true;
        }
        // A Prometheus rule file: top-level groups whose rules carry
        // alert:/record:. groups: alone is not identifiable as ours.
        if col0("groups:") {
            return head.lines().any(|l| {
                let t = l.trim_start();
                t.starts_with("- alert:")
                    || t.starts_with("alert:")
                    || t.starts_with("- record:")
                    || t.starts_with("record:")
            });
        }
        false
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let mut out = Retrieved::default();
        let Ok(doc) = serde_yaml::from_str::<Value>(contents) else {
            out.unparseable = 1;
            return out;
        };
        let Some(root) = doc.as_mapping() else {
            out.unparseable = 1;
            return out;
        };
        let em = Emitter {
            rel_path,
            snapshot_id,
        };
        // Sloth first (native root or CRD `spec:`), then rule files; a
        // claimed file that is neither degrades to an unparseable count.
        if get(root, "slos").is_some() {
            em.sloth(root, "", &mut out);
        } else if let Some(spec) = get(root, "spec").and_then(Value::as_mapping) {
            if get(spec, "slos").is_some() {
                em.sloth(spec, "spec.", &mut out);
            } else {
                out.unparseable = 1;
            }
        } else if let Some(groups) = get(root, "groups").and_then(Value::as_sequence) {
            em.rule_groups(groups, &mut out);
        } else {
            out.unparseable = 1;
        }
        out
    }
}

/// Shared packet plumbing for one file.
struct Emitter<'a> {
    rel_path: &'a str,
    snapshot_id: &'a str,
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
            format: "prometheus-rules".to_string(),
            file_path: self.rel_path.to_string(),
            line: 0,
            unit: unit.to_string(),
            key: key.to_string(),
            resolved_value: value,
            resolution,
            provenance,
        }
    }

    /// An explicit scalar, or — when the authored text is a template — an
    /// unresolvable: nothing is rendered on the scan path, so a templated
    /// value can never be judged, only abstained on.
    fn scalar(&self, unit: &str, key: &str, key_path: &str, v: &Value) -> ConfigPacket {
        let rendered = render_value(v);
        if rendered.contains("{{") {
            self.packet(
                unit,
                key,
                None,
                Resolution::Unresolvable,
                vec![ProvenanceStep::new(self.rel_path, key_path, "templated")],
            )
        } else {
            self.packet(
                unit,
                key,
                Some(rendered),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(self.rel_path, key_path, "explicit")],
            )
        }
    }

    /// An authored absence: no platform supplies this key, so the fact is
    /// the empty string (the `step.uses.ref` precedent), decidable by a
    /// `nonempty` pattern spec.
    fn authored_absent(&self, unit: &str, key: &str, key_path: &str) -> ConfigPacket {
        self.packet(
            unit,
            key,
            Some(String::new()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(self.rel_path, key_path, "absent")],
        )
    }

    /// A SHAPE-ONLY presence marker: `nonempty` or the empty string. The
    /// value itself (a URL, a PromQL expression) never rides in a packet.
    fn presence_marker(
        &self,
        unit: &str,
        key: &str,
        key_path: &str,
        v: Option<&Value>,
    ) -> ConfigPacket {
        match v {
            Some(v) if !render_value(v).trim().is_empty() => self.packet(
                unit,
                key,
                Some("nonempty".to_string()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(self.rel_path, key_path, "explicit")],
            ),
            _ => self.authored_absent(unit, key, key_path),
        }
    }

    fn rule_groups(&self, groups: &[Value], out: &mut Retrieved) {
        for (gidx, group) in groups.iter().enumerate() {
            let Some(g) = group.as_mapping() else {
                continue;
            };
            let gname = match get(g, "name").and_then(Value::as_str) {
                Some(n) => n.to_string(),
                None => format!("group[{gidx}]"),
            };
            let gunit = format!("group:{gname}");

            // group.interval: explicit, else the global evaluation_interval
            // — a Prometheus SERVER setting this file cannot see.
            match get(g, "interval") {
                Some(v) => out.packets.push(self.scalar(
                    &gunit,
                    "group.interval",
                    &format!("groups.{gname}.interval"),
                    v,
                )),
                None => out.packets.push(self.packet(
                    &gunit,
                    "group.interval",
                    None,
                    Resolution::Unresolvable,
                    vec![
                        ProvenanceStep::new(
                            self.rel_path,
                            &format!("groups.{gname}.interval"),
                            "absent",
                        ),
                        ProvenanceStep::new("", "global evaluation_interval", "project-setting"),
                    ],
                )),
            }

            let rules = get(g, "rules").and_then(Value::as_sequence);
            for rule in rules.into_iter().flatten() {
                let Some(rule) = rule.as_mapping() else {
                    continue;
                };
                // Recording rules carry no alert semantics: detected (they
                // make the file claimable) but not inventoried.
                let Some(aname) = get(rule, "alert").and_then(Value::as_str) else {
                    continue;
                };
                let unit = format!("rule:{gname}/{aname}");
                let kp = |k: &str| format!("groups.{gname}.rules.{aname}.{k}");

                // rule.for: explicit, else the documented 0s default (the
                // alert fires on first evaluation).
                match get(rule, "for") {
                    Some(v) => out
                        .packets
                        .push(self.scalar(&unit, "rule.for", &kp("for"), v)),
                    None => out.packets.push(self.packet(
                        &unit,
                        "rule.for",
                        Some("0s".to_string()),
                        Resolution::PlatformDefault,
                        vec![
                            ProvenanceStep::new(self.rel_path, &kp("for"), "absent"),
                            ProvenanceStep::new("", "for", "platform-default"),
                        ],
                    )),
                }

                // rule.labels.severity: explicit, else an authored absence.
                let labels = get(rule, "labels").and_then(Value::as_mapping);
                match labels.and_then(|l| get(l, "severity")) {
                    Some(v) => out.packets.push(self.scalar(
                        &unit,
                        "rule.labels.severity",
                        &kp("labels.severity"),
                        v,
                    )),
                    None => out.packets.push(self.authored_absent(
                        &unit,
                        "rule.labels.severity",
                        &kp("labels.severity"),
                    )),
                }

                // rule.annotations.runbook: runbook_url or runbook, as a
                // shape-only presence marker.
                let annotations = get(rule, "annotations").and_then(Value::as_mapping);
                let runbook =
                    annotations.and_then(|a| get(a, "runbook_url").or_else(|| get(a, "runbook")));
                out.packets.push(self.presence_marker(
                    &unit,
                    "rule.annotations.runbook",
                    &kp("annotations.runbook_url"),
                    runbook,
                ));

                // rule.expr: shape-only non-emptiness of the expression.
                out.packets.push(self.presence_marker(
                    &unit,
                    "rule.expr",
                    &kp("expr"),
                    get(rule, "expr"),
                ));
            }
        }
    }

    fn sloth(&self, base: &serde_yaml::Mapping, prefix: &str, out: &mut Retrieved) {
        let service = get(base, "service")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let Some(slos) = get(base, "slos").and_then(Value::as_sequence) else {
            out.unparseable = 1;
            return;
        };
        for (idx, slo) in slos.iter().enumerate() {
            let Some(s) = slo.as_mapping() else { continue };
            let name = match get(s, "name").and_then(Value::as_str) {
                Some(n) => n.to_string(),
                None => format!("slo[{idx}]"),
            };
            let unit = format!("slo:{service}/{name}");
            let kp = |k: &str| format!("{prefix}slos.{name}.{k}");

            // slo.objective: required by sloth; absence is authored breakage.
            match get(s, "objective") {
                Some(v) => {
                    out.packets
                        .push(self.scalar(&unit, "slo.objective", &kp("objective"), v))
                }
                None => {
                    out.packets
                        .push(self.authored_absent(&unit, "slo.objective", &kp("objective")))
                }
            }

            // slo.time_window: read if a variant carries it, but absent means
            // the sloth GENERATION-time --default-slo-period governs —
            // outside this file, so unresolvable, never a guessed 30d.
            match get(s, "time_window") {
                Some(v) => {
                    out.packets
                        .push(self.scalar(&unit, "slo.time_window", &kp("time_window"), v))
                }
                None => out.packets.push(self.packet(
                    &unit,
                    "slo.time_window",
                    None,
                    Resolution::Unresolvable,
                    vec![
                        ProvenanceStep::new(self.rel_path, &kp("time_window"), "absent"),
                        ProvenanceStep::new(
                            "",
                            "sloth --default-slo-period (30d default)",
                            "project-setting",
                        ),
                    ],
                )),
            }

            // slo.alerting.page_alert / ticket_alert: authored state —
            // "labeled" (labels present), "configured" (present, unlabeled),
            // "disabled" (disable: true), or "" (absent).
            let alerting = get(s, "alerting").and_then(Value::as_mapping);
            for which in ["page_alert", "ticket_alert"] {
                let key = format!("slo.alerting.{which}");
                let key_path = kp(&format!("alerting.{which}"));
                let Some(sub) = alerting.and_then(|a| get(a, which)) else {
                    out.packets
                        .push(self.authored_absent(&unit, &key, &key_path));
                    continue;
                };
                let sub_map = sub.as_mapping();
                let disabled = sub_map
                    .and_then(|m| get(m, "disable"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let labeled = sub_map
                    .and_then(|m| get(m, "labels"))
                    .and_then(Value::as_mapping)
                    .is_some_and(|l| !l.is_empty());
                let state = if disabled {
                    "disabled"
                } else if labeled {
                    "labeled"
                } else {
                    "configured"
                };
                out.packets.push(self.packet(
                    &unit,
                    &key,
                    Some(state.to_string()),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(self.rel_path, &key_path, "explicit")],
                ));
            }
        }
    }
}

fn get<'a>(m: &'a serde_yaml::Mapping, key: &str) -> Option<&'a Value> {
    m.get(Value::String(key.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packets(yaml: &str) -> Retrieved {
        PrometheusRules.retrieve("alerts/rules.yml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    const LITERAL_RULES: &str = "groups:\n- name: api\n  interval: 30s\n  rules:\n  - alert: HighErrorRate\n    expr: rate(errors[5m]) > 0.1\n    for: 5m\n    labels:\n      severity: page\n    annotations:\n      runbook_url: https://runbooks.internal/high-error-rate\n      summary: \"errors on {{ $labels.instance }}\"\n";

    const BARE_ALERT: &str =
        "groups:\n- name: api\n  rules:\n  - alert: NoMeta\n    expr: up == 0\n";

    // --- matches_head: conservative content identification ---

    #[test]
    fn matches_head_claims_literal_rule_files() {
        let r = PrometheusRules;
        assert!(r.matches_head("alerts/rules.yml", LITERAL_RULES));
        assert!(r.matches_head(
            "recording.yaml",
            "groups:\n- name: agg\n  rules:\n  - record: job:up:sum\n    expr: sum(up)\n"
        ));
    }

    #[test]
    fn matches_head_claims_sloth_native_and_crd_shapes() {
        let r = PrometheusRules;
        assert!(r.matches_head(
            "slo/api.yml",
            "version: prometheus/v1\nservice: api\nslos:\n- name: availability\n  objective: 99.9\n"
        ));
        assert!(r.matches_head(
            "slo/api.yaml",
            "apiVersion: sloth.slok.dev/v1\nkind: PrometheusServiceLevel\nspec:\n  service: api\n"
        ));
    }

    #[test]
    fn matches_head_declines_what_is_not_conservatively_ours() {
        let r = PrometheusRules;
        // Generic Kubernetes manifests are family .20's, not ours.
        assert!(!r.matches_head(
            "k8s/deploy.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\n"
        ));
        // A PrometheusRule CRD is a Kubernetes manifest too.
        assert!(!r.matches_head(
            "k8s/rules.yaml",
            "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nspec:\n  groups: []\n"
        ));
        // Unknown YAML is not a sighting and not a claim.
        assert!(!r.matches_head("docs/notes.yaml", "a: b\n"));
        // groups: without any alert/record rule is not identifiable as ours.
        assert!(!r.matches_head("cfg.yml", "groups:\n- name: x\n  settings: {}\n"));
        // Non-YAML extensions are never consulted.
        assert!(!r.matches_head("rules.txt", LITERAL_RULES));
    }

    #[test]
    fn matches_head_declines_helm_templated_rule_files() {
        // No templating resolution beyond literal YAML: a templated file is
        // declined here and SIGHTED by the walk (prometheus-rules-templated).
        let templated = "groups:\n- name: api\n  rules:\n  - alert: A\n    expr: up == 0\n    for: {{- .Values.forDuration }}\n";
        assert!(!PrometheusRules.matches_head("chart/templates/rules.yml", templated));
        // But Prometheus's OWN templating in annotations stays literal.
        assert!(PrometheusRules.matches_head("alerts/rules.yml", LITERAL_RULES));
    }

    // --- per-alert facts with file + group + rule provenance ---

    #[test]
    fn explicit_alert_facts_resolve_as_authored_with_group_rule_chain() {
        let got = packets(LITERAL_RULES);
        let f = find(&got, "rule:api/HighErrorRate", "rule.for");
        assert_eq!(f.resolved_value.as_deref(), Some("5m"));
        assert_eq!(f.resolution, Resolution::AsAuthored);
        assert_eq!(
            f.provenance[0].key_path, "groups.api.rules.HighErrorRate.for",
            "provenance chains file + group + rule name"
        );
        assert_eq!(f.provenance[0].role, "explicit");

        let sev = find(&got, "rule:api/HighErrorRate", "rule.labels.severity");
        assert_eq!(sev.resolved_value.as_deref(), Some("page"));
        assert_eq!(sev.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn runbook_and_expr_are_shape_only_markers_never_content() {
        let got = packets(LITERAL_RULES);
        let rb = find(&got, "rule:api/HighErrorRate", "rule.annotations.runbook");
        assert_eq!(
            rb.resolved_value.as_deref(),
            Some("nonempty"),
            "the URL itself must never ride in a packet"
        );
        let expr = find(&got, "rule:api/HighErrorRate", "rule.expr");
        assert_eq!(
            expr.resolved_value.as_deref(),
            Some("nonempty"),
            "PromQL content must never ride in a packet"
        );
        // Nothing anywhere in the packets carries the URL or the PromQL.
        for p in &got.packets {
            let v = p.resolved_value.as_deref().unwrap_or("");
            assert!(!v.contains("runbooks.internal"), "leaked URL: {p:?}");
            assert!(!v.contains("rate(errors"), "leaked PromQL: {p:?}");
        }
    }

    #[test]
    fn absent_for_resolves_the_documented_zero_seconds_default() {
        let got = packets(BARE_ALERT);
        let p = find(&got, "rule:api/NoMeta", "rule.for");
        assert_eq!(p.resolved_value.as_deref(), Some("0s"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
        assert_eq!(p.provenance[1].file, "", "a platform default names no file");
    }

    #[test]
    fn absent_severity_runbook_and_expr_are_authored_absences() {
        // No platform supplies a severity label or a runbook annotation:
        // absence is an authored fact, the empty string (the step.uses.ref
        // precedent), decidable by a `nonempty` pattern spec.
        let got = packets(BARE_ALERT);
        let sev = find(&got, "rule:api/NoMeta", "rule.labels.severity");
        assert_eq!(sev.resolved_value.as_deref(), Some(""));
        assert_eq!(sev.resolution, Resolution::AsAuthored);
        assert_eq!(sev.provenance[0].role, "absent");
        let rb = find(&got, "rule:api/NoMeta", "rule.annotations.runbook");
        assert_eq!(rb.resolved_value.as_deref(), Some(""));
        let expr = find(&got, "rule:api/NoMeta", "rule.expr");
        assert_eq!(expr.resolved_value.as_deref(), Some("nonempty"));
    }

    #[test]
    fn group_interval_explicit_else_unresolvable_global_setting() {
        let got = packets(LITERAL_RULES);
        let p = find(&got, "group:api", "group.interval");
        assert_eq!(p.resolved_value.as_deref(), Some("30s"));
        assert_eq!(p.resolution, Resolution::AsAuthored);

        let got = packets(BARE_ALERT);
        let p = find(&got, "group:api", "group.interval");
        assert_eq!(
            p.resolution,
            Resolution::Unresolvable,
            "the global evaluation_interval lives in the server config"
        );
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance.last().unwrap().role, "project-setting");
    }

    #[test]
    fn templated_values_inside_literal_yaml_are_unresolvable_not_guessed() {
        // A QUOTED template smuggled into otherwise literal YAML parses fine
        // but resolves to nothing without rendering: an abstention class.
        let got = packets(
            "groups:\n- name: api\n  rules:\n  - alert: T\n    expr: up == 0\n    for: \"{{ .Values.forDuration }}\"\n",
        );
        let p = find(&got, "rule:api/T", "rule.for");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance[0].role, "templated");
    }

    #[test]
    fn recording_rules_emit_no_per_rule_packets() {
        let got =
            packets("groups:\n- name: agg\n  rules:\n  - record: job:up:sum\n    expr: sum(up)\n");
        assert!(
            got.packets.iter().all(|p| !p.unit.starts_with("rule:")),
            "record rules carry no alert semantics: {:?}",
            got.packets
        );
        // The group-level fact still emits.
        assert!(got.packets.iter().any(|p| p.unit == "group:agg"));
    }

    // --- sloth SLO definitions ---

    const SLOTH_NATIVE: &str = "version: prometheus/v1\nservice: api\nslos:\n- name: availability\n  objective: 99.9\n  alerting:\n    name: ApiAvailability\n    page_alert:\n      labels:\n        severity: page\n    ticket_alert:\n      disable: true\n";

    #[test]
    fn sloth_native_emits_objective_window_and_alerting_facts() {
        let got = packets(SLOTH_NATIVE);
        let obj = find(&got, "slo:api/availability", "slo.objective");
        assert_eq!(obj.resolved_value.as_deref(), Some("99.9"));
        assert_eq!(obj.resolution, Resolution::AsAuthored);
        assert_eq!(obj.provenance[0].key_path, "slos.availability.objective");

        // The window is a sloth GENERATION-time setting: absent from the
        // file means unresolvable, never a guessed 30d.
        let win = find(&got, "slo:api/availability", "slo.time_window");
        assert_eq!(win.resolution, Resolution::Unresolvable);
        assert_eq!(win.provenance.last().unwrap().role, "project-setting");

        let page = find(&got, "slo:api/availability", "slo.alerting.page_alert");
        assert_eq!(
            page.resolved_value.as_deref(),
            Some("labeled"),
            "page alert configured with labels"
        );
        let ticket = find(&got, "slo:api/availability", "slo.alerting.ticket_alert");
        assert_eq!(ticket.resolved_value.as_deref(), Some("disabled"));
    }

    #[test]
    fn sloth_without_alerting_is_an_authored_absence() {
        let got =
            packets("version: prometheus/v1\nservice: api\nslos:\n- name: lat\n  objective: 99\n");
        let page = find(&got, "slo:api/lat", "slo.alerting.page_alert");
        assert_eq!(page.resolved_value.as_deref(), Some(""));
        assert_eq!(page.resolution, Resolution::AsAuthored);
        assert_eq!(page.provenance[0].role, "absent");
    }

    #[test]
    fn sloth_crd_form_reads_under_spec_with_spec_prefixed_provenance() {
        let got = packets(
            "apiVersion: sloth.slok.dev/v1\nkind: PrometheusServiceLevel\nmetadata:\n  name: api\nspec:\n  service: api\n  slos:\n  - name: availability\n    objective: 99.9\n",
        );
        let obj = find(&got, "slo:api/availability", "slo.objective");
        assert_eq!(obj.resolved_value.as_deref(), Some("99.9"));
        assert_eq!(
            obj.provenance[0].key_path,
            "spec.slos.availability.objective"
        );
    }

    // --- degradation ---

    #[test]
    fn malformed_yaml_degrades_to_an_unparseable_count() {
        let got = packets("groups: [unclosed\n  - {");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    #[test]
    fn claimed_yaml_that_is_neither_rules_nor_sloth_counts_unparseable() {
        // Cannot happen via the walk (matches_head gates), but the retriever
        // must still degrade honestly if handed the wrong file.
        let got = packets("some: config\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }
}
