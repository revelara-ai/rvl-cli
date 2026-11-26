//! Prometheus alert/recording rules + sloth SLO retriever: family (3) of the
//! G6 config lane, and the first CONTENT-identified format (rule files have
//! no canonical path, so the walk consults [`ConfigRetriever::matches_head`]
//! with a bounded head before a file degrades to a sighting).
//!
//! Claims, conservatively:
//!
//!   * literal Prometheus rule files — top-level `groups:` whose rules carry
//!     `alert:` / `record:`;
//!   * the same rule groups under `spec.groups` of a rule resource
//!     ([`rule_container`]): a `PrometheusRule`, a VictoriaMetrics `VMRule`,
//!     or a Google Managed Prometheus `Rules` / `ClusterRules` /
//!     `GlobalRules`, unless an Argo/Flux or operator CR in the same file
//!     makes the file another family's;
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
//!     (no platform supplies a severity), emitted as the empty string. Also
//!     a guard predicate ([`crate::ConfigPredicate`]) of the same key, read
//!     lower-cased and from the `priority` label when `severity` is absent,
//!     so `when rule.labels.severity one_of [critical, page, p1]` matches
//!     `Critical` and `priority: P1`. A templated label states no predicate.
//!   * `rule.annotations.runbook` — presence of a `runbook_url` / `runbook`
//!     annotation. SHAPE-ONLY: the packet carries the marker `nonempty`,
//!     never the URL (runbook locations are repo-internal content).
//!   * `rule.annotations.runbook.target` — where that annotation points, as
//!     a status only: `resolved` (a schemeless, hostless path, `#fragment`
//!     dropped, that exists relative to the rule file's directory or the
//!     repository root), `missing` (it exists in neither), or `external`
//!     (any scheme or host; never fetched). A templated path is
//!     unresolvable. Emitted only when the walk hands the retriever the
//!     repository root and the annotation is set; the link itself never
//!     rides in a packet either.
//!   * the RC-006 abstain facts, each a guard predicate: per alert rule
//!     `rule.annotations.link_like` (`present` when an annotation key names
//!     a link or a value holds one, see [`link_like`]), `rule.name_unique`
//!     (`false` when the group has another rule of the same alert name and
//!     not all of them are paging rules without a runbook), and
//!     `rule.kustomize_patched` (`true` for a `PrometheusRule` a kustomize
//!     patch targets); per file, from one walk of the repository
//!     ([`crate::prometheus_repo`]), `repo.alertmanager.mentions_runbook`
//!     and `repo.alertmanager.paging_receiver`. `rule.kustomize_patched`
//!     and the repo facts are emitted only when the walk hands over the
//!     root. Three more: per file `file.rule_pack_path` (`true` when the
//!     path holds a [`RULE_PACK_PATH_TOKENS`] token), per alert rule
//!     `rule.group.upstream_mixin` (`true` when the group name is one of
//!     [`UPSTREAM_MIXIN_GROUPS`]), and from the walk
//!     `repo.alertmanager.disabled`.
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
//! A paging rule (severity `critical`, `page` or `p1`) with no runbook is
//! the finding RC-006 asks for, and a blind check of such flags found its
//! wrong and disputed flags where one of these held. So the
//! `rule.annotations.runbook` packet of a rule with no runbook, or a
//! templated one, is carried undecided with the first reason that holds:
//! a templated runbook value, a link-like annotation (a judge must read the
//! link), a skill package or copy-me template path, an Alertmanager config
//! or template that composes the link, receivers that page nobody,
//! Alertmanager switched off in Helm values, receivers whose only
//! paging-capable integration is a webhook, a duplicate alert name, a group
//! name copied from an upstream mixin, a kustomize patch that can change
//! the severity. Every packet of a rule file that is a
//! vendored or generated pack
//! ([`crate::non_production::vendored_token`]) is carried undecided too,
//! the way a non-production file's are. The rule's other packets keep
//! their values: none of these reasons is about `for:` or the expression.
//!
//! Recording rules are detected (they make a file claimable) but emit no
//! per-rule packets: `for:` and severity semantics are alert-only, and a
//! record rule's health is promtool's job, not a reliability control's.

use crate::argo_flux::{group_of, head_scan};
use crate::prometheus_repo::{Paging, RepoFacts};
use crate::{
    render_value, ConfigPacket, ConfigPredicate, ConfigRetriever, ProvenanceStep, Resolution,
    Retrieved,
};
use serde::Deserialize;
use serde_yaml::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub struct PrometheusRules;

/// Helm/Go-template markers, distinguished from Prometheus's own alert
/// templating (`{{ $labels.x }}`, `{{ $value }}`), which is legitimate inside
/// literal rule files: Helm control lines carry `{{-` and Helm data comes
/// from `.Values` / `.Release`.
pub(crate) fn helm_templated(text: &str) -> bool {
    text.contains("{{-") || text.contains(".Values") || text.contains(".Release")
}

/// The severities that page, read lower-cased: the guard of the RC-006 spec
/// as it was measured. A duplicate alert name only counts against a rule
/// when its twins are not all paging rules without a runbook.
const PAGING_SEVERITIES: &[&str] = &["critical", "page", "p1"];

/// Annotation key fragments (any case) that name a link of some kind.
const LINK_KEY_WORDS: &[&str] = &[
    "runbook",
    "playbook",
    "sop",
    "wiki",
    "doc",
    "procedure",
    "remediation",
    "troubleshoot",
    "guide",
    "link",
    "url",
];

/// Annotation value fragments (any case) that hold a link of some kind.
const LINK_VALUE_WORDS: &[&str] = &["http://", "https://", "runbook", "playbook"];

/// Path tokens (any case, of any directory or the file stem) of a rule file
/// that ships for others to copy or adapt: a skill package an assistant
/// installs, or a template a user fills in. The rule's severity and
/// annotations are the consumer's to set. Read for rule files only: a
/// chart's `templates/` is a production path for other retrievers, and a
/// `PrometheusRule` in one is a chart whose consumer decides its values.
const RULE_PACK_PATH_TOKENS: &[&str] = &["skill", "skills", "template", "templates"];

/// Rule group names of the upstream monitoring mixins, as kube-prometheus
/// and the kube-prometheus-stack chart render them: kubernetes-mixin,
/// node-exporter, Alertmanager, Prometheus, prometheus-operator,
/// kube-state-metrics and etcd. A group of one of these names is a copy of
/// the upstream pack even where no vendored path token says so, and its
/// runbook links are the upstream's choice, not the repository's.
const UPSTREAM_MIXIN_GROUPS: &[&str] = &[
    "alertmanager.rules",
    "config-reloaders",
    "etcd",
    "general.rules",
    "k8s.rules",
    "kube-apiserver-availability.rules",
    "kube-apiserver-burnrate.rules",
    "kube-apiserver-histogram.rules",
    "kube-apiserver-slos",
    "kube-prometheus-general.rules",
    "kube-prometheus-node-recording.rules",
    "kube-scheduler.rules",
    "kube-state-metrics",
    "kubelet.rules",
    "kubernetes-apps",
    "kubernetes-resources",
    "kubernetes-storage",
    "kubernetes-system",
    "kubernetes-system-apiserver",
    "kubernetes-system-controller-manager",
    "kubernetes-system-kube-proxy",
    "kubernetes-system-kubelet",
    "kubernetes-system-scheduler",
    "node-exporter",
    "node-exporter.rules",
    "node-network",
    "node.rules",
    "prometheus",
    "prometheus-operator",
];

/// The [`RULE_PACK_PATH_TOKENS`] token of `rel_path`, if any: its
/// directories and file stem split at every character that is not a letter
/// or a digit.
fn rule_pack_token(rel_path: &str) -> Option<&'static str> {
    let stem = rel_path.rsplit_once('.').map_or(rel_path, |(stem, _)| stem);
    stem.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .find_map(|t| RULE_PACK_PATH_TOKENS.iter().copied().find(|w| *w == t))
}

/// Whether an `apiVersion` + `kind` is a resource whose `spec.groups` hold
/// Prometheus rule groups.
fn rule_container(api_version: &str, kind: &str) -> bool {
    matches!(
        (group_of(api_version), kind),
        ("monitoring.coreos.com", "PrometheusRule")
            | ("operator.victoriametrics.com", "VMRule")
            | (
                "monitoring.googleapis.com",
                "Rules" | "ClusterRules" | "GlobalRules"
            )
    )
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
        // A rule resource is ours unless the file is another family's: the
        // Kubernetes family declines any file with a foreign group, but the
        // Argo/Flux and operator retrievers claim theirs from mixed files.
        if head_scan(head)
            .iter()
            .any(|(api, kind)| rule_container(api, kind))
        {
            return !crate::argo_flux::ArgoFlux.matches_head(rel_path, head)
                && !crate::operators::OperatorCrs.matches_head(rel_path, head);
        }
        // Any other manifest is the Kubernetes family's, not ours.
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
        retrieve_in(None, None, rel_path, contents, snapshot_id)
    }

    /// One file with the root: a runbook link can be resolved, and the
    /// repository is walked once for its facts.
    fn retrieve_with_root(
        &self,
        root: &Path,
        rel_path: &str,
        contents: &str,
        snapshot_id: &str,
    ) -> Retrieved {
        let facts = RepoFacts::read(root);
        retrieve_in(Some(root), Some(&facts), rel_path, contents, snapshot_id)
    }

    /// The walk's entry: every claimed file shares one walk of the
    /// repository for its facts.
    fn retrieve_all(
        &self,
        root: &Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let facts = RepoFacts::read(root);
        let mut out = Retrieved::default();
        for (rel, contents) in files {
            let got = retrieve_in(Some(root), Some(&facts), rel, contents, snapshot_id);
            out.packets.extend(got.packets);
            out.predicates.extend(got.predicates);
            out.unparseable += got.unparseable;
        }
        out
    }
}

/// A rule file that is not deployed to production, or is a vendored or
/// generated pack, carries every fact undecided
/// ([`crate::non_production::undecide_unit`]).
fn retrieve_in(
    repo_root: Option<&Path>,
    repo: Option<&RepoFacts>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    let mut out = retrieve_file(repo_root, repo, rel_path, contents, snapshot_id);
    crate::non_production::undecide_unit(repo_root, rel_path, &mut out);
    if let Some(token) = crate::non_production::vendored_token(repo_root, rel_path) {
        let why = format!("vendored or generated rule pack: {token}");
        for p in &mut out.packets {
            crate::non_production::undecide(p, &why);
        }
    }
    out
}

fn retrieve_file(
    repo_root: Option<&Path>,
    repo: Option<&RepoFacts>,
    rel_path: &str,
    contents: &str,
    snapshot_id: &str,
) -> Retrieved {
    let mut out = Retrieved::default();
    let docs: Result<Vec<Value>, _> = serde_yaml::Deserializer::from_str(contents)
        .map(Value::deserialize)
        .collect();
    let Ok(docs) = docs else {
        out.unparseable = 1;
        return out;
    };
    let em = Emitter {
        root: repo_root,
        repo,
        rel_path,
        snapshot_id,
    };
    // Sloth first (native root or CRD `spec:`), then rule files and rule
    // resources; a claimed file with none of them degrades to an
    // unparseable count. Other documents of a rule resource's file (its
    // Service, its ServiceMonitor) are not ours and are skipped.
    let mut read = false;
    for root in docs.iter().filter_map(Value::as_mapping) {
        let spec = get(root, "spec").and_then(Value::as_mapping);
        let str_of = |k: &str| get(root, k).and_then(Value::as_str).unwrap_or("");
        let rule_groups = spec
            .and_then(|s| get(s, "groups"))
            .and_then(Value::as_sequence)
            .filter(|_| rule_container(str_of("apiVersion"), str_of("kind")));
        if get(root, "slos").is_some() {
            em.sloth(root, "", &mut out);
        } else if let Some(spec) = spec.filter(|s| get(s, "slos").is_some()) {
            em.sloth(spec, "spec.", &mut out);
        } else if let Some(groups) = get(root, "groups").and_then(Value::as_sequence) {
            em.rule_groups(groups, None, "", &mut out);
        } else if let Some(groups) = rule_groups {
            // Only a PrometheusRule is a kustomize patch target here.
            let target = (str_of("kind") == "PrometheusRule").then(|| {
                get(root, "metadata")
                    .and_then(Value::as_mapping)
                    .and_then(|m| get(m, "name"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
            });
            em.rule_groups(groups, target, "spec.", &mut out);
        } else {
            continue;
        }
        read = true;
    }
    if read {
        em.file_predicates(&mut out);
    } else {
        out.unparseable = 1;
    }
    out
}

/// What the rule's group says about one alert rule.
#[derive(Clone, Copy)]
struct RuleFacts<'a> {
    /// The group has no other rule of this alert name, or every one of them
    /// is a paging rule without a runbook.
    unique: bool,
    /// The group name is one of [`UPSTREAM_MIXIN_GROUPS`].
    upstream: bool,
    /// The name of the `PrometheusRule` the rule is in; `None` for any
    /// other container.
    patch_target: Option<&'a str>,
}

/// Shared packet plumbing for one file.
struct Emitter<'a> {
    root: Option<&'a Path>,
    /// The repository's facts; `None` when no root was handed over.
    repo: Option<&'a RepoFacts>,
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
            key: crate::key_ledger::declared("prometheus-rules", key),
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

    /// `rule.annotations.runbook.target`: the status of where the runbook
    /// annotation points. None without a root (nothing can be resolved) or
    /// without an annotation (the presence key already judges that).
    fn runbook_target(
        &self,
        unit: &str,
        key_path: &str,
        v: Option<&Value>,
    ) -> Option<ConfigPacket> {
        let root = self.root?;
        let link = render_value(v?);
        let link = link.trim();
        if link.is_empty() {
            return None;
        }
        let key = "rule.annotations.runbook.target";
        let status = if is_external(link) {
            "external"
        } else if link.contains("{{") {
            // `{{ $externalURL }}/runbooks/x`: nothing is rendered on the
            // scan path, so where it points is unknowable here.
            return Some(self.packet(
                unit,
                key,
                None,
                Resolution::Unresolvable,
                vec![ProvenanceStep::new(self.rel_path, key_path, "templated")],
            ));
        } else if resolves_in_repo(root, self.rel_path, link) {
            "resolved"
        } else {
            "missing"
        };
        Some(self.packet(
            unit,
            key,
            Some(status.to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(self.rel_path, key_path, "explicit")],
        ))
    }

    /// A guard predicate about `unit` of this file.
    fn predicate(&self, unit: &str, key: &str, value: &str) -> ConfigPredicate {
        ConfigPredicate {
            file_path: self.rel_path.to_string(),
            unit: unit.to_string(),
            key: crate::key_ledger::declared("prometheus-rules", key),
            values: vec![value.to_string()],
        }
    }

    /// The file's and the repository's facts, true of every rule in the
    /// file.
    fn file_predicates(&self, out: &mut Retrieved) {
        let unit = crate::FILE_SCOPE;
        out.predicates.push(self.predicate(
            unit,
            "file.rule_pack_path",
            &rule_pack_token(self.rel_path).is_some().to_string(),
        ));
        let Some(repo) = self.repo else { return };
        out.predicates.push(self.predicate(
            unit,
            "repo.alertmanager.mentions_runbook",
            &repo.mentions_runbook.to_string(),
        ));
        out.predicates.push(self.predicate(
            unit,
            "repo.alertmanager.paging_receiver",
            repo.paging.as_str(),
        ));
        out.predicates.push(self.predicate(
            unit,
            "repo.alertmanager.disabled",
            &repo.alertmanager_disabled.to_string(),
        ));
    }

    /// The groups of one rule file or rule resource. `patch_target` is the
    /// name of the `PrometheusRule` they are in, `None` for any other
    /// container; `prefix` leads every key path (`spec.` in a resource).
    fn rule_groups(
        &self,
        groups: &[Value],
        patch_target: Option<&str>,
        prefix: &str,
        out: &mut Retrieved,
    ) {
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
                    &format!("{prefix}groups.{gname}.interval"),
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
                            &format!("{prefix}groups.{gname}.interval"),
                            "absent",
                        ),
                        ProvenanceStep::new("", "global evaluation_interval", "project-setting"),
                    ],
                )),
            }

            // Recording rules carry no alert semantics: detected (they make
            // the file claimable) but not inventoried.
            let rules: Vec<(&str, &serde_yaml::Mapping)> = get(g, "rules")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(Value::as_mapping)
                .filter_map(|r| Some((get(r, "alert")?.as_str()?, r)))
                .collect();
            // Whether each alert name is held by one rule, or by several
            // that are all paging rules without a runbook: a twin that is
            // not (the warning half of a mixin's pair) may be the rule a
            // reader meant.
            let mut twins: BTreeMap<&str, Vec<bool>> = BTreeMap::new();
            for (aname, rule) in &rules {
                twins.entry(aname).or_default().push(would_flag(rule));
            }
            for (aname, rule) in rules {
                let unit = format!("rule:{gname}/{aname}");
                let kp = |k: &str| format!("{prefix}groups.{gname}.rules.{aname}.{k}");
                let unique = twins
                    .get(aname)
                    .is_none_or(|t| t.len() == 1 || t.iter().all(|f| *f));
                let upstream = UPSTREAM_MIXIN_GROUPS.contains(&gname.as_str());
                let rule_facts = RuleFacts {
                    unique,
                    upstream,
                    patch_target,
                };
                self.alert_rule(&unit, &kp, rule, rule_facts, out);
            }
        }
    }

    /// The packets and predicates of one alert rule.
    fn alert_rule(
        &self,
        unit: &str,
        kp: &dyn Fn(&str) -> String,
        rule: &serde_yaml::Mapping,
        facts: RuleFacts,
        out: &mut Retrieved,
    ) {
        let RuleFacts {
            unique,
            upstream,
            patch_target,
        } = facts;
        // rule.for: explicit, else the documented 0s default (the alert
        // fires on first evaluation).
        match get(rule, "for") {
            Some(v) => out
                .packets
                .push(self.scalar(unit, "rule.for", &kp("for"), v)),
            None => out.packets.push(self.packet(
                unit,
                "rule.for",
                Some("0s".to_string()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(self.rel_path, &kp("for"), "absent"),
                    ProvenanceStep::new("", "for", "platform-default"),
                ],
            )),
        }

        // rule.labels.severity: explicit, else an authored absence. The
        // guard predicate reads it lower-cased, `priority` standing in.
        let labels = get(rule, "labels").and_then(Value::as_mapping);
        match labels.and_then(|l| get(l, "severity")) {
            Some(v) => out.packets.push(self.scalar(
                unit,
                "rule.labels.severity",
                &kp("labels.severity"),
                v,
            )),
            None => out.packets.push(self.authored_absent(
                unit,
                "rule.labels.severity",
                &kp("labels.severity"),
            )),
        }
        if let Some(severity) = severity(rule) {
            out.predicates
                .push(self.predicate(unit, "rule.labels.severity", &severity));
        }

        // rule.annotations.runbook: runbook_url or runbook, as a shape-only
        // presence marker.
        let annotations = get(rule, "annotations").and_then(Value::as_mapping);
        let runbook = runbook(rule);
        let mut packet = self.presence_marker(
            unit,
            "rule.annotations.runbook",
            &kp("annotations.runbook_url"),
            runbook,
        );
        let link = link_like(annotations);
        let patched =
            patch_target.is_some_and(|name| self.repo.is_some_and(|r| r.patches_rule(name)));
        let templated = runbook.is_some_and(|v| render_value(v).contains("{{"));
        if packet.resolved_value.as_deref() == Some("") || templated {
            let repo = self.repo;
            let pack = rule_pack_token(self.rel_path)
                .map(|t| format!("a skill package or template to copy: {t}"));
            let why = [
                (templated, "templated runbook value"),
                (link, "a link-like annotation: a reader must judge the link"),
                (pack.is_some(), pack.as_deref().unwrap_or("")),
                (
                    repo.is_some_and(|r| r.mentions_runbook),
                    "an Alertmanager config or template mentions a runbook",
                ),
                (
                    repo.is_some_and(|r| r.paging == Paging::No),
                    "no receiver can page: alerts go to chat, email or nowhere",
                ),
                (
                    repo.is_some_and(|r| r.alertmanager_disabled),
                    "Helm values switch Alertmanager off",
                ),
                (
                    repo.is_some_and(|r| r.paging == Paging::WebhookOnly),
                    "only a webhook receiver: whether it pages cannot be told",
                ),
                (!unique, "another rule of the group has this alert name"),
                (upstream, "the group name of an upstream mixin rule pack"),
                (patched, "a kustomize patch targets this PrometheusRule"),
            ]
            .into_iter()
            .find_map(|(holds, why)| holds.then_some(why));
            if let Some(why) = why {
                crate::non_production::undecide(&mut packet, why);
            }
        }
        out.packets.push(packet);
        if let Some(p) = self.runbook_target(unit, &kp("annotations.runbook_url"), runbook) {
            out.packets.push(p);
        }
        let present = if link { "present" } else { "absent" };
        out.predicates
            .push(self.predicate(unit, "rule.annotations.link_like", present));
        out.predicates
            .push(self.predicate(unit, "rule.name_unique", &unique.to_string()));
        out.predicates.push(self.predicate(
            unit,
            "rule.group.upstream_mixin",
            &upstream.to_string(),
        ));
        if self.repo.is_some() {
            out.predicates.push(self.predicate(
                unit,
                "rule.kustomize_patched",
                &patched.to_string(),
            ));
        }

        // rule.expr: shape-only non-emptiness of the expression.
        out.packets
            .push(self.presence_marker(unit, "rule.expr", &kp("expr"), get(rule, "expr")));
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
            for (which, key) in [
                ("page_alert", "slo.alerting.page_alert"),
                ("ticket_alert", "slo.alerting.ticket_alert"),
            ] {
                let key_path = kp(&format!("alerting.{which}"));
                let Some(sub) = alerting.and_then(|a| get(a, which)) else {
                    out.packets
                        .push(self.authored_absent(&unit, key, &key_path));
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
                    key,
                    Some(state.to_string()),
                    Resolution::AsAuthored,
                    vec![ProvenanceStep::new(self.rel_path, &key_path, "explicit")],
                ));
            }
        }
    }
}

/// The runbook annotation of an alert rule: `runbook_url`, else `runbook`.
fn runbook(rule: &serde_yaml::Mapping) -> Option<&Value> {
    let annotations = get(rule, "annotations").and_then(Value::as_mapping)?;
    get(annotations, "runbook_url").or_else(|| get(annotations, "runbook"))
}

/// The severity a guard reads: the `severity` label, else `priority`,
/// trimmed and lower-cased; the empty string when neither is set. `None`
/// for a templated label, whose rendered value is unknowable here.
fn severity(rule: &serde_yaml::Mapping) -> Option<String> {
    let labels = get(rule, "labels").and_then(Value::as_mapping);
    let Some(v) = labels.and_then(|l| get(l, "severity").or_else(|| get(l, "priority"))) else {
        return Some(String::new());
    };
    let v = render_value(v);
    (!v.contains("{{")).then(|| v.trim().to_lowercase())
}

/// Whether the rule is what RC-006 flags: a paging severity and no runbook.
fn would_flag(rule: &serde_yaml::Mapping) -> bool {
    let paging = severity(rule).is_some_and(|s| PAGING_SEVERITIES.contains(&s.as_str()));
    paging && runbook(rule).is_none_or(|v| render_value(v).trim().is_empty())
}

/// Whether any annotation key names a link ([`LINK_KEY_WORDS`]) or any
/// annotation value holds one ([`LINK_VALUE_WORDS`]), in any case.
fn link_like(annotations: Option<&serde_yaml::Mapping>) -> bool {
    annotations.into_iter().flatten().any(|(k, v)| {
        let k = render_value(k).to_lowercase();
        let v = render_value(v).to_lowercase();
        LINK_KEY_WORDS.iter().any(|w| k.contains(w))
            || LINK_VALUE_WORDS.iter().any(|w| v.contains(w))
    })
}

/// A link with a scheme (`https:`, `mailto:`, RFC 3986's grammar) or a host
/// (`//wiki/x`) points outside the repository. It is never fetched.
fn is_external(link: &str) -> bool {
    if link.starts_with("//") {
        return true;
    }
    match link.split_once(':') {
        Some((scheme, _)) => {
            scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        None => false,
    }
}

/// Whether a repo link, its `#fragment` dropped, names a path that exists
/// relative to the rule file's directory or the repository root (a leading
/// `/` means the root only). The path is normalized lexically and a `..`
/// above the root names nothing, so no check leaves the root.
fn resolves_in_repo(root: &Path, rule_file: &str, link: &str) -> bool {
    let path = link.split('#').next().unwrap_or("");
    // A link naming no path (`#section`) names no runbook.
    if path.split('/').all(|seg| seg.is_empty() || seg == ".") {
        return false;
    }
    let rule_dir: Vec<&str> = match rule_file.rsplit_once('/') {
        Some((dir, _)) if !path.starts_with('/') => dir.split('/').collect(),
        _ => Vec::new(),
    };
    let mut bases = vec![rule_dir];
    if !bases[0].is_empty() {
        bases.push(Vec::new());
    }
    bases.into_iter().any(|mut parts| {
        for seg in path.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return false;
                    }
                }
                s => parts.push(s),
            }
        }
        !parts.is_empty() && root.join(parts.join("/")).exists()
    })
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
        // Another monitoring.coreos.com kind is not a rule resource.
        assert!(!r.matches_head(
            "k8s/monitor.yaml",
            "apiVersion: monitoring.coreos.com/v1\nkind: ServiceMonitor\nspec:\n  endpoints: []\n"
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
    fn a_rule_file_under_a_non_production_path_carries_every_fact_undecided() {
        let got = PrometheusRules.retrieve("deploy/test-apps/rules.yml", BARE_ALERT, "snap");
        assert!(!got.packets.is_empty());
        // An unresolvable packet abstains already and keeps its own chain.
        for p in got
            .packets
            .iter()
            .filter(|p| p.resolution != Resolution::Unresolvable)
        {
            assert_eq!(
                p.resolved_value.as_deref(),
                Some("undecided: non-production path: test"),
                "{}",
                p.key
            );
        }
    }

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

    // --- rule.annotations.runbook.target: a status, never the link ---

    /// A rule file at `alerts/rules.yml` whose one alert links `link`, retrieved
    /// with a repository root holding `docs/runbooks/high-errors.md` and
    /// `alerts/runbooks/disk.md`.
    fn target(link: &str) -> ConfigPacket {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("docs/runbooks")).unwrap();
        std::fs::write(root.join("docs/runbooks/high-errors.md"), "# steps\n").unwrap();
        std::fs::create_dir_all(root.join("alerts/runbooks")).unwrap();
        std::fs::write(root.join("alerts/runbooks/disk.md"), "# steps\n").unwrap();
        let yaml = format!(
            "groups:\n- name: api\n  rules:\n  - alert: A\n    expr: up == 0\n    annotations:\n      runbook_url: {link:?}\n"
        );
        let got = PrometheusRules.retrieve_with_root(root, "alerts/rules.yml", &yaml, "snap");
        for p in &got.packets {
            // An undecided reason is fixed text; only the link must not ride.
            let v = p.resolved_value.as_deref().unwrap_or("");
            let reason = v.starts_with(crate::UNDECIDED_PREFIX);
            assert!(
                !v.contains(if reason { link } else { "runbook" }),
                "the link rides in a packet: {p:?}"
            );
        }
        find(&got, "rule:api/A", "rule.annotations.runbook.target").clone()
    }

    #[test]
    fn runbook_target_resolves_from_the_rule_directory_or_the_root() {
        for link in [
            "runbooks/disk.md",
            "./runbooks/disk.md",
            "../docs/runbooks/high-errors.md",
            "docs/runbooks/high-errors.md",
            "/docs/runbooks/high-errors.md",
            "docs/runbooks/high-errors.md#mitigation",
            "docs/runbooks",
        ] {
            let p = target(link);
            assert_eq!(p.resolved_value.as_deref(), Some("resolved"), "{link}");
            assert_eq!(p.resolution, Resolution::AsAuthored, "{link}");
            assert_eq!(p.provenance[0].role, "explicit");
        }
    }

    #[test]
    fn runbook_target_is_missing_when_neither_base_has_the_path() {
        for link in [
            "docs/runbooks/gone.md",
            // A leading `/` is the root only, never the rule's directory.
            "/runbooks/disk.md",
            // A `..` above the root names nothing.
            "../../docs/runbooks/high-errors.md",
            "#mitigation",
        ] {
            assert_eq!(
                target(link).resolved_value.as_deref(),
                Some("missing"),
                "{link}"
            );
        }
    }

    #[test]
    fn runbook_target_is_external_for_any_scheme_or_host() {
        for link in [
            "https://runbooks.example.com/high-errors",
            "http://wiki/runbooks/disk.md",
            "mailto:oncall@example.com",
            "//wiki.example.com/runbooks",
            "https://{{ $labels.cluster }}.example.com/runbook",
        ] {
            assert_eq!(
                target(link).resolved_value.as_deref(),
                Some("external"),
                "{link}"
            );
        }
    }

    #[test]
    fn runbook_target_with_a_templated_path_is_unresolvable() {
        let p = target("{{ $externalURL }}/runbooks/disk.md");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance[0].role, "templated");
    }

    #[test]
    fn runbook_target_needs_a_root_and_an_annotation() {
        // Without the root nothing can be resolved, and without an annotation
        // the presence key already says so: no target packet either way.
        let got = packets(LITERAL_RULES);
        assert!(got
            .packets
            .iter()
            .all(|p| p.key != "rule.annotations.runbook.target"));
        let dir = tempfile::tempdir().unwrap();
        let got = PrometheusRules.retrieve_with_root(dir.path(), "rules.yml", BARE_ALERT, "snap");
        assert!(got
            .packets
            .iter()
            .all(|p| p.key != "rule.annotations.runbook.target"));
    }

    #[test]
    fn repo_link_resolves_passes_fails_and_abstains_on_the_three_statuses() {
        let specs = rvl_spec::SpecCache::load(
            r#"{"config_keys":[{"format":"prometheus-rules","key":"rule.annotations.runbook.target",
                "expect":{"kind":"pattern","name":"repo_link_resolves"},"confidence":0.9,
                "control":"RC-006","severity":"medium","fix":"link a runbook that exists"}]}"#,
        )
        .expect("the spec file parses");
        for (link, verdict) in [
            ("docs/runbooks/high-errors.md", rvl_core::Verdict::Satisfies),
            ("docs/runbooks/gone.md", rvl_core::Verdict::Violates),
            ("https://runbooks.example.com/x", rvl_core::Verdict::Abstain),
        ] {
            let f = crate::eval::evaluate(&target(link), &[], &specs);
            assert_eq!(f.verdict, verdict, "{link}: {}", f.reason);
            assert!(
                !f.reason.contains("runbooks"),
                "the link leaks into a reason: {}",
                f.reason
            );
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

    // --- rule resources: PrometheusRule, VMRule, Google Managed Prometheus ---

    const PROMETHEUS_RULE: &str = "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nmetadata:\n  name: api\nspec:\n  groups:\n  - name: api\n    rules:\n    - alert: ApiDown\n      expr: up == 0\n      labels:\n        severity: critical\n";

    #[test]
    fn matches_head_claims_rule_resources_unless_another_family_owns_the_file() {
        let r = PrometheusRules;
        assert!(r.matches_head("deploy/rules.yaml", PROMETHEUS_RULE));
        assert!(r.matches_head(
            "deploy/vmrule.yaml",
            "apiVersion: operator.victoriametrics.com/v1beta1\nkind: VMRule\nspec:\n  groups: []\n"
        ));
        assert!(r.matches_head(
            "deploy/gmp.yaml",
            "apiVersion: monitoring.googleapis.com/v1\nkind: ClusterRules\nspec:\n  groups: []\n"
        ));
        // A Service beside the rules: the Kubernetes family declines the
        // mixed file, so the rules are read here.
        let mixed = format!(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n---\n{PROMETHEUS_RULE}"
        );
        assert!(r.matches_head("deploy/all.yaml", &mixed));
        // An Argo CD Application beside them keeps the file Argo's.
        let argo = format!("apiVersion: argoproj.io/v1alpha1\nkind: Application\nmetadata:\n  name: api\n---\n{PROMETHEUS_RULE}");
        assert!(!r.matches_head("deploy/app.yaml", &argo));
    }

    #[test]
    fn a_prometheus_rule_resource_emits_the_rule_facts_under_spec() {
        let mixed = format!(
            "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n---\n{PROMETHEUS_RULE}"
        );
        let got = PrometheusRules.retrieve("deploy/rules.yaml", &mixed, "snap");
        assert_eq!(got.unparseable, 0);
        let sev = find(&got, "rule:api/ApiDown", "rule.labels.severity");
        assert_eq!(sev.resolved_value.as_deref(), Some("critical"));
        assert_eq!(
            sev.provenance[0].key_path,
            "spec.groups.api.rules.ApiDown.labels.severity"
        );
        let rb = find(&got, "rule:api/ApiDown", "rule.annotations.runbook");
        assert_eq!(rb.resolved_value.as_deref(), Some(""));
        assert!(got.packets.iter().any(|p| p.unit == "group:api"));
    }

    #[test]
    fn a_vmrule_emits_the_rule_facts() {
        let vmrule = "apiVersion: operator.victoriametrics.com/v1beta1\nkind: VMRule\nmetadata:\n  name: db\nspec:\n  groups:\n  - name: db\n    rules:\n    - alert: DbDown\n      expr: up == 0\n      labels:\n        severity: page\n      annotations:\n        runbook_url: https://runbooks.example.com/db\n";
        let got = PrometheusRules.retrieve("deploy/vmrule.yaml", vmrule, "snap");
        let sev = find(&got, "rule:db/DbDown", "rule.labels.severity");
        assert_eq!(sev.resolved_value.as_deref(), Some("page"));
        let rb = find(&got, "rule:db/DbDown", "rule.annotations.runbook");
        assert_eq!(rb.resolved_value.as_deref(), Some("nonempty"));
    }

    #[test]
    fn a_rule_resource_with_no_groups_counts_unparseable() {
        let got = PrometheusRules.retrieve(
            "deploy/rules.yaml",
            "apiVersion: monitoring.coreos.com/v1\nkind: PrometheusRule\nspec: {}\n",
            "snap",
        );
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    // --- the severity guard predicate ---

    fn predicate<'a>(got: &'a Retrieved, unit: &str, key: &str) -> Option<&'a [String]> {
        got.predicates
            .iter()
            .find(|f| f.unit == unit && f.key == key)
            .map(|f| f.values.as_slice())
    }

    #[test]
    fn the_severity_predicate_is_lower_cased_and_falls_back_to_priority() {
        let got = packets("groups:\n- name: g\n  rules:\n  - alert: A\n    expr: up == 0\n    labels:\n      severity: Critical\n  - alert: B\n    expr: up == 0\n    labels:\n      priority: P1\n  - alert: C\n    expr: up == 0\n    labels:\n      severity: warning\n      priority: P1\n  - alert: D\n    expr: up == 0\n  - alert: E\n    expr: up == 0\n    labels:\n      severity: \"{{ $labels.sev }}\"\n");
        let sev = |a: &str| predicate(&got, &format!("rule:g/{a}"), "rule.labels.severity");
        assert_eq!(sev("A"), Some(&["critical".to_string()][..]));
        assert_eq!(sev("B"), Some(&["p1".to_string()][..]));
        assert_eq!(
            sev("C"),
            Some(&["warning".to_string()][..]),
            "severity wins"
        );
        assert_eq!(sev("D"), Some(&[String::new()][..]));
        assert_eq!(sev("E"), None, "a templated label states nothing");
        // The packet keeps the label as authored.
        let p = find(&got, "rule:g/A", "rule.labels.severity");
        assert_eq!(p.resolved_value.as_deref(), Some("Critical"));
        let p = find(&got, "rule:g/B", "rule.labels.severity");
        assert_eq!(p.resolved_value.as_deref(), Some(""));
    }

    // --- the RC-006 abstain conditions, each with a twin that still emits ---

    /// The `rule.annotations.runbook` value of `unit` in `rule_file`, retrieved
    /// from a repository of `files` (the rule file among them).
    fn runbook_in(files: &[(&str, &str)], rule_file: &str, unit: &str) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("platform");
        for (path, text) in files {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        let text = files.iter().find(|(p, _)| *p == rule_file).unwrap().1;
        let got = PrometheusRules.retrieve_with_root(&root, rule_file, text, "snap");
        find(&got, unit, "rule.annotations.runbook")
            .resolved_value
            .clone()
    }

    const RULES: &str = "deploy/prometheus/rules.yaml";

    /// One critical alert with the given annotations block.
    fn critical(annotations: &str) -> String {
        format!("groups:\n- name: api\n  rules:\n  - alert: ApiDown\n    expr: up == 0\n    labels:\n      severity: critical\n{annotations}")
    }

    fn undecided(why: &str) -> Option<String> {
        Some(format!("{}{why}", crate::UNDECIDED_PREFIX))
    }

    const UNIT: &str = "rule:api/ApiDown";

    #[test]
    fn a_link_like_annotation_is_undecided() {
        for annotations in [
            "    annotations:\n      dashboard_url: x\n",
            "    annotations:\n      Playbook: x\n",
            "    annotations:\n      description: see https://wiki.example.com/api\n",
            "    annotations:\n      description: follow the runbook\n",
        ] {
            assert_eq!(
                runbook_in(&[(RULES, &critical(annotations))], RULES, UNIT),
                undecided("a link-like annotation: a reader must judge the link"),
                "{annotations}"
            );
        }
        let plain = critical("    annotations:\n      summary: the API is down\n");
        assert_eq!(
            runbook_in(&[(RULES, &plain)], RULES, UNIT),
            Some(String::new())
        );
    }

    #[test]
    fn an_alertmanager_template_that_mentions_a_runbook_is_undecided() {
        let rules = critical("");
        let tmpl = "{{ define \"pager\" }}{{ .CommonAnnotations.runbook }}{{ end }}";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("alertmanager/pager.tmpl", tmpl)],
                RULES,
                UNIT
            ),
            undecided("an Alertmanager config or template mentions a runbook")
        );
        let other = "{{ define \"pager\" }}{{ .CommonAnnotations.summary }}{{ end }}";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("alertmanager/pager.tmpl", other)],
                RULES,
                UNIT
            ),
            Some(String::new())
        );
    }

    #[test]
    fn receivers_that_page_nobody_are_undecided() {
        let rules = critical("");
        let chat = "route:\n  receiver: chat\nreceivers:\n- name: chat\n  slack_configs:\n  - channel: '#alerts'\n";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("alertmanager/alertmanager.yml", chat)],
                RULES,
                UNIT
            ),
            undecided("no receiver can page: alerts go to chat, email or nowhere")
        );
        let pager = "route:\n  receiver: pager\nreceivers:\n- name: pager\n  pagerduty_configs:\n  - routing_key: K\n";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("alertmanager/alertmanager.yml", pager)],
                RULES,
                UNIT
            ),
            Some(String::new())
        );
    }

    #[test]
    fn a_duplicate_alert_name_is_undecided_unless_every_twin_would_flag() {
        let pair = "groups:\n- name: api\n  rules:\n  - alert: ApiDown\n    expr: up == 0\n    labels:\n      severity: warning\n  - alert: ApiDown\n    expr: up == 0\n    for: 10m\n    labels:\n      severity: critical\n";
        assert_eq!(
            runbook_in(&[(RULES, pair)], RULES, UNIT),
            undecided("another rule of the group has this alert name")
        );
        let both = pair.replace("severity: warning", "severity: critical");
        assert_eq!(
            runbook_in(&[(RULES, &both)], RULES, UNIT),
            Some(String::new())
        );
    }

    #[test]
    fn a_kustomize_patch_of_the_prometheus_rule_is_undecided() {
        let path = "deploy/base/rules.yaml";
        let unit = "rule:api/ApiDown";
        let patch = |name: &str| {
            format!("resources: [../base]\npatches:\n- path: severity.yaml\n  target:\n    kind: PrometheusRule\n    name: {name}\n")
        };
        assert_eq!(
            runbook_in(
                &[
                    (path, PROMETHEUS_RULE),
                    ("deploy/ring/kustomization.yaml", &patch("api"))
                ],
                path,
                unit
            ),
            undecided("a kustomize patch targets this PrometheusRule")
        );
        assert_eq!(
            runbook_in(
                &[
                    (path, PROMETHEUS_RULE),
                    ("deploy/ring/kustomization.yaml", &patch("etcd"))
                ],
                path,
                unit
            ),
            Some(String::new())
        );
    }

    #[test]
    fn a_templated_runbook_value_is_undecided() {
        let templated = critical("    annotations:\n      runbook: \"{{ $externalURL }}\"\n");
        let got = packets(&templated);
        assert_eq!(
            find(&got, UNIT, "rule.annotations.runbook").resolved_value,
            undecided("templated runbook value")
        );
        let literal = critical("    annotations:\n      runbook: docs/api.md\n");
        let got = packets(&literal);
        assert_eq!(
            find(&got, UNIT, "rule.annotations.runbook")
                .resolved_value
                .as_deref(),
            Some("nonempty")
        );
    }

    #[test]
    fn a_non_production_path_is_undecided() {
        let rules = critical("");
        assert_eq!(
            runbook_in(
                &[("examples/rules.yaml", &rules)],
                "examples/rules.yaml",
                UNIT
            ),
            undecided("non-production path: examples")
        );
        assert_eq!(
            runbook_in(&[(RULES, &rules)], RULES, UNIT),
            Some(String::new())
        );
    }

    #[test]
    fn a_vendored_or_generated_pack_is_undecided_on_every_fact() {
        let rules = critical("");
        let path = "monitoring/mixins/api/alerts.yaml";
        assert_eq!(
            runbook_in(&[(path, &rules)], path, UNIT),
            undecided("vendored or generated rule pack: mixins")
        );
        let got = PrometheusRules.retrieve(path, &rules, "snap");
        let p = find(&got, UNIT, "rule.for");
        assert_eq!(
            p.resolved_value,
            undecided("vendored or generated rule pack: mixins")
        );
        assert_eq!(
            runbook_in(&[(RULES, &rules)], RULES, UNIT),
            Some(String::new())
        );
    }

    #[test]
    fn a_skill_package_or_template_path_is_undecided() {
        let rules = critical("");
        for (path, token) in [
            ("skills/alerting/rules.yaml", "skills"),
            ("agent/skill/prometheus/alerts.yml", "skill"),
            ("monitoring/alert-template.yaml", "template"),
            // A chart's own PrometheusRule is the chart consumer's to decide.
            ("charts/api/Templates/rules.yaml", "templates"),
        ] {
            assert_eq!(
                runbook_in(&[(path, &rules)], path, UNIT),
                undecided(&format!("a skill package or template to copy: {token}")),
                "{path}"
            );
        }
        assert_eq!(
            runbook_in(&[(RULES, &rules)], RULES, UNIT),
            Some(String::new())
        );
        // A token is a whole word, not a substring.
        let path = "deploy/skillful/rules.yaml";
        assert_eq!(
            runbook_in(&[(path, &rules)], path, UNIT),
            Some(String::new())
        );
        // Only the runbook is the consumer's: the rule's other facts stand.
        let got = PrometheusRules.retrieve("skills/rules.yaml", &rules, "snap");
        assert_eq!(
            find(&got, UNIT, "rule.for").resolved_value.as_deref(),
            Some("0s")
        );
    }

    const PAGERDUTY: &str = "route:\n  receiver: pager\nreceivers:\n- name: pager\n  pagerduty_configs:\n  - routing_key: K\n";

    #[test]
    fn alertmanager_switched_off_in_helm_values_is_undecided() {
        let rules = critical("");
        let off = "kube-prometheus-stack:\n  alertmanager:\n    enabled: false\n";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("deploy/helm/values.yaml", off)],
                RULES,
                UNIT
            ),
            undecided("Helm values switch Alertmanager off")
        );
        let on = "kube-prometheus-stack:\n  alertmanager:\n    enabled: true\n";
        assert_eq!(
            runbook_in(
                &[
                    (RULES, &rules),
                    ("deploy/helm/values.yaml", on),
                    ("alertmanager/alertmanager.yml", PAGERDUTY)
                ],
                RULES,
                UNIT
            ),
            Some(String::new())
        );
    }

    #[test]
    fn a_webhook_only_receiver_is_undecided() {
        let rules = critical("");
        let hook = "route:\n  receiver: hook\nreceivers:\n- name: hook\n  webhook_configs:\n  - url: http://bridge:8080/\n";
        assert_eq!(
            runbook_in(
                &[(RULES, &rules), ("alertmanager/alertmanager.yml", hook)],
                RULES,
                UNIT
            ),
            undecided("only a webhook receiver: whether it pages cannot be told")
        );
        assert_eq!(
            runbook_in(
                &[
                    (RULES, &rules),
                    ("alertmanager/alertmanager.yml", PAGERDUTY)
                ],
                RULES,
                UNIT
            ),
            Some(String::new())
        );
    }

    #[test]
    fn an_upstream_mixin_group_name_is_undecided() {
        let rules = critical("").replace("- name: api", "- name: kubernetes-apps");
        assert_eq!(
            runbook_in(&[(RULES, &rules)], RULES, "rule:kubernetes-apps/ApiDown"),
            undecided("the group name of an upstream mixin rule pack")
        );
        let first_party = critical("").replace("- name: api", "- name: kubernetes-api-gateway");
        assert_eq!(
            runbook_in(
                &[(RULES, &first_party)],
                RULES,
                "rule:kubernetes-api-gateway/ApiDown"
            ),
            Some(String::new())
        );
    }

    #[test]
    fn a_rule_with_a_runbook_keeps_its_value_whatever_the_repository_says() {
        let rules =
            critical("    annotations:\n      runbook_url: https://runbooks.example.com/api\n");
        let chat = "route:\n  receiver: chat\nreceivers:\n- name: chat\n  slack_configs:\n  - channel: '#alerts'\n";
        assert_eq!(
            runbook_in(&[(RULES, &rules), ("alertmanager.yml", chat)], RULES, UNIT).as_deref(),
            Some("nonempty")
        );
    }

    #[test]
    fn the_abstain_facts_are_guard_predicates() {
        let dir = tempfile::tempdir().unwrap();
        let pair = "groups:\n- name: api\n  rules:\n  - alert: ApiDown\n    expr: up == 0\n    labels:\n      severity: warning\n    annotations:\n      dashboard: https://grafana.example.com/d/api\n  - alert: ApiDown\n    expr: up == 0\n    labels:\n      severity: critical\n";
        let got = PrometheusRules.retrieve_with_root(dir.path(), RULES, pair, "snap");
        let one = |unit: &str, key: &str| predicate(&got, unit, key).map(|v| v.join(","));
        assert_eq!(one(UNIT, "rule.name_unique").as_deref(), Some("false"));
        assert_eq!(
            one(UNIT, "rule.annotations.link_like").as_deref(),
            Some("present")
        );
        assert_eq!(
            one(UNIT, "rule.kustomize_patched").as_deref(),
            Some("false")
        );
        let repo = |key: &str| one(crate::FILE_SCOPE, key);
        assert_eq!(
            repo("repo.alertmanager.mentions_runbook").as_deref(),
            Some("false")
        );
        assert_eq!(
            repo("repo.alertmanager.paging_receiver").as_deref(),
            Some("none_declared")
        );
        assert_eq!(repo("repo.alertmanager.disabled").as_deref(), Some("false"));
        assert_eq!(repo("file.rule_pack_path").as_deref(), Some("false"));
        assert_eq!(
            one(UNIT, "rule.group.upstream_mixin").as_deref(),
            Some("false")
        );
        // Without the root the repository is unknown, and says nothing.
        let got = packets(pair);
        assert!(predicate(&got, crate::FILE_SCOPE, "repo.alertmanager.paging_receiver").is_none());
        assert!(predicate(&got, UNIT, "rule.kustomize_patched").is_none());
        assert!(predicate(&got, crate::FILE_SCOPE, "repo.alertmanager.disabled").is_none());
        // The path and the group name are the file's own, read without it.
        let got = PrometheusRules.retrieve("skills/rules.yaml", pair, "snap");
        assert_eq!(
            predicate(&got, crate::FILE_SCOPE, "file.rule_pack_path"),
            Some(&["true".to_string()][..])
        );
        let mixin = pair.replace("- name: api", "- name: etcd");
        let got = packets(&mixin);
        assert_eq!(
            predicate(&got, "rule:etcd/ApiDown", "rule.group.upstream_mixin"),
            Some(&["true".to_string()][..])
        );
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
