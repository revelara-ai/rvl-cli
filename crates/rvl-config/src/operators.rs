//! Operator custom-resource retriever (po-pk3fp.13): the backup and
//! policy-enforcement CRs the RC-030/045/049/054 frames ask about, which were
//! identity-only `kubernetes` sightings until now.
//!
//! Like the Argo/Flux family ([`crate::argo_flux`]), these resources have no
//! canonical path, so files are claimed by CONTENT: an apiVersion group this
//! module names, paired with a kind it parses. Packet formats are per-product
//! so spec identities and waiver class rules read naturally:
//!
//!   * `cnpg` (`postgresql.cnpg.io`) —
//!     - Cluster: `cluster.backup.method` (`barmanObjectStore`,
//!       `volumeSnapshot`, `plugin`, joined with `+`; else absent),
//!       `cluster.backup.retentionPolicy` (only where `spec.backup` carries a
//!       method: with the plugin, retention lives on a separate ObjectStore
//!       resource), `cluster.backup.wal-archiving` (`enabled` when an object
//!       store or a WAL-archiver plugin is configured, else absent: a volume
//!       snapshot alone cannot recover to a point in time).
//!     - ScheduledBackup: `scheduledbackup.schedule` (required field),
//!       `scheduledbackup.suspend` (documented `false`).
//!   * `kyverno` (`kyverno.io` ClusterPolicy / Policy) —
//!     `rule.validate.failureAction`, one packet per `validate` rule with the
//!     EFFECTIVE action: the rule's own `validate.failureAction`, else the
//!     policy-wide `spec.validationFailureAction`, else the documented
//!     `Audit`. Rules that only mutate or generate emit nothing.
//!   * `gatekeeper` (`constraints.gatekeeper.sh`, any kind) —
//!     `constraint.enforcementAction`, else the documented `deny`.
//!
//! Privacy: values are modes and shapes only. A bucket path, a schedule's
//! target cluster, an allowed-registry list or a policy's match rules are
//! never emitted; the allowlist is org input a spec cannot judge anyway,
//! which is why the enforcement MODE is the fact (frame cell M2b).
//!
//! Seed-grade bounds, recorded for the corpus follow-up: Kyverno's
//! `validationFailureActionOverrides` (per-namespace) is not read, the newer
//! `policies.kyverno.io` ValidatingPolicy kind is not parsed, and "this
//! Cluster has no ScheduledBackup at all" is not a fact one file can decide
//! (the ScheduledBackup may live in another repo).

use crate::argo_flux::{get, group_of, head_scan, Emitter};
use crate::{render_value, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};
use serde::Deserialize as _;
use serde_yaml::{Mapping, Value};

pub struct OperatorCrs;

const FORMAT_CNPG: &str = "cnpg";
const FORMAT_KYVERNO: &str = "kyverno";
const FORMAT_GATEKEEPER: &str = "gatekeeper";

/// The CNPG plugin that provides object-store backup and WAL archiving.
const BARMAN_CLOUD_PLUGIN: &str = "barman-cloud.cloudnative-pg.io";

impl ConfigRetriever for OperatorCrs {
    fn format_id(&self) -> &'static str {
        "operator-crs"
    }

    /// No canonical path; [`Self::matches_head`] claims by content.
    fn matches(&self, _rel_path: &str) -> bool {
        false
    }

    fn matches_head(&self, rel_path: &str, head: &str) -> bool {
        if !(rel_path.ends_with(".yml") || rel_path.ends_with(".yaml")) {
            return false;
        }
        head_scan(head)
            .iter()
            .any(|(api, kind)| product(group_of(api), kind).is_some())
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        retrieve(rel_path, contents, snapshot_id)
    }
}

/// The packet format for a (group, kind) this module parses. Group-qualified
/// on purpose: `Cluster` and `Policy` are common kind names in other groups.
fn product(group: &str, kind: &str) -> Option<&'static str> {
    match group {
        "postgresql.cnpg.io" if matches!(kind, "Cluster" | "ScheduledBackup") => Some(FORMAT_CNPG),
        "kyverno.io" if matches!(kind, "ClusterPolicy" | "Policy") => Some(FORMAT_KYVERNO),
        // Every kind in this group is a constraint: the kind is the name of
        // the ConstraintTemplate it instantiates.
        "constraints.gatekeeper.sh" if !kind.is_empty() => Some(FORMAT_GATEKEEPER),
        _ => None,
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
        let api = get(m, "apiVersion").and_then(Value::as_str).unwrap_or("");
        let kind = get(m, "kind").and_then(Value::as_str).unwrap_or("");
        let Some(format) = product(group_of(api), kind) else {
            // A foreign document in a claimed file is not ours to judge.
            continue;
        };
        recognized_docs += 1;
        let name = mapping(Some(m), "metadata")
            .and_then(|md| get(md, "name"))
            .and_then(Value::as_str)
            .unwrap_or("unnamed");
        let spec = mapping(Some(m), "spec");
        if format == FORMAT_KYVERNO {
            let policy = format!("{}:{name}", kind.to_ascii_lowercase());
            emit_kyverno_rules(&mut out, rel_path, snapshot_id, &policy, spec);
            continue;
        }
        type Emit = fn(&mut Emitter, Option<&Mapping>);
        let (unit, emit): (String, Emit) = match (format, kind) {
            (FORMAT_CNPG, "Cluster") => (format!("cluster:{name}"), emit_cnpg_cluster),
            (FORMAT_CNPG, _) => (format!("scheduledbackup:{name}"), emit_scheduled_backup),
            _ => (format!("constraint:{kind}/{name}"), emit_constraint),
        };
        emit(
            &mut Emitter::new(&mut out, rel_path, snapshot_id, format, unit),
            spec,
        );
    }
    if recognized_docs == 0 && out.unparseable == 0 {
        // Claimed by head shape, but nothing recognized parsed out: coverage
        // says the lane saw and skipped it (the Argo/Flux contract).
        out.unparseable = 1;
    }
    out
}

/// A CNPG Cluster's backup posture (RC-030) and whether it can recover to a
/// point in time (RC-054).
fn emit_cnpg_cluster(e: &mut Emitter, spec: Option<&Mapping>) {
    let backup = mapping(spec, "backup");
    let in_tree: Vec<&str> = ["barmanObjectStore", "volumeSnapshot"]
        .into_iter()
        .filter(|m| backup.is_some_and(|b| get(b, m).is_some_and(|v| !v.is_null())))
        .collect();
    // The barman-cloud plugin replaces the in-tree object store; its position
    // in `spec.plugins` anchors the provenance.
    let plugin = spec
        .and_then(|s| get(s, "plugins"))
        .and_then(Value::as_sequence)
        .and_then(|plugins| {
            plugins.iter().enumerate().find_map(|(i, p)| {
                let p = p.as_mapping()?;
                (get(p, "name").and_then(Value::as_str) == Some(BARMAN_CLOUD_PLUGIN))
                    .then_some((i, p))
            })
        });

    let mut methods = in_tree.clone();
    if plugin.is_some() {
        methods.push("plugin");
    }
    let explicit = |e: &mut Emitter, key: &str, key_path: &str, value: &str| {
        let p = vec![ProvenanceStep::new(e.file, key_path, "explicit")];
        e.push(key, Some(value.to_string()), Resolution::AsAuthored, p);
    };
    if methods.is_empty() {
        e.absent("cluster.backup.method", "spec.backup");
    } else {
        let key_path = if in_tree.is_empty() {
            "spec.plugins"
        } else {
            "spec.backup"
        };
        explicit(e, "cluster.backup.method", key_path, &methods.join("+"));
    }

    if !in_tree.is_empty() {
        match backup.and_then(|b| get(b, "retentionPolicy")) {
            Some(v) => e.authored(
                "cluster.backup.retentionPolicy",
                "spec.backup.retentionPolicy",
                v,
            ),
            // CNPG documents no default: without a policy, backups are kept
            // until someone deletes them.
            None => e.absent(
                "cluster.backup.retentionPolicy",
                "spec.backup.retentionPolicy",
            ),
        }
    }

    let wal_plugin =
        plugin.filter(|(_, p)| get(p, "isWALArchiver").and_then(Value::as_bool) == Some(true));
    if in_tree.contains(&"barmanObjectStore") {
        explicit(
            e,
            "cluster.backup.wal-archiving",
            "spec.backup.barmanObjectStore",
            "enabled",
        );
    } else if let Some((i, _)) = wal_plugin {
        explicit(
            e,
            "cluster.backup.wal-archiving",
            &format!("spec.plugins[{i}].isWALArchiver"),
            "enabled",
        );
    } else {
        e.absent(
            "cluster.backup.wal-archiving",
            "spec.backup.barmanObjectStore",
        );
    }
}

fn emit_scheduled_backup(e: &mut Emitter, spec: Option<&Mapping>) {
    let sget = |k: &str| spec.and_then(|s| get(s, k));
    match sget("schedule") {
        Some(v) => e.authored("scheduledbackup.schedule", "spec.schedule", v),
        None => e.absent("scheduledbackup.schedule", "spec.schedule"),
    }
    match sget("suspend") {
        Some(v) => e.authored("scheduledbackup.suspend", "spec.suspend", v),
        None => e.platform_default(
            "scheduledbackup.suspend",
            "spec.suspend",
            "suspend",
            "false",
        ),
    }
}

/// Kyverno's two actions, canonically capitalized: releases before 1.13
/// accepted the lower-case spellings, and a string-compared spec should not
/// have to list both. Anything else renders as authored.
fn failure_action(v: &Value) -> String {
    let raw = render_value(v);
    match raw.to_ascii_lowercase().as_str() {
        "enforce" => "Enforce".to_string(),
        "audit" => "Audit".to_string(),
        _ => raw,
    }
}

/// One packet per `validate` rule, carrying the action that rule runs under.
fn emit_kyverno_rules(
    out: &mut Retrieved,
    file: &str,
    snapshot_id: &str,
    policy: &str,
    spec: Option<&Mapping>,
) {
    const KEY: &str = "rule.validate.failureAction";
    let policy_wide = spec.and_then(|s| get(s, "validationFailureAction"));
    let rules = spec
        .and_then(|s| get(s, "rules"))
        .and_then(Value::as_sequence);
    for (i, rule) in rules.into_iter().flatten().enumerate() {
        let Some(rule) = rule.as_mapping() else {
            continue;
        };
        let Some(validate) = get(rule, "validate") else {
            continue; // mutate / generate / verifyImages: no failure action
        };
        let rule_name = match get(rule, "name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => i.to_string(),
        };
        let unit = format!("{policy}/rule:{rule_name}");
        let mut e = Emitter::new(out, file, snapshot_id, FORMAT_KYVERNO, unit);
        let rule_path = format!("spec.rules[{i}].validate.failureAction");
        let own = validate.as_mapping().and_then(|v| get(v, "failureAction"));
        match (own, policy_wide) {
            (Some(v), _) => {
                let p = vec![ProvenanceStep::new(file, &rule_path, "explicit")];
                e.push(KEY, Some(failure_action(v)), Resolution::AsAuthored, p);
            }
            (None, Some(v)) => {
                let p = vec![
                    ProvenanceStep::new(file, &rule_path, "absent"),
                    ProvenanceStep::new(file, "spec.validationFailureAction", "inherited"),
                ];
                e.push(KEY, Some(failure_action(v)), Resolution::AsAuthored, p);
            }
            (None, None) => {
                let p = vec![
                    ProvenanceStep::new(file, &rule_path, "absent"),
                    ProvenanceStep::new(file, "spec.validationFailureAction", "absent"),
                    ProvenanceStep::new("", "failureAction", "platform-default"),
                ];
                e.push(
                    KEY,
                    Some("Audit".to_string()),
                    Resolution::PlatformDefault,
                    p,
                );
            }
        }
    }
}

fn emit_constraint(e: &mut Emitter, spec: Option<&Mapping>) {
    match spec.and_then(|s| get(s, "enforcementAction")) {
        Some(v) => e.authored("constraint.enforcementAction", "spec.enforcementAction", v),
        None => e.platform_default(
            "constraint.enforcementAction",
            "spec.enforcementAction",
            "enforcementAction",
            "deny",
        ),
    }
}

fn mapping<'a>(m: Option<&'a Mapping>, key: &str) -> Option<&'a Mapping> {
    m.and_then(|m| get(m, key)).and_then(Value::as_mapping)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConfigPacket, ABSENT_RENDERING};

    fn packets(yaml: &str) -> Retrieved {
        OperatorCrs.retrieve("deploy/cr.yaml", yaml, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:#?}", got.packets))
    }

    fn value<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a str {
        find(got, unit, key).resolved_value.as_deref().unwrap()
    }

    const CNPG_HEAD: &str =
        "apiVersion: postgresql.cnpg.io/v1\nkind: Cluster\nmetadata:\n  name: pg\n";

    #[test]
    fn matches_head_claims_only_the_named_groups_and_kinds() {
        let r = OperatorCrs;
        assert!(r.matches_head("db/pg.yaml", CNPG_HEAD));
        assert!(r.matches_head(
            "db/backup.yml",
            "apiVersion: postgresql.cnpg.io/v1\nkind: ScheduledBackup\n"
        ));
        assert!(r.matches_head(
            "policy/p.yaml",
            "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\n"
        ));
        // Any kind in the constraints group is a constraint, and a licence
        // comment on the apiVersion line must not hide the group.
        assert!(r.matches_head(
            "policy/c.yaml",
            "apiVersion: constraints.gatekeeper.sh/v1beta1 # Copyright 2019\nkind: K8sAllowedRepos\n"
        ));
        // A ConstraintTemplate is Rego, not an enforcement setting.
        assert!(!r.matches_head(
            "policy/t.yaml",
            "apiVersion: templates.gatekeeper.sh/v1\nkind: ConstraintTemplate\n"
        ));
        // Kinds this module does not parse, and other groups' same-named kinds.
        assert!(!r.matches_head(
            "db/pooler.yaml",
            "apiVersion: postgresql.cnpg.io/v1\nkind: Pooler\n"
        ));
        assert!(!r.matches_head(
            "capi/cluster.yaml",
            "apiVersion: cluster.x-k8s.io/v1beta1\nkind: Cluster\n"
        ));
        assert!(!r.matches_head("k8s/deploy.yaml", "apiVersion: apps/v1\nkind: Deployment\n"));
        assert!(!r.matches_head("notes.txt", CNPG_HEAD), "only YAML files");
    }

    #[test]
    fn cnpg_cluster_without_backup_is_decidably_unprotected() {
        let got = packets(&format!("{CNPG_HEAD}spec:\n  instances: 3\n"));
        let method = find(&got, "cluster:pg", "cluster.backup.method");
        assert_eq!(method.format, "cnpg");
        assert_eq!(method.resolved_value.as_deref(), Some(ABSENT_RENDERING));
        assert_eq!(method.resolution, Resolution::AsAuthored);
        assert_eq!(method.provenance[0].key_path, "spec.backup");
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.wal-archiving"),
            ABSENT_RENDERING
        );
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == "cluster.backup.retentionPolicy"),
            "no backup, so retention has nothing to retain: the method packet is the finding"
        );
    }

    #[test]
    fn cnpg_object_store_backup_archives_wal_and_carries_its_retention() {
        let got = packets(&format!(
            "{CNPG_HEAD}spec:\n  backup:\n    retentionPolicy: 30d\n    barmanObjectStore:\n      destinationPath: s3://acme-prod-backups/pg\n"
        ));
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.method"),
            "barmanObjectStore"
        );
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.retentionPolicy"),
            "30d"
        );
        let wal = find(&got, "cluster:pg", "cluster.backup.wal-archiving");
        assert_eq!(wal.resolved_value.as_deref(), Some("enabled"));
        assert_eq!(wal.provenance[0].key_path, "spec.backup.barmanObjectStore");
        // The privacy line: the bucket path never leaves the machine.
        assert!(got.packets.iter().all(|p| !p
            .resolved_value
            .as_deref()
            .unwrap_or("")
            .contains("acme")));
    }

    #[test]
    fn cnpg_volume_snapshot_alone_has_no_wal_archive_and_no_retention() {
        let got = packets(&format!(
            "{CNPG_HEAD}spec:\n  backup:\n    volumeSnapshot:\n      className: csi\n"
        ));
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.method"),
            "volumeSnapshot"
        );
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.retentionPolicy"),
            ABSENT_RENDERING
        );
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.wal-archiving"),
            ABSENT_RENDERING,
            "a snapshot without archived WAL cannot recover to a point in time"
        );
    }

    #[test]
    fn cnpg_barman_cloud_plugin_counts_as_a_backup_method() {
        let got = packets(&format!(
            "{CNPG_HEAD}spec:\n  plugins:\n  - name: barman-cloud.cloudnative-pg.io\n    isWALArchiver: true\n    parameters:\n      barmanObjectName: store\n"
        ));
        assert_eq!(value(&got, "cluster:pg", "cluster.backup.method"), "plugin");
        let wal = find(&got, "cluster:pg", "cluster.backup.wal-archiving");
        assert_eq!(wal.resolved_value.as_deref(), Some("enabled"));
        assert_eq!(wal.provenance[0].key_path, "spec.plugins[0].isWALArchiver");
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == "cluster.backup.retentionPolicy"),
            "plugin retention lives on the ObjectStore resource, not here"
        );
        // The plugin without the archiver flag backs up but does not archive.
        let got = packets(&format!(
            "{CNPG_HEAD}spec:\n  plugins:\n  - name: barman-cloud.cloudnative-pg.io\n"
        ));
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.wal-archiving"),
            ABSENT_RENDERING
        );
        // Some other plugin is not a backup.
        let got = packets(&format!(
            "{CNPG_HEAD}spec:\n  plugins:\n  - name: example.io/other\n"
        ));
        assert_eq!(
            value(&got, "cluster:pg", "cluster.backup.method"),
            ABSENT_RENDERING
        );
    }

    #[test]
    fn scheduled_backup_emits_schedule_and_suspend_state() {
        let head = "apiVersion: postgresql.cnpg.io/v1\nkind: ScheduledBackup\nmetadata:\n  name: nightly\n";
        let got = packets(&format!(
            "{head}spec:\n  schedule: \"0 0 2 * * *\"\n  suspend: true\n  cluster:\n    name: pg\n"
        ));
        let unit = "scheduledbackup:nightly";
        assert_eq!(value(&got, unit, "scheduledbackup.schedule"), "0 0 2 * * *");
        let suspend = find(&got, unit, "scheduledbackup.suspend");
        assert_eq!(suspend.resolved_value.as_deref(), Some("true"));
        assert_eq!(suspend.resolution, Resolution::AsAuthored);

        let got = packets(&format!("{head}spec:\n  cluster:\n    name: pg\n"));
        assert_eq!(
            value(&got, unit, "scheduledbackup.schedule"),
            ABSENT_RENDERING
        );
        let suspend = find(&got, unit, "scheduledbackup.suspend");
        assert_eq!(suspend.resolved_value.as_deref(), Some("false"));
        assert_eq!(suspend.resolution, Resolution::PlatformDefault);
    }

    const KYVERNO_HEAD: &str =
        "apiVersion: kyverno.io/v1\nkind: ClusterPolicy\nmetadata:\n  name: registries\n";

    #[test]
    fn kyverno_rule_action_resolves_rule_then_policy_then_the_audit_default() {
        let got = packets(&format!(
            "{KYVERNO_HEAD}spec:\n  validationFailureAction: enforce\n  rules:\n  - name: own\n    validate:\n      failureAction: Audit\n      message: no\n  - name: inherits\n    validate:\n      message: no\n  - name: mutates\n    mutate:\n      patchStrategicMerge: {{}}\n"
        ));
        let key = "rule.validate.failureAction";
        let own = find(&got, "clusterpolicy:registries/rule:own", key);
        assert_eq!(own.format, "kyverno");
        assert_eq!(own.resolved_value.as_deref(), Some("Audit"));
        assert_eq!(
            own.provenance.last().unwrap().key_path,
            "spec.rules[0].validate.failureAction"
        );
        let inherits = find(&got, "clusterpolicy:registries/rule:inherits", key);
        assert_eq!(
            inherits.resolved_value.as_deref(),
            Some("Enforce"),
            "the legacy lower-case spelling renders canonically"
        );
        assert_eq!(inherits.resolution, Resolution::AsAuthored);
        let last = inherits.provenance.last().unwrap();
        assert_eq!(
            (last.key_path.as_str(), last.role.as_str()),
            ("spec.validationFailureAction", "inherited")
        );
        assert_eq!(got.packets.len(), 2, "a mutate rule has no failure action");
    }

    #[test]
    fn kyverno_rule_with_no_action_anywhere_runs_under_the_audit_default() {
        let got = packets(
            "apiVersion: kyverno.io/v1\nkind: Policy\nmetadata:\n  name: p\nspec:\n  rules:\n  - validate:\n      message: no\n",
        );
        // An unnamed rule is addressed by its index.
        let p = find(&got, "policy:p/rule:0", "rule.validate.failureAction");
        assert_eq!(p.resolved_value.as_deref(), Some("Audit"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance.last().unwrap().role, "platform-default");
    }

    #[test]
    fn kyverno_policy_with_no_validate_rules_is_recognized_and_silent() {
        let got = packets(&format!(
            "{KYVERNO_HEAD}spec:\n  rules:\n  - name: gen\n    generate:\n      kind: ConfigMap\n"
        ));
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0, "recognized, with nothing to report");
    }

    #[test]
    fn gatekeeper_constraint_action_is_authored_or_the_deny_default() {
        let head = "apiVersion: constraints.gatekeeper.sh/v1beta1\nkind: K8sAllowedRepos\nmetadata:\n  name: repos\n";
        let got = packets(&format!(
            "{head}spec:\n  enforcementAction: dryrun\n  parameters:\n    repos:\n    - registry.acme.internal/\n"
        ));
        let p = find(
            &got,
            "constraint:K8sAllowedRepos/repos",
            "constraint.enforcementAction",
        );
        assert_eq!(p.format, "gatekeeper");
        assert_eq!(p.resolved_value.as_deref(), Some("dryrun"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(got.packets.len(), 1, "the allowlist is never emitted");

        let got = packets(&format!("{head}spec:\n  parameters: {{}}\n"));
        let p = find(
            &got,
            "constraint:K8sAllowedRepos/repos",
            "constraint.enforcementAction",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("deny"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn foreign_documents_are_skipped_and_an_empty_claim_counts_unparseable() {
        let got = packets(&format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n---\n{CNPG_HEAD}spec: {{}}\n"
        ));
        assert!(got.packets.iter().all(|p| p.unit == "cluster:pg"));
        assert_eq!(got.unparseable, 0);
        let got = packets("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
        let got = packets("spec: [unclosed\n  - {");
        assert_eq!(got.unparseable, 1);
    }
}
