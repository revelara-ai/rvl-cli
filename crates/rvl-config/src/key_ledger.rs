//! The ledger of every config key the retrievers can emit, and the standing
//! mint queue derived from it (po-av01j.133.4).
//!
//! A scan's `no_spec_keys` names the unjudged keys ONE repo happened to
//! contain. That is a sample: a key no scanned repo used never shows up, and a
//! key a retriever emits purely as supporting evidence looks like a gap
//! forever. This ledger is the repo-independent version. Every emitted
//! `(format, key)` is declared here once, with what the factory is expected to
//! do about it:
//!
//!   * [`Intent::Judged`] — a spec is wanted. Until the loaded artifact
//!     carries one, the key is in the MINT QUEUE.
//!   * [`Intent::VocabularyOnly`] — emitted as a fact that other keys or the
//!     provenance chain rely on, and deliberately never judged. The reason is
//!     mandatory, so "nobody got to it" cannot hide behind the marker.
//!
//! Whether a judged key HAS a spec is not recorded here. Specs ship in the
//! signed artifact, not in this repo, so a static copy would drift;
//! [`mint_queue`] answers it against the artifact actually
//! loaded.
//!
//! The ledger cannot silently fall behind the retrievers: every packet
//! constructor names its key through [`declared`], which fails debug builds
//! (and so every retriever test) on an undeclared key, and the tests below
//! fail on a constructor that bypasses it or an entry nothing emits.

use rvl_spec::SpecCache;
use serde::Serialize;

/// What the factory is expected to do about an emitted key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// A spec is wanted for this key.
    Judged,
    /// Vocabulary only, not judged. Carries the reason.
    VocabularyOnly(&'static str),
}

/// One `(format, key)` identity a retriever emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmittedKey {
    pub format: &'static str,
    pub key: &'static str,
    pub intent: Intent,
}

const fn judged(format: &'static str, key: &'static str) -> EmittedKey {
    EmittedKey {
        format,
        key,
        intent: Intent::Judged,
    }
}

const fn vocabulary_only(
    format: &'static str,
    key: &'static str,
    reason: &'static str,
) -> EmittedKey {
    EmittedKey {
        format,
        key,
        intent: Intent::VocabularyOnly(reason),
    }
}

/// Every key the registered retrievers emit, sorted by (format, key).
pub const EMITTED_KEYS: &[EmittedKey] = &[
    judged("argo-cd", "application.ignoreDifferences"),
    judged("argo-cd", "application.project"),
    judged("argo-cd", "application.syncPolicy.automated"),
    judged("argo-cd", "application.syncPolicy.automated.prune"),
    judged("argo-cd", "application.syncPolicy.automated.selfHeal"),
    judged("argo-cd", "application.syncPolicy.retry"),
    judged("argo-cd", "application.targetRevision.shape"),
    judged("dep-manifests", "cargo_toml.package.edition"),
    judged(
        "dep-manifests",
        "cargo_toml.workspace_dependencies.loosest_pin",
    ),
    judged("dep-manifests", "dockerfile.base_image_pin"),
    judged("dep-manifests", "go_mod.go"),
    judged("dep-manifests", "go_mod.replace.count"),
    judged("dep-manifests", "go_mod.toolchain"),
    judged("dep-manifests", "package_json.engines.node"),
    judged("dep-manifests", "package_json.overrides.count"),
    judged("dep-manifests", "package_json.package_manager.pin"),
    judged("dep-manifests", "pyproject.dependencies.loosest_pin"),
    judged("dep-manifests", "pyproject.requires_python"),
    judged("dep-manifests", "requirements_txt.loosest_pin"),
    judged("flux", "gitrepository.interval"),
    judged("flux", "gitrepository.ref.shape"),
    judged("flux", "helmrelease.install.remediation.retries"),
    judged("flux", "helmrelease.interval"),
    judged("flux", "helmrelease.timeout"),
    judged("flux", "helmrelease.upgrade.remediation.retries"),
    judged("flux", "helmrepository.interval"),
    judged("flux", "kustomization.interval"),
    judged("flux", "kustomization.prune"),
    judged("flux", "kustomization.timeout"),
    judged("flux", "kustomization.wait"),
    judged("github-actions", "job.continue-on-error"),
    judged("github-actions", "job.permissions"),
    judged("github-actions", "job.timeout-minutes"),
    judged("github-actions", "job.uses.ref"),
    judged("github-actions", "step.uses.ref"),
    judged("github-actions", "workflow.concurrency"),
    judged("gitlab-ci", "job.allow_failure"),
    judged("gitlab-ci", "job.retry"),
    judged("gitlab-ci", "job.timeout"),
    judged("kubernetes", "container.image-pull-policy"),
    judged("kubernetes", "container.image.pin"),
    judged("kubernetes", "container.liveness-probe"),
    judged("kubernetes", "container.readiness-probe"),
    judged("kubernetes", "container.resources.limits.cpu"),
    judged("kubernetes", "container.resources.limits.memory"),
    judged("kubernetes", "container.resources.requests.cpu"),
    judged("kubernetes", "container.resources.requests.memory"),
    judged("kubernetes", "container.security-context"),
    judged("kubernetes", "container.startup-probe"),
    judged("kubernetes", "hpa.max-replicas"),
    judged("kubernetes", "hpa.min-replicas"),
    judged("kubernetes", "pdb.max-unavailable"),
    judged("kubernetes", "pdb.min-available"),
    judged("kubernetes", "pod.priority-class-name"),
    judged("kubernetes", "pod.security-context"),
    judged("kubernetes", "pod.termination-grace-period-seconds"),
    judged("kubernetes", "workload.replicas"),
    judged("kubernetes", "workload.strategy.max-surge"),
    judged("kubernetes", "workload.strategy.max-unavailable"),
    judged("kubernetes", "workload.strategy.type"),
    judged("prometheus-rules", "group.interval"),
    judged("prometheus-rules", "rule.annotations.runbook"),
    judged("prometheus-rules", "rule.expr"),
    judged("prometheus-rules", "rule.for"),
    judged("prometheus-rules", "rule.labels.severity"),
    judged("prometheus-rules", "slo.alerting.page_alert"),
    judged("prometheus-rules", "slo.alerting.ticket_alert"),
    judged("prometheus-rules", "slo.objective"),
    judged("prometheus-rules", "slo.time_window"),
    judged("terraform", "module.pin-class"),
    vocabulary_only(
        "terraform",
        "module.source",
        "the raw source identity; module.source-class is its judgeable shape",
    ),
    judged("terraform", "module.source-class"),
    vocabulary_only(
        "terraform",
        "module.version-pin",
        "the raw version constraint or ref; module.pin-class is its judgeable shape",
    ),
    judged("terraform", "provider.version-constraint"),
    judged("terraform", "resource.lifecycle.prevent_destroy"),
    judged("terraform", "terraform.backend"),
    judged("terraform", "terraform.required_version"),
];

/// The ledger entry for one emitted identity.
pub fn lookup(format: &str, key: &str) -> Option<&'static EmittedKey> {
    EMITTED_KEYS
        .iter()
        .find(|e| e.format == format && e.key == key)
}

/// The key of a packet under construction. Every retriever names its keys
/// through here, so a key missing from [`EMITTED_KEYS`] fails debug builds at
/// the point of emission. Release builds emit it unchanged: an undeclared key
/// is an authoring bug, never a reason to fail a user's scan.
pub(crate) fn declared(format: &str, key: &str) -> String {
    debug_assert!(
        lookup(format, key).is_some(),
        "config key `{format} {key}` is emitted but not declared in key_ledger::EMITTED_KEYS; \
         declare it as judged (it joins the mint queue) or as vocabulary only (with a reason)"
    );
    key.to_string()
}

/// Where one emitted key stands against a loaded spec artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// The artifact carries a spec for it.
    Specced,
    /// A spec is wanted and the artifact has none.
    MintQueue,
    /// Deliberately not judged.
    VocabularyOnly,
}

/// A spec in the artifact wins over the marker: a key somebody judged after
/// all is judged, and its ledger entry is what needs the update.
fn classify(entry: &EmittedKey, specs: &SpecCache) -> KeyState {
    if specs.config_key(entry.format, entry.key).is_some() {
        return KeyState::Specced;
    }
    match entry.intent {
        Intent::Judged => KeyState::MintQueue,
        Intent::VocabularyOnly(_) => KeyState::VocabularyOnly,
    }
}

/// One row of the [`MintQueue`] report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyRow {
    pub format: &'static str,
    pub key: &'static str,
    pub state: KeyState,
    /// Why the key is not judged; empty unless `state` is `vocabulary_only`.
    pub reason: &'static str,
}

/// The whole ledger classified against one artifact.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MintQueue {
    pub emitted: usize,
    pub specced: usize,
    pub mint_queue: usize,
    pub vocabulary_only: usize,
    /// One row per ledger entry, in ledger order.
    pub keys: Vec<KeyRow>,
}

/// Classify every emitted key against `specs`. With an empty cache every
/// judged key is in the queue, which is the true statement about a machine
/// with no artifact installed.
pub fn mint_queue(specs: &SpecCache) -> MintQueue {
    let mut out = MintQueue {
        emitted: EMITTED_KEYS.len(),
        ..Default::default()
    };
    for e in EMITTED_KEYS {
        let state = classify(e, specs);
        let reason = match (state, e.intent) {
            (KeyState::VocabularyOnly, Intent::VocabularyOnly(r)) => r,
            _ => "",
        };
        match state {
            KeyState::Specced => out.specced += 1,
            KeyState::MintQueue => out.mint_queue += 1,
            KeyState::VocabularyOnly => out.vocabulary_only += 1,
        }
        out.keys.push(KeyRow {
            format: e.format,
            key: e.key,
            state,
            reason,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_spec::{ConfigExpect, ConfigKeySpec, SpecFile};

    /// The retriever sources, with their test modules cut off.
    fn retriever_sources() -> Vec<(&'static str, &'static str)> {
        [
            ("argo_flux.rs", include_str!("argo_flux.rs")),
            ("dep_manifests.rs", include_str!("dep_manifests.rs")),
            ("github_actions.rs", include_str!("github_actions.rs")),
            ("gitlab_ci.rs", include_str!("gitlab_ci.rs")),
            ("kubernetes/helm.rs", include_str!("kubernetes/helm.rs")),
            (
                "kubernetes/kustomize.rs",
                include_str!("kubernetes/kustomize.rs"),
            ),
            (
                "kubernetes/manifest.rs",
                include_str!("kubernetes/manifest.rs"),
            ),
            ("kubernetes/mod.rs", include_str!("kubernetes/mod.rs")),
            ("prometheus.rs", include_str!("prometheus.rs")),
            ("terraform.rs", include_str!("terraform.rs")),
        ]
        .into_iter()
        .map(|(name, src)| (name, src.split("#[cfg(test)]").next().unwrap_or(src)))
        .collect()
    }

    fn specs_for(keys: &[(&str, &str)]) -> SpecCache {
        SpecCache::from_file(SpecFile {
            config_keys: keys
                .iter()
                .map(|(format, key)| ConfigKeySpec {
                    format: format.to_string(),
                    key: key.to_string(),
                    expect: ConfigExpect::Present,
                    confidence: 0.9,
                    rationale: String::new(),
                    control: String::new(),
                    severity: String::new(),
                    fix: String::new(),
                })
                .collect(),
            ..Default::default()
        })
    }

    #[test]
    fn ledger_is_sorted_and_has_no_duplicates() {
        for w in EMITTED_KEYS.windows(2) {
            assert!(
                (w[0].format, w[0].key) < (w[1].format, w[1].key),
                "{} {} must sort strictly before {} {}",
                w[0].format,
                w[0].key,
                w[1].format,
                w[1].key
            );
        }
    }

    #[test]
    fn every_vocabulary_only_marker_gives_a_reason() {
        for e in EMITTED_KEYS {
            if let Intent::VocabularyOnly(reason) = e.intent {
                assert!(
                    !reason.trim().is_empty(),
                    "{} {} is marked vocabulary only with no reason",
                    e.format,
                    e.key
                );
            }
        }
    }

    /// The emission half of the gate: a packet constructor that writes
    /// `key: key.to_string()` skips the ledger check, and a key added through
    /// it would never be asked for a declaration.
    #[test]
    fn every_packet_constructor_names_its_key_through_the_ledger() {
        let mut constructors = 0;
        for (name, src) in retriever_sources() {
            for (i, line) in src.lines().enumerate() {
                // A struct-field initializer, not a `key: &str` parameter.
                let field = line.trim_start();
                if !field.starts_with("key: ") || field.starts_with("key: &") {
                    continue;
                }
                constructors += 1;
                assert!(
                    line.contains("key_ledger::declared("),
                    "{name}:{}: a packet key must go through key_ledger::declared(): {}",
                    i + 1,
                    line.trim()
                );
            }
        }
        assert!(
            constructors >= 8,
            "found only {constructors} packet constructors; the guard no longer sees them"
        );
    }

    /// The stale half: an entry nothing emits would sit in the mint queue
    /// asking for a spec that could never fire.
    #[test]
    fn every_ledger_key_is_named_by_a_retriever() {
        let sources = retriever_sources();
        for e in EMITTED_KEYS {
            let literal = format!("\"{}\"", e.key);
            assert!(
                sources.iter().any(|(_, src)| src.contains(&literal)),
                "{} {} is in the ledger but no retriever names it",
                e.format,
                e.key
            );
        }
    }

    #[test]
    fn every_ledger_format_belongs_to_a_registered_retriever() {
        // argo-flux is one retriever emitting under two tool identities.
        let mut formats: Vec<&str> = crate::registry()
            .iter()
            .map(|r| r.format_id())
            .filter(|f| *f != "argo-flux")
            .collect();
        formats.extend(["argo-cd", "flux"]);
        for e in EMITTED_KEYS {
            assert!(
                formats.contains(&e.format),
                "{} {} names a format no retriever emits",
                e.format,
                e.key
            );
        }
    }

    #[test]
    #[should_panic(expected = "not declared in key_ledger::EMITTED_KEYS")]
    fn an_undeclared_key_fails_at_the_point_of_emission() {
        declared("github-actions", "job.not-in-the-ledger");
    }

    #[test]
    fn classify_splits_specced_queued_and_vocabulary_only() {
        let specs = specs_for(&[("github-actions", "job.timeout-minutes")]);
        let state = |format, key| classify(lookup(format, key).unwrap(), &specs);
        assert_eq!(
            state("github-actions", "job.timeout-minutes"),
            KeyState::Specced
        );
        assert_eq!(
            state("github-actions", "workflow.concurrency"),
            KeyState::MintQueue
        );
        assert_eq!(
            state("terraform", "module.source"),
            KeyState::VocabularyOnly
        );
    }

    #[test]
    fn a_spec_outranks_the_vocabulary_only_marker() {
        let specs = specs_for(&[("terraform", "module.source")]);
        let entry = lookup("terraform", "module.source").unwrap();
        assert_eq!(classify(entry, &specs), KeyState::Specced);
    }

    #[test]
    fn mint_queue_accounts_for_every_emitted_key() {
        let specs = specs_for(&[
            ("github-actions", "job.timeout-minutes"),
            ("kubernetes", "workload.replicas"),
            // A spec for a key no retriever emits is not the ledger's to count.
            ("github-actions", "job.never-emitted"),
        ]);
        let q = mint_queue(&specs);
        assert_eq!(q.emitted, EMITTED_KEYS.len());
        assert_eq!(q.keys.len(), q.emitted);
        assert_eq!(q.specced, 2);
        assert_eq!(q.vocabulary_only, 2);
        assert_eq!(q.specced + q.mint_queue + q.vocabulary_only, q.emitted);
        let row = q.keys.iter().find(|r| r.key == "module.version-pin");
        assert!(
            row.is_some_and(|r| r.state == KeyState::VocabularyOnly && !r.reason.is_empty()),
            "{row:?}"
        );
    }

    #[test]
    fn an_empty_artifact_queues_every_judged_key() {
        let q = mint_queue(&SpecCache::default());
        assert_eq!(q.specced, 0);
        assert_eq!(q.mint_queue + q.vocabulary_only, q.emitted);
    }
}
