//! Triage: collapse per-site findings into the items a developer would read.
//!
//! The measured gap this crate exists for: 895 technically-correct findings on the
//! reference Go repo triaged to 25 reader-facing items (2.8%), and the first
//! complaint about the old matcher scanner was "every line of code is a new
//! instance of a similar risk". Correctness and actionability are different
//! axes; analyzers get disabled above ~10% developer-PERCEIVED false positives
//! regardless of technical precision.
//!
//! The split mirrors rvl-spec: grouping and rollup here are deterministic;
//! which classes are worth surfacing is JUDGMENT, consumed as data (a class
//! verdict file produced by the LLM judge and reviewable by a human), never
//! computed here. 245 findings that all say "RLSPool.QueryRow has no deadline"
//! are one problem with 245 instances; surfacing them individually IS the spam,
//! no matter how each is judged.

use rvl_core::{scope_of, Site, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The class key: finding SHAPE, not location. Actionability is a property of
/// the shape, so judgment is paid per shape and stays consistent across sites.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ClassKey {
    pub client_type: String,
    pub method: String,
    pub reason: String,
    pub scope: String,
}

/// The spec-class key for a site: "<type>.<method>". Minted here so every
/// producer of a findings row (the scan engine, the eval harness) writes the
/// same string, and a future per-class gate has one place to parse it back.
pub fn class_key_string(site: &Site) -> String {
    let (t, m) = site.api_key();
    format!("{t}.{m}")
}

pub fn class_of(site: &Site, reason: &str) -> ClassKey {
    ClassKey {
        client_type: if site.client_type.is_empty() {
            "?".into()
        } else {
            site.client_type.clone()
        },
        method: site.method.clone(),
        // The leading clause names the rule that fired; the tail carries
        // site-specific detail that must not fragment the class.
        reason: reason
            .split(';')
            .next()
            .unwrap_or(reason)
            .chars()
            .take(40)
            .collect(),
        scope: scope_of(&site.file_path).as_str().into(),
    }
}

/// A judged class verdict, produced offline by the class judge (script 24) and
/// optionally reviewed by a human. Same lifecycle as a spec.
#[derive(Debug, Clone, Deserialize)]
pub struct ClassJudgment {
    pub api: String,
    pub scope: String,
    #[serde(default)]
    pub verdict: String, // surface | rollup | low_value | depends
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub fix: String,
}

#[derive(Debug, Serialize)]
pub struct TriagedItem {
    pub class: ClassKey,
    pub disposition: String,
    pub severity: String,
    pub fix: String,
    pub site_count: usize,
    pub example_sites: Vec<String>,
}

/// Group violating findings into classes and apply judgments. Classes without a
/// judgment surface as `unjudged` rather than being dropped: silent suppression
/// of an unjudged class is how a real problem disappears without anyone
/// deciding it should.
pub fn triage(
    sites: &[Site],
    verdicts: &[(String, Verdict, String)], // (site_id, verdict, reason)
    judgments: &[ClassJudgment],
) -> Vec<TriagedItem> {
    let by_id: BTreeMap<&str, &Site> = sites
        .iter()
        .map(|s| (Box::leak(s.id().into_boxed_str()) as &str, s))
        .collect();
    let mut classes: BTreeMap<ClassKey, Vec<String>> = BTreeMap::new();
    for (id, v, reason) in verdicts {
        if *v != Verdict::Violates {
            continue;
        }
        if let Some(s) = by_id.get(id.as_str()) {
            classes
                .entry(class_of(s, reason))
                .or_default()
                .push(id.clone());
        }
    }

    let judge = |k: &ClassKey| -> Option<&ClassJudgment> {
        judgments.iter().find(|j| {
            j.scope == k.scope
                && (j.api.contains(&k.method)
                    && (k.client_type == "?"
                        || j.api.contains(&k.client_type)
                        || j.api
                            .contains(k.client_type.rsplit('/').next().unwrap_or(""))))
        })
    };

    let mut out: Vec<TriagedItem> = classes
        .into_iter()
        .map(|(k, ids)| {
            let j = judge(&k);
            TriagedItem {
                disposition: j
                    .map(|j| j.verdict.clone())
                    .unwrap_or_else(|| "unjudged".into()),
                severity: j.map(|j| j.severity.clone()).unwrap_or_default(),
                fix: j.map(|j| j.fix.clone()).unwrap_or_default(),
                site_count: ids.len(),
                example_sites: ids.into_iter().take(3).collect(),
                class: k,
            }
        })
        .filter(|t| t.disposition != "low_value")
        .collect();
    out.sort_by_key(|t| std::cmp::Reverse(t.site_count));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(path: &str, line: u32, ct: &str, m: &str) -> Site {
        Site {
            file_path: path.into(),
            line_number: line,
            client_type: ct.into(),
            method: m.into(),
            ..Default::default()
        }
    }

    #[test]
    fn instances_of_one_shape_collapse_to_one_item() {
        let sites: Vec<Site> = (1..=50)
            .map(|i| site("a/f.go", i, "db.Pool", "Query"))
            .collect();
        let verdicts: Vec<_> = sites
            .iter()
            .map(|s| (s.id(), Verdict::Violates, "no bound anywhere".to_string()))
            .collect();
        let items = triage(&sites, &verdicts, &[]);
        assert_eq!(items.len(), 1, "50 instances of one shape are one item");
        assert_eq!(items[0].site_count, 50);
    }

    #[test]
    fn unjudged_classes_surface_rather_than_vanish() {
        let s = vec![site("a/f.go", 1, "db.Pool", "Query")];
        let v = vec![(s[0].id(), Verdict::Violates, "no bound".to_string())];
        let items = triage(&s, &v, &[]);
        assert_eq!(
            items[0].disposition, "unjudged",
            "suppressing an unjudged class is a decision nobody made"
        );
    }

    #[test]
    fn low_value_classes_are_suppressed_only_when_judged_so() {
        let s = vec![site("a/f.go", 1, "pgx.Tx", "Exec")];
        let v = vec![(s[0].id(), Verdict::Violates, "no bound".to_string())];
        let j = vec![ClassJudgment {
            api: "pgx.Tx.Exec()".into(),
            scope: "runtime".into(),
            verdict: "low_value".into(),
            severity: "low".into(),
            fix: String::new(),
        }];
        assert!(triage(&s, &v, &j).is_empty());
    }

    #[test]
    fn different_scopes_do_not_share_a_class() {
        let s = vec![
            site("internal/f.go", 1, "db.Pool", "Query"),
            site("migrations/m.go", 1, "db.Pool", "Query"),
        ];
        let v: Vec<_> = s
            .iter()
            .map(|x| (x.id(), Verdict::Violates, "no bound".to_string()))
            .collect();
        assert_eq!(triage(&s, &v, &[]).len(), 2);
    }
}
