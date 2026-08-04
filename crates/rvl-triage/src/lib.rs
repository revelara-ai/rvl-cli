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
        // The class reason is the RULE NAME that fired: the leading `;` clause,
        // stripped of any `:` tail. Both tails carry site-specific detail
        // ("only phase bounds: connect_timeout=5s; ...") that must not fragment
        // the class. What remains is a fixed phrase from the propagation
        // layer's vocabulary, so it is stored and displayed WHOLE -- a length
        // cap here once cut "no bound anywhere and the search was complete"
        // to "...the search was com" in every ladder row (po-3t3oj.39).
        reason: reason
            .split(';')
            .next()
            .unwrap_or(reason)
            .split(':')
            .next()
            .unwrap_or(reason)
            .trim()
            .to_string(),
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
    // Keyed on site_key (file:line:client_type:method), NOT id() (file:line):
    // chained calls share a line, so id() collides and a violate on `.execute`
    // would be rematched to the `.select` site and mislabeled (po-3t3oj.35).
    // The `verdicts` ids MUST therefore be site_keys, supplied by the caller.
    let by_key: BTreeMap<&str, &Site> = sites
        .iter()
        .map(|s| (Box::leak(s.site_key().into_boxed_str()) as &str, s))
        .collect();
    let mut classes: BTreeMap<ClassKey, Vec<String>> = BTreeMap::new();
    for (key, v, reason) in verdicts {
        if *v != Verdict::Violates {
            continue;
        }
        if let Some(s) = by_key.get(key.as_str()) {
            // Store the readable `file:line` for example_sites; grouping is by
            // the class derived from the correctly-matched site.
            classes.entry(class_of(s, reason)).or_default().push(s.id());
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
            .map(|s| {
                (
                    s.site_key(),
                    Verdict::Violates,
                    "no bound anywhere".to_string(),
                )
            })
            .collect();
        let items = triage(&sites, &verdicts, &[]);
        assert_eq!(items.len(), 1, "50 instances of one shape are one item");
        assert_eq!(items[0].site_count, 50);
    }

    #[test]
    fn chained_line_labels_the_violating_call_not_a_sibling() {
        // Regression (po-3t3oj.35): `db.selectFrom(...).select(...).execute()`
        // puts a not_applicable `.select` and a violating `.execute` on ONE
        // line. Keyed on file:line the violate would be mislabeled `.select`;
        // keyed on site_key it is correctly the `.execute`.
        let sel = site("a/repo.ts", 10, "kysely.SelectQueryBuilder", "select");
        let exec = site("a/repo.ts", 10, "kysely.SelectQueryBuilder", "execute");
        let sites = vec![sel.clone(), exec.clone()];
        // Only the .execute is a violate; the .select is not_applicable.
        let verdicts = vec![
            (
                sel.site_key(),
                Verdict::NotApplicable,
                "does not block".into(),
            ),
            (
                exec.site_key(),
                Verdict::Violates,
                "no bound anywhere".into(),
            ),
        ];
        let items = triage(&sites, &verdicts, &[]);
        assert_eq!(items.len(), 1, "one violate -> one item");
        assert_eq!(
            items[0].class.method, "execute",
            "labels the violating call"
        );
        assert_eq!(items[0].class.client_type, "kysely.SelectQueryBuilder");
    }

    #[test]
    fn unjudged_classes_surface_rather_than_vanish() {
        let s = vec![site("a/f.go", 1, "db.Pool", "Query")];
        let v = vec![(s[0].site_key(), Verdict::Violates, "no bound".to_string())];
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
    fn class_reason_is_the_whole_rule_name_never_cut_mid_word() {
        // Regression (po-3t3oj.39): a 40-char cap displayed every ladder row as
        // "no bound anywhere and the search was com". The rule name is a fixed
        // phrase and must survive whole.
        let s = site("a/f.ts", 1, "kysely.RawBuilder", "execute");
        let k = class_of(&s, "no bound anywhere and the search was complete");
        assert_eq!(k.reason, "no bound anywhere and the search was complete");

        // Variable tails after ':' or ';' are site detail, not class identity:
        // the rule name alone is the class, so detail cannot fragment it.
        let a = class_of(&s, "only phase bounds: connect_timeout=5s; acquire=2s");
        let b = class_of(&s, "only phase bounds: statement_timeout=30s");
        assert_eq!(a.reason, "only phase bounds");
        assert_eq!(a, b, "same rule with different detail is ONE class");
    }

    #[test]
    fn different_scopes_do_not_share_a_class() {
        let s = vec![
            site("internal/f.go", 1, "db.Pool", "Query"),
            site("migrations/m.go", 1, "db.Pool", "Query"),
        ];
        let v: Vec<_> = s
            .iter()
            .map(|x| (x.site_key(), Verdict::Violates, "no bound".to_string()))
            .collect();
        assert_eq!(triage(&s, &v, &[]).len(), 2);
    }
}
