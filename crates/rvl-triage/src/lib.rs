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
    /// Control reference (e.g. "RC-043"), empty if the judgment names none.
    /// This is how a finding is born control-mapped: the judgment layer owns
    /// the mapping and triage only carries it through.
    #[serde(default)]
    pub control: String,
}

#[derive(Debug, Serialize)]
pub struct TriagedItem {
    pub class: ClassKey,
    pub disposition: String,
    pub severity: String,
    pub fix: String,
    /// Control reference carried from the class judgment (e.g. "RC-043").
    pub control: String,
    pub site_count: usize,
    pub example_sites: Vec<String>,
}

/// A judgment's `api` with the form the corpus authors it in normalised away:
/// surrounding whitespace and a trailing `()` (`pgx.Tx.Exec()`).
fn normalize_judgment_api(api: &str) -> &str {
    let a = api.trim();
    a.strip_suffix("()").unwrap_or(a).trim_end()
}

/// The client-type half of `api` given the method it must end with, or None if
/// it does not end with that method at a dot boundary.
///
/// Peels the METHOD off the end rather than splitting at the last dot, because
/// a method can itself contain one: the content lane authors
/// `secret.<rule_id>`, and a rule id like `gcp.api_key` would make a last-dot
/// split read the client type as `secret.gcp`. Anchoring on the method the
/// class actually has keeps both halves exact.
fn judgment_client_type<'a>(api: &'a str, method: &str) -> Option<&'a str> {
    normalize_judgment_api(api)
        .strip_suffix(method)?
        .strip_suffix('.')
        .filter(|t| !t.is_empty())
}

/// How specifically `j` matches class `k`: higher is more specific, None is no
/// match. EXACT comparison throughout (po-av01j.96).
///
/// The old guard tested `j.api.contains(&k.method)` and friends, which meant
/// `"db.RLSPool.QueryRow".contains("Query")` silenced the whole `Query` class —
/// 184 real sites on a dogfood scan, dropped without anyone deciding to. Three
/// more holes came from the same shape: an unresolved client type (`"?"`)
/// skipped the type guard entirely and so absorbed any judgment in scope, an
/// empty method made `contains("")` universally true, and `find` returned file
/// order rather than the best match.
fn judgment_match_rank(j: &ClassJudgment, k: &ClassKey) -> Option<u8> {
    if j.scope != k.scope {
        return None;
    }
    if k.method.is_empty() {
        return None;
    }
    let jt = judgment_client_type(&j.api, &k.method)?;
    if jt == k.client_type {
        return Some(2);
    }
    // Judgments may name only the last PATH segment of a qualified type
    // (`v9.Client` for `github.com/redis/go-redis/v9.Client`), which is the
    // flexibility the substring match was really there for. Compared WHOLE, so
    // a bare `Client` no longer matches every package's client.
    //
    // An unresolved client type is `"?"`, which contains no `/` and so only
    // ever matches a judgment that literally writes `?`. That is deliberate:
    // a class whose type could not be resolved must fall through to `unjudged`
    // and be surfaced, not silently inherit an unrelated judgment.
    if k.client_type.rsplit('/').next() == Some(jt) {
        return Some(1);
    }
    None
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
        // Most specific wins, never file order (po-av01j.96). A wrong match
        // does not just suppress: it also stamps the class with another
        // judgment's severity, fix text and RC control code.
        judgments
            .iter()
            .filter_map(|j| judgment_match_rank(j, k).map(|rank| (rank, j.api.len(), j)))
            .max_by_key(|(rank, len, _)| (*rank, *len))
            .map(|(_, _, j)| j)
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
                control: j.map(|j| j.control.clone()).unwrap_or_default(),
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
        // po-av01j.97: this test used to key the verdict on `id()` ("file:line")
        // while triage keys `by_key` on `site_key()`
        // ("file:line:client_type:method"). The verdict never rematched, so NO
        // class was ever formed and the function returned empty for reasons
        // that had nothing to do with suppression. Proved before fixing: the
        // old body was also empty with ZERO judgments, and empty with a
        // `surface` judgment that must never suppress, so the assertion would
        // have held even with the low_value filter deleted outright.
        //
        // The three arms below are what make it non-vacuous: the class must be
        // FORMED first, `surface` must NOT suppress it, and only `low_value`
        // may remove it.
        let s = vec![site("a/f.go", 1, "pgx.Tx", "Exec")];
        let v = vec![(s[0].site_key(), Verdict::Violates, "no bound".to_string())];
        let judgment = |verdict: &str| {
            vec![ClassJudgment {
                api: "pgx.Tx.Exec()".into(),
                scope: "runtime".into(),
                verdict: verdict.into(),
                severity: "low".into(),
                fix: String::new(),
                control: String::new(),
            }]
        };

        // 1. the class forms at all — without this the other two prove nothing
        let unjudged = triage(&s, &v, &[]);
        assert_eq!(
            unjudged.len(),
            1,
            "the violate must form a class to begin with"
        );
        assert_eq!(unjudged[0].disposition, "unjudged");

        // 2. a judgment that is not low_value must leave it standing
        let surfaced = triage(&s, &v, &judgment("surface"));
        assert_eq!(
            surfaced.len(),
            1,
            "only low_value suppresses, not any judgment"
        );
        assert_eq!(surfaced[0].disposition, "surface");

        // 3. and low_value removes it
        assert!(triage(&s, &v, &judgment("low_value")).is_empty());
    }

    #[test]
    fn judgment_control_reference_flows_to_the_triaged_item() {
        // A finding is born control-mapped: the judgment names the control and
        // triage must carry it through, never invent or drop it.
        let s = vec![site("app/cfg.py", 3, "secret", "aws_access_key_id")];
        let v = vec![(
            s[0].site_key(),
            Verdict::Violates,
            "hardcoded AWS access key ID".to_string(),
        )];
        let j = vec![ClassJudgment {
            api: "secret.aws_access_key_id".into(),
            scope: "runtime".into(),
            verdict: "surface".into(),
            severity: "high".into(),
            fix: "rotate and move to a secret manager".into(),
            control: "RC-043".into(),
        }];
        let items = triage(&s, &v, &j);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].control, "RC-043");
        assert_eq!(items[0].disposition, "surface");
        // An unjudged class carries no control.
        let bare = triage(&s, &v, &[]);
        assert_eq!(bare[0].control, "");
    }

    // --- Judgment matching is EXACT, never substring (po-av01j.96) ---

    fn judgment(api: &str, verdict: &str) -> ClassJudgment {
        ClassJudgment {
            api: api.into(),
            scope: "runtime".into(),
            verdict: verdict.into(),
            severity: "low".into(),
            fix: String::new(),
            control: String::new(),
        }
    }

    /// Triage one violating site and return its disposition.
    fn disposition_of(ct: &str, method: &str, judgments: &[ClassJudgment]) -> String {
        let s = vec![site("a/f.go", 1, ct, method)];
        let v = vec![(s[0].site_key(), Verdict::Violates, "no bound".to_string())];
        triage(&s, &v, judgments)
            .first()
            .map(|t| t.disposition.clone())
            .unwrap_or_else(|| "SUPPRESSED".into())
    }

    #[test]
    fn a_judgment_for_query_row_does_not_silence_query() {
        // THE reported bug: "db.RLSPool.QueryRow".contains("Query") is true, so
        // a low_value judgment on QueryRow dropped the whole Query class —
        // 184 real sites in a dogfood scan of a Go backend, silently.
        let j = vec![judgment("db.RLSPool.QueryRow", "low_value")];
        assert_eq!(
            disposition_of("db.RLSPool", "Query", &j),
            "unjudged",
            "Query must not inherit QueryRow's judgment"
        );
        // and the judgment still applies to the class it actually names
        assert_eq!(disposition_of("db.RLSPool", "QueryRow", &j), "SUPPRESSED");
    }

    #[test]
    fn the_same_prefix_trap_in_both_directions() {
        // Exec/ExecContext, Get/GetObject, Do/Download, Send/SendMessage.
        for (judged, other) in [
            ("ExecContext", "Exec"),
            ("GetObject", "Get"),
            ("Download", "Do"),
            ("SendMessage", "Send"),
        ] {
            let j = vec![judgment(&format!("s3.Client.{judged}"), "low_value")];
            assert_eq!(
                disposition_of("s3.Client", other, &j),
                "unjudged",
                "{other} must not inherit {judged}'s judgment"
            );
        }
    }

    #[test]
    fn a_trailing_call_suffix_still_matches() {
        // The corpus writes `pgx.Tx.Exec()`; that is the shape the substring
        // match was papering over, so exact matching has to normalise it rather
        // than regress the format the judgments are authored in.
        let j = vec![judgment("pgx.Tx.Exec()", "low_value")];
        assert_eq!(disposition_of("pgx.Tx", "Exec", &j), "SUPPRESSED");
    }

    #[test]
    fn a_short_client_type_still_matches_a_fully_qualified_one() {
        // Sites carry `github.com/redis/go-redis/v9.Client`; judgments are
        // authored against the last path segment. Matching the SEGMENT is exact
        // at both ends — unlike `contains`, which also accepted `Client`.
        let j = vec![judgment("v9.Client.Get", "low_value")];
        assert_eq!(
            disposition_of("github.com/redis/go-redis/v9.Client", "Get", &j),
            "SUPPRESSED"
        );
        let loose = vec![judgment("Client.Get", "low_value")];
        assert_eq!(
            disposition_of("github.com/redis/go-redis/v9.Client", "Get", &loose),
            "unjudged",
            "a bare type name must not match every package's Client"
        );
    }

    #[test]
    fn an_unresolved_client_type_is_not_a_wildcard() {
        // Hole 2: class_of maps an empty client_type to "?", and the old guard
        // skipped the type check entirely for it — so one redis judgment
        // silenced every unknown-client Get in scope.
        let j = vec![judgment("redis.Client.Get", "low_value")];
        assert_eq!(
            disposition_of("", "Get", &j),
            "unjudged",
            "an unknown client type must not absorb an unrelated judgment"
        );
    }

    #[test]
    fn a_dotted_method_still_parses_into_the_right_halves() {
        // The content lane authors `secret.<rule_id>`, and a rule id containing
        // a dot would make a last-dot split read the client type as
        // `secret.gcp`. Anchoring on the method the class has keeps it exact.
        let j = vec![judgment("secret.gcp.api_key", "low_value")];
        assert_eq!(disposition_of("secret", "gcp.api_key", &j), "SUPPRESSED");
        // and it must still not bleed onto a neighbouring rule id
        assert_eq!(disposition_of("secret", "gcp.api_key_id", &j), "unjudged");
    }

    #[test]
    fn an_empty_method_matches_nothing() {
        // Hole 3: contains("") is always true, so a judgment with no method
        // matched every class in its scope.
        let j = vec![judgment("db.RLSPool.", "low_value")];
        assert_eq!(disposition_of("db.RLSPool", "Query", &j), "unjudged");
        assert_eq!(disposition_of("anything.Else", "Do", &j), "unjudged");
    }

    #[test]
    fn the_most_specific_judgment_wins_regardless_of_file_order() {
        // Hole 4: `find` returned FILE ORDER, so the wrong judgment could also
        // mislabel severity, fix text and the RC control code — not only
        // suppression. Order the corpus adversarially and require the same
        // answer both ways.
        let specific = ClassJudgment {
            api: "github.com/redis/go-redis/v9.Client.Get".into(),
            scope: "runtime".into(),
            verdict: "surface".into(),
            severity: "high".into(),
            fix: "bound it".into(),
            control: "RC-019".into(),
        };
        let general = judgment("v9.Client.Get", "rollup");
        for corpus in [
            vec![general.clone(), specific.clone()],
            vec![specific.clone(), general.clone()],
        ] {
            let s = vec![site(
                "a/f.go",
                1,
                "github.com/redis/go-redis/v9.Client",
                "Get",
            )];
            let v = vec![(s[0].site_key(), Verdict::Violates, "no bound".to_string())];
            let items = triage(&s, &v, &corpus);
            assert_eq!(items[0].disposition, "surface", "exact match must win");
            assert_eq!(items[0].control, "RC-019", "and carry ITS control");
            assert_eq!(items[0].severity, "high");
        }
    }

    #[test]
    fn scope_still_gates_the_match() {
        let mut j = judgment("db.RLSPool.Query", "low_value");
        j.scope = "test".into();
        // The site is under a runtime path, so a test-scoped judgment must miss.
        assert_eq!(disposition_of("db.RLSPool", "Query", &[j]), "unjudged");
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
