//! The config-spec VERIFICATION lane: apply [`rvl_spec::ConfigKeySpec`]s to
//! config packets, mechanically and with the same abstention semantics as the
//! call-site lane's `spec_gate`.
//!
//! Nothing here decides config semantics. The spec says what satisfies; the
//! packet says what the repo resolves to and how it was produced; this module
//! combines them. Every abstention names the lever that closes it:
//!
//!   * no spec for the (format, key) → mint one (the factory's queue);
//!   * spec confidence below the floor → verify/refute the spec (the
//!     verification run — a wrong config spec is multiplied across every repo
//!     using the format, exactly like a wrong API spec);
//!   * value set outside the repo → out-of-repo declaration (policy file);
//!   * unknown pattern name or expectation kind → the spec is newer than this
//!     scanner: upgrade;
//!   * guard predicate not retrieved → same lever: the retriever does not
//!     state the fact a conditional spec asks about.

use crate::{ConfigPacket, ConfigPredicate, Resolution};
use rvl_core::Verdict;
use rvl_spec::{ConfigExpect, SpecCache, MIN_CONFIDENCE};

/// A verdict about one config packet. `control`/`severity`/`fix` are carried
/// from the deciding spec so the renderer needs no second lookup; empty when
/// no spec decided (abstentions).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigFinding {
    pub packet_id: String,
    pub verdict: Verdict,
    pub reason: String,
    pub control: String,
    pub severity: String,
    pub fix: String,
}

/// Match a NAMED pattern against a value. Patterns are code-defined so a
/// signed spec never carries executable pattern syntax; a name this binary
/// does not know returns `None` and the caller abstains (a spec authored for
/// a newer scanner must degrade safely, never guess).
pub fn pattern_matches(name: &str, value: &str) -> Option<bool> {
    match name {
        // A full 40-hex-char commit SHA: the action-pinning control.
        "sha40" => Some(value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())),
        // Any non-empty value: presence-of-a-key controls where absence is
        // an AUTHORED fact with no platform default behind it (e.g. an alert
        // rule with no severity label — the packet's value is "").
        "nonempty" => Some(!value.is_empty()),
        // Any real authored value at all: the presence judgment for
        // decidable-absent keys, whose packets render the absence as
        // [`crate::ABSENT_RENDERING`] (an automated Argo Application with no
        // retry). An empty value — an authored absence, e.g. an unpinned
        // `uses:` ref — is not configured either.
        "configured" => Some(!value.is_empty() && value != crate::ABSENT_RENDERING),
        _ => None,
    }
}

/// Seconds in a duration string of the Go / Prometheus grammar: one or more
/// `<number><unit>` terms (`30s`, `1h30m`, `1.5h`, `2d`). `None` for anything
/// else, including a bare number: only `0` needs no unit, and guessing one
/// for `15` is how a bound starts flagging correct configurations.
fn parse_duration_secs(text: &str) -> Option<f64> {
    const UNITS: &[(&str, f64)] = &[
        ("ns", 1e-9),
        ("us", 1e-6),
        ("\u{b5}s", 1e-6),
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
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let number: f64 = rest[..digits].parse().ok()?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let (_, scale) = UNITS.iter().find(|(u, _)| *u == &rest[..unit_len])?;
        total += number * scale;
        rest = &rest[unit_len..];
    }
    Some(total)
}

/// A compact citation of how the value was produced, for reasons. Uses the
/// LAST provenance step: the one that actually supplied (or failed to
/// supply) the value.
fn provenance_note(p: &ConfigPacket) -> String {
    match p.provenance.last() {
        Some(step) if step.file.is_empty() => format!("{} ({})", step.key_path, step.role),
        Some(step) => format!("{} in {} ({})", step.key_path, step.file, step.role),
        None => String::new(),
    }
}

/// Apply the specs to one packet.
/// True when NOTHING in the repo authors this key: no provenance step reports a
/// value being supplied, only absences plus an out-of-repo setting.
///
/// This is what lets `Present` decide on an Unresolvable packet without
/// guessing at the external value: the question is whether the repo authored
/// anything, and the provenance chain already answers it. An Unresolvable
/// packet that DOES carry an authoring step (a value set in-repo that still
/// cannot be resolved) keeps abstaining.
fn authored_nowhere(p: &ConfigPacket) -> bool {
    !p.provenance
        .iter()
        .any(|s| matches!(s.role.as_str(), "explicit" | "inherited" | "default-block"))
}

pub fn evaluate(
    p: &ConfigPacket,
    predicates: &[ConfigPredicate],
    specs: &SpecCache,
) -> ConfigFinding {
    let id = p.id();
    let abstain = |reason: String| ConfigFinding {
        packet_id: id.clone(),
        verdict: Verdict::Abstain,
        reason,
        control: String::new(),
        severity: String::new(),
        fix: String::new(),
    };

    let Some(spec) = specs.config_key(&p.format, &p.key) else {
        return abstain(format!("no config spec for {}.{}", p.format, p.key));
    };
    if spec.confidence < MIN_CONFIDENCE {
        return abstain(format!(
            "config spec confidence {:.2} below {MIN_CONFIDENCE}",
            spec.confidence
        ));
    }
    let decided = |verdict: Verdict, reason: String| ConfigFinding {
        packet_id: id.clone(),
        verdict,
        reason,
        control: spec.control.clone(),
        severity: spec.severity.clone(),
        fix: spec.fix.clone(),
    };

    // A conditional spec is peeled to the expectation it guards BEFORE anything
    // about the value is consulted, so the inner expectation keeps every one of
    // its own semantics below (po-av01j.133.10). Nested guards are a
    // conjunction: the first that fails to hold ends the judgment.
    let mut expect = &spec.expect;
    while let ConfigExpect::When { guard, then } = expect {
        let Some(fact) = predicates
            .iter()
            .find(|f| f.key == guard.key && f.applies_to(p))
        else {
            // The retriever stated nothing about this unit. Judging `then`
            // anyway is the unconditional spec the guard exists to prevent,
            // and not-applicable would be a pass on a guess.
            return abstain(format!(
                "guard predicate '{}' was not retrieved for this unit: the spec is \
                 newer than this scanner, or the fact is not decidable from the repo",
                guard.key
            ));
        };
        if !fact.values.iter().any(|v| guard.any_of.contains(v)) {
            return decided(
                Verdict::NotApplicable,
                format!(
                    "guard not met: {} is {}, not any of {}",
                    guard.key,
                    fact.values.join(", "),
                    guard.any_of.join(", ")
                ),
            );
        }
        expect = then;
    }

    // An out-of-repo VALUE is unknowable here, so the value-bearing variants
    // abstain before the expectation is consulted and none of them can guess.
    //
    // `Present` IS THE EXCEPTION, and it is not a special case so much as the
    // definition of the variant (po-av01j.143). It asks about AUTHORSHIP, not
    // about the effective value: "an EXPLICIT setting must be present in the
    // repo ... the control asks for an authored bound, and 'the platform picked
    // one for you' is the finding". Not knowing the external default is
    // therefore not an obstacle to deciding -- it IS the finding.
    //
    // Without this the ratified github-actions job.permissions spec was INERT.
    // A workflow with no permissions block at any level resolves to
    // Unresolvable (the GITHUB_TOKEN default is an org setting the retriever
    // cannot see, which is honest), so the spec abstained on exactly the case
    // it exists to catch and had never fired once in six rounds of dogfooding.
    if p.resolution == Resolution::Unresolvable {
        if matches!(expect, ConfigExpect::Present) && authored_nowhere(p) {
            return decided(
                Verdict::Violates,
                format!(
                    "not authored anywhere in the repo; the effective value is an \
                     out-of-repo default: {}",
                    provenance_note(p)
                ),
            );
        }
        return abstain(format!(
            "effective value is set outside the repo: {}",
            provenance_note(p)
        ));
    }
    let value = p.resolved_value.as_deref().unwrap_or("");

    match expect {
        ConfigExpect::Present => match p.resolution {
            Resolution::AsAuthored | Resolution::Rendered => decided(
                Verdict::Satisfies,
                format!(
                    "explicitly set: {} = {value}; {}",
                    p.key,
                    provenance_note(p)
                ),
            ),
            Resolution::PlatformDefault => decided(
                Verdict::Violates,
                format!("not explicitly set: platform default {value} governs"),
            ),
            Resolution::Unresolvable => unreachable!("handled above"),
        },
        ConfigExpect::AtLeast { value: want } => match value.trim().parse::<f64>() {
            Ok(got) if got >= *want => decided(
                Verdict::Satisfies,
                format!("{} = {value} meets the minimum of {want}", p.key),
            ),
            Ok(got) => decided(
                Verdict::Violates,
                format!("below the minimum of {want}: {} = {got}", p.key),
            ),
            // Not a number: an unresolved template or an unexpected unit is
            // not evidence of a violation, so this abstains rather than
            // failing. Guessing here is how a spec starts flagging correct
            // configurations.
            Err(_) => abstain(format!(
                "{} = {value:?} is not numeric, so a numeric bound cannot be judged",
                p.key
            )),
        },
        ConfigExpect::AtMost { value: want } => match value.trim().parse::<f64>() {
            Ok(got) if got <= *want => decided(
                Verdict::Satisfies,
                format!("{} = {value} is within the maximum of {want}", p.key),
            ),
            Ok(got) => decided(
                Verdict::Violates,
                format!("above the maximum of {want}: {} = {got}", p.key),
            ),
            Err(_) => abstain(format!(
                "{} = {value:?} is not numeric, so a numeric bound cannot be judged",
                p.key
            )),
        },
        ConfigExpect::Equals { value: want } => {
            if value == want {
                decided(
                    Verdict::Satisfies,
                    format!("{} = {value}; {}", p.key, provenance_note(p)),
                )
            } else {
                decided(
                    Verdict::Violates,
                    format!("not equal to {want}: {} = {value}", p.key),
                )
            }
        }
        ConfigExpect::NotEquals { value: unwanted } => {
            if value != unwanted {
                decided(
                    Verdict::Satisfies,
                    format!("{} = {value}; {}", p.key, provenance_note(p)),
                )
            } else {
                decided(
                    Verdict::Violates,
                    format!("equal to {unwanted}: {}", provenance_note(p)),
                )
            }
        }
        ConfigExpect::DurationAtLeast { value: want }
        | ConfigExpect::DurationAtMost { value: want } => {
            let at_least = matches!(expect, ConfigExpect::DurationAtLeast { .. });
            let (Some(bound), Some(got)) = (parse_duration_secs(want), parse_duration_secs(value))
            else {
                // The same rule as the numeric bounds: an unresolved template
                // or an authored absence is not evidence of a violation, and
                // neither is a spec whose own bound does not parse.
                return abstain(format!(
                    "{} = {value:?} against {want:?} is not a duration comparison, so the bound cannot be judged",
                    p.key
                ));
            };
            let (met, missed) = if at_least {
                (got >= bound, "below the minimum of")
            } else {
                (got <= bound, "above the maximum of")
            };
            if met {
                let side = if at_least {
                    "meets the minimum of"
                } else {
                    "is within the maximum of"
                };
                decided(
                    Verdict::Satisfies,
                    format!("{} = {value} {side} {want}", p.key),
                )
            } else {
                decided(
                    Verdict::Violates,
                    format!("{missed} {want}: {} = {value}", p.key),
                )
            }
        }
        ConfigExpect::Unknown => {
            abstain("unknown expectation kind: the spec is newer than this scanner".to_string())
        }
        ConfigExpect::OneOf { values } => {
            if values.iter().any(|v| v == value) {
                decided(
                    Verdict::Satisfies,
                    format!("{} = {value}; {}", p.key, provenance_note(p)),
                )
            } else {
                decided(
                    Verdict::Violates,
                    format!("not one of {}: {} = {value}", values.join(", "), p.key),
                )
            }
        }
        ConfigExpect::When { .. } => unreachable!("peeled above"),
        ConfigExpect::Pattern { name } => match pattern_matches(name, value) {
            None => abstain(format!(
                "unknown pattern '{name}': the spec is newer than this scanner"
            )),
            Some(true) => decided(
                Verdict::Satisfies,
                format!("{} = {value} matches {name}; {}", p.key, provenance_note(p)),
            ),
            Some(false) => decided(
                Verdict::Violates,
                format!("does not match {name}: {} = {value}", p.key),
            ),
        },
    }
}

/// Apply the specs to every packet. Index-aligned 1:1 with the input, the
/// same contract as `propagate_all`.
pub fn evaluate_all(
    packets: &[ConfigPacket],
    predicates: &[ConfigPredicate],
    specs: &SpecCache,
) -> Vec<ConfigFinding> {
    packets
        .iter()
        .map(|p| evaluate(p, predicates, specs))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProvenanceStep;
    use rvl_spec::{ConfigGuard, ConfigKeySpec, SpecFile};

    /// The unconditional variants never read a predicate, so their tests judge
    /// with none.
    fn evaluate(p: &ConfigPacket, specs: &SpecCache) -> ConfigFinding {
        super::evaluate(p, &[], specs)
    }

    fn packet(key: &str, value: Option<&str>, resolution: Resolution) -> ConfigPacket {
        ConfigPacket {
            snapshot_id: "s".into(),
            format: "github-actions".into(),
            file_path: ".github/workflows/ci.yml".into(),
            line: 0,
            unit: "job:build".into(),
            key: key.into(),
            resolved_value: value.map(str::to_string),
            resolution,
            provenance: vec![ProvenanceStep::new(
                ".github/workflows/ci.yml",
                "jobs.build.x",
                "explicit",
            )],
        }
    }

    fn cache(key: &str, expect: ConfigExpect, confidence: f64) -> SpecCache {
        SpecCache::from_file(SpecFile {
            config_keys: vec![ConfigKeySpec {
                format: "github-actions".into(),
                key: key.into(),
                expect,
                confidence,
                rationale: String::new(),
                control: "RC-013".into(),
                severity: "medium".into(),
                fix: "set it".into(),
            }],
            ..Default::default()
        })
    }

    #[test]
    fn no_spec_abstains_and_names_the_mint_lever() {
        let f = evaluate(
            &packet("job.timeout-minutes", Some("15"), Resolution::AsAuthored),
            &SpecCache::default(),
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.starts_with("no config spec"), "{}", f.reason);
    }

    #[test]
    fn low_confidence_spec_abstains_a_wrong_config_spec_is_multiplied() {
        let c = cache("job.timeout-minutes", ConfigExpect::Present, 0.5);
        let f = evaluate(
            &packet("job.timeout-minutes", Some("15"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("confidence"), "{}", f.reason);
    }

    #[test]
    fn present_expectation_passes_authored_and_fails_platform_default() {
        let c = cache("job.timeout-minutes", ConfigExpect::Present, 0.9);
        let ok = evaluate(
            &packet("job.timeout-minutes", Some("15"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies);
        assert_eq!(ok.control, "RC-013", "the deciding spec's control rides");

        let bad = evaluate(
            &packet(
                "job.timeout-minutes",
                Some("360"),
                Resolution::PlatformDefault,
            ),
            &c,
        );
        assert_eq!(
            bad.verdict,
            Verdict::Violates,
            "a platform default is not an authored bound"
        );
        assert!(bad.reason.contains("not explicitly set"), "{}", bad.reason);
    }

    #[test]
    fn rendered_resolution_satisfies_present_like_authored() {
        // Helm renders with committed values stamp `rendered`; still an
        // in-repo authored setting for Present purposes.
        let c = cache("job.timeout-minutes", ConfigExpect::Present, 0.9);
        let f = evaluate(
            &packet("job.timeout-minutes", Some("15"), Resolution::Rendered),
            &c,
        );
        assert_eq!(f.verdict, Verdict::Satisfies);
    }

    /// The REAL shape the GitHub Actions retriever emits when neither the job
    /// nor the workflow authors `permissions`: every in-repo step reports an
    /// absence, and the effective value lives in an org setting.
    fn unauthored_unresolvable(key: &str) -> ConfigPacket {
        let mut p = packet(key, None, Resolution::Unresolvable);
        p.provenance = vec![
            ProvenanceStep::new(
                ".github/workflows/ci.yml",
                "jobs.build.permissions",
                "absent",
            ),
            ProvenanceStep::new(".github/workflows/ci.yml", "permissions", "absent"),
            ProvenanceStep::new("", "GITHUB_TOKEN default permissions", "repo-setting"),
        ];
        p
    }

    // po-av01j.143. `Present` asks about AUTHORSHIP, so an out-of-repo default
    // is not an obstacle to deciding -- it is the finding. Without this the
    // ratified job.permissions spec was inert: it abstained on precisely the
    // case it exists to catch and never fired once in six rounds.
    #[test]
    fn present_violates_when_the_key_is_authored_nowhere_in_the_repo() {
        let c = cache("job.permissions", ConfigExpect::Present, 0.9);
        let f = evaluate(&unauthored_unresolvable("job.permissions"), &c);
        assert_eq!(f.verdict, Verdict::Violates, "{}", f.reason);
        assert!(
            f.reason.contains("not authored anywhere"),
            "the reason must say WHY: {}",
            f.reason
        );
    }

    // The value-bearing variants genuinely need a value, so they must keep
    // abstaining on the identical packet. This is the line between "I can
    // decide without the value" and "I cannot".
    #[test]
    fn value_bearing_expectations_still_abstain_when_unresolvable() {
        for expect in [
            ConfigExpect::Equals {
                value: "read".into(),
            },
            ConfigExpect::OneOf {
                values: vec!["read".into()],
            },
            ConfigExpect::Pattern {
                name: "sha40".into(),
            },
        ] {
            let c = cache("job.permissions", expect, 0.9);
            let f = evaluate(&unauthored_unresolvable("job.permissions"), &c);
            assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
        }
    }

    // An Unresolvable packet that DOES carry an authoring step keeps abstaining
    // even for `Present`: something in the repo set it, and what it resolves to
    // is genuinely unknown.
    // po-av01j.129. "replicas >= 2" was unstatable: equals("1") is backwards
    // because an expectation flags what does NOT match, and one_of enumerating
    // counts breaks outside the list. Authoring the class anyway produced the
    // po-av01j.44 inversion, where a PodDisruptionBudget presence check PASSED
    // the configuration that pins disruptionsAllowed at 0 forever.
    #[test]
    fn at_least_decides_both_ways_on_a_numeric_value() {
        let c = cache(
            "workload.replicas",
            ConfigExpect::AtLeast { value: 2.0 },
            0.9,
        );
        let ok = evaluate(
            &packet("workload.replicas", Some("3"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies, "{}", ok.reason);
        let bad = evaluate(
            &packet("workload.replicas", Some("1"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(bad.verdict, Verdict::Violates, "{}", bad.reason);
        // The boundary is inclusive: exactly the minimum satisfies.
        let edge = evaluate(
            &packet("workload.replicas", Some("2"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(edge.verdict, Verdict::Satisfies, "{}", edge.reason);
    }

    #[test]
    fn at_most_decides_both_ways() {
        let c = cache(
            "pod.termination-grace",
            ConfigExpect::AtMost { value: 60.0 },
            0.9,
        );
        assert_eq!(
            evaluate(
                &packet("pod.termination-grace", Some("30"), Resolution::AsAuthored),
                &c
            )
            .verdict,
            Verdict::Satisfies
        );
        assert_eq!(
            evaluate(
                &packet("pod.termination-grace", Some("120"), Resolution::AsAuthored),
                &c
            )
            .verdict,
            Verdict::Violates
        );
    }

    // A NON-NUMERIC value abstains rather than failing. An unresolved Helm
    // template or an unexpected unit is not evidence of a violation, and
    // guessing is how a spec starts flagging correct configurations.
    #[test]
    fn a_non_numeric_value_abstains_rather_than_violating() {
        let c = cache(
            "workload.replicas",
            ConfigExpect::AtLeast { value: 2.0 },
            0.9,
        );
        for v in ["{{ .Values.replicas }}", "", "many"] {
            let f = evaluate(
                &packet("workload.replicas", Some(v), Resolution::AsAuthored),
                &c,
            );
            assert_eq!(f.verdict, Verdict::Abstain, "{v:?} -> {}", f.reason);
        }
    }

    #[test]
    fn unresolvable_abstains_no_matter_what_the_spec_expects() {
        let c = cache("job.permissions", ConfigExpect::Present, 0.9);
        let f = evaluate(
            &packet("job.permissions", None, Resolution::Unresolvable),
            &c,
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("outside the repo"), "{}", f.reason);
    }

    #[test]
    fn equals_decides_both_ways_including_via_platform_default() {
        let c = cache(
            "job.continue-on-error",
            ConfigExpect::Equals {
                value: "false".into(),
            },
            0.9,
        );
        // Absent -> documented default false: satisfies through the default.
        let ok = evaluate(
            &packet(
                "job.continue-on-error",
                Some("false"),
                Resolution::PlatformDefault,
            ),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies);
        let bad = evaluate(
            &packet(
                "job.continue-on-error",
                Some("true"),
                Resolution::AsAuthored,
            ),
            &c,
        );
        assert_eq!(bad.verdict, Verdict::Violates);
    }

    #[test]
    fn sha40_pattern_decides_pins_and_unknown_patterns_abstain() {
        let c = cache(
            "step.uses.ref",
            ConfigExpect::Pattern {
                name: "sha40".into(),
            },
            0.9,
        );
        let sha = "8f4b7f84864484a7bf31766abe9204da3cbe65b3";
        let ok = evaluate(
            &packet("step.uses.ref", Some(sha), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies);
        let tag = evaluate(
            &packet("step.uses.ref", Some("v5"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(tag.verdict, Verdict::Violates);

        let newer = cache(
            "step.uses.ref",
            ConfigExpect::Pattern {
                name: "some-future-pattern".into(),
            },
            0.9,
        );
        let f = evaluate(
            &packet("step.uses.ref", Some(sha), Resolution::AsAuthored),
            &newer,
        );
        assert_eq!(
            f.verdict,
            Verdict::Abstain,
            "a spec newer than the scanner degrades to abstention, never a guess"
        );
        assert!(f.reason.contains("newer than this scanner"), "{}", f.reason);
    }

    #[test]
    fn nonempty_pattern_decides_authored_absences() {
        // The presence-of-a-key controls: an authored absence packet (value
        // "") violates, any authored value satisfies.
        let c = cache(
            "rule.labels.severity",
            ConfigExpect::Pattern {
                name: "nonempty".into(),
            },
            0.9,
        );
        let ok = evaluate(
            &packet("rule.labels.severity", Some("page"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies);
        let bad = evaluate(
            &packet("rule.labels.severity", Some(""), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(bad.verdict, Verdict::Violates);
    }

    #[test]
    fn configured_pattern_judges_decidable_authored_absence() {
        // The G6 family-6 lever: an as-authored-absent packet (value
        // ABSENT_RENDERING, e.g. an automated Application without retry)
        // violates a `configured` spec; any real authored value satisfies.
        let c = cache(
            "job.retry",
            ConfigExpect::Pattern {
                name: "configured".into(),
            },
            0.9,
        );
        let absent = evaluate(
            &packet(
                "job.retry",
                Some(crate::ABSENT_RENDERING),
                Resolution::AsAuthored,
            ),
            &c,
        );
        assert_eq!(absent.verdict, Verdict::Violates, "{}", absent.reason);
        let set = evaluate(
            &packet("job.retry", Some(r#"{"limit":5}"#), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(set.verdict, Verdict::Satisfies, "{}", set.reason);
        // An empty value (an authored absence, e.g. an unpinned `uses:` ref)
        // is not configured either.
        assert_eq!(pattern_matches("configured", ""), Some(false));
    }

    /// A cache built from the artifact's JSON, the way a served spec arrives.
    fn cache_from_json(key: &str, expect: &str) -> SpecCache {
        SpecCache::load(&format!(
            r#"{{"config_keys":[{{"format":"github-actions","key":"{key}","expect":{expect},
                "confidence":0.9,"control":"RC-050","severity":"medium","fix":"set it"}}]}}"#
        ))
        .expect("the spec file parses")
    }

    // po-pk3fp.13. "Not the default project" was unstatable: equals flags what
    // does NOT match, so it can only name the one value that is wanted, and
    // one_of cannot enumerate every project name an org might use.
    #[test]
    fn not_equals_decides_both_ways() {
        let c = cache_from_json(
            "application.project",
            r#"{"kind":"not_equals","value":"default"}"#,
        );
        let ok = evaluate(
            &packet(
                "application.project",
                Some("payments"),
                Resolution::AsAuthored,
            ),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies, "{}", ok.reason);
        let bad = evaluate(
            &packet(
                "application.project",
                Some("default"),
                Resolution::PlatformDefault,
            ),
            &c,
        );
        assert_eq!(bad.verdict, Verdict::Violates, "{}", bad.reason);
        assert!(bad.reason.starts_with("equal to default"), "{}", bad.reason);
    }

    // Flux remediation retries: -1 means "remediate forever", the strongest
    // setting, and at_least 1 flagged it. not_equals 0 states the control.
    #[test]
    fn not_equals_zero_passes_the_retry_forever_sentinel() {
        let c = cache_from_json("job.retry", r#"{"kind":"not_equals","value":"0"}"#);
        for (v, want) in [
            ("-1", Verdict::Satisfies),
            ("3", Verdict::Satisfies),
            ("0", Verdict::Violates),
        ] {
            let f = evaluate(&packet("job.retry", Some(v), Resolution::AsAuthored), &c);
            assert_eq!(f.verdict, want, "{v} -> {}", f.reason);
        }
    }

    #[test]
    fn not_equals_still_abstains_when_unresolvable() {
        let c = cache_from_json(
            "job.permissions",
            r#"{"kind":"not_equals","value":"write-all"}"#,
        );
        let f = evaluate(&unauthored_unresolvable("job.permissions"), &c);
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
    }

    #[test]
    fn duration_strings_parse_to_seconds() {
        for (text, want) in [
            ("30s", 30.0),
            ("10m", 600.0),
            ("1h30m", 5400.0),
            ("1h0m0s", 3600.0),
            ("500ms", 0.5),
            ("1.5h", 5400.0),
            ("2d", 172_800.0),
            ("1w", 604_800.0),
            ("0", 0.0),
            (" 5m ", 300.0),
        ] {
            assert_eq!(parse_duration_secs(text), Some(want), "{text}");
        }
        // A bare number has no unit, and guessing one is how a bound starts
        // flagging correct configurations.
        for text in [
            "15",
            "",
            "m",
            "10x",
            "5m3",
            "absent",
            "{{ .Values.i }}",
            "-5m",
        ] {
            assert_eq!(parse_duration_secs(text), None, "{text:?}");
        }
    }

    // The frames' M4 cell: a reconcile interval is a DURATION, and at_most
    // abstained on "10m" because it is not a number.
    #[test]
    fn duration_bounds_decide_both_ways_and_include_the_boundary() {
        let at_most = cache_from_json(
            "kustomization.interval",
            r#"{"kind":"duration_at_most","value":"10m"}"#,
        );
        for (v, want) in [
            ("5m", Verdict::Satisfies),
            ("600s", Verdict::Satisfies),
            ("1h", Verdict::Violates),
        ] {
            let f = evaluate(
                &packet("kustomization.interval", Some(v), Resolution::AsAuthored),
                &at_most,
            );
            assert_eq!(f.verdict, want, "{v} -> {}", f.reason);
        }
        let at_least = cache_from_json("rule.for", r#"{"kind":"duration_at_least","value":"1m"}"#);
        for (v, want) in [
            ("5m", Verdict::Satisfies),
            ("60s", Verdict::Satisfies),
            ("10s", Verdict::Violates),
        ] {
            let f = evaluate(
                &packet("rule.for", Some(v), Resolution::AsAuthored),
                &at_least,
            );
            assert_eq!(f.verdict, want, "{v} -> {}", f.reason);
        }
    }

    // A value that is not a duration abstains, and so does a spec whose own
    // bound is not one: neither is evidence about the repo.
    #[test]
    fn a_non_duration_value_or_bound_abstains() {
        let c = cache_from_json(
            "kustomization.interval",
            r#"{"kind":"duration_at_most","value":"10m"}"#,
        );
        for v in [crate::ABSENT_RENDERING, "15", "{{ .Values.interval }}"] {
            let f = evaluate(
                &packet("kustomization.interval", Some(v), Resolution::AsAuthored),
                &c,
            );
            assert_eq!(f.verdict, Verdict::Abstain, "{v:?} -> {}", f.reason);
        }
        let broken = cache_from_json(
            "kustomization.interval",
            r#"{"kind":"duration_at_most","value":"soon"}"#,
        );
        let f = evaluate(
            &packet("kustomization.interval", Some("5m"), Resolution::AsAuthored),
            &broken,
        );
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
    }

    // An expectation kind this binary does not know must not take the whole
    // artifact down with it: it loads, and that one key abstains.
    #[test]
    fn an_expectation_kind_from_a_newer_scanner_abstains() {
        let c = cache_from_json(
            "job.timeout-minutes",
            r#"{"kind":"some_future_kind","value":"x"}"#,
        );
        let f = evaluate(
            &packet("job.timeout-minutes", Some("15"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(f.verdict, Verdict::Abstain);
        assert!(f.reason.contains("newer than this scanner"), "{}", f.reason);
    }

    #[test]
    fn one_of_accepts_members_only() {
        let c = cache(
            "job.permissions",
            ConfigExpect::OneOf {
                values: vec!["read-all".into(), r#"{"contents":"read"}"#.into()],
            },
            0.9,
        );
        let ok = evaluate(
            &packet("job.permissions", Some("read-all"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(ok.verdict, Verdict::Satisfies);
        let bad = evaluate(
            &packet("job.permissions", Some("write-all"), Resolution::AsAuthored),
            &c,
        );
        assert_eq!(bad.verdict, Verdict::Violates);
    }

    #[test]
    fn evaluate_all_is_index_aligned_with_its_packets() {
        let c = cache("job.timeout-minutes", ConfigExpect::Present, 0.9);
        let packets = vec![
            packet("job.timeout-minutes", Some("15"), Resolution::AsAuthored),
            packet("job.other", Some("x"), Resolution::AsAuthored),
        ];
        let findings = evaluate_all(&packets, &[], &c);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].verdict, Verdict::Satisfies);
        assert_eq!(findings[1].verdict, Verdict::Abstain);
        assert_eq!(findings[1].packet_id, packets[1].id());
    }

    // ---- po-av01j.133.10: the conditional variant ----

    fn when_publishing(then: ConfigExpect) -> ConfigExpect {
        ConfigExpect::When {
            guard: ConfigGuard {
                key: "workflow.publishes_image".into(),
                any_of: vec!["true".into()],
            },
            then: Box::new(then),
        }
    }

    fn predicate(unit: &str, key: &str, values: &[&str]) -> ConfigPredicate {
        ConfigPredicate {
            file_path: ".github/workflows/ci.yml".into(),
            unit: unit.into(),
            key: key.into(),
            values: values.iter().map(|v| v.to_string()).collect(),
        }
    }

    fn unset_concurrency() -> ConfigPacket {
        let mut p = packet(
            "workflow.concurrency",
            Some("none"),
            Resolution::PlatformDefault,
        );
        p.unit = "workflow".into();
        p
    }

    // The rejected candidate, restated. Unconditionally, `present` on
    // workflow.concurrency fires on every lint workflow in existence.
    #[test]
    fn a_held_guard_judges_the_inner_expectation_both_ways() {
        let c = cache(
            "workflow.concurrency",
            when_publishing(ConfigExpect::Present),
            0.9,
        );
        let facts = [predicate(
            crate::FILE_SCOPE,
            "workflow.publishes_image",
            &["true"],
        )];
        let bad = super::evaluate(&unset_concurrency(), &facts, &c);
        assert_eq!(bad.verdict, Verdict::Violates, "{}", bad.reason);
        assert_eq!(bad.control, "RC-013");

        let mut set = unset_concurrency();
        set.resolved_value = Some("deploy".into());
        set.resolution = Resolution::AsAuthored;
        let ok = super::evaluate(&set, &facts, &c);
        assert_eq!(ok.verdict, Verdict::Satisfies, "{}", ok.reason);
    }

    // The inner expectation is judged as ITSELF, not as the `when` that wraps
    // it. A duration floor read off the outer spec is taken for a ceiling, so
    // the too-short interval passes and the long one is flagged.
    #[test]
    fn a_guarded_duration_floor_stays_a_floor() {
        let c = cache(
            "workflow.concurrency",
            when_publishing(ConfigExpect::DurationAtLeast { value: "5m".into() }),
            0.9,
        );
        let facts = [predicate(
            crate::FILE_SCOPE,
            "workflow.publishes_image",
            &["true"],
        )];
        let mut p = unset_concurrency();
        p.resolution = Resolution::AsAuthored;
        p.resolved_value = Some("10m".into());
        let ok = super::evaluate(&p, &facts, &c);
        assert_eq!(ok.verdict, Verdict::Satisfies, "{}", ok.reason);

        p.resolved_value = Some("1m".into());
        let bad = super::evaluate(&p, &facts, &c);
        assert_eq!(bad.verdict, Verdict::Violates, "{}", bad.reason);
        assert!(bad.reason.contains("below the minimum"), "{}", bad.reason);
    }

    // A guard that holds over a kind this scanner does not know abstains on
    // the kind, the same as the unguarded spec.
    #[test]
    fn a_held_guard_over_an_unknown_kind_abstains() {
        let c = cache(
            "workflow.concurrency",
            when_publishing(ConfigExpect::Unknown),
            0.9,
        );
        let facts = [predicate(
            crate::FILE_SCOPE,
            "workflow.publishes_image",
            &["true"],
        )];
        let mut p = unset_concurrency();
        p.resolution = Resolution::AsAuthored;
        let f = super::evaluate(&p, &facts, &c);
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
        assert!(
            f.reason.contains("unknown expectation kind"),
            "{}",
            f.reason
        );
    }

    #[test]
    fn an_unmet_guard_is_not_applicable_and_says_which_guard() {
        let c = cache(
            "workflow.concurrency",
            when_publishing(ConfigExpect::Present),
            0.9,
        );
        let facts = [predicate(
            crate::FILE_SCOPE,
            "workflow.publishes_image",
            &["false"],
        )];
        let f = super::evaluate(&unset_concurrency(), &facts, &c);
        assert_eq!(f.verdict, Verdict::NotApplicable, "{}", f.reason);
        assert!(
            f.reason.contains("workflow.publishes_image"),
            "the reason must name the guard: {}",
            f.reason
        );
        assert_eq!(f.control, "RC-013", "a spec decided this, so it rides");
    }

    // The safety property. A guard this scanner cannot read must neither fire
    // the inner expectation unconditionally (the noise the variant exists to
    // remove) nor pass silently.
    #[test]
    fn a_guard_with_no_retrieved_predicate_abstains_and_names_the_lever() {
        let c = cache(
            "workflow.concurrency",
            when_publishing(ConfigExpect::Present),
            0.9,
        );
        let f = super::evaluate(&unset_concurrency(), &[], &c);
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
        assert!(
            f.reason.contains("guard predicate") && f.reason.contains("newer than this scanner"),
            "{}",
            f.reason
        );
    }

    // A predicate describes ONE unit. Another file's fact, or another job's,
    // must not open or close this packet's guard.
    #[test]
    fn a_predicate_for_another_unit_or_file_does_not_reach_the_packet() {
        let guard_on_job = ConfigExpect::When {
            guard: ConfigGuard {
                key: "job.publishes_image".into(),
                any_of: vec!["true".into()],
            },
            then: Box::new(ConfigExpect::Present),
        };
        let c = cache("job.timeout-minutes", guard_on_job, 0.9);
        let p = packet(
            "job.timeout-minutes",
            Some("360"),
            Resolution::PlatformDefault,
        );
        let other_job = [predicate("job:release", "job.publishes_image", &["true"])];
        assert_eq!(
            super::evaluate(&p, &other_job, &c).verdict,
            Verdict::Abstain
        );
        let mut other_file = predicate("job:build", "job.publishes_image", &["true"]);
        other_file.file_path = ".github/workflows/other.yml".into();
        assert_eq!(
            super::evaluate(&p, &[other_file], &c).verdict,
            Verdict::Abstain
        );
        let same = [predicate("job:build", "job.publishes_image", &["true"])];
        assert_eq!(super::evaluate(&p, &same, &c).verdict, Verdict::Violates);
    }

    #[test]
    fn a_set_valued_predicate_holds_on_any_shared_member() {
        let on_push = ConfigExpect::When {
            guard: ConfigGuard {
                key: "workflow.triggers".into(),
                any_of: vec!["push".into(), "release".into()],
            },
            then: Box::new(ConfigExpect::Present),
        };
        let c = cache("workflow.concurrency", on_push, 0.9);
        let run = |events: &[&str]| {
            let facts = [predicate(crate::FILE_SCOPE, "workflow.triggers", events)];
            super::evaluate(&unset_concurrency(), &facts, &c).verdict
        };
        assert_eq!(run(&["pull_request", "push"]), Verdict::Violates);
        assert_eq!(run(&["pull_request"]), Verdict::NotApplicable);
    }

    // The inner expectation keeps ALL of its own semantics behind a held guard,
    // including the `present` authorship exception on an unresolvable value and
    // the abstention of a value-bearing variant on the same packet.
    #[test]
    fn the_inner_expectation_keeps_its_unresolvable_semantics() {
        let facts = [predicate(
            crate::FILE_SCOPE,
            "workflow.publishes_image",
            &["true"],
        )];
        let p = unauthored_unresolvable("job.permissions");
        let present = cache(
            "job.permissions",
            when_publishing(ConfigExpect::Present),
            0.9,
        );
        assert_eq!(
            super::evaluate(&p, &facts, &present).verdict,
            Verdict::Violates
        );
        let equals = cache(
            "job.permissions",
            when_publishing(ConfigExpect::Equals {
                value: "read".into(),
            }),
            0.9,
        );
        assert_eq!(
            super::evaluate(&p, &facts, &equals).verdict,
            Verdict::Abstain
        );
    }

    // Guards nest as a conjunction: every one must hold.
    #[test]
    fn nested_guards_must_all_hold() {
        let both = ConfigExpect::When {
            guard: ConfigGuard {
                key: "workflow.triggers".into(),
                any_of: vec!["push".into()],
            },
            then: Box::new(when_publishing(ConfigExpect::Present)),
        };
        let c = cache("workflow.concurrency", both, 0.9);
        let run = |publishes: &str| {
            let facts = [
                predicate(crate::FILE_SCOPE, "workflow.triggers", &["push"]),
                predicate(crate::FILE_SCOPE, "workflow.publishes_image", &[publishes]),
            ];
            super::evaluate(&unset_concurrency(), &facts, &c).verdict
        };
        assert_eq!(run("true"), Verdict::Violates);
        assert_eq!(run("false"), Verdict::NotApplicable);
    }
}
