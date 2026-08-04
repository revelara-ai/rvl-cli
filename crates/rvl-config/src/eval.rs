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
//!   * unknown pattern name → the spec is newer than this scanner: upgrade.

use crate::{ConfigPacket, Resolution};
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
        _ => None,
    }
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
pub fn evaluate(p: &ConfigPacket, specs: &SpecCache) -> ConfigFinding {
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
    // An out-of-repo value is unknowable here regardless of what the spec
    // expects: judged before the expectation so no variant can guess.
    if p.resolution == Resolution::Unresolvable {
        return abstain(format!(
            "effective value is set outside the repo: {}",
            provenance_note(p)
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
    let value = p.resolved_value.as_deref().unwrap_or("");

    match &spec.expect {
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
        ConfigExpect::Equals { value: want } => {
            if value == want {
                decided(
                    Verdict::Satisfies,
                    format!("{} = {value}; {}", p.key, provenance_note(p)),
                )
            } else {
                decided(
                    Verdict::Violates,
                    format!("unexpected value: {} = {value}, expected {want}", p.key),
                )
            }
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
                    format!(
                        "unexpected value: {} = {value}, expected one of {}",
                        p.key,
                        values.join(", ")
                    ),
                )
            }
        }
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
pub fn evaluate_all(packets: &[ConfigPacket], specs: &SpecCache) -> Vec<ConfigFinding> {
    packets.iter().map(|p| evaluate(p, specs)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProvenanceStep;
    use rvl_spec::{ConfigKeySpec, SpecFile};

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
        let findings = evaluate_all(&packets, &c);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].verdict, Verdict::Satisfies);
        assert_eq!(findings[1].verdict, Verdict::Abstain);
        assert_eq!(findings[1].packet_id, packets[1].id());
    }
}
