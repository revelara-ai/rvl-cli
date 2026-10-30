//! The time limits on the child processes a scan runs.
//!
//! Two limits, both wall-clock, both fail-OPEN like every other degraded lane:
//!
//! * the SCAN BUDGET (`--scan-budget`, `.revelara.yaml` `scanner.timeout`):
//!   the whole scan's helpers and agent calls together. A helper still running
//!   when it runs out is killed; a helper not yet started is not started.
//! * the HELPER TIMEOUT (`--helper-timeout`, `scanner.helper_timeout`): any
//!   one helper run, so one language that hangs cannot spend the budget the
//!   other languages need.
//!
//! The flag is not `--timeout`: on `rvl scan` that already names the
//! submission-mode HTTP timeout (and `RVL_SCAN_TIMEOUT`), and one flag with
//! two meanings chosen by mode is a trap.
//!
//! In-process lanes (config, content, structure) are not interruptible and are
//! not bounded here: they read files, they do not wait on anything.

use std::path::Path;
use std::time::{Duration, Instant};

/// The default scan budget. Generous on purpose: it exists to stop a HUNG
/// scan from hanging CI, not to hurry a large repository.
pub const DEFAULT_SCAN_BUDGET: Duration = Duration::from_secs(30 * 60);

/// The default timeout for one helper run.
pub const DEFAULT_HELPER_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// One limit as given: a duration, or `0` for none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit(pub Option<Duration>);

/// Parse a limit: bare seconds (`90`) or one unit suffix (`90s`, `15m`, `1h`).
/// `0` turns the limit off. The clap value parser for both flags.
pub fn parse_limit(s: &str) -> Result<Limit, String> {
    let s = s.trim();
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => s.split_at(i),
        None => (s, "s"),
    };
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => {
            return Err(format!(
                "{s:?} is not a duration (e.g. 90, 90s, 15m, 1h; 0 for none)"
            ))
        }
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{s:?} is not a duration (e.g. 90, 90s, 15m, 1h; 0 for none)"))?;
    Ok(Limit((n > 0).then(|| Duration::from_secs(n * scale))))
}

/// A duration the way the flags spell one: `90s`, `15m`, `1h`, `1m30s`.
pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    match (s / 3600, s % 3600 / 60, s % 60) {
        (0, 0, _) if d < Duration::from_secs(1) => format!("{}ms", d.as_millis()),
        (0, 0, sec) => format!("{sec}s"),
        (0, m, 0) => format!("{m}m"),
        (0, m, sec) => format!("{m}m{sec}s"),
        (h, 0, 0) => format!("{h}h"),
        _ => format!("{s}s"),
    }
}

/// Which limit set a child's deadline. Named in the degradation it causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    ScanBudget(Duration),
    HelperTimeout(Duration),
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cause::ScanBudget(d) => write!(f, "the scan budget of {} (--scan-budget)", human(*d)),
            Cause::HelperTimeout(d) => {
                write!(f, "the helper timeout of {} (--helper-timeout)", human(*d))
            }
        }
    }
}

/// The limits in force for one scan, started when the scan started.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    deadline: Option<(Instant, Cause)>,
    helper_timeout: Option<Duration>,
}

impl Limits {
    /// Start the clock now.
    pub fn start(budget: Option<Duration>, helper_timeout: Option<Duration>) -> Limits {
        Limits {
            deadline: budget.map(|b| (Instant::now() + b, Cause::ScanBudget(b))),
            helper_timeout,
        }
    }

    /// No limit at all: replaying a stream, or a test.
    pub fn none() -> Limits {
        Limits::start(None, None)
    }

    /// Resolve both limits for a scan of `root` and start the clock: the flag,
    /// then `.revelara.yaml`, then the default.
    pub fn resolve(root: &Path, budget: Option<Limit>, helper_timeout: Option<Limit>) -> Limits {
        let yaml = YamlLimits::load(root);
        let pick = |flag: Option<Limit>, yaml: Option<Limit>, default| {
            flag.or(yaml).map_or(Some(default), |l| l.0)
        };
        Limits::start(
            pick(budget, yaml.budget, DEFAULT_SCAN_BUDGET),
            pick(helper_timeout, yaml.helper_timeout, DEFAULT_HELPER_TIMEOUT),
        )
    }

    /// Time left in the scan budget; `None` when there is no budget.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|(d, _)| d.saturating_duration_since(Instant::now()))
    }

    /// The scan budget, when it has already run out.
    pub fn spent(&self) -> Option<Cause> {
        self.deadline
            .filter(|(d, _)| Instant::now() >= *d)
            .map(|(_, c)| c)
    }

    /// The deadline for a child starting NOW, and the limit that sets it: the
    /// sooner of the scan deadline and the helper timeout.
    pub fn child_deadline(&self) -> Option<(Instant, Cause)> {
        let own = self
            .helper_timeout
            .map(|t| (Instant::now() + t, Cause::HelperTimeout(t)));
        match (self.deadline, own) {
            (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
            (a, b) => a.or(b),
        }
    }
}

/// `scanner.timeout` and `scanner.helper_timeout` from `<root>/.revelara.yaml`.
/// The scanner crate's per-key view of that file, the pattern `base_ref.rs`
/// and `waiver.rs` follow. A value that does not parse is warned about and
/// ignored, so a typo falls back to the default rather than to no limit.
#[derive(Default)]
struct YamlLimits {
    budget: Option<Limit>,
    helper_timeout: Option<Limit>,
}

impl YamlLimits {
    fn load(root: &Path) -> YamlLimits {
        #[derive(serde::Deserialize, Default)]
        #[serde(default)]
        struct File {
            scanner: Scanner,
        }
        #[derive(serde::Deserialize, Default)]
        #[serde(default)]
        struct Scanner {
            timeout: Option<serde_yaml::Value>,
            helper_timeout: Option<serde_yaml::Value>,
        }
        let Ok(text) = std::fs::read_to_string(root.join(".revelara.yaml")) else {
            return YamlLimits::default();
        };
        let Ok(f) = serde_yaml::from_str::<File>(&text) else {
            return YamlLimits::default();
        };
        let read = |key: &str, v: Option<serde_yaml::Value>| {
            let text = match v? {
                serde_yaml::Value::Number(n) => n.to_string(),
                serde_yaml::Value::String(s) => s,
                other => format!("{other:?}"),
            };
            parse_limit(&text)
                .map_err(|e| {
                    eprintln!("warning: .revelara.yaml scanner.{key}: {e}; using the default")
                })
                .ok()
        };
        YamlLimits {
            budget: read("timeout", f.scanner.timeout),
            helper_timeout: read("helper_timeout", f.scanner.helper_timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_is_seconds_or_one_unit_and_zero_is_none() {
        assert_eq!(parse_limit("90"), Ok(Limit(Some(Duration::from_secs(90)))));
        assert_eq!(parse_limit("90s"), Ok(Limit(Some(Duration::from_secs(90)))));
        assert_eq!(
            parse_limit("15m"),
            Ok(Limit(Some(Duration::from_secs(900))))
        );
        assert_eq!(
            parse_limit("1h"),
            Ok(Limit(Some(Duration::from_secs(3600))))
        );
        assert_eq!(parse_limit("0"), Ok(Limit(None)));
        for bad in ["", "m", "1.5m", "-3", "10d", "1m30s"] {
            assert!(parse_limit(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_flag_beats_the_yaml_which_beats_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let l = Limits::resolve(dir.path(), None, None);
        assert_eq!(l.helper_timeout, Some(DEFAULT_HELPER_TIMEOUT));
        assert!(matches!(l.deadline, Some((_, Cause::ScanBudget(d))) if d == DEFAULT_SCAN_BUDGET));

        std::fs::write(
            dir.path().join(".revelara.yaml"),
            "scanner:\n  timeout: 10m\n  helper_timeout: 0\n",
        )
        .unwrap();
        let l = Limits::resolve(dir.path(), None, None);
        assert_eq!(l.helper_timeout, None, "0 in the yaml turns the limit off");
        assert!(matches!(l.deadline, Some((_, Cause::ScanBudget(d))) if d.as_secs() == 600));

        let l = Limits::resolve(dir.path(), Some(Limit(Some(Duration::from_secs(5)))), None);
        assert!(matches!(l.deadline, Some((_, Cause::ScanBudget(d))) if d.as_secs() == 5));
    }

    #[test]
    fn a_bad_yaml_value_falls_back_to_the_default_not_to_no_limit() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".revelara.yaml"),
            "scanner:\n  timeout: soon\n",
        )
        .unwrap();
        let l = Limits::resolve(dir.path(), None, None);
        assert!(matches!(l.deadline, Some((_, Cause::ScanBudget(d))) if d == DEFAULT_SCAN_BUDGET));
    }

    #[test]
    fn a_child_gets_the_sooner_of_the_two_limits() {
        let l = Limits::start(Some(Duration::from_secs(600)), Some(Duration::from_secs(5)));
        assert!(matches!(
            l.child_deadline(),
            Some((_, Cause::HelperTimeout(_)))
        ));
        let l = Limits::start(Some(Duration::from_secs(5)), Some(Duration::from_secs(600)));
        assert!(matches!(
            l.child_deadline(),
            Some((_, Cause::ScanBudget(_)))
        ));
        assert!(Limits::none().child_deadline().is_none());
        assert!(Limits::none().spent().is_none());
        assert!(Limits::start(Some(Duration::ZERO), None).spent().is_some());
    }

    #[test]
    fn durations_print_the_way_the_flags_spell_them() {
        assert_eq!(human(Duration::from_secs(90)), "1m30s");
        assert_eq!(human(Duration::from_secs(1800)), "30m");
        assert_eq!(human(Duration::from_secs(3600)), "1h");
        assert_eq!(human(Duration::from_secs(2)), "2s");
    }
}
