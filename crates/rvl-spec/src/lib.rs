//! The spec cache: the asset that compounds.
//!
//! A spec answers a question about an API or a config type, not about a call
//! site. `net/http.Client.Do blocks, and a context or client config can bound
//! it` is true in every repository that imports it, so specs earned once pay
//! forever. Per-site labels are worth nothing to the next repo.
//!
//! This inverts the cost model that made the per-site scanner unaffordable. On
//! polaris, 1525 call sites reduced to 76 spec questions (23x), and the spec
//! answers reproduced a per-site finding at roughly 1/40th the cost: seven APIs
//! judged non-blocking removed 285 sites, 18.7% of the corpus, which matched
//! the 14-19% not-applicable rate the per-site panel measured over two runs.
//!
//! It also changes the risk profile, and the change is not benign. A wrong spec
//! is applied to every site using that API at once, so spec error is
//! MULTIPLIED where per-site error is isolated. Hence the confidence floor
//! below, and hence `depends` never collapsing to `yes`.

use rvl_core::{RepoConfig, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A spec below this confidence does not decide anything; the site abstains.
/// Set by the multiplier, not by ordinary caution.
pub const MIN_CONFIDENCE: f64 = 0.6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Blocking {
    Yes,
    No,
    /// Conditional on the call, so the spec alone cannot settle it.
    Depends,
    Unknown,
}

/// Where a bound can come from. Only mechanisms the spec lists are searched for,
/// which is what keeps propagation from inventing bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mechanism {
    CallArg,
    Context,
    ClientConfig,
    ServerConfig,
    /// A decorator or annotation on the enclosing function bounds the call.
    /// Python's dominant idiom -- @shared_task(time_limit=120) bounds every
    /// call inside the task -- and it had no representation at all until the
    /// fixture gold set scored app/reports.py wrong.
    Decorator,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    pub method: String,
    pub blocking: Blocking,
    #[serde(default)]
    pub bounded_by: Vec<Mechanism>,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub site_count: u32,
}

/// What a config field actually bounds. The distinction is load-bearing: a
/// transport setting only dial and TLS-handshake timeouts bounds the connection
/// phase and leaves the response read unbounded, so calling it "bounded" is a
/// false pass. `net/http.Server` specced phase_only for the same reason:
/// WriteTimeout deadlines the connection write and never cancels the request
/// context, so the handler goroutine and its query keep running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Bounds {
    WholeCall,
    PhaseOnly,
    Unrelated,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ThisClient,
    ServedRequests,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSpec {
    #[serde(rename = "type")]
    pub type_name: String,
    pub bounds: Bounds,
    pub scope: Scope,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
}

/// Whether the control governs a scope at all. Judged once per scope class,
/// not per site: five answers cover every repository.
///
/// The canon these encode was corrected by human adjudication and is narrower
/// than it first looks. A migration may relax statement_timeout for DDL and
/// still needs SOME bound, so "no bound of any kind" is a finding. A backfill
/// is not exempt for being a backfill: it can saturate the database it reads,
/// and a hang is expensive when the work is not retryable or rollbackable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeSpec {
    pub scope: String,
    /// False means the control does not apply here and the site satisfies by
    /// non-applicability.
    pub applies: bool,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default)]
    pub rationale: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SpecFile {
    #[serde(default)]
    pub apis: Vec<ApiSpec>,
    #[serde(default)]
    pub configs: Vec<ConfigSpec>,
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
}

/// What repo-level config imposes on served requests, if anything.
#[derive(Debug, Clone, PartialEq)]
pub enum ServedBound {
    /// Every applicable spec agrees.
    Agreed(Bounds),
    /// Specs disagree. Not resolved by picking a winner: taking the strongest
    /// is optimistic, and for a safety property optimism is the one bias you
    /// cannot afford. The affected sites abstain and a human decides.
    Conflict(Vec<String>),
    None,
}

#[derive(Debug, Default)]
pub struct SpecCache {
    apis: HashMap<(String, String), ApiSpec>,
    configs: HashMap<String, ConfigSpec>,
    scopes: HashMap<String, ScopeSpec>,
}

impl SpecCache {
    pub fn load(text: &str) -> anyhow::Result<Self> {
        let f: SpecFile = serde_json::from_str(text)?;
        Ok(Self::from_file(f))
    }

    pub fn from_file(f: SpecFile) -> Self {
        let mut c = SpecCache::default();
        for a in f.apis {
            c.apis.insert((a.type_name.clone(), a.method.clone()), a);
        }
        for s in f.configs {
            c.configs.insert(s.type_name.clone(), s);
        }
        for s in f.scopes {
            c.scopes.insert(s.scope.clone(), s);
        }
        c
    }

    /// True when the control does not govern this scope. Absent or
    /// low-confidence scope specs default to APPLYING: silently exempting a
    /// scope is how a real violation disappears, and three of five overturned
    /// verdicts in adjudication came from exemptions that were too broad.
    pub fn scope_exempt(&self, scope: &str) -> Option<&ScopeSpec> {
        self.scopes
            .get(scope)
            .filter(|s| !s.applies && s.confidence >= MIN_CONFIDENCE)
    }

    pub fn api(&self, key: &(String, String)) -> Option<&ApiSpec> {
        self.apis.get(key)
    }
    pub fn config(&self, type_name: &str) -> Option<&ConfigSpec> {
        self.configs.get(type_name)
    }
    pub fn len(&self) -> usize {
        self.apis.len() + self.configs.len() + self.scopes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge another cache in, preferring the higher-confidence spec. This is
    /// what lets a shipped baseline cache be extended by locally-inferred specs
    /// without a human resolving every overlap.
    pub fn merge(&mut self, other: SpecCache) {
        for (k, v) in other.apis {
            match self.apis.get(&k) {
                Some(existing) if existing.confidence >= v.confidence => {}
                _ => {
                    self.apis.insert(k, v);
                }
            }
        }
        for (k, v) in other.configs {
            match self.configs.get(&k) {
                Some(existing) if existing.confidence >= v.confidence => {}
                _ => {
                    self.configs.insert(k, v);
                }
            }
        }
    }

    /// What the repo's own construction sites impose on served requests.
    pub fn served_bound(&self, cfg: &RepoConfig) -> ServedBound {
        let mut seen: Vec<(String, Bounds)> = Vec::new();
        for c in &cfg.constructions {
            let Some(spec) = self.config(&c.type_name) else { continue };
            if spec.scope != Scope::ServedRequests || spec.confidence < MIN_CONFIDENCE {
                continue;
            }
            if matches!(spec.bounds, Bounds::WholeCall | Bounds::PhaseOnly)
                && !seen.iter().any(|(t, _)| t == &c.type_name)
            {
                seen.push((c.type_name.clone(), spec.bounds));
            }
        }
        match seen.len() {
            0 => ServedBound::None,
            _ => {
                let first = seen[0].1;
                if seen.iter().all(|(_, b)| *b == first) {
                    ServedBound::Agreed(first)
                } else {
                    ServedBound::Conflict(
                        seen.iter().map(|(t, b)| format!("{t}={b:?}")).collect(),
                    )
                }
            }
        }
    }
}

/// The verdict a spec forces on its own, before any evidence is searched.
/// Returns `None` when the site still has to be decided from evidence.
pub fn spec_gate(spec: Option<&ApiSpec>) -> Option<(Verdict, String)> {
    let Some(s) = spec else {
        return Some((Verdict::Abstain, "no spec for this API".into()));
    };
    match s.blocking {
        Blocking::No => Some((
            Verdict::NotApplicable,
            format!("spec: {} does not block", s.method),
        )),
        Blocking::Unknown => Some((Verdict::Abstain, "spec: API unrecognised".into())),
        // `depends` is not `yes`. sync.Once.Do blocks only if another goroutine
        // is running the wrapped function and inherits whatever that function
        // does; collapsing that to blocking produced a false violates on a site
        // a human confirmed was not applicable.
        Blocking::Depends => Some((
            Verdict::Abstain,
            "spec: blocking depends on the call; needs per-site judgement".into(),
        )),
        Blocking::Yes if s.confidence < MIN_CONFIDENCE => Some((
            Verdict::Abstain,
            format!("spec confidence {:.2} below {MIN_CONFIDENCE}", s.confidence),
        )),
        Blocking::Yes => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_core::ConfigFact;

    fn api(blocking: Blocking, confidence: f64) -> ApiSpec {
        ApiSpec {
            type_name: "t".into(), method: "Do".into(), blocking,
            bounded_by: vec![Mechanism::Context], confidence,
            rationale: String::new(), site_count: 1,
        }
    }

    #[test]
    fn depends_routes_to_judgement_rather_than_asserting() {
        let (v, why) = spec_gate(Some(&api(Blocking::Depends, 0.9))).unwrap();
        assert_eq!(v, Verdict::Abstain);
        assert!(why.contains("depends"));
    }

    #[test]
    fn low_confidence_blocking_spec_abstains() {
        let (v, _) = spec_gate(Some(&api(Blocking::Yes, 0.55))).unwrap();
        assert_eq!(v, Verdict::Abstain, "a shaky spec applies to every site at once");
        assert!(spec_gate(Some(&api(Blocking::Yes, 0.9))).is_none());
    }

    #[test]
    fn non_blocking_is_not_applicable_not_satisfies() {
        let (v, _) = spec_gate(Some(&api(Blocking::No, 0.9))).unwrap();
        assert_eq!(v, Verdict::NotApplicable);
    }

    #[test]
    fn missing_spec_abstains() {
        assert_eq!(spec_gate(None).unwrap().0, Verdict::Abstain);
    }

    fn cache(specs: Vec<(&str, Bounds, Scope, f64)>) -> SpecCache {
        SpecCache::from_file(SpecFile { scopes: vec![],
            apis: vec![],
            configs: specs.into_iter().map(|(t, b, s, c)| ConfigSpec {
                type_name: t.into(), bounds: b, scope: s, confidence: c,
                rationale: String::new(),
            }).collect(),
        })
    }

    fn repo(types: &[&str]) -> RepoConfig {
        RepoConfig {
            snapshot_id: "r".into(),
            constructions: types.iter().map(|t| ConfigFact {
                type_name: (*t).into(), fields: vec!["Timeout".into()],
                ..Default::default()
            }).collect(),
        }
    }

    #[test]
    fn conflicting_server_specs_are_not_resolved_by_taking_the_strongest() {
        // The real case: internal/config.ServerConfig merely HOLDS timeout
        // values and was specced whole_call, while net/http.Server actually
        // enforces them and was specced phase_only. Taking the max silently
        // turned "not really bounded" into a false pass.
        let c = cache(vec![
            ("cfg.ServerConfig", Bounds::WholeCall, Scope::ServedRequests, 0.9),
            ("net/http.Server", Bounds::PhaseOnly, Scope::ServedRequests, 0.9),
        ]);
        match c.served_bound(&repo(&["cfg.ServerConfig", "net/http.Server"])) {
            ServedBound::Conflict(v) => assert_eq!(v.len(), 2),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn agreeing_server_specs_are_used() {
        let c = cache(vec![("net/http.Server", Bounds::PhaseOnly, Scope::ServedRequests, 0.9)]);
        assert_eq!(c.served_bound(&repo(&["net/http.Server"])), ServedBound::Agreed(Bounds::PhaseOnly));
    }

    #[test]
    fn low_confidence_config_specs_are_ignored_entirely() {
        let c = cache(vec![("net/http.Server", Bounds::WholeCall, Scope::ServedRequests, 0.3)]);
        assert_eq!(c.served_bound(&repo(&["net/http.Server"])), ServedBound::None);
    }

    #[test]
    fn merge_prefers_higher_confidence() {
        let mut base = SpecCache::from_file(SpecFile { scopes: vec![], apis: vec![api(Blocking::Yes, 0.7)], configs: vec![] });
        let mut better = api(Blocking::No, 0.95);
        better.rationale = "local".into();
        base.merge(SpecCache::from_file(SpecFile { scopes: vec![], apis: vec![better], configs: vec![] }));
        let got = base.api(&("t".into(), "Do".into())).unwrap();
        assert_eq!(got.blocking, Blocking::No);
        assert_eq!(got.rationale, "local");
    }
}
