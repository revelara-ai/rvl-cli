//! Where a finding with no spec goes: its quadrant and its authoring lane.
//!
//! A finding becomes a spec only if it is DETERMINISTIC and TRANSFERABLE. The
//! two are independent, and the second does most of the work: a finding a rule
//! can decide from one site is still worth nothing to a shared corpus when the
//! identity it keys on exists in one repository only.
//!
//!   * deterministic — a rule can decide it from one site, which needs a
//!     resolved identity to key the rule on;
//!   * transferable — that identity exists outside the scanned repository.
//!
//! Both are facts the retrievers already state, so the routing is computed
//! here and does not depend on a person reading each finding. A finding that
//! passes both goes to the lane of what it keys on. Every other finding stays
//! with the agent lenses, permanently: it is not pending a spec.
//!
//! Two more questions decide whether a routed finding is then MINTED: whether
//! the spec vocabulary can state it, and whether it fires at different rates
//! in different repositories. Neither can be read from one scan, so neither is
//! computed here.

use serde::Serialize;

/// What a finding keys on. This selects the lane once both gates pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysOn {
    /// A key in a config file format.
    ConfigKey,
    /// A call to an API, by client type and method.
    ApiCall,
}

/// The cell of the deterministic x transferable grid a finding is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Quadrant {
    /// Both gates pass: the one cell a spec comes from.
    DeterministicTransferable,
    /// A rule could decide it, for this repository only.
    DeterministicNotTransferable,
    /// The API is shared, and there is no resolved identity to key a rule on.
    TransferableNotDeterministic,
    Neither,
}

/// Where the finding is authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lane {
    /// An API spec, keyed on client type and method (lane G1).
    ApiSpec,
    /// A config key spec, keyed on format and key (lane G6).
    ConfigKeySpec,
    /// No spec. The finding stays with the agent lenses.
    Agent,
}

impl Lane {
    /// The lane as a reader sees it in a table.
    pub fn label(self) -> &'static str {
        match self {
            Lane::ApiSpec => "API spec (G1)",
            Lane::ConfigKeySpec => "config key spec (G6)",
            Lane::Agent => "agent",
        }
    }
}

/// The computed routing of one finding. The two gates are carried next to the
/// quadrant they make, so a reader of the JSON does not have to parse a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Routing {
    pub deterministic: bool,
    pub transferable: bool,
    pub quadrant: Quadrant,
    pub lane: Lane,
}

/// Route one finding from its two gates and what it keys on.
pub fn route(keys_on: KeysOn, deterministic: bool, transferable: bool) -> Routing {
    let quadrant = match (deterministic, transferable) {
        (true, true) => Quadrant::DeterministicTransferable,
        (true, false) => Quadrant::DeterministicNotTransferable,
        (false, true) => Quadrant::TransferableNotDeterministic,
        (false, false) => Quadrant::Neither,
    };
    let lane = match (quadrant, keys_on) {
        (Quadrant::DeterministicTransferable, KeysOn::ApiCall) => Lane::ApiSpec,
        (Quadrant::DeterministicTransferable, KeysOn::ConfigKey) => Lane::ConfigKeySpec,
        _ => Lane::Agent,
    };
    Routing {
        deterministic,
        transferable,
        quadrant,
        lane,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_finding_that_passes_both_gates_gets_a_spec_lane() {
        for keys_on in [KeysOn::ApiCall, KeysOn::ConfigKey] {
            for (deterministic, transferable) in [(true, false), (false, true), (false, false)] {
                assert_eq!(
                    route(keys_on, deterministic, transferable).lane,
                    Lane::Agent,
                    "{keys_on:?} {deterministic} {transferable}"
                );
            }
        }
    }

    #[test]
    fn a_finding_that_passes_both_gates_routes_by_what_it_keys_on() {
        assert_eq!(route(KeysOn::ApiCall, true, true).lane, Lane::ApiSpec);
        assert_eq!(
            route(KeysOn::ConfigKey, true, true).lane,
            Lane::ConfigKeySpec
        );
    }

    #[test]
    fn the_quadrant_is_the_pair_of_gates() {
        let q = |d, t| route(KeysOn::ApiCall, d, t).quadrant;
        assert_eq!(q(true, true), Quadrant::DeterministicTransferable);
        assert_eq!(q(true, false), Quadrant::DeterministicNotTransferable);
        assert_eq!(q(false, true), Quadrant::TransferableNotDeterministic);
        assert_eq!(q(false, false), Quadrant::Neither);
    }

    #[test]
    fn routing_serializes_both_gates_the_quadrant_and_the_lane() {
        let v = serde_json::to_value(route(KeysOn::ApiCall, true, false)).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "deterministic": true,
                "transferable": false,
                "quadrant": "deterministic_not_transferable",
                "lane": "agent",
            })
        );
    }
}
