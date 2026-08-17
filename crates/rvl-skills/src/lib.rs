//! Skill/lens distribution: install the Revelara workflow skills and lenses
//! (the /rvl:scan lens set, CAST/STPA interrogatory workflows, assessment
//! skills) into the developer's coding-agent harness (po-av01j.14).
//!
//! Distribution ONLY. This crate downloads signed plugin content from the
//! Revelara backend (the same plugin system `rvl plugin install` uses),
//! caches it locally like the spec cache, and installs it per detected
//! harness. It never launches agents and never uploads anything: the fetch
//! surface is GET-only by construction (see [`fetch::Fetcher`]).

pub mod agents;
pub mod fetch;
pub mod flow;
pub mod harness;
/// Re-export: the comparison moved to `rvl-core` when the `status` update
/// nag (po-av01j.185 item 5) needed the same rule without this crate's
/// download machinery. Kept as `rvl_skills::semver` so call sites here and
/// in `rvl` are unchanged.
pub use rvl_core::semver;
pub mod store;
pub mod v1;
pub mod verify;
