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
pub mod semver;
pub mod store;
pub mod verify;
