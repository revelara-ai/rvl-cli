//! rustindex — the Rust retriever helper (po-av01j.11).
//!
//! Wraps the pinned rust-analyzer `scip` CLI (wayfinder po-ae75b.8, binding):
//! SCIP protobuf in, versioned Site packets out, with source re-read for
//! snippets. Retrieval only: this helper decides nothing about reliability.
//!
//! Engine notes (empirical, pinned rust-analyzer 1.96.0):
//! - A trait method on a concrete receiver resolves to the IMPL symbol
//!   (`impl#[PgPool][Executor]execute().`) — high confidence tier.
//! - dyn-Trait dispatch AND uninstantiated generic dispatch both resolve to
//!   the TRAIT method symbol (`Executor#execute().`); the moniker cannot tell
//!   them apart, so the enclosing source is re-read for a visibly-`dyn`
//!   receiver: dyn → mid tier (trait identity as `dyn crate::Trait`),
//!   otherwise the site abstains (empty client_type, fail-toward-abstain).
//! - `.await` desugaring emits `Future#poll` / `Try#branch` occurrences whose
//!   source token does not match the symbol name; the token-text-match filter
//!   removes that noise mechanically.
//! - macro call sites carry the macro's own symbol (`tracing 0.1.0 info!`);
//!   expansion-internal calls do not leak occurrences to the call site.

pub mod catalog;
pub mod derive;
pub mod ra;
pub mod symbol;
