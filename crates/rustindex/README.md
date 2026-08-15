# rustindex — Rust retriever helper

Emits the versioned packet stream rvl consumes, for Rust source. The Rust
sibling of `goindex`/`pyindex`/`tsindex`, with one structural difference: it
lives IN the rvl workspace (the toolchain is guaranteed wherever rvl
builds), so the packet contract types come from `rvl-core` directly and field
agreement is by construction. It is still invoked as a subprocess through the
same HelperRetriever seam (`RVLSCAN_RUSTINDEX`, adjacent-to-binary, PATH), so
the packet contract is identical to every other helper.

    rustindex --retrieve --root <repo> --name <snapshot>   # full load
    rustindex --retrieve --root <repo> --files a.rs,b.rs   # incremental (filtered full run)
    rustindex --packet-schema                              # negotiate before loading

## Engine (wayfinder po-ae75b.8, binding)

The engine is the **rust-analyzer `scip` CLI**, pinned (`ra::PINNED_VERSION`,
currently 1.96.0, the rustup component of the pinned toolchain). SCIP protobuf
is parsed with the `scip` crate; snippets, receivers, constant arguments, and
macro spans are re-read from source. Embedded `ra_ap_*` crates are the
pre-registered escape valve via the migration protocol — not used.

Identity enforcement, recorded per-stream in a `rust_workspace_provenance`
record:

- version vs pin: mismatch warns (fatal under `RVLSCAN_RUSTINDEX_STRICT_PIN=1`).
- checksum: `RVLSCAN_RUST_ANALYZER_SHA256`, when set, must match the binary's
  sha256 (fail closed). The actual sha256 is always recorded.
- the moniker fixture test (`tests/fixture.rs`) is the behavioral canary: a
  rust-analyzer upgrade that changes moniker shapes fails it loudly.

`RVLSCAN_RUST_ANALYZER` overrides binary discovery (else PATH).

## Build-dep gate (binding)

The cargo workspace must LOAD at init: `cargo metadata` (which implies the
dependency resolution rust-analyzer's build scripts + proc-macro server run
on) is checked first. A non-loading workspace **abstains** — non-zero exit
with the reason — never a heuristic tier. A missing committed `Cargo.lock`
is reported on stderr and the generated lockfile's sha256/size are snapshotted
into the provenance record.

## What it emits

One JSON object per line, `packet_schema: 2`, `lang: "rust"`, plus `site_key`
(`file:line:client_type:method`) for downstream joins. Site classes:

- **G1 client calls** (empty `site_kind`): reqwest/hyper, sqlx/tokio-postgres,
  redis, lapin, rdkafka, tonic identities (see `catalog.rs`).
- **G2 `server_entry`**: axum `Router::route/nest`, actix-web
  `App/Scope::route/service`, warp `serve`, rocket `mount`. The route path
  literal rides `const_args`.
- **G3 `background_job`**: tokio `spawn`/`spawn_blocking`/`spawn_local`,
  `std::thread::spawn`, async-std `spawn`, tokio-cron-scheduler. Every
  spawn-family registration is inventoried; whether a spawn is a governed job
  is spec-side judgment.
- **G4 `emission_point`** aggregates (one per enclosing function × framework ×
  category): tracing/log level macros (`log`), span identities (`trace`),
  sentry captures (`error_capture`). Category and count ride `const_args`
  per the G4 convention.

## Confidence tiers (charter)

Empirical moniker behavior on the pinned engine (see `tests/fixture.rs`):

| dispatch shape | moniker | packet |
|---|---|---|
| inherent / trait method on concrete receiver | `impl#[Type][Trait]m().` | `client_type` = concrete type — **high** |
| dyn-Trait dispatch, receiver visibly `dyn` in source | `Trait#m().` | `client_type` = `dyn crate::Trait` — **mid** |
| generic receiver, no instantiation at the site | `Trait#m().` (same as dyn) | empty `client_type`, `client_type_resolved: false` — **abstain** |

The moniker alone cannot separate dyn from generic dispatch; the enclosing
source is re-read for a visibly-`dyn` receiver declaration, and anything not
visibly dyn abstains (fail-toward-abstain).

`macro_expansion` is genuinely populated: emission sites derived from macro
symbols, and any site whose position falls inside a macro invocation span
(paren-matched from source), carry `macro_expansion: true`. `.await` desugar
occurrences (`Future::poll`, `Try::branch`) are dropped by the token-text
filter. cfg'd-out code is OUT of the population: rust-analyzer indexes the
active cfg set, so occurrences under inactive `#[cfg(...)]` branches do not
exist in the index (documented, not flagged per-site).

Rust has no keyword arguments, so a chain-level bound
(`.timeout(d).send()`) is surfaced as name-keyed const-arg evidence on the
sibling call site (the builder method's name is a mechanical fact from the
moniker) — that is what propagation's `call_arg` mechanism credits.

## Gate protocol (scaffolding)

Rust gate floors follow the expansion gate protocol (po-ae75b.2): RELATIVE
formula — decided% >= Go comparator − 10 on the pinned backend corpus;
precision Wilson LB >= 0.90 on n >= 50 quarantined gate-grade sites; gate
sets are single-use, minted at first gate and re-verified at cutover. The
gate machinery is language-generic (`rvl-eval gate`, `language: rust` in the
manifest); minting + adjudication is HITL and tracked as its own bead under
the epic. The seed spec corpus (`crates/rvl/tests/testdata/
rust_seed_specs.json`) is test-grade and permanently gate-ineligible.
