# Test packets must describe the helper, not the author

Many `rvl` tests feed the scanner a `--retrieved` packet stream instead of
running a retriever helper. That keeps them fast and toolchain-free. It also
lets them drift: a hand-written packet encodes what its author *meant* the
helper to emit, and it stays green when the helper emits something else.

This happened. csindex's golden stream carried the fully-qualified
`client_type` the spec expects while the real retriever emitted a bare name,
and later while csindex did not compile at all (po-av01j.47). The contract
test could never have caught the defect it existed to guard.

## The rule

Every packet field a test hand-authors, that a live helper also produces, is
either:

1. **Generated from a live run and committed**, with a test that diffs the
   live output against the file. Regenerate after an intended helper change
   and review the diff like code. Or:
2. **Named once in a table** that a live-helper test checks against the
   helper's own fixture output.

A live-helper test that skips when its toolchain is absent must fail instead
when `CI` is set and CI provisions that toolchain. A green skip reads the same
as a green pass.

## Where each lane stands (audit 2026-09-29, po-av01j.57)

Method: each helper was run over its checked-in fixture and its output compared
with every hand-authored packet the `rvl` tests use for that language.

| Lane | Hand-authored packets in `rvl` tests | Bound to the live helper by |
| --- | --- | --- |
| C# (csindex) | The golden stream for `scan_decides_csharp_g1_sites_from_a_retrieved_stream`. Its `client_type`/`func`/`site_kind` matched csindex, but `symbol`, `receiver`, lines and snippets were invented, and nothing tied it to csindex. The live test skipped because CI had no .NET SDK. | Rule 1: `crates/rvl/tests/fixtures/csharp_retrieved_golden.jsonl` is csindex's output. `csindex_live_output_matches_the_committed_golden` diffs it. CI installs .NET 8, and a missing SDK under `CI` fails. |
| Go (goindex) | G2 `server_entry` records, the G4 `recover_block` and `log/slog.Logger` aggregates. **One was impossible:** a `Use` middleware registration on `net/http.ServeMux`. goindex inventories no `Use` on a ServeMux, so the healthy-shape test judged a packet that no Go repo can produce. It now uses the stdlib shape, a wrapped handler on `HandleFunc`. | Rule 2: `GO_HAND_AUTHORED_IDENTITIES` in `crates/rvl/tests/cli.rs`, checked by `go_hand_authored_identities_are_what_goindex_emits`. |
| Go, stand-ins | `github.com/jackc/pgx/v5.Tx` `Query` in the config, dep-manifest, Terraform, Prometheus, Kubernetes and Argo/Flux lane tests. | Not bound, by design. These give the other lanes' tests one G1 site with a matching seed spec, and they make no claim about the Go lane. The `<import path>.<Type>` form is pinned by goindex's own `packet_test.go`. |
| Python (pyindex) | One `retrieval_stats` record (`test_files_skipped_paths`). | Its fields match `pyindex.py`'s emitter. The live Python tests in `cli.rs` run pyindex. |
| TypeScript, Java, Rust, C/C++ | None. Their seed specs are exercised only through live end-to-end scans. | cindex's `golden.rs` runs cindex itself. The TypeScript live tests in `cli.rs` still skip in the `check` job, which does not `npm ci` in `helpers/tsindex`. tsindex's own `node --test` suite runs in the `helpers` job. |

## Regenerating the C# golden

```bash
RVL_UPDATE_GOLDEN=1 cargo test -p rvl --test cli csindex_live_output
git diff crates/rvl/tests/fixtures/csharp_retrieved_golden.jsonl
```

The regenerated stream then feeds the no-SDK contract test. Check that its
satisfies/violates/abstain assertions still hold for the reasons they claim.
