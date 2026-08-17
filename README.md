# rvl

The Revelara reliability scanner.

`rvl` analyzes codebases for reliability risks and grounds its findings in
the Revelara controls catalog and incident corpus. The scan is deterministic
and makes no model calls: it resolves the API surfaces your code actually
calls, matches them against a signed spec cache, and returns a blocking /
advisory ladder with an exit code a git hook or CI job can gate on.

Customer code never leaves the machine. See [Privacy](docs/privacy.md).

## Install

```sh
brew install revelara-ai/tap/rvl
```

That is the whole install: the cask ships `rvl` plus the `goindex`, `cindex`
and `rustindex` retriever helpers, and the remaining helpers are carried
inside the binary.

Or download a release archive for your platform from the
[releases page](https://github.com/revelara-ai/rvl-cli/releases) and put its
contents on your `PATH`.

## Quick start

```sh
rvl login                  # store API credentials in ~/.revelara/config.yaml
rvl init                   # write .revelara.yaml, install the agent skills
rvl doctor                 # what is missing on this machine, for THIS repo
rvl scan                   # scan the current directory
rvl hook install           # gate `git commit` on the scan
```

A scan prints a finding ladder with a short id per finding:

```
■ BLOCKING (base severity elevated by incident evidence)
  svc/main.py:4 — requests.get has no timeout or deadline — not at the call,
  not on a client or session it is built from, and not anywhere up the call
  chain, and requests applies no default of its own; it can hang indefinitely
    severity: high
    control RC-019 · explain: rvl explain bfyx
```

Follow a finding from there:

```sh
rvl explain bfyx                        # the sites, the control, the fix
rvl suppress bfyx --reason="…"          # waive it in .revelara.yaml
```

`suppress` writes `scanner.waivers` into `./.revelara.yaml`, so a waiver is a
committed, reviewable decision your team shares through git rather than a
setting on one laptop.

## Documentation

| Document | What is in it |
| --- | --- |
| [Command reference](docs/commands.md) | Every command, grouped by what it is for. |
| [Gating commits and CI](docs/gating.md) | Git hooks, the exit-code contract, `--strict`, and asserting on coverage in CI. |
| [How a scan finds your code](docs/retrievers.md) | Per-language retrievers, their toolchain prerequisites, and the five resolution slots. |
| [Coding-agent skills and lenses](docs/agent-skills.md) | `rvl skills`, the `/rvl:*` commands, and the managed context block. |
| [Configuration](docs/configuration.md) | `.revelara.yaml` keys, environment variables, compatibility flags. |
| [Privacy](docs/privacy.md) | What can and cannot ride on the wire, and how to see it. |
| [Releasing](docs/releasing.md) | Cutting a release, and how each retriever helper is packaged. |
| [The `--out` document contract](docs/out-contract.md) | The machine-readable scan document consumed by orchestrators. |

End-user guides are hosted, not in this repo:
[local scanning](https://app.revelara.ai/help/local-scanning) covers hooks and
per-language setup in depth, and the
[project configuration guide](https://app.revelara.ai/help/revelara-config)
covers `.revelara.yaml`. The docs in this repository are for people working
*on* `rvl`.

## Development

### Build and run

```sh
make build          # cargo build
make dev            # build, then put the helpers next to the binary
make test           # cargo test --workspace
make lint           # cargo clippy --workspace --all-targets -- -D warnings
make fmt fmt-check  # cargo fmt --all [--check]
make install        # release build + helpers into $PREFIX/bin (default ~/.local/bin)
make help           # every target with its one-line description
```

`make dev` then `target/debug/rvl scan <path>` is the inner loop. Raw `cargo`
still works for anything the Makefile does not wrap.

A locally built `rvl scan <path>` already resolves the scripted retrievers
from the copies embedded in the binary, so `make helpers` is only needed for
`goindex` (which cargo cannot build) and when **developing** a scripted
helper: it copies `pyindex.py` / `javaindex.java` next to the binary, and the
adjacent slot outranks the embedded one, so an edit takes effect without
re-embedding. On a gvm box with a mismatched `GOROOT`, override the Go
invocation: `make helpers GO='env -u GOROOT go'`.

### The rule the workspace is built around

**Retrievers report facts; specs carry judgment; propagation combines them
mechanically.** A retriever says what the code *is* — this call site, this
client type, this method — and never whether it is a problem. What a matched
surface *means* is spec knowledge, authored elsewhere and consumed here as
data. That split is why adding a language costs compiler-frontend work and no
reliability judgment, and why the scanner can ship as a binary plus a JSON
cache rather than as a model. It has been violated before, and both times
produced a matcher that failed its own sanity check. Do not put a verdict in a
retriever.

### Workspace layout

Sixteen crates under `crates/`, plus a `helpers/` tree of retrievers that are
not Rust.

| Crate | What it is |
| --- | --- |
| `rvl` | The CLI: command surface, scan orchestration, `doctor`, `hook`, `init`, rendering. Also declares the `cindex` and `rustindex` bin targets (`src/bin/`) so release packaging can pack them beside `rvl`. |
| `rvl-core` | Shared types, mirroring the JSON packet contract the retrievers emit, field for field. |
| `rvl-spec` | The spec cache: a spec answers a question about an API, not about a call site, so it is earned once and paid forever. |
| `rvl-cache` | Spec-cache distribution: versioning, signing, sync, quarantine of artifacts that fail verification. |
| `rvl-propagate` | Deterministic propagation: apply specs to every call site, no inference, no model calls. |
| `rvl-triage` | Collapse per-site findings into the handful of items a developer would actually read. |
| `rvl-index` | The incremental-scan packet index, keyed by content hash, so a warm pre-commit scan re-retrieves only what changed. |
| `rvl-config` | The config/IaC lane: per-*format* retrievers (CI, deploy, supply chain, capacity) plus config-spec verification. |
| `rvl-content` | The content-pattern lane: in-process, language-agnostic secret detection. |
| `rvl-emission` | The emission-point lane: aggregate facts about logging, tracing and error-handling sites. |
| `rvl-structure` | The repo-structure lane: test conventions, coverage config, dep-manifest hygiene, runbook presence. |
| `rvl-data` | The platform commands (`risk`, `control`, `evidence`, `knowledge`, …), held to byte-identical JSON parity with the Go CLI via golden tests. |
| `rvl-skills` | Skill and lens distribution into coding-agent harnesses. Download-only by construction. |
| `rvl-eval` | Destination-gate metrics and provenance enforcement. Its own binary, not linked into `rvl`, and deliberately excluded from the release tap. |
| `cindex`, `rustindex` | The C/C++ (libclang) and Rust (rust-analyzer SCIP) retrievers, as libraries; their executables are bins of the `rvl` package. |

`helpers/` holds the out-of-process retrievers, one directory per language,
each with its own README: `goindex` (a Go module, with its own `go test`
suite), `pyindex` (Python), `tsindex` (Node + TypeScript), `javaindex`
(single-file Java, JEP 330 source mode) and `csindex` (.NET/Roslyn, not
shipped in releases). The three scripted ones are `include_str!`d into the
binary by `crates/rvl/src/embedded_helpers.rs`, so editing one and rebuilding
is enough to change what a release carries.

### Tests and gates

CI (`.github/workflows/ci.yml`) runs, and a change is expected to pass all of
them locally first:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build -p rvl --bin cindex --bin rustindex   # so the C/C++ e2e runs instead of skipping
cargo test --workspace

cd helpers/goindex && go mod verify && go vet ./... && go test ./...
go run . -packet-schema                           # must print a schema version
```

Two of those are worth understanding rather than just satisfying. Building
`cindex` matters because the C/C++ end-to-end tests skip themselves when the
helper is absent, and a helper the suite never builds is a lane the suite
never covers. `-packet-schema` must be printable without loading anything,
because a consumer negotiates on that number before paying for a load.

CI also greps the whole tree for an internal codename and fails the build if
it appears anywhere, including in comments and docs. The product is Revelara
and the CLI is `rvl`.

The end-to-end suites in `crates/rvl/tests/` are the ones most likely to catch
a regression that unit tests miss, and each was written against a real
failure. They run a *copy* of the binary in an empty directory with `HOME`
pointed at a tempdir, because a developer machine has `make helpers` output
next to `target/debug/rvl` and a populated `~/.revelara`, either of which
would let a test pass without the feature existing.

| Suite | What it pins |
| --- | --- |
| `fresh_install.rs` | A fresh install can actually scan: the binary alone, no helpers on the machine. |
| `degraded_retriever_gate.rs` | A gate over a retriever that cannot run does not report success having scanned nothing. |
| `no_source_repo_gate.rs` | A repo with no supported language commits cleanly instead of erroring. |
| `v1_hook_compat.rs` | Hook shims written by the previous Go CLI still drive a real `git commit` / `git push` after an upgrade. |
| `doctor_cli.rs` | `rvl doctor [--fix]` end to end. |

### Where a change goes

- **A new language** → a retriever under `helpers/` (or a crate, if it can be
  pure Rust), emitting packets against the `rvl-core` contract; then a
  resolution slot and a `doctor` lane. No reliability judgment anywhere in it.
- **A new reliability judgment** → the spec cache, not the code. If you find
  yourself hard-coding "this API is fine", you are in the wrong repository.
- **A new command** → `crates/rvl/src/main.rs` for the clap surface, with the
  work in the crate that owns it; platform commands live in `rvl-data` and owe
  golden-parity tests.
- **A change to what `--out` emits** → [`docs/out-contract.md`](docs/out-contract.md)
  is the contract, and orchestrators consume it. Update it in the same change.
- **A change to packaging or the release flow** →
  [`docs/releasing.md`](docs/releasing.md); `dist-workspace.toml` and
  `crates/rvl/Cargo.toml` both carry long comments explaining why the current
  shape is the way it is. Read them before simplifying either.

## License

Apache-2.0. See [LICENSE](LICENSE).
