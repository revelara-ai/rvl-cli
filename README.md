# rvlscan

The Revelara reliability scanner.

`rvlscan` analyzes codebases for reliability risks and grounds its findings in
the Revelara controls catalog and incident corpus.

> Status: early development (0.x). Interfaces and output formats are unstable
> until v1.0.0.

## Install

Via Homebrew (once a release is published):

```sh
brew install revelara-ai/tap/rvlscan
```

Or download a release archive from the
[releases page](https://github.com/revelara-ai/rvlscan/releases).

## Usage

Scan a repository with a single command:

```sh
rvlscan scan [PATH]        # PATH defaults to the current directory
```

With no `--retrieved`, rvlscan detects the languages under `PATH` (Go via
`go.mod` or any `*.go`; Python via `pyproject.toml`/`setup.py` or any `*.py`),
runs the matching retriever helper (`goindex` / `pyindex`) itself, and feeds the
packets into the scan pipeline. Multiple detected languages run each helper and
concatenate their packets.

Helpers are discovered in this order:

1. an env override — `RVLSCAN_GOINDEX` / `RVLSCAN_PYINDEX` (path to the helper
   binary, or, for Python, the `pyindex.py` script);
2. a helper next to the `rvlscan` binary;
3. a helper on `PATH` (`goindex`; for Python, `pyindex` or `pyindex.py`).

To scan a prebuilt packet stream instead of running a helper, pass the escape
hatch:

```sh
rvlscan scan --retrieved packets.jsonl
```

`explain` takes the same inputs plus a finding id:

```sh
rvlscan explain <id> [PATH]
rvlscan explain <id> --retrieved packets.jsonl
```

The signed spec cache is used by default (run `rvlscan sync` to populate it).
`--specs-file` is a loudly-announced dev override.

## Development

This is a Cargo workspace. The `rvlscan` binary lives in `crates/rvlscan`.

```sh
make build          # cargo build
make test lint      # cargo test; clippy -D warnings
make dev            # build + install helpers next to the binary
```

`make dev` (or `make helpers`) builds `goindex` and copies `pyindex.py` into
`target/<profile>/` next to the `rvlscan` binary, so a locally built
`rvlscan scan <path>` resolves its retriever via the adjacent-to-binary
discovery path with **no env var** — the same layout a release archive ships.
On a gvm box with a mismatched `GOROOT`, override the Go invocation:
`make helpers GO='env -u GOROOT go'`. Raw `cargo` still works for anything the
Makefile does not wrap.

## Releases

Releases are cut by pushing a v-prefixed semver tag (e.g. `v0.1.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew formula to `revelara-ai/homebrew-tap`.

### Shipping the retriever helpers

For a released `rvlscan` to scan with zero configuration, each release archive
must place the retriever helpers **next to the `rvlscan` binary** (the
adjacent-to-binary discovery slot). Two helpers, two shapes:

- **`pyindex.py`** is platform-independent (stdlib Python). It is added to
  every archive verbatim; scanning Python requires `python3` on the user's
  `PATH` at runtime.
- **`goindex`** is a compiled Go binary and must be cross-compiled **per
  target triple** (`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, …) and
  injected into the matching archive. cargo-dist does not build non-Rust
  artifacts itself, so this is a release-CI build step (`GOOS`/`GOARCH` matrix
  matching `dist-workspace.toml` `targets`) that emits `goindex` into each
  archive's binary directory. **This CI wiring is not yet in place** — until
  it is, released users fall back to `RVLSCAN_GOINDEX` / a `goindex` on `PATH`.
  It must be validated against a real release (do not merge speculative release
  changes; CI credits are limited).

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
