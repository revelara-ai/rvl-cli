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
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

## Releases

Releases are cut by pushing a v-prefixed semver tag (e.g. `v0.1.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew formula to `revelara-ai/homebrew-tap`.
Helper binaries ship as pinned, checksummed release assets.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
