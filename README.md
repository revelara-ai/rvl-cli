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
