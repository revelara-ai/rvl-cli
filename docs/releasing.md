# Releasing

Releases are cut by pushing a v-prefixed semver tag (e.g. `v1.0.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew cask to `revelara-ai/homebrew-tap`.

The dist configuration lives in `dist-workspace.toml`, and
`.github/workflows/release.yml` is generated from it — edit the TOML and
regenerate, never hand-edit the workflow. Two of its choices are load-bearing
and commented in place: `installers = []` (dist 0.32 can only emit a Homebrew
*formula*, and the tap ships `rvl` as a *cask*, so the cask is rendered by
`ci/render-cask.sh` from the same release's `dist-manifest.json`), and
`github-build-setup`, which splices `.github/build-setup.yml` into each
per-target build job.

## Shipping the retriever helpers

Each helper reaches a released `rvl` by the cheapest route its nature allows,
so a fresh install scans with no setup:

- **`pyindex.py` / `tsindex.js` / `javaindex.java`** are platform-independent
  text. They are `include_str!`d into the binary
  (`crates/rvl/src/embedded_helpers.rs`) and written to
  `~/.revelara/helpers/<version>/` on first use — one build carries them for
  every target, and there is nothing to package.
- **`cindex` / `rustindex`** are bin targets of the `rvl` package
  (`crates/rvl/src/bin/`), so `[package.metadata.dist] binaries` in
  `crates/rvl/Cargo.toml` packs them into the **same** archive as `rvl` (each
  was previously its own dist app, archive and formula), and the generated
  cask installs each as its own `binary` stanza.
- **`goindex`** is a compiled Go binary that cargo cannot build. Release CI
  cross-compiles it per target triple into `crates/rvl/dist-extras/`
  (`.github/build-setup.yml`, spliced into dist's build job via
  `github-build-setup`), and `[package.metadata.dist] include` packs it.
- **`csindex`** is deliberately not shipped: the assembly is ~39 KB but pulls
  ~9 MB of `Microsoft.CodeAnalysis` behind it, more than the rest of the
  archive combined. Scanning a C# repo without it fails closed with the one
  `dotnet build` command that installs it into `~/.revelara/helpers/csindex`,
  where resolution finds it — no environment variable at any point. A future
  `rvl-csindex` cask should install into that same directory so the two routes
  compose.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## See also

- [How a scan finds your code](retrievers.md) — the resolution order these
  packaging decisions are aimed at
