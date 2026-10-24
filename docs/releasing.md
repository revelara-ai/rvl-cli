# Releasing

Releases are cut by pushing a v-prefixed semver tag (e.g. `v1.0.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives, a CycloneDX SBOM and SLSA provenance, and publishes the Homebrew
cask to `revelara-ai/homebrew-tap`.

The release commit (the one that sets the new version in `Cargo.toml`, and
that the tag points at) also renames the heading
`## After <previous> (not released yet)` in
[release-notes.md](release-notes.md) to `## <version> (<release date>)`, and
changes each "the first release after <previous>" in that section's
"Minimum version to probe for" lines to the version. A change merged after the
tag starts a new `## After <version> (not released yet)` section at the top.

A change reaches `main` through a pull request. A maintainer's approval sends
it to a merge queue, which runs CI on the change merged with the current
`main` and merges it when that run is green.

The dist configuration lives in `dist-workspace.toml`, and
`.github/workflows/release.yml` is generated from it — edit the TOML and
regenerate, never hand-edit the workflow. Two of its choices are load-bearing
and commented in place: `installers = []` (dist 0.32 can only emit a Homebrew
*formula*, and the tap ships `rvl` as a *cask*, so the cask is rendered by
`ci/render-cask.sh` from the same release's `dist-manifest.json`), and
`github-build-setup`, which splices `.github/build-setup.yml` into each
per-target build job.

A release ships the `rvl` app and nothing else: no other app and no source
tarball (`source-tarball = false`). CI runs `dist plan` on every change and
`ci/check-release-plan.sh` fails it when the plan lists a second app, anything
of the evaluation harness, or a source tarball.

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
- **`libclang/`**, the engine `cindex` loads, is vendored, not built: a
  pinned, checksummed libclang so a release scans C/C++ the same way on every
  machine. `crates/cindex/libclang.pin` names the LLVM version and, per target
  triple, the download and its sha256. `ci/fetch-libclang.sh` (also spliced in
  via `.github/build-setup.yml`) verifies every download against the pin,
  fails the build on a mismatch, and writes `crates/rvl/dist-extras/libclang/`
  (the library, clang's builtin headers of the same version, and LLVM's
  license), which `include` packs beside `cindex`. The same step sets
  `CINDEX_REQUIRE_VENDORED_LIBCLANG` for the build, so a release `cindex`
  whose bundle is missing fails closed rather than using the system clang.
  Adding a release target means pinning a library for it first:
  `cargo test -p cindex` fails until `libclang.pin` and the `targets` in
  `dist-workspace.toml` agree.
- **`onnxruntime/`**, the engine of local model inference (`rvl-model`), is
  vendored the same way: `crates/rvl-model/onnxruntime.pin` names the ONNX
  Runtime version and, per target triple, Microsoft's release archive and its
  sha256. `ci/fetch-onnxruntime.sh` verifies the download, fails the build on
  a mismatch, and writes `crates/rvl/dist-extras/onnxruntime/` (the library,
  ONNX Runtime's license and its third-party notices), which `include` packs
  beside `rvl`. The step sets `RVL_REQUIRE_VENDORED_ONNXRUNTIME`, so a release
  `rvl` whose bundle is missing fails closed rather than loading a system
  runtime. `cargo test -p rvl-model` fails until `onnxruntime.pin` and the
  `targets` in `dist-workspace.toml` agree, and the smoke test fails an archive
  without the bundle.
- **`csindex`** is deliberately not shipped: the assembly is ~39 KB but pulls
  ~9 MB of `Microsoft.CodeAnalysis` behind it, more than the rest of the
  archive combined. Scanning a C# repo without it fails closed with the one
  `dotnet build` command that installs it into `~/.revelara/helpers/csindex`,
  where resolution finds it — no environment variable at any point. A future
  `rvl-csindex` cask should install into that same directory so the two routes
  compose.

## Release targets

A release builds `aarch64-apple-darwin`, `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` (`targets` in `dist-workspace.toml`).
`x86_64-apple-darwin` (Intel macOS) was dropped after 1.7.1: ONNX Runtime
publishes no Intel macOS build after 1.23.2, so an archive for it could not
carry the pinned runtime, and a scan there would differ from the same scan on
any other machine. `ci/check-release-plan.sh` fails a plan that lists it
again, and the cask's macOS block requires arm64.

## Smoke test of every archive

Before `host` uploads anything, each per-target archive is run on the runner
that built it. `global-artifacts-jobs = ["./smoke"]` in `dist-workspace.toml`
makes the generated workflow call `.github/workflows/smoke.yml` once the
builds succeed, with one job for each entry of the plan's build matrix. `host`
does not run unless every one of those jobs passed. Each job runs
`ci/smoke-archive.sh`, which unpacks the archive and checks two things:

- `rvl --version` names the release version.
- A scan of `ci/smoke/repo` with the seed specs in `ci/smoke/specs.json`
  reaches a verdict under `--strict`. The fixture has one unbounded call each
  in Go, C and Python. Each of those lanes must be `scanned` and decide a
  `violates` site, with goindex and cindex served from the archive and pyindex
  from the copy embedded in `rvl`. The scan runs with a scratch `HOME` and
  with every helper override unset, so nothing on the runner can stand in for
  a helper the archive should carry.

On a pull request the builds are skipped, so the smoke jobs are too. To see
them run before a real release, push a version tag to a fork.
`crates/rvl/tests/release_smoke.rs` holds the wiring to its contract and runs
the script against a fake archive.

The macOS binaries are not notarized. The cask clears the quarantine flag
instead (`ci/render-cask.sh`).

## SBOM and provenance

Each release publishes two supply-chain assets beside the archives:

- **`rvl.cdx.xml`**, a CycloneDX SBOM of the Rust
  dependency tree.
  `cargo-cyclonedx = true` in `dist-workspace.toml` makes the generated
  workflow build it in the global-artifacts job. It lists crates only. The Go
  modules of `goindex` (see `helpers/goindex/go.mod`), the vendored
  `libclang` and the vendored ONNX Runtime are in the archive and not in the
  SBOM.
- **`rvl.intoto.jsonl`**, SLSA Build Level 3 provenance for every asset of the
  release, the SBOM included. `.github/workflows/slsa-provenance.yml` runs
  after `announce`, hashes the artifacts of the release run with
  `ci/slsa-subjects.sh`, and calls
  [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator),
  which signs the provenance and uploads it to the release.

To verify a downloaded archive with
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

```bash
slsa-verifier verify-artifact rvl-x86_64-unknown-linux-gnu.tar.xz \
  --provenance-path rvl.intoto.jsonl \
  --source-uri github.com/revelara-ai/rvl-cli \
  --source-tag v1.2.3
```

Three things to know before you change this:

- The generator must be referenced by a release tag (`@v2.1.0`), never by a
  commit SHA. It verifies its own ref and refuses to run from a SHA.
- The provenance job is a post-announce job, so it also runs for a prerelease.
  If `announce` does not succeed, the release has no provenance until the
  failed jobs are re-run.
- In the generated `release.yml`, the upload step reads
  `steps.cargo-cyclonedx.output.paths`. That is a typo in cargo-dist 0.32
  (`output` for `outputs`) and it expands to nothing. The SBOM is uploaded
  anyway, because `dist build` lists `target/distrib/rvl.cdx.xml` in the
  manifest's `upload_files`. Do not fix it by hand: `dist plan` fails the
  Release check when the file differs from its generator.

`crates/rvl/tests/release_supply_chain.rs` holds this configuration to its
contract, because nothing short of a tag can run it.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## See also

- [How a scan finds your code](retrievers.md) — the resolution order these
  packaging decisions are aimed at
