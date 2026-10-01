# dist-extras

Staging directory for release artifacts cargo cannot build.

Release CI cross-compiles `helpers/goindex` for each target triple into
`goindex` here, immediately before `dist build` runs; `[package.metadata.dist]
include` in `../Cargo.toml` then packs it into the release archive next to the
`rvl` binary, where helper resolution finds it with no environment set.

It also receives `libclang/`, the pinned libclang `cindex` loads in a release
(`ci/fetch-libclang.sh`, checksums in `crates/cindex/libclang.pin`). `include`
packs the directory beside `cindex`, which looks for it there.

The built binary is deliberately NOT committed: it is per-target and
reproducible from `helpers/goindex` with a Go toolchain. A local
`make helpers` writes goindex next to your dev binary instead.
