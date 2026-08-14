# dist-extras

Staging directory for release artifacts cargo cannot build.

Release CI cross-compiles `helpers/goindex` for each target triple into
`goindex` here, immediately before `dist build` runs; `[package.metadata.dist]
include` in `../Cargo.toml` then packs it into the release archive next to the
`rvlscan` binary, where helper resolution finds it with no environment set.

The built binary is deliberately NOT committed: it is per-target and
reproducible from `helpers/goindex` with a Go toolchain. A local
`make helpers` writes goindex next to your dev binary instead.
