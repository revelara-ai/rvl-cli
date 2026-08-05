# goindex — Go retriever helper

Emits the versioned packet stream rvlscan consumes. Retrieval only: this
helper decides nothing about reliability, it only says what the code is.

    goindex -root <repo> -retrieve -name <snapshot>     # full load
    goindex -root <repo> -retrieve -files a.go,b.go     # incremental reload
    goindex -packet-schema                              # negotiate before loading

Every emitted record carries:

- `packet_schema` — the contract version (currently `2`). rvlscan absorbs
  helper churn behind this number; a consumer that does not know a version
  refuses the stream rather than guessing at its shape. It agrees with
  pyindex's and tsindex's `PACKET_SCHEMA` and `rvl_core::PACKET_SCHEMA`.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types and
  different verdicts. Measured on a 1528-site corpus: 1528 distinct site keys
  vs 1526 distinct file:line pairs. Downstream indexes and joins key on
  `site_key`, and `rvl_index::site_key` must agree with `siteKey` here.
- `const_args` (v2) — constant-valued arguments at the call site, as
  `{index, name, value, how}`. Literal tokens report `how: "literal"`;
  constants the Go type checker folds for free (a named `const`, a folded
  constant expression like `2*time.Second`) report `how: "named_constant"`.
  Go calls are purely positional, so `name` is always absent. Evidence, never
  a verdict — what a value MEANS is spec-layer knowledge, and there is no deep
  constant propagation.
- `macro_expansion` (v2) — whether the site sits inside a macro expansion.
  Always `false` for Go (no macros); mechanical for C/C++ retrievers.

A cold full load is paid at explicit init, never on the hook path; the
incremental path (`-files`) reloads only what changed.
