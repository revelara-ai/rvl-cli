# goindex — Go retriever helper

Emits the versioned packet stream rvlscan consumes. Retrieval only: this
helper decides nothing about reliability, it only says what the code is.

    goindex -root <repo> -retrieve -name <snapshot>     # full load
    goindex -root <repo> -retrieve -files a.go,b.go     # incremental reload
    goindex -packet-schema                              # negotiate before loading

Every emitted record carries:

- `packet_schema` — the contract version. rvlscan absorbs helper churn behind
  this number; a consumer that does not know a version refuses the stream
  rather than guessing at its shape.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types and
  different verdicts. Measured on a 1528-site corpus: 1528 distinct site keys
  vs 1526 distinct file:line pairs. Downstream indexes and joins key on
  `site_key`, and `rvl_index::site_key` must agree with `siteKey` here.

A cold full load is paid at explicit init, never on the hook path; the
incremental path (`-files`) reloads only what changed.
