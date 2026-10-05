# goindex — Go retriever helper

Emits the versioned packet stream rvl consumes. Retrieval only: this
helper decides nothing about reliability, it only says what the code is.

    goindex -root <repo> -retrieve -name <snapshot>     # full load
    goindex -root <repo> -retrieve -files a.go,b.go     # incremental reload
    goindex -packet-schema                              # negotiate before loading

`-packet-schema` prints two lines: the contract version, then
`content-version <12 hex digits>`, the start of a sha256 of the helper's Go sources, which the binary embeds. The first
line is what a consumer negotiates on. The second identifies this build of the
helper: rvl compares it with the copy it ships and warns in `COVERAGE` when
the two differ (see "Helper drift" in `docs/retrievers.md`).

Every emitted record carries:

- `packet_schema` — the contract version (currently `2`). rvl absorbs
  helper churn behind this number; a consumer that does not know a version
  refuses the stream rather than guessing at its shape. It agrees with
  pyindex's and tsindex's `PACKET_SCHEMA` and `rvl_core::PACKET_SCHEMA`.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types and
  different verdicts. Measured on a 1528-site corpus: 1528 distinct site keys
  vs 1526 distinct file:line pairs. Downstream indexes and joins key on
  `site_key`, and `rvl_index::site_key` must agree with `siteKey` here.
- `lang` — always `"go"`. Named the same way the sibling helpers name theirs
  (`"python"`, `"typescript"`, `"csharp"`, `"java"`, `"rust"`, `"c_cpp"`), and
  stamped in `encodeRetrieved` next to `packet_schema` and `site_key` so every
  record kind carries it. Go emitted nothing here until po-av01j.63, which made
  a Go site indistinguishable from one whose language could not be resolved —
  and a consumer that cannot tell those apart has to treat both as unknown.
- `const_args` (v2) — constant-valued arguments at the call site, as
  `{index, name, value, how}`. Literal tokens report `how: "literal"`;
  constants the Go type checker folds for free (a named `const`, a folded
  constant expression like `2*time.Second`) report `how: "named_constant"`.
  Go calls are purely positional, so `name` is always absent. Evidence, never
  a verdict — what a value MEANS is spec-layer knowledge, and there is no deep
  constant propagation.
- `macro_expansion` (v2) — whether the site sits inside a macro expansion.
  Always `false` for Go (no macros); mechanical for C/C++ retrievers.

The candidate-extractor tables -- the G1 I/O method names and the G4 emission
framework list -- are corpus data in `extractor_corpus.json`, embedded at build
time, not code constants (po-av01j.219). Its `known_unretrieved` list names I/O
the tables deliberately do not retrieve (`io.ReadAll`), and every `-retrieve`
run counts those calls on the `repo_config` record's `retrieval` census beside
`candidates` (call sites emitted) and `calls_resolved` (every call whose callee
type-resolved). That census is the retrieval denominator: coverage is
resolution over what these tables retrieve, and the census is how much they
retrieve. It is computed before any `-files` filter, so it is always whole-repo.

A discarded error (`_ = f.Close()`, `n, _ := strconv.Atoi(s)`) rides the same
stream as an aggregate with `site_kind: "misuse_shape"`: one packet per
function and callee, with `misuse_class: discarded_error` and `misuse_count`
in `const_args` (`misuse.go`). It is not a call site and is not in the census.
Whether a discard is legitimate is spec knowledge, so every one is emitted.
See "Misuse shapes" in `docs/retrievers.md`.

A cold full load is paid at explicit init, never on the hook path; the
incremental path (`-files`) reloads only what changed.
