# cindex — C/C++ retriever helper

Emits the versioned packet stream rvlscan consumes, for C and C++ source. The
C/C++ sibling of `goindex`/`pyindex`/`tsindex`. Retrieval only: this helper
decides nothing about reliability, it only says what the code is.

    cindex --retrieve --root <repo> --name <snapshot>      # full load
    cindex --retrieve --root <repo> --files a.c,b.cc       # incremental reload
    cindex --packet-schema                                 # negotiate before loading
    cindex --engine-check                                  # does a libclang load? (prints its version)

Unlike the other helpers this one lives IN the Rust workspace
(`crates/cindex`): `cargo build` drops it next to the `rvlscan` binary, which
is the adjacent slot helper discovery already checks. It remains a separate
subprocess speaking the same JSONL contract — the packet stream is the
boundary that keeps retrieval honest, and in-process linking was considered
and rejected for that reason.

## Engine: the libclang C API (pinned decision)

Per the wayfinder engine decision (po-ae75b.9): the **libclang C API**,
loaded at RUNTIME via `clang-sys`'s `runtime` feature. LibTooling is the
pre-registered escape valve with a migration protocol and is deliberately NOT
used.

- The workspace builds on machines with no libclang installed; only running
  a retrieval loads the library. When none is found the helper fails CLOSED
  with actionable stderr (install `libclang-dev` or set `LIBCLANG_PATH`) —
  rvlscan surfaces that error rather than silently under-reporting a detected
  C/C++ repo.
- **Pinning discipline:** a dev build uses the system libclang (floor:
  libclang 6.0, the `clang_6_0` API feature). RELEASE artifacts must vendor a
  pinned, checksummed LLVM build so scan results are reproducible across
  machines — that packaging rides its own bead; nothing in this crate may
  grow a dependency on system-specific clang behavior beyond the C API.
- `--engine-check` exists so callers (tests, doctors) can probe the engine
  cheaply; engine-dependent tests SKIP with a log line when it fails.

## Compile-database rules (native paths only)

C/C++ typing evidence comes from `compile_commands.json` — checked at
`<root>/compile_commands.json`, then `<root>/build/compile_commands.json`
(the CMake layout). There is NO build interception shipped with the scanner:
generating the db is user-run tooling (`cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`,
`bear -- make`, bazel extractors), documented, never wrapped.

- Each db entry parses as its own TU with its EXACT flags (compiler argv0,
  `-c`, `-o`, and the source file stripped; relative `-I`/`-isystem`/
  `-iquote`/`-include`/`-imacros` values resolved against the entry's
  `directory`, which itself resolves against `--root` when relative — real
  dbs are absolute, fixtures are relocatable).
- Duplicate entries for one file keep the first (deterministic). TUs are
  parsed in sorted file order.
- **A TU that fails to parse is COUNTED, never guessed at**: the
  `retrieval_stats` record carries `tus_total` / `tus_parsed` / `tus_failed`,
  and coverage claims stop at what actually parsed.
- Files not listed in the db are not scanned: the gate population for C/C++
  is compile-db repos (expansion gate protocol, po-ae75b.2).

### No-db fallback: the curated extern-C allowlist (low tier)

A repo with C sources and no compile db still gets a LOW-tier inventory:
`.c` files are best-effort parsed (`CXTranslationUnit_KeepGoing`, no flags)
and ONLY calls whose unmangled names sit on the curated allowlist are
emitted, stamped `client_type_resolved: false`:

- `curl_easy_*` / `curl_multi_*` → `libcurl.CURL`
- `PQ*` (exec/connect/prepare/send families) → `libpq.PGconn`
- `redis*` (connect/command families) → `hiredis.redisContext`
- POSIX socket verbs `connect`/`send`/`recv`/`sendto`/`recvfrom`/
  `sendmsg`/`recvmsg` → `posix.socket`

Everything else abstains. **C++ without a db is a documented abstention
class** — a flagless C++ parse is guesswork — counted in
`cpp_files_skipped_no_db`. POSIX `read`/`write` are deliberately OFF the
allowlist even in db mode: telling a socket fd from a file fd needs dataflow
(follow-up bead), and a wrong guess multiplies.

## What it emits

One JSON object per line (JSONL) to stdout: Site packets plus one
`{"kind":"retrieval_stats", ...}` record (consumers route unknown kinds away
from Site parsing, so the stats record is additive). Every site carries the
schema-v2 contract fields (`packet_schema: 2`, agreeing with
`rvl_core::PACKET_SCHEMA` and the other helpers):

- `site_key` — `file:line:client_type:method`, unique across the stream
  (sites re-emitted through headers included by many TUs are deduped on it).
- `const_args` (v2) — constant-valued arguments as `{index, name, value, how}`.
  C/C++ calls are positional, so `name` is always `""`. An enum-constant
  reference reports the constant NAME (`CURLOPT_TIMEOUT`) as
  `how: "named_constant"` — this is the libcurl-class enum discrimination the
  spec layer keys on. Literal tokens report `how: "literal"`; other
  constant-foldable expressions (casts of `sizeof`, constant arithmetic)
  report the folded value as `named_constant` (goindex's folded-expression
  convention). Evidence, never a verdict.
- `macro_expansion` (v2) — set MECHANICALLY from the detailed preprocessing
  record: a site whose expansion-point offset falls inside a recorded macro
  expansion range is flagged. No heuristics, no macro understanding.
- `snippet`, `enclosing_function_body`, `symbol`, `receiver` — source-level
  provenance, extents read straight from the file.
- `callers` / `callees` / `client_construction` — **empty in v1** (pyindex
  precedent): cross-TU graph walking is future work and the keys keep the
  shape stable.
- `lang` — `"c_cpp"`.

## C/C++ typing tiers

The hardest typing story in the inventory, split into explicit tiers:

| Case | Behavior | Tier signal |
| --- | --- | --- |
| C free function on the identity allowlist (db mode) | emitted | `client_type_resolved: true` |
| C++ member call, gRPC-generated `::Stub` receiver type | emitted at the stub identity | `client_type_resolved: true` |
| C++ member call, strong I/O verb (`execute`, `perform`, `request`, …) | emitted at the receiver's declared type | `client_type_resolved: true` |
| C++ member call, weak verb (`get`, `send`, `query`, …) on an out-of-repo (third-party) type | emitted | `client_type_resolved: true` |
| **Virtual dispatch** (weak or strong verb) | emitted at the STATIC interface identity | **mid tier:** `provenance.callee_candidates` = 1 + overriding definitions in the TU (>1 = ambiguous dispatch) |
| **Uninstantiated template** (dependent callee) | **abstains** — counted in `calls_unresolved`, never guessed | — |
| Weak verb on an in-repo, non-virtual type | not emitted (noise floor) | — |
| No-db `.c` allowlist match | emitted | LOW: `client_type_resolved: false` |

A virtual call is emitted against the interface where the method is declared:
the spec question ("does `Backend::fetch` block?") governs every implementer,
which is exactly the mid-confidence semantics the gate protocol quarantines.
Uninstantiated templates have no types to ask about — abstention, documented,
counted.

## Performance posture

What is implemented now vs deliberately documented for later:

- **Now:** per-TU parse with exact flags; deterministic TU order; site dedup;
  `--files` filtering re-parses only the named TUs (compile-db entries or
  no-db `.c` files). Incremental scans ride rvlscan's existing hash-gate.
- **Documented, follow-up beads:** per-TU index shards built at `index init`
  + preamble-cached re-parse (clang's preamble makes header-heavy TUs cheap
  on re-parse), background re-index via the existing detached-reindex
  pattern, and header→TU invalidation (a changed `.h` maps to no helper
  today, so header edits take the full-rescan path rather than guessing).

## Tests

`cargo test -p cindex`. Golden packet tests run the built helper over the
checked-in fixtures (`testdata/fixture-c`, `fixture-cpp`, `fixture-nodb`)
and pin the CURLOPT_TIMEOUT const-arg discrimination, the macro flag, the
virtual/template tiers, the no-db allowlist tier, and the failed-TU
accounting. Engine-dependent tests skip (loudly) without libclang; the pure
compile-db plumbing (shell splitting, arg filtering, the allowlist) is unit
tested and always runs.
