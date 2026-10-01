# cindex — C/C++ retriever helper

Emits the versioned packet stream rvl consumes, for C and C++ source. The
C/C++ sibling of `goindex`/`pyindex`/`tsindex`. Retrieval only: this helper
decides nothing about reliability, it only says what the code is.

    cindex --retrieve --root <repo> --name <snapshot>      # full load
    cindex --retrieve --root <repo> --files a.c,b.cc       # incremental reload
    cindex --packet-schema                                 # negotiate before loading
    cindex --engine-check                                  # does a libclang load? (prints its version)

Unlike the other helpers this one lives IN the Rust workspace
(`crates/cindex`): `cargo build` drops it next to the `rvl` binary, which
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
  rvl surfaces that error rather than silently under-reporting a detected
  C/C++ repo.
- **Pinning discipline:** a dev build uses the system libclang (floor:
  libclang 6.0, the `clang_6_0` API feature). RELEASE archives vendor a
  pinned, checksummed libclang so scan results are reproducible across
  machines (see "Release engine" below). Nothing in this crate may grow a
  dependency on system-specific clang behavior beyond the C API.
- `--engine-check` exists so callers (tests, doctors) can probe the engine
  cheaply; engine-dependent tests SKIP with a log line when it fails. It
  prints one line: the clang version, then which engine loaded it —
  `[vendored <path>]`, `[system]` or `[LIBCLANG_PATH <path>]`.

## Release engine: the vendored libclang (po-av01j.49)

**Pinned version: LLVM 18.1.1**, for every release target.
[`libclang.pin`](libclang.pin) is the single source of truth: per Rust
target triple, the library download and its sha256, plus the clang source
tarball whose `lib/Headers` supplies the builtin headers. The comments in
that file say where each artifact comes from and why.

Release CI (`.github/build-setup.yml`) runs
[`ci/fetch-libclang.sh <triple> crates/rvl/dist-extras`](../../ci/fetch-libclang.sh)
before `dist build`. It checks every download against the pin, fails the
release on any mismatch, and only then writes the bundle, which dist's
`include` packs beside `cindex`:

    rvl-<triple>/
      rvl  cindex  rustindex  goindex
      libclang/
        libclang.so | libclang.dylib   the pinned library
        include/                       clang 18.1.1 builtin headers (stddef.h ...)
        LICENSE.TXT                    LLVM's license

Engine resolution at run time (`src/engine.rs`), first match wins:

1. `LIBCLANG_PATH`: an explicit override, used as-is.
2. `libclang/` beside the **symlink-resolved** `cindex`. Homebrew runs the
   helper through a link in its `bin`; the bundle sits beside the Caskroom
   original. A half-present bundle fails closed.
3. The system libclang. A release build (compiled with
   `CINDEX_REQUIRE_VENDORED_LIBCLANG`, which release CI sets) never takes this
   step: with its bundle missing it fails closed, because a release that
   quietly scans with a different clang is not reproducible.

On the vendored engine every TU also gets `-resource-dir <bundle>`. The
vendored library reports a relative resource dir and cannot find its own
builtin headers; without them any TU that includes a libc header takes a
fatal `'stddef.h' file not found` and still comes back as "parsed".

To bump the pin, change every line of `libclang.pin` together (one LLVM
version for all targets, the headers from that same version), and run
`cargo test -p cindex`: `tests/libclang_pin.rs` holds the pinned triples to
`dist-workspace.toml`'s `targets` and exercises the fetch script's
fail-closed paths.

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
- **A TU that parses with errors is COUNTED as incomplete** (po-av01j.138).
  Clang recovers from an error by dropping the construct: with
  `<curl/curl.h>` missing, `CURL *h = curl_easy_init();` parses as a
  multiplication of undeclared identifiers and the statement vanishes, calls
  and all, leaving no call expression to count. So `tus_parsed` includes
  `tus_incomplete` (TUs with any error diagnostic, paths in
  `tus_incomplete_paths`), and `includes_missing` / `decls_unresolved` say
  why. An incomplete TU still emits the sites that DID resolve, but its zero
  is never reported as a clean one: `rvl scan` shows the lane as `partial`.
  `calls_callee_unresolved` counts only calls clang formed whose callee did
  not resolve; it is not a completeness claim (it was `calls_unresolved`).
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
| **Uninstantiated template** (dependent callee) | **abstains** — counted in `calls_callee_unresolved`, never guessed | — |
| Weak verb on an in-repo, non-virtual type | not emitted (noise floor) | — |
| No-db `.c` allowlist match | emitted | LOW: `client_type_resolved: false` |

A virtual call is emitted against the interface where the method is declared:
the spec question ("does `Backend::fetch` block?") governs every implementer,
which is exactly the mid-confidence semantics the gate protocol quarantines.
Uninstantiated templates have no types to ask about — abstention, documented,
counted.

## G2 server entries: civetweb and mongoose (po-av01j.50)

HTTP handler registrations of the embedded C servers ride the same stream,
stamped `site_kind: "server_entry"`. rvl routes them to the G2 server-entry
lane (`rvl_propagate::server_entry`) and never to the G1 client-call lane.
G1 packets carry no `site_kind` key at all. The set is identity-driven like
the G1 allowlist, and it is emitted in no-db mode too (LOW tier):

| Call | `client_type` | Route path |
| --- | --- | --- |
| `mg_set_request_handler(ctx, uri, handler, cbdata)` (civetweb) | `civetweb.mg_context` | a literal `uri` rides `const_args` (index 1) |
| `mg_http_listen(mgr, url, fn, fn_data)` (mongoose) | `mongoose.mg_mgr` | none: this is the listener, its routes live in `fn` |
| `mg_http_match_uri(hm, glob)` (mongoose) | `mongoose.mg_http_message` | a literal `glob` rides `const_args` (index 1) |
| `mg_match(hm->uri, mg_str(glob), caps)` (mongoose) | `mongoose.mg_http_message` | the literal rides `snippet` |

`mg_match` is mongoose's general glob matcher, so it is gated two ways, both
mechanical: its first argument must read a field named `uri`, and its
enclosing function must be one that the same TU passes to `mg_http_listen`
as the event handler. A method match, or a match outside a registered
handler, is not emitted. The gate needs resolved declarations, so it does
not apply in no-db mode.

A mongoose server has no closed route table: the event handler can dispatch
by `strcmp`, or in another TU. The listener registration therefore stays a
route registration with no resolvable path, and the lane can find a mongoose
health endpoint (RC-020 satisfied) but never asserts that one is absent.
The civetweb C++ wrapper (`CivetServer::addHandler`) is not inventoried.

## Performance posture

What is implemented now vs deliberately documented for later:

- **Now:** per-TU parse with exact flags; deterministic TU order; site dedup;
  `--files` filtering re-parses only the named TUs (compile-db entries or
  no-db `.c` files). Incremental scans ride rvl's existing hash-gate.
- **Documented, follow-up beads:** per-TU index shards built at `index init`
  + preamble-cached re-parse (clang's preamble makes header-heavy TUs cheap
  on re-parse), background re-index via the existing detached-reindex
  pattern, and header→TU invalidation (a changed `.h` maps to no helper
  today, so header edits take the full-rescan path rather than guessing).

## Tests

`cargo test --workspace` (or `cargo build -p rvl --bin cindex && cargo test -p
cindex` — the `cindex` executable is a bin of the `rvl` package, not of this
one, so that this helper ships inside rvl's release archive; see `src/lib.rs`).
Golden packet tests run the built helper over the
checked-in fixtures (`testdata/fixture-c`, `fixture-cpp`, `fixture-nodb`)
and pin the CURLOPT_TIMEOUT const-arg discrimination, the macro flag, the
virtual/template tiers, the no-db allowlist tier, and the failed-TU
accounting. `testdata/fixture-server` pins the civetweb/mongoose G2
server entries and the `mg_match` event-handler gate. Engine-dependent tests skip (loudly) without libclang; the pure
compile-db plumbing (shell splitting, arg filtering, the allowlist) is unit
tested and always runs.
