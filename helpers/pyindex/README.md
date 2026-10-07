# pyindex — Python retriever helper

Emits the versioned packet stream rvl consumes, for Python source. The
Python sibling of `goindex`. Retrieval only: this helper decides nothing about
reliability, it only says what the code is.

    pyindex --retrieve --root <repo> --name <snapshot>     # full load
    pyindex --retrieve --root <repo> --files a.py,b.py     # incremental reload
    pyindex --retrieve --root <repo> --include-tests       # also read test paths
    pyindex --packet-schema                                # negotiate before loading

`--packet-schema` prints two lines: the contract version, then
`content-version <12 hex digits>`, the start of a sha256 of `pyindex.py` itself. The first
line is what a consumer negotiates on. The second identifies this build of the
helper: rvl compares it with the copy it ships and warns in `COVERAGE` when
the two differ (see "Helper drift" in `docs/retrievers.md`).

Standard library only (`ast`, `argparse`, `hashlib`, `json`, `os`, `sys`). No pyright, no
LibCST, no third-party anything — a deliberate conservative choice for
pinnability and a clean dependency story.

## What it emits

One JSON object per line (JSONL) to stdout, one per detected call site. A site
is a `receiver.method(...)` call whose method name is a plausible I/O verb.
Every record carries:

- `packet_schema` — the contract version (currently `2`). rvl absorbs
  helper churn behind this number; a consumer that does not know a version
  refuses the stream rather than guessing at its shape. It agrees with
  goindex's `PacketSchema`, tsindex's `PACKET_SCHEMA`, and
  `rvl_core::PACKET_SCHEMA`.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types (and
  different verdicts), so downstream indexes and joins key on `site_key`, and
  `rvl_index::site_key` must agree with the key built here.
- `snapshot_id`, `file_path` (relative to `--root`), `line_number` (1-based).
- `symbol` — the enclosing function/method name, or `""` at module scope.
- `func` — the called method (the attribute: `get`, `execute`, `request`).
- `receiver` — source text of the receiver expression (`session`, `self.client`,
  `requests`).
- `client_type` — the resolved dotted client type/module, best-effort; `""` when
  unresolved.
- `snippet` — source of the full call expression, so a call-time `timeout=` is
  visible.
- `enclosing_function_body` — source of the enclosing `def`, or `""` at module
  scope.
- `client_construction` — where the receiver was constructed in-scope (so a
  construction-time `timeout=` is visible), as `{file, line, symbol, source}`
  snippets. Empty when none is found.
- `provenance` — metadata about the SEARCH, not a claim about the code. At
  minimum `{client_type_resolved, callers_total, callers_included,
  callees_total, callees_included}`. `client_type_resolved` is the per-site
  confidence signal. A call site also carries `ancestry_depth_searched`,
  `chain_roots`, `hit_depth_cap` and `hit_caller_budget` (see "The call
  graph" below).
- `const_args` (v2) — constant-valued arguments at the call site, as
  `{index, name, value, how}`. `index` is the zero-based position as written;
  `name` is the keyword (`timeout=5` → `"timeout"`), `""` for positional
  arguments. Literal tokens report `how: "literal"`; names resolved through
  the module-level `NAME = <literal>` constant map report
  `how: "named_constant"` (same module-scoped, last-write-wins best effort as
  the assignment tracking — no deep constant propagation). Values render via
  `repr()`. Evidence, never a verdict.
- `macro_expansion` (v2) — always `false` for Python (no macros); mechanical
  for C/C++ retrievers.
- `callers`, `callees` — the in-repo functions above and below the enclosing
  function, as `{file, line, symbol, source}` snippets (see "The call graph"
  below). Empty for a site at module scope, and on server-entry, emission
  and decorator-registration records.
- `lang` — `"python"`.

## The `retrieval_stats` record (one per run)

After the site packets, pyindex writes exactly one repo-scoped line,
`{"packet_schema":2,"kind":"retrieval_stats","lang":"python","files_total":…,
"files_parsed":…,"files_failed":…,"sites":…,"test_files_skipped":…,
"test_files_skipped_paths":[…]}`, on every successful run, even one that
found no sites: rvl's silent-zero guard keys on it to tell "ran and found
nothing" from "never ran". `test_files_skipped` (v2, additive) is how many
test files the run declined to read, and `test_files_skipped_paths` names
them (repo-relative, in discovery order) so rvl's packet index can flag
each one and a warm scan can report the repository-wide count; those files
are not in `files_total`, because they were never attempted.

## What it skips

Test code is not scanned for API surfaces, the way goindex has always
skipped `_test.go`. A file is test material when, relative to `--root`,
any directory segment is exactly `tests`, `test`, `testing` or `fixtures`,
or its basename is `conftest.py`, `test_*.py` or `*_test.py`. Exact matches
only, never substrings: `contest/handler.py`, `attestation.py` and
`latest.py` are production code. A `--files` set made only of test paths is
a counted skip, not the "requested files do not exist" error.
`--include-tests` turns the skip off; `rvl scan --include-tests` passes it
through.

## Resolution engine: stdlib `ast`, and its confidence tradeoff

Go has a compile-time type system goindex can lean on. Python does not, so full
type resolution would mean shelling out to a heavyweight external checker or a
third-party CST library — trading pinnability for resolution we still could not
fully trust, because a dynamically-typed receiver is a best-effort inference no
matter who does it.

So pyindex resolves receivers structurally, from the standard library `ast`:

- **Imports.** `import requests` binds `requests → requests`;
  `import a.b as c` binds `c → a.b`; `from redis import Redis` binds
  `Redis → redis.Redis`.
- **Assignments.** `session = requests.Session()` resolves the constructor
  through the imports and records `session → requests.Session`. `r = Redis(...)`
  records `r → redis.Redis`. `self.http = requests.Session()` records
  `self.http → requests.Session`. A constructor that is not an imported name
  (`cur = conn.cursor()`) does not resolve.
- **Receivers.** At each call site the receiver is matched against those two
  maps; a module reference (`requests.get`) resolves via the import directly.

Because dynamic typing caps confidence, resolution is reported per site rather
than assumed. When a receiver resolves through a tracked import/assignment,
`provenance.client_type_resolved` is `true` (a higher tier for the downstream
panel). When it cannot be resolved, the site is **still emitted** with
`client_type: ""` and `client_type_resolved: false` — a low tier, not a dropped
site. Tracking is module-scoped and last-write-wins (no real name scoping); like
goindex's assignment tracking this is knowingly unsound in rare cases and
recorded here rather than hidden.

## Client-detection heuristic

Without a type checker we cannot ask "is this an HTTP client?", so detection
keys off the **method name**, split into two tiers by how likely the name is to
also be an ordinary container/string method:

- **Strong I/O verbs** — almost never methods on a `list`/`dict`/`str`
  (`execute`, `executemany`, `request`, `post`, `put`, `patch`, `delete`,
  `head`, `options`, `fetchone`, `fetchall`, `fetchmany`, `do`, `publish`,
  `subscribe`, `sendall`, `recv`, `recvfrom`, `urlopen`, `check_output`,
  `check_call`). Emitted whether or not the receiver resolved — a
  `cur.execute(sql)` on an unresolved cursor is a real DB call site, it just
  lands at low confidence.
- **Weak I/O verbs** — ambiguous with builtins (`get`, `send`, `connect`,
  `call`, `run`, `query`, `invoke`, `read`, `write`). Emitted **only** when the
  receiver resolves to a concrete client, so `requests.get(...)` and
  `session.get(...)` survive but `somedict.get(k)` is dropped as noise.

Everything else — `items.append(x)`, `os.path.join(...)`, `s.strip()` — has a
method in neither set and is never emitted. This is a small, conservative
allowlist that favours a resolvable, meaningful set over indexing every
attribute call in the file.

## The call graph: callers, callees and chain roots

pyindex builds one call graph over the whole tree and gives each call site
(and each background-job call site) the same three things goindex gives a Go
site:

- `callers` — the functions that reach the enclosing function, nearest
  first: its direct callers, then theirs, breadth-first. At most 4 are
  emitted; `provenance.callers_total` counts all that the walk found.
- `callees` — the in-repo functions the enclosing function calls directly,
  in call order. At most 4 are emitted; `provenance.callees_total` counts
  them all.
- `provenance.chain_roots` — the functions the upward walk stopped at
  because nothing calls them. Each root carries structural facts, never a
  classification: `symbol` (the qualified name, `Syncer.sync_all`),
  `package` (the dotted module), `signature`, `doc` (the summary line of the
  docstring), `exported` (no leading underscore), `in_package_main` (the
  module has an `if __name__ == "__main__":` guard, or is `__main__.py`),
  `referenced_as_value` (how often the function is named without being
  called: passed to a router, a scheduler, a thread) and `decorators` (raw
  source). Whether a root is a real entrypoint is a judgment and stays
  downstream.

The walk reports where it stopped short. `hit_depth_cap` is true when it
reached 12 levels with callers still to follow, and `hit_caller_budget` is
true when it found more callers than it emitted. `ancestry_depth_searched`
is how many levels it walked. rvl reasons from "no bound found" only when
neither flag is set.

### What makes an edge

Python has no type checker to ask, so an edge exists only where the callee
expression resolves structurally to exactly one definition in the tree:

| Call | Resolves to |
| --- | --- |
| `foo()` | a def nested in an enclosing function, a module-level def, or an imported name |
| `mod.foo()` | a top-level def of an imported module. Re-exports are followed. |
| `self.foo()`, `cls.foo()` | a method on the enclosing class, or on an in-repo base class |
| `Cls.foo()` | the same lookup, by class |
| `obj.foo()` | a method of `Cls`, where `obj = Cls(...)` in the same function or at module scope, or `self.obj = Cls(...)` in the same class |
| `Cls()` | `Cls.__init__`, when the tree defines one |
| `Cls().foo()` | a method on the value constructed in place |

Everything else makes **no edge**: a method on a parameter, a callable
taken out of a dict, `super().foo()`, a name that a parameter or a local
shadows. pyindex does not match by name. A caller's source is read downstream
as in scope of the site, so a guessed caller is evidence for a chain that
may not exist. The cost is the other direction: a function that is only
reached dynamically is reported as a chain root, with
`referenced_as_value` and `decorators` as the facts that say so.

Imports resolve to files as follows. A relative import (`from .gateway
import x`) is counted up from the importing module's package. An absolute
import matches a module by its full dotted path from `--root`, or by a
suffix of it when the directory above is not a package (`src/app/x.py`
imports as `app.x`). When two files can answer to one import, or the name
is a standard-library module with no exact match, the import resolves to
nothing. A function that calls itself is not counted as its own caller.

### Scope of the graph

- Test paths are not in the graph unless `--include-tests` is given, so a
  test is never a caller of production code by default.
- With `--files`, packets and `retrieval_stats` cover the listed files
  only, but the graph still spans the whole tree: a reloaded file gets the
  packets a full run gives it. A file outside `--files` that does not
  parse loses its own edges and is not counted as a failure.
- The Go-only context facts (`direct_callers`,
  `direct_callers_passing_bounded_ctx`, `ancestors_traced`,
  `ancestors_with_deadline`) are not emitted. They describe a
  `context.Context` data flow that Python does not have.

## Tests

`python3 -m unittest` from this directory (or `python3 test_pyindex.py`). The
tests assert the two properties every consumer depends on — schema stamped and
site_key unique + well-formed — plus that a known client resolves, that a
construction/timeout is retrievable, and that noise calls are not emitted.
`testdata/fixture_graph/` is a small package with a known multi-hop call
chain (`main -> run_once -> sync_user -> fetch_profile`) for the call-graph
tests.
`testdata/fixture_misuse/` holds one function per rule of the misuse-shape
inventory (`site_kind: "misuse_shape"`): overbroad catches, blocking calls and
synchronous waits inside `async def`, tasks that nothing holds, and coroutines
that are never awaited, each beside the shapes that must not be emitted. See
"Misuse shapes" in `docs/retrievers.md`.
`testdata/fixture_tests/` holds one file per test-path convention beside
three production files, for the tests that pin what is skipped, what is
counted and named, and what `--include-tests` restores.
