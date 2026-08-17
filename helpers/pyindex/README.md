# pyindex — Python retriever helper

Emits the versioned packet stream rvl consumes, for Python source. The
Python sibling of `goindex`. Retrieval only: this helper decides nothing about
reliability, it only says what the code is.

    pyindex --retrieve --root <repo> --name <snapshot>     # full load
    pyindex --retrieve --root <repo> --files a.py,b.py     # incremental reload
    pyindex --packet-schema                                # negotiate before loading

Standard library only (`ast`, `argparse`, `json`, `os`, `sys`). No pyright, no
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
  confidence signal.
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
- `callers`, `callees` — **empty arrays** (see below).
- `lang` — `"python"`.

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

## callers/callees are empty in v1

This helper reads a single file's imports and local assignments; it does not
build a cross-module call graph. The `callers` and `callees` keys are emitted as
empty arrays so the packet shape is stable and a later version can fill them
without a schema bump. Graph walking (goindex's upward ancestry + downward
callees) is out of scope for v1.

## Tests

`python3 -m unittest` from this directory (or `python3 test_pyindex.py`). The
tests assert the two properties every consumer depends on — schema stamped and
site_key unique + well-formed — plus that a known client resolves, that a
construction/timeout is retrievable, and that noise calls are not emitted.
