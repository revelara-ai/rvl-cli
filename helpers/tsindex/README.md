# tsindex — TypeScript retriever helper

Emits the versioned packet stream rvlscan consumes, for TypeScript source. The
TypeScript sibling of `goindex` and `pyindex`. Retrieval only: this helper
decides nothing about reliability, it only says what the code is.

    node tsindex.js --retrieve --root <repo> --name <snapshot>     # full load
    node tsindex.js --retrieve --root <repo> --files a.ts,b.ts     # incremental reload
    node tsindex.js --packet-schema                                # negotiate before loading

Install once with `npm install` (its only dependency is `typescript`). rvlscan
invokes it as `node tsindex.js …`, the same way it runs `pyindex.py` under
`python3`; helper discovery is env override (`RVLSCAN_TSINDEX`) → a helper next
to the rvlscan binary → `PATH`.

## What it emits

One JSON object per line (JSONL) to stdout, one per detected call site. A site
is a `receiver.method(...)` call. Every record carries:

- `packet_schema` — the contract version (always `1`). rvlscan absorbs helper
  churn behind this number; a consumer that does not know a version refuses the
  stream rather than guessing at its shape. It agrees with goindex's
  `PacketSchema`, pyindex's `PACKET_SCHEMA`, and `rvl_index::site_key`.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types (and
  different verdicts), so downstream indexes and joins key on `site_key`. Two
  calls on one line with different client types (e.g. `redis.get(k)` and
  `axios.get(u)`) get distinct keys because the client type discriminates them.
- `snapshot_id`, `file_path` (root-relative, forward slashes), `line_number`
  (1-based).
- `symbol` — the enclosing function/method name, or `""` at module scope.
- `func` — the called method (`query`, `get`, `execute`).
- `receiver` — source text of the receiver expression (`pool`, `this.db`,
  `axios`).
- `client_type` — the resolved, package-qualified type (`pg.Pool`,
  `axios.AxiosStatic`, `ioredis.Redis`); `""` when unresolved.
- `client_version` — the resolved package's version from its `package.json`,
  when readable; `""` otherwise. Kept a **separate field** rather than folded
  into `client_type`, so `site_key` (which contains `client_type`) stays stable
  across version bumps and matches `rvl_index::site_key`.
- `snippet` — source of the full call expression, so a call-time `{ timeout }`
  is visible.
- `enclosing_function_body` — source of the enclosing function, or `""` at
  module scope.
- `client_construction` — where the receiver was constructed in-scope (so a
  construction-time timeout/config is visible), as `{file, line, symbol,
  source}` snippets. Best-effort; empty when none is found.
- `provenance` — metadata about the SEARCH, not a claim about the code:
  `{client_type_resolved, confidence_tier, callers_total, callers_included,
  callees_total, callees_included}`. `client_type_resolved` and
  `confidence_tier` are the per-site confidence signals.
- `callers`, `callees` — **empty arrays in v1** (see below).
- `lang` — `"typescript"`.

## The `repo_config` record (one per run)

In addition to the per-site packets, tsindex emits **exactly one** repo-scoped
line, mirroring goindex's `RepoConfig`:

    {"packet_schema":1,"kind":"repo_config","snapshot_id":"<name>",
     "constructions":[{"type":"typeorm.DataSource","fields":["query_timeout"]}]}

Its `kind` is the literal `"repo_config"`; `rvl_core::parse_stream` keys on that
to route it away from the site stream. `constructions` is a **deduped** list of
`{type, fields}`, one entry per distinct constructed client type that sets at
least one timeout-ish field (fields are unioned across every construction of
that type). The line is emitted **even when `constructions` is empty**.

Why repo-scoped: a DI-injected pool/`DataSource` carries its `query_timeout` in
a central module, nowhere near the call sites it governs, so per-site (even
upward) retrieval can never reach it. This record carries the fact forward.

**What it scans.** Object/config literals passed to a client CONSTRUCTION:
`new X({...})` (TypeORM `DataSource`, node-postgres `Pool`, `ioredis` `Redis`,
`MongoClient`, ...) and a small set of client FACTORIES (`axios.create`,
`got.extend`, `createPool`, `createConnection`, `createClient`). The literal is
scanned for timeout-ish property names, descending **one level** into a nested
literal (TypeORM's `extra`, a dialect's `pool`). Timeout-ish is a
case-insensitive substring match: `query_timeout`, `statement_timeout`,
`maxQueryExecutionTime`, `connectionTimeoutMillis`, `connectTimeout`,
`commandTimeout`, `requestTimeout`, `idleTimeoutMillis`, `socketTimeout`,
`timeout`, `deadline`.

**`type` resolution** reuses the site packets' package-identity resolver: the
constructed type resolves to `<pkg>.<TypeName>` (`typeorm.DataSource`, `pg.Pool`,
`axios.AxiosInstance`); when it cannot be attributed to an external package
(a local subclass, an unresolved factory) it falls back to the
constructor/factory identifier text (`GlobalWorkspaceDataSource`,
`axios.create`).

This is **retrieval only**: the record reports *which* type set *which* timeout
fields — never whether that field actually bounds anything, and never the
field's value. Detection is on field-name PRESENCE, so a dynamic
`query_timeout: config.get('...')` is still recorded (the name is present even
though the value is computed).

**Detection limit.** Only an **inline** object-literal argument is scanned. A
construction handed a pre-built options *variable* — `new DataSource(opts)`,
where `opts` (and its `extra.query_timeout`) is a separate `const` — is not
traced back to that variable, so its fields are missed. (In twenty, the
`core.datasource.ts` `new DataSource(typeORMCoreModuleOptions as ...)` is missed
for this reason, but the same `query_timeout` fact is still retrieved from the
inline-literal `new GlobalWorkspaceDataSource({... extra: { query_timeout }})`.)

## Resolution engine: the TypeScript compiler API + TypeChecker

Unlike Python, TypeScript ships a real type system, so tsindex uses the
official `typescript` npm package and its **TypeChecker** to resolve a
receiver's type — `checker.getTypeAtLocation(receiver)` → the type's symbol →
the symbol's declaration source file. This is the deliberate, on-record choice
of the **stable** compiler API over the pre-release native port (typescript-go):
proven and dependable, at the cost of dragging a **Node runtime** into the
toolchain. That tradeoff is why the helper is a `.js` run under `node` rather
than a self-contained binary; packaging/bundling for release is tracked
separately (po-3t3oj.26) and out of scope here.

A `Program` is built over `--root`: if a `tsconfig.json` is present it is
honored (its file list and compiler options); otherwise every non-`.d.ts`
`*.ts`/`*.tsx` under root (skipping `node_modules`, `dist`, `build`, …) is a
root file with conservative default options.

### Package-identity inference

A resolved type's declaration usually lives in a `.d.ts` under
`node_modules/<pkg>/`. tsindex maps that path back to the npm package —
`pg` for `node_modules/pg/lib/index.d.ts`, `@scope/name` for a scoped
package — and forms `client_type = "<pkg>.<TypeName>"` from the package name
and the type's symbol name (`pg.Pool`, `ioredis.Redis`, `axios.AxiosStatic`).
The package's own `package.json` supplies `client_version`.

When a resolved type's declaration is **not** under `node_modules` (path
mappings, re-exports, a monorepo package), a fallback attributes it via the
receiver's binding import specifier: the bare module string on the `import`
that introduced the receiver's root identifier (`import { Pool } from 'pg'` →
`pg`). This is weaker than the path signal but recovers a package name the
compiler could not attribute to a directory.

### Confidence tiers (the dynamic-typing reality)

TypeScript is gradually typed, so resolution is reported per site rather than
assumed:

- **`high`** (`client_type_resolved: true`) — the checker resolved a concrete
  named type from an identifiable external package. `pool.query`, `axios.get`,
  `redis.get`, `this.db.query`.
- **`low`** (`client_type_resolved: false`, `client_type: ""`) — the receiver
  is `any`/`unknown`, unresolved, or resolves only to a TypeScript built-in lib
  type (`Array`, `Map`, `Promise`, `string`). The site is **still emitted**
  when its method is a strong I/O verb (see below) — a `cursor.execute(sql)` on
  an `any` cursor is a real DB call site, it just lands at low confidence. This
  is abstain-friendly: a site is never dropped for want of a type.

## Client-detection heuristic

The primary signal is the **resolved receiver type**: a call whose receiver
resolves to a concrete named type from an external npm package is a client call
and is emitted regardless of method name (that is how `query`/`get`, otherwise
ambiguous verbs, survive on real clients). For unresolved/built-in receivers we
fall back to a method-name allowlist, split by how likely the name is to also be
an ordinary container/string method:

- **Strong I/O verbs** — almost never methods on `Array`/`Map`/`Promise`/string
  (`execute`, `executemany`, `request`, `post`, `put`, `patch`, `head`,
  `options`, `fetchone`/`fetchall`/`fetchmany`, `publish`, `subscribe`,
  `sendall`, `recv`, `recvfrom`). Emitted whether or not the receiver resolved.
- **Weak I/O verbs** — collide with builtins (`get`, `send`, `connect`, `call`,
  `run`, `query`, `invoke`, `read`, `write`, `delete`, `fetch`, `exec`, `do`).
  Emitted **only** when the receiver resolves to an external client, so
  `redis.get(k)` survives but `someMap.get(k)` is dropped as noise.
- **Noise methods** — suppressed even on a resolved external client: chainable /
  event / container methods a real client object also carries but that are not
  I/O calls (`.then`, `.catch`, `.map`, `.filter`, `.forEach`, `.push`, `.on`,
  `.once`, `.emit`, `.toString`, `.valueOf`, …).

Everything else — `items.push(x)`, `s.trim()`, `obj.toString()` — has a method
in neither allowlist and an unresolved-or-builtin receiver, and is never
emitted. A deliberately small, conservative allowlist that favours a
resolvable, meaningful set over indexing every property call in the file.

## callers/callees are empty in v1

This helper reports per-site evidence and in-scope construction, not a
cross-module call graph. `callers` and `callees` are emitted as empty arrays so
the packet shape is stable and a later version can fill them (goindex's upward
ancestry + downward callees) without a schema bump.

## Fixture stubs

`testdata/fixture/` is a small well-typed project (`tsconfig.json`, a
`package.json`, and `src/service.ts`) exercising `pg`, `axios`, and `ioredis`
client calls plus non-client noise. To keep the checker resolving
**package-qualified** types with **zero network** and a fast test, its
`node_modules/{pg,axios,ioredis}` are **hand-written minimal `.d.ts` stubs**
(with a `package.json` carrying `name`/`version`), not real installs. They are
tracked (the helper's own `/node_modules` is git-ignored); the resolution path
they exercise — declaration under `node_modules/<pkg>/` → `<pkg>.<TypeName>` —
is exactly the one a real install takes.

## Tests

`node --test` from this directory. The tests assert the two properties every
consumer depends on — schema stamped, and `site_key` unique + equal to the
`file:line:client_type:func` formula — plus that a known client (pg/axios/
ioredis) resolves at tier `high` with a package-qualified `client_type`, that a
construction is retrievable, that two calls on one line with different client
types keep distinct keys, that an unresolved strong-verb call still emits at
`low`, and that noise (`.push`/`.map`/`.toString`) is not emitted.
