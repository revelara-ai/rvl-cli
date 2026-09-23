# tsindex — TypeScript retriever helper

Emits the versioned packet stream rvl consumes, for TypeScript source. The
TypeScript sibling of `goindex` and `pyindex`. Retrieval only: this helper
decides nothing about reliability, it only says what the code is.

    node tsindex.js --retrieve --root <repo> --name <snapshot>     # full load
    node tsindex.js --retrieve --root <repo> --files a.ts,b.ts     # incremental reload
    node tsindex.js --retrieve --root <repo> --include-tests       # also read test paths
    node tsindex.js --packet-schema                                # negotiate before loading

Install once with `npm install` (its only dependency is `typescript`). rvl
invokes it as `node tsindex.js …`, the same way it runs `pyindex.py` under
`python3`; helper discovery is env override (`RVL_TSINDEX`) → a helper next
to the rvl binary → `PATH`.

## What it emits

One JSON object per line (JSONL) to stdout, one per detected call site. A site
is a `receiver.method(...)` call. Every record carries:

- `packet_schema` — the contract version (currently `2`). rvl absorbs
  helper churn behind this number; a consumer that does not know a version
  refuses the stream rather than guessing at its shape. It agrees with
  goindex's `PacketSchema`, pyindex's `PACKET_SCHEMA`, and
  `rvl_core::PACKET_SCHEMA`.
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
  when readable; `""` otherwise, and always `""` for a syntactically resolved
  type (there is no installed package to read a version from). Kept a
  **separate field** rather than folded into `client_type`, so `site_key`
  (which contains `client_type`) stays stable across version bumps and matches
  `rvl_index::site_key`.
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
- `const_args` (v2) — constant-valued arguments at the call site, as
  `{index, name, value, how}`. `index` is the zero-based position as written;
  `name` is always `""` (TypeScript has no keyword arguments). Literal tokens
  (string/numeric/`true`/`false`/`null`, incl. substitution-free templates and
  `-1`) report `how: "literal"`; one-hop named constants (an identifier
  declared `const` with a literal initializer, or an enum member the checker
  folds via `getConstantValue`) report `how: "named_constant"`. Evidence,
  never a verdict — no deep constant propagation.
- `macro_expansion` (v2) — always `false` for TypeScript (no macros);
  mechanical for C/C++ retrievers.
- `callers`, `callees` — **empty arrays** (see below).
- `lang` — `"typescript"`.

## The `repo_config` record (one per run)

In addition to the per-site packets, tsindex emits **exactly one** repo-scoped
line, mirroring goindex's `RepoConfig`:

    {"packet_schema":2,"kind":"repo_config","snapshot_id":"<name>",
     "constructions":[{"type":"typeorm.DataSource","fields":["query_timeout"]}],
     "test_files_skipped":12,"test_files_skipped_paths":["e2e/login.ts", ...],
     "dependency_trees_uninstalled":2,
     "dependency_trees_uninstalled_paths":["backend","frontend"],
     "unmappable_specifiers":["@app/db"]}

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
`axios.AxiosInstance`); on an uninstalled tree it resolves syntactically to the
same `<pkg>.<TypeName>` for a `new X({...})` and to the bare package for a
factory (`axios`); and when it cannot be attributed to an external package at
all (a local subclass, a locally-defined factory) it falls back to the
constructor/factory identifier text (`GlobalWorkspaceDataSource`).

`dependency_trees_uninstalled` (additive) is how many declaring workspaces had
no installed `node_modules`, and `_paths` names them. A non-zero count means
this run resolved client types from IMPORT SYNTAX rather than the TypeChecker
— tier `medium`, no `client_version` — so the reader can tell a degraded scan
from a full one instead of inferring it from a low site count.
`unmappable_specifiers` names the import specifiers neither path could
attribute (tsconfig path aliases). Like `test_files_skipped` these are
retrieval statistics, not construction facts.

`test_files_skipped` (v2, additive) is how many test files this run declined
to read, and `test_files_skipped_paths` names them (repo-relative, sorted)
so rvl's packet index can flag each one and a warm scan can report the
repository-wide count; see "What it skips" below. They are retrieval
statistics, not construction facts, and ride this record because this is
the one line the helper writes on every run.

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

## What it skips

Test code is not scanned for API surfaces, the way goindex has always
skipped `_test.go`. On one real repo 700+ of 889 violates were Playwright
and msw calls inside E2E tests. A file is test material when, relative to
`--root`:

- any directory segment is exactly `tests`, `test`, `__tests__`,
  `__mocks__`, `e2e`, `spec`, `fixtures`, `testdata` or `cypress`;
- the basename contains `.test.`, `.spec.` or `.cy.`;
- the basename is a standard Playwright / Cypress / Vitest / Jest config or
  setup file: `playwright.config.*`, `cypress.config.*`, `vitest.config.*`,
  `vitest.workspace.*`, `vitest.setup.*`, `jest.config.*`, `jest.setup.*`,
  `setupTests.*`.

Exact matches only, never substrings: `attestation.ts`, `lib/contest/`,
`packages/test-utils/` and `vite.config.ts` are production code. Skipped
files are counted after the `--files` filter, so the count describes what
THIS invocation declined to read, and their constructions are left out of
`repo_config` too (a timeout set in test scaffolding must not credit a bound
to production). `--include-tests` turns the skip off; `rvl scan
--include-tests` passes it through.

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

### Resolution without an installed `node_modules`

The TypeChecker needs the package on disk. A SPEC KEY does not: an import
statement names the package, and the source names the type.

    import { Pool } from 'pg';           //         -> package `pg`
    const pool = new Pool({ ... });      // pool    -> pg.Pool
    constructor(private db: Pool) {}     // this.db -> pg.Pool
    import Redis from 'ioredis';         //
    const redis = new Redis();           // redis   -> ioredis.Redis
    import axios from 'axios';           // axios   -> axios

So when the checker comes back empty, tsindex attributes the receiver
syntactically and reports tier `medium`. The first cases reproduce the
checker's key EXACTLY, which is the point: the ratified TypeScript judgments
are keyed on `pg.Pool`, `ioredis.Redis`, `typeorm.DataSource`, and an
approximate key would match nothing. What syntax cannot reach is a name
declared INSIDE the package — a module object's type (`axios.AxiosStatic`), a
member of a property chain (`client.chat.completions`), a handler callback's
parameter (express's `res`) — and there it falls back to the bare import path,
which names the same thing one level coarser and still classifies through
`rvl_spec::client_family`.

Two consequences are deliberate:

- The **awaitability gate is skipped** at tier `medium`. It is a type test, and
  with no package `callReturnsThenable` fails open on every call, so keeping it
  would admit every property call in the file — the zod/knex builder flood it
  was written to stop. At `medium` a named I/O verb is required instead, which
  is why `axios.create(...)` and `z.string()` are not sites while
  `pool.query(...)` and `redis.get(...)` are.
- The **framework tables key on the package**, not on `<pkg>.<Type>`, so a
  bare `express`, `node-cron` or `winston` still reaches the server-entry,
  background-job and emission lanes. A logger landing in the G1 client lane
  would be a wrong KIND of site, not merely a coarser key.

Measured on this helper's own fixture, identical source and `tsconfig`, only
`node_modules` differing: 32 sites installed, 6 before this existed, 26 after.
An installed tree is bit-identical to before — the fallback runs only after the
checker has failed. An installed tree is still strictly better (versions, the
awaitability filter, chained and callback-typed receivers), which is why a
TypeScript gate set must still pin lockfile provenance.

**Abstain.** For a year an uninstalled tree abstained outright (exit 3), on the
argument that a partial result which looks complete is worse than none. That
cost 68 of the fleet's 97 TypeScript repos. The abstain now fires only for the
residue syntax genuinely cannot cross: a tree with no installed
`node_modules` whose external imports ALL go through tsconfig `paths` aliases,
which name a workspace directory rather than a package and can only be
followed through the package contents that are missing. The stderr message
names those specifiers.

### Confidence tiers (the dynamic-typing reality)

TypeScript is gradually typed, so resolution is reported per site rather than
assumed:

- **`high`** (`client_type_resolved: true`) — the checker resolved a concrete
  named type from an identifiable external package. `pool.query`, `axios.get`,
  `redis.get`, `this.db.query`.
- **`medium`** (`client_type_resolved: true`) — the checker could not resolve
  the type, but the SOURCE names it: an import statement names the package and
  a `new Pool()`, a `db: Pool` annotation or a `private db: Pool` property
  names the type. See "Resolution without an installed node_modules" below.
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
`testdata/fixture-tests/` holds one file per test-path convention beside
three production files, for the tests that pin what is skipped, what is
counted, and what `--include-tests` restores.

The uninstalled-tree tests copy `testdata/fixture/` **without** its
`node_modules` rather than carrying a second fixture, so the two runs differ in
exactly one thing — which is the property the whole lane turns on. They pin
that the same `pg.Pool` / `ioredis.Redis` / `bullmq.Queue` site keys come back,
at tier `medium` with no version; that the installed run is unchanged at
`high`; that builder and factory calls do not flood in once the awaitability
gate is unavailable; that loggers and spans still route to the emission lane;
and that a tree whose only external imports are path aliases still abstains
and names them.
