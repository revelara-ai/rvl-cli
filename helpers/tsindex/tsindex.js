#!/usr/bin/env node
// tsindex -- TypeScript retriever helper for rvl.
//
// Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
// This is the TypeScript sibling of helpers/goindex and helpers/pyindex. It
// emits the SAME versioned packet stream rvl consumes, for TypeScript
// source instead of Go/Python.
//
// The split this enforces
//
//   Per-language work is RETRIEVAL: mechanical, semantically neutral, no
//   reliability opinion. "Here is the call site." "Here is the client this
//   receiver was constructed from." That is compiler-frontend work. JUDGEMENT
//   stays semantic -- the LLM panel now, a distilled student later. Nothing
//   here decides whether a call is bounded, retried, or safe. It only reports
//   what exists and where, and how confident the resolution was.
//
// Engine: the official TypeScript compiler API (`typescript` npm package) and
// its TypeChecker. Unlike Python, TypeScript ships a real type system, so we
// lean on it: a receiver's type is resolved through the checker rather than
// guessed from imports. The tradeoff is a Node runtime in the toolchain (the
// helper is a `.js` run under `node`, discovered by rvl the same way
// pyindex.py is discovered and run under `python3`). We deliberately use the
// stable `typescript` compiler API rather than the pre-release native port.
//
// callers/callees are empty in v1: this helper reports per-site evidence and
// in-scope construction, not a cross-module call graph. The keys are emitted
// (as empty arrays) so the packet shape is stable and a later version can fill
// them without a schema bump.

'use strict';

const fs = require('fs');
const path = require('path');

// The `typescript` package is this helper's PREREQUISITE, not part of it: the
// script is embedded in the rvl binary and extracted to
// ~/.revelara/helpers/<version>/, and the compiler is 9 MB that would have to
// be carried for every target (po-aml3h). rvl points NODE_PATH at the
// scanned repository, so a project with its own `node_modules` needs nothing;
// anything else gets ONE command rather than a raw module-resolution stack.
//
// Exit 4 is rvl's HELPER_EXIT_PREREQ_MISSING: "not set up yet", which
// degrades this language and scans the rest of the repo, as distinct from
// "broken" (which asks the reader to file a bug).
// The version is PINNED, and the pin is load-bearing: npm's `typescript` now
// resolves to the 7.x native port, whose JS surface has no `ts.sys` and no
// `createProgram`. Suggesting a bare `npm install typescript` would hand the
// reader a package that fails differently.
const TS_REQUIREMENT = '^5.9.3';

function missingTypeScript(detail) {
  process.stderr.write(
    'tsindex: ' + detail + '\n' +
    '  (searched from ' + __dirname + ', NODE_PATH=' + (process.env.NODE_PATH || '') + ')\n' +
    'tsindex: install a compatible compiler with: npm install --no-audit --no-fund --prefix ' +
    __dirname + ' "typescript@' + TS_REQUIREMENT + '"\n'
  );
  process.exit(4);
}

let ts;
try {
  ts = require('typescript');
} catch (e) {
  missingTypeScript('the `typescript` package is not installed where node can find it');
}
// Checked by CAPABILITY rather than by version string: rvl points NODE_PATH
// at the repository being scanned, so the compiler that answers here is
// whatever that project depends on, and "does it expose the API we drive"
// survives a version scheme changing under us. Without this the 7.x port
// crashes mid-run with a raw module stack, which reads as a broken scanner
// rather than a machine that needs one command.
if (!ts || typeof ts.createProgram !== 'function' || !ts.sys) {
  missingTypeScript(
    'the `typescript` package found (version ' + ((ts && ts.version) || 'unknown') +
    ') does not expose the compiler API this helper drives'
  );
}

// PACKET_SCHEMA is the version of the emitted packet contract. rvl absorbs
// helper churn behind this number: a consumer that does not know a version
// refuses the stream rather than guessing at its shape. It MUST agree with
// goindex's PacketSchema, pyindex's PACKET_SCHEMA, and rvl_core::PACKET_SCHEMA.
//
// v2 adds const_args (constant-valued arguments at the call site) and
// macro_expansion (always false for TypeScript, which has no macros;
// mechanical for C/C++). v2 is a strict superset of v1.
const PACKET_SCHEMA = 2;

// Byte cap per emitted snippet, mirroring goindex's maxSnippetBytes and
// pyindex's MAX_SNIPPET_BYTES. A pathologically long function body should not
// blow up a packet line.
const MAX_SNIPPET_BYTES = 2400;

// Construction snippets to include per site (mirrors goindex maxCtorsEmitted).
const MAX_CTORS_EMITTED = 2;

// ---------------------------------------------------------------------------
// Client-detection heuristic.
//
// TypeScript is typed, so the primary signal is the RESOLVED RECEIVER TYPE: a
// call whose receiver resolves to a concrete named type from an external npm
// package is a client call and is emitted regardless of the method name. That
// is the strong, high-confidence path (`pool.query`, `axios.get`, `redis.get`
// all resolve even though `query`/`get` are otherwise ambiguous verbs).
//
// But TypeScript is also gradually typed: receivers land as `any`/`unknown`,
// come from untyped modules, or resolve only to a built-in lib type. For those
// we fall back to the same method-name allowlist pyindex uses, split by how
// likely the name is to be an ordinary container/string method:
//
//   STRONG_IO_METHODS -- verbs almost never found on Array/Map/Promise/string
//     (execute, request, fetchall, ...). Emitted whether or not the receiver
//     resolved: an `cur.execute(sql)` on an `any` cursor is still a real DB
//     call site, it just lands at low confidence.
//
//   WEAK_IO_METHODS -- verbs that collide with builtins (`Map.get`, `Set.delete`,
//     `arr.fetch`... `get`, `send`, `query`, `delete`, `read`, `write`, ...).
//     Emitted ONLY when the receiver resolves to an external client, so
//     `redis.get(k)` survives but `someMap.get(k)` is dropped as noise.
//
// NOISE_METHODS are suppressed even on a resolved external client: chainable /
// event / container methods (`.then`, `.map`, `.on`, `.toString`, ...) that a
// real client object also carries but are not I/O calls.
//
// Everything else -- `items.push(x)`, `s.trim()`, `obj.toString()` -- has a
// method name in neither allowlist and an unresolved-or-builtin receiver, and
// is never emitted. A deliberately conservative, documented allowlist.
// ---------------------------------------------------------------------------

const STRONG_IO_METHODS = new Set([
  // DB drivers / cursors / ORMs
  'execute', 'executemany', 'fetchone', 'fetchall', 'fetchmany',
  // HTTP verbs that are almost never container methods
  'request', 'post', 'put', 'patch', 'head', 'options',
  // messaging / rpc
  'publish', 'subscribe',
  // sockets
  'sendall', 'recv', 'recvfrom',
]);

const WEAK_IO_METHODS = new Set([
  // ambiguous with builtin containers/strings -- require a resolved receiver
  'get', 'send', 'connect', 'call', 'run', 'query', 'invoke',
  'read', 'write', 'delete', 'fetch', 'exec', 'do',
]);

// ---------------------------------------------------------------------------
// G3 background-job registration surfaces (po-av01j.4).
//
// Schedulers, cron registrations, dispatchers, and worker handler
// registrations ride the SAME packet stream, marked
// site_kind="background_job". Like the I/O-method allowlists this is a
// RETRIEVAL selection table, not a judgment: it picks which sites to mark;
// whether a registration needs a bound is spec knowledge downstream
// (ApiSpec.site_kinds). Detection is TYPE-driven through the checker — the
// receiver (or constructed class) must resolve into the framework's npm
// package — so an untyped lookalike is never guessed at (abstain-by-omission).
// ---------------------------------------------------------------------------

// Method calls that register/dispatch background work, keyed on the resolved
// `<pkg>.<Type>` client type. `type: null` accepts any type from the package
// (typings vary across cron libraries; the package identity is the signal).
const JOB_REGISTRATIONS = [
  { pkg: 'bullmq', type: 'Queue', methods: new Set(['add', 'addBulk']) },
  { pkg: 'agenda', type: null, methods: new Set(['define', 'every', 'schedule']) },
  { pkg: 'node-cron', type: null, methods: new Set(['schedule']) },
];

// Constructions that ARE registrations: `new Worker(name, processor)` hands
// bullmq the handler, so the new-expression is the registration site.
const JOB_CTOR_TYPES = [{ pkg: 'bullmq', type: 'Worker' }];

// isJobRegistration reports whether a RESOLVED client method call registers
// background work: `<pkg>.<Type>` must match an entry's package (and type,
// when the entry pins one) and the method its set.
function isJobRegistration(clientType, method) {
  for (const entry of JOB_REGISTRATIONS) {
    if (!entry.methods.has(method)) continue;
    if (entry.type === null) {
      if (clientType.startsWith(entry.pkg + '.')) return true;
    } else if (clientType === entry.pkg + '.' + entry.type) {
      return true;
    }
  }
  return false;
}

// isJobCtor reports whether a resolved constructed type is a handler
// registration (see JOB_CTOR_TYPES).
function isJobCtor(clientType) {
  return JOB_CTOR_TYPES.some((e) => clientType === e.pkg + '.' + e.type);
}

// G2 server-entry detection (po-av01j.3).
//
// Server-entry sites (HTTP handler registrations, route definitions,
// middleware attachments) ride the SAME packet stream, distinguished by the
// additive `site_kind` field. Detection is deliberately conservative and
// TYPED: a registration is emitted only when the receiver RESOLVES to a type
// from a known server framework package (express, fastify), or a route
// decorator's identifier resolves to @nestjs/common. An unresolved
// `app.get(...)` could as easily be an HTTP client, so it abstains from this
// lane (and falls through to the ordinary G1 rules).
// ---------------------------------------------------------------------------

// Mirrors rvl_core::SITE_KIND_SERVER_ENTRY.
const SITE_KIND_SERVER_ENTRY = 'server_entry';

// npm packages whose resolved types are server frameworks.
const SERVER_PACKAGES = new Set(['express', 'fastify']);

// Route-registration verbs on a server framework receiver (lowercased).
const SERVER_ROUTE_METHODS = new Set([
  'get', 'post', 'put', 'delete', 'patch', 'options', 'head', 'all', 'route',
]);

// Middleware-chain attachment verbs on a server framework receiver
// (lowercased; `register`/`addhook` are fastify's plugin/hook surface).
const SERVER_MIDDLEWARE_METHODS = new Set(['use', 'register', 'addhook']);

// NestJS route decorators, matched by name AND by the identifier resolving to
// @nestjs/common (a local helper named Get never matches).
const NEST_ROUTE_DECORATORS = new Set([
  'Get', 'Post', 'Put', 'Delete', 'Patch', 'Options', 'Head', 'All',
]);

// isServerFrameworkType reports whether a resolved `<pkg>.<Type>` client type
// belongs to a known server framework package.
function isServerFrameworkType(clientType) {
  const i = clientType.lastIndexOf('.');
  if (i < 0) return false;
  return SERVER_PACKAGES.has(clientType.slice(0, i));

}

const NOISE_METHODS = new Set([
  // chainable / promise
  'then', 'catch', 'finally',
  // object / string
  'toString', 'valueOf', 'hasOwnProperty',
  // event emitter
  'on', 'once', 'off', 'emit', 'addListener', 'removeListener',
  // array-ish
  'map', 'filter', 'forEach', 'reduce', 'push', 'pop', 'slice', 'concat',
]);

// ---------------------------------------------------------------------------
// Repo-level config retrieval (the `repo_config` packet).
//
// A DI-injected pool/DataSource carries its `query_timeout` in a central module,
// nowhere near the call sites that use it, so per-site retrieval can never reach
// it. Mirroring goindex's RepoConfig, we emit ONE repo-scoped record per run
// listing DB/HTTP client CONSTRUCTIONS that set a timeout-ish config field. This
// is RETRIEVAL ONLY: we report the observed fact (which type set which timeout
// fields), never whether that field actually bounds anything -- that judgement
// is the spec author's, downstream.
//
// TIMEOUT_FIELD_SUBSTRINGS is matched case-insensitively as a SUBSTRING against
// each construction-literal property name. `timeout`/`deadline` subsume most of
// the list; the explicit long names (`maxQueryExecutionTime`, ...) cover the few
// that carry no `timeout`/`deadline` substring. The ORIGINAL property name is
// what we record, not the matched substring.
// ---------------------------------------------------------------------------

const TIMEOUT_FIELD_SUBSTRINGS = [
  'query_timeout', 'statement_timeout', 'statementtimeout',
  'maxqueryexecutiontime', 'connectiontimeoutmillis', 'connecttimeout',
  'commandtimeout', 'requesttimeout', 'idletimeoutmillis', 'sockettimeout',
  'timeout', 'deadline',
];

// Factory calls whose first object-literal argument configures a constructed
// client, so `axios.create({timeout})`, `got.extend({timeout})`,
// `createPool({...})`, `mysql.createPool({...})` are covered alongside
// `new Pool({...})`. Matched on the last name of the callee.
const FACTORY_CALL_NAMES = new Set([
  'create', 'extend', 'createPool', 'createConnection', 'createClient',
]);

function isTimeoutish(name) {
  if (!name) return false;
  const lc = name.toLowerCase();
  return TIMEOUT_FIELD_SUBSTRINGS.some((s) => lc.includes(s));
}

// propertyName returns the source name of an object-literal member, for both
// `{ query_timeout: X }` (PropertyAssignment) and `{ timeout }` (shorthand).
function propertyName(p) {
  if (!p.name) return '';
  if (ts.isStringLiteral(p.name)) return p.name.text;
  if (typeof p.name.getText === 'function') return p.name.getText();
  return '';
}

// collectTimeoutFields scans an object literal for timeout-ish property names,
// descending ONE level into nested object literals (TypeORM's `extra`, a
// dialect's `pool`, ...). `depth` guards that single level. Found names are
// added to `out` (a Set, so duplicates across a literal collapse).
function collectTimeoutFields(objLiteral, depth, out) {
  if (!objLiteral || !ts.isObjectLiteralExpression(objLiteral)) return;
  for (const p of objLiteral.properties) {
    const name = propertyName(p);
    if (name && isTimeoutish(name)) out.add(name);
    if (
      depth < 1 &&
      ts.isPropertyAssignment(p) &&
      p.initializer &&
      ts.isObjectLiteralExpression(p.initializer)
    ) {
      collectTimeoutFields(p.initializer, depth + 1, out);
    }
  }
}

// firstObjectArg returns the first argument of a new/call expression when it is
// an object literal (the config literal), else null.
function firstObjectArg(node) {
  const args = node.arguments;
  if (!args || args.length === 0) return null;
  return ts.isObjectLiteralExpression(args[0]) ? args[0] : null;
}

// isFactoryCall reports whether a CallExpression is a known client factory
// (`axios.create`, `got.extend`, `createPool`, ...), keyed on the callee's last
// name so both `createPool(...)` and `mysql.createPool(...)` qualify.
function isFactoryCall(node) {
  const callee = node.expression;
  let name = '';
  if (ts.isIdentifier(callee)) name = callee.text;
  else if (ts.isPropertyAccessExpression(callee)) name = callee.name.text;
  return FACTORY_CALL_NAMES.has(name);
}

// constructedType resolves the type a construction produces to `<pkg>.<Type>`,
// reusing the same package-identity resolver the site packets use (so pnpm's
// `.pnpm/` path layer is already collapsed by packageFromDeclPath's lastIndexOf
// on `/node_modules/`). Falls back to the constructor/factory identifier text
// (`DataSource`, `Pool`, `axios.create`) when the type cannot be attributed to
// an external package.
function constructedType(node, checker, program) {
  const { clientType, resolved } = resolveClientType(node, checker, program);
  // Guard against a degenerate pnpm path with no inner node_modules leaking a
  // `.pnpm` pseudo-package into the type; normal pnpm layouts resolve cleanly.
  if (resolved && clientType && !clientType.startsWith('.pnpm')) {
    return clientType;
  }
  const callee = node.expression;
  return callee && typeof callee.getText === 'function' ? callee.getText() : '';
}

function cap(text) {
  if (text == null) return '';
  if (text.length > MAX_SNIPPET_BYTES) {
    return text.slice(0, MAX_SNIPPET_BYTES) + '\n// ... truncated';
  }
  return text;
}

// ---------------------------------------------------------------------------
// Package-identity inference.
//
// A resolved type's declaration usually lives in a `.d.ts` under
// `node_modules/<pkg>/`. We map that back to the npm package: `pg` for
// `node_modules/pg/lib/index.d.ts`, `@scope/name` for a scoped package. The
// package's own `package.json` gives a version, emitted as `client_version`.
// ---------------------------------------------------------------------------

// packageFromDeclPath extracts the npm package name (and its dir) from a
// declaration file path that lives under node_modules. Handles scoped packages
// (@scope/name). Returns null when the path is not under node_modules.
function packageFromDeclPath(fileName) {
  const norm = fileName.replace(/\\/g, '/');
  const marker = '/node_modules/';
  const idx = norm.lastIndexOf(marker);
  if (idx < 0) return null;
  const after = norm.slice(idx + marker.length);
  const parts = after.split('/');
  if (parts.length === 0 || !parts[0]) return null;
  let pkg;
  let dir;
  if (parts[0].startsWith('@')) {
    if (parts.length < 2) return null;
    pkg = parts[0] + '/' + parts[1];
    dir = norm.slice(0, idx + marker.length) + parts[0] + '/' + parts[1];
  } else {
    pkg = parts[0];
    dir = norm.slice(0, idx + marker.length) + parts[0];
  }
  return { pkg, dir };
}

// When a module has no nameable symbol, the checker falls back to spelling the
// type as the module's ABSOLUTE path (`"/abs/.../zod/v3/external"`, or the
// `typeof import("...")` form). That path is machine-local, and client_type is
// part of site_key (`file:line:client_type:method`) -- so letting it through
// makes the key depend on where the repo happens to sit on disk, and no
// published spec can ever match it. It is also a shape leak: reports carry
// client_type, and an absolute path exposes the caller's directory layout.
//
// Rewrite such a name to the package-relative module subpath, which names the
// same module identically on every host. Returns '' when no stable name can be
// derived, which the caller treats as unresolved: dropping the site is strictly
// better than emitting a machine-dependent key.
function stableTypeName(typeName, pkgInfo, declFileName) {
  if (!typeName) return '';
  const looksLikePath = typeName.includes('/') || typeName.includes('import(');
  if (!looksLikePath) return typeName;

  if (!pkgInfo || !pkgInfo.dir || !declFileName) return '';
  const dir = pkgInfo.dir.replace(/\\/g, '/').replace(/(?<!\/)\/+$/, '');
  const decl = declFileName.replace(/\\/g, '/');
  if (!decl.startsWith(dir + '/')) return '';

  // Package-relative, minus the declaration extension: `v3/external`.
  const sub = decl
    .slice(dir.length + 1)
    .replace(/\.d\.[cm]?ts$/, '')
    .replace(/\.[cm]?tsx?$/, '');
  return sub || '';
}

// Cache package.json version lookups by package dir.
const _versionCache = new Map();
function packageVersion(pkgDir) {
  if (_versionCache.has(pkgDir)) return _versionCache.get(pkgDir);
  let version = '';
  try {
    const raw = fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8');
    const meta = JSON.parse(raw);
    if (meta && typeof meta.version === 'string') version = meta.version;
  } catch (_e) {
    version = '';
  }
  _versionCache.set(pkgDir, version);
  return version;
}

// packageFromImport is the fallback when a resolved type's declaration is not
// under node_modules (path mappings, re-exports, a monorepo package). It walks
// the receiver's symbol back to the import that bound its root identifier and
// reads the bare module specifier. Weaker than the path signal but recovers a
// package name the compiler could not attribute to a node_modules directory.
function packageFromImport(symbol) {
  if (!symbol || !symbol.declarations) return null;
  for (const decl of symbol.declarations) {
    let node = decl;
    while (node && !ts.isSourceFile(node)) {
      if (
        ts.isImportSpecifier(node) ||
        ts.isImportClause(node) ||
        ts.isNamespaceImport(node)
      ) {
        // climb to the ImportDeclaration
        let imp = node;
        while (imp && !ts.isImportDeclaration(imp)) imp = imp.parent;
        if (imp && ts.isStringLiteral(imp.moduleSpecifier)) {
          const spec = imp.moduleSpecifier.text;
          if (spec && !spec.startsWith('.') && !spec.startsWith('/')) {
            // strip a subpath: `@scope/name/sub` -> `@scope/name`, `pkg/sub` -> `pkg`
            const parts = spec.split('/');
            const pkg = spec.startsWith('@')
              ? parts.slice(0, 2).join('/')
              : parts[0];
            return { pkg };
          }
        }
      }
      node = node.parent;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Receiver type resolution via the TypeChecker.
//
// Returns { clientType, resolved, version }:
//   resolved   -- true when the checker resolved a concrete named type from an
//                 identifiable EXTERNAL package (the high-confidence tier).
//   clientType -- "<pkg>.<TypeName>" when resolved, else "".
//   version    -- the package version, when readable from its package.json.
//
// A type that is `any`/`unknown`, unresolved, or declared only in a TypeScript
// default lib (Array, Map, Promise, string, ...) is NOT an external client:
// resolved=false, clientType="". The site may still be emitted at low
// confidence via the method-name allowlist, but it is never claimed as a
// resolved package client.
// ---------------------------------------------------------------------------

// Does this call return something awaitable?
//
// Resolving to an external package is not sufficient to make a call a CLIENT
// call. Validation, assertion, date and query-BUILDER packages all resolve
// cleanly while crossing no boundary at all: on infisical, 99.5% of resolved
// sites carried no I/O verb, and zod + knex builders were 86.5% of those.
//
// A package blocklist is the wrong axis -- knex is both a real query client
// (`knex.raw`) and a schema builder (`knex.ColumnBuilder.notNullable`), so the
// package name cannot separate them. What does separate them is structural: a
// call that crosses a process, network or disk boundary is awaitable in
// TypeScript, and a synchronous fluent builder is not. knex's query builders
// are thenable and stay in; its ColumnBuilder is not and drops out.
//
// Fails OPEN (returns true) on any uncertainty. Dropping a site is the
// destructive direction -- it silently costs recall -- so an unreadable or
// unresolved type keeps the site rather than guessing it away.
// Keyed by `<client_type>.<method>`, not by call site: whether a method returns
// something awaitable is a property of its signature, so the answer is the same
// at every call. Without this the checker materializes a type per call site --
// 82k of them on infisical, which exhausts the V8 heap outright. Overloads that
// differ in awaitability by argument type would be collapsed here; that is
// vanishingly rare and worth the ~70x reduction in checker work.
const _thenableCache = new Map();

function callReturnsThenable(call, checker, cacheKey) {
  if (cacheKey && _thenableCache.has(cacheKey)) return _thenableCache.get(cacheKey);
  const answer = _computeReturnsThenable(call, checker);
  if (cacheKey) _thenableCache.set(cacheKey, answer);
  return answer;
}

function _computeReturnsThenable(call, checker) {
  let t;
  try {
    t = checker.getTypeAtLocation(call);
  } catch (_e) {
    return true;
  }
  if (!t) return true;
  if (t.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return true;
  try {
    // A union counts as awaitable when any constituent is: `T | Promise<T>`
    // still performs I/O on the branch that matters.
    const parts = t.isUnion && t.isUnion() ? t.types : [t];
    return parts.some((p) => !!checker.getPropertyOfType(p, 'then'));
  } catch (_e) {
    return true;
  }
}

function resolveClientType(receiver, checker, program) {
  const unresolved = { clientType: '', resolved: false, version: '' };
  let type;
  try {
    type = checker.getTypeAtLocation(receiver);
  } catch (_e) {
    return unresolved;
  }
  if (!type) return unresolved;
  if (type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown)) return unresolved;

  let sym = type.getSymbol() || type.aliasSymbol;
  if (!sym) return unresolved;

  const decls = sym.getDeclarations && sym.getDeclarations();
  if (!decls || decls.length === 0) {
    // No declaration to attribute to a package: try the import specifier of the
    // receiver's own symbol as a last resort.
    return unresolved;
  }
  const declFile = decls[0].getSourceFile();
  // Built-in lib types (Array/Map/Promise/string/...) are not external clients.
  if (program.isSourceFileDefaultLibrary(declFile)) return unresolved;

  let typeName = sym.getName();
  if (!typeName || typeName === '__type' || typeName === '__object') {
    try {
      typeName = checker.typeToString(type);
    } catch (_e) {
      typeName = '';
    }
  }
  if (!typeName) return unresolved;

  // Primary: declaration under node_modules/<pkg>/.
  const pkgInfo = packageFromDeclPath(declFile.fileName);
  if (pkgInfo) {
    // Never let a machine-local path reach client_type; see stableTypeName.
    const stable = stableTypeName(typeName, pkgInfo, declFile.fileName);
    if (!stable) return unresolved;
    return {
      clientType: pkgInfo.pkg + '.' + stable,
      resolved: true,
      version: packageVersion(pkgInfo.dir),
    };
  }
  // Fallback: attribute via the receiver's binding import specifier. Only a
  // best-effort recovery; still counts as resolved when a bare package name is
  // found, since the type itself was concrete and named.
  let recvSym;
  try {
    recvSym = checker.getSymbolAtLocation(receiver);
  } catch (_e) {
    recvSym = undefined;
  }
  const imp = packageFromImport(recvSym) || packageFromImport(sym);
  if (imp) {
    // No package dir here to make a subpath from, so a path-shaped name has no
    // stable spelling available: fail closed rather than emit a local path.
    const stable = stableTypeName(typeName, null, null);
    if (!stable) return unresolved;
    return { clientType: imp.pkg + '.' + stable, resolved: true, version: '' };
  }
  return unresolved;
}

// ---------------------------------------------------------------------------
// Enclosing function + construction retrieval
// ---------------------------------------------------------------------------

// enclosingFunction returns {name, node} for the innermost function-like
// ancestor of `node`, or {name:"", node:null} at module scope.
function enclosingFunction(node) {
  let cur = node.parent;
  while (cur) {
    if (
      ts.isFunctionDeclaration(cur) ||
      ts.isMethodDeclaration(cur) ||
      ts.isConstructorDeclaration(cur) ||
      ts.isFunctionExpression(cur) ||
      ts.isArrowFunction(cur) ||
      ts.isGetAccessorDeclaration(cur) ||
      ts.isSetAccessorDeclaration(cur)
    ) {
      return { name: functionName(cur), node: cur };
    }
    cur = cur.parent;
  }
  return { name: '', node: null };
}

function functionName(fn) {
  if (ts.isConstructorDeclaration(fn)) return 'constructor';
  if (fn.name && typeof fn.name.getText === 'function') return fn.name.getText();
  // Anonymous function/arrow: name it after what it is assigned to, if anything.
  const p = fn.parent;
  if (p && ts.isVariableDeclaration(p) && p.name) return p.name.getText();
  if (p && ts.isPropertyAssignment(p) && p.name) return p.name.getText();
  if (p && ts.isPropertyDeclaration(p) && p.name) return p.name.getText();
  return '';
}

// constructionFor returns the in-scope construction of a simple identifier
// receiver ({file,line,symbol,source}), so a construction-time timeout/config
// is retrievable. Best-effort: only a variable/parameter/property declaration
// with an initializer, in a scanned source file, is emitted. Property-access
// receivers (`this.http`) are not traced in v1.
function constructionFor(receiver, checker, root, relPathOf, isScanned) {
  if (!ts.isIdentifier(receiver)) return [];
  let sym;
  try {
    sym = checker.getSymbolAtLocation(receiver);
  } catch (_e) {
    return [];
  }
  if (!sym) return [];
  const decl = sym.valueDeclaration || (sym.declarations && sym.declarations[0]);
  if (!decl) return [];
  const declFile = decl.getSourceFile();
  if (!isScanned(declFile)) return [];
  const isCtorShape =
    (ts.isVariableDeclaration(decl) && decl.initializer) ||
    (ts.isPropertyDeclaration(decl) && decl.initializer) ||
    ts.isParameter(decl);
  if (!isCtorShape) return [];
  const { line } = declFile.getLineAndCharacterOfPosition(decl.getStart());
  return [
    {
      file: relPathOf(declFile.fileName),
      line: line + 1,
      symbol: ts.isIdentifier(receiver) ? receiver.getText() : '',
      source: cap(decl.getText()),
    },
  ].slice(0, MAX_CTORS_EMITTED);
}

// ---------------------------------------------------------------------------
// G4 emission-point inventory (po-av01j.5).
//
// Log statements, span/trace instrumentation, and error-handling sites ride
// the SAME packet stream, stamped site_kind: "emission_point". VOLUME CONTROL
// is the load-bearing constraint: emission packets are AGGREGATES -- one per
// (enclosing function, framework identity, category), with the category and
// call count riding const_args (emission_category / emission_count, how:
// "aggregate") -- never one packet per log line.
//
// Classification is type-driven like G1: a call is an emission only when the
// checker resolves its receiver into a known telemetry package (winston,
// pino, @opentelemetry, @sentry), plus the two mechanical identities `console`
// (receiver text) and `catch_clause` (the swallow fact below). The framework
// list is the candidate extractor: it decides what gets inventoried, never
// what a match means -- that is the spec layer's job (EmissionSpec).
//
// Recognized emission calls are routed OUT of the G1 site list: a logger.info
// must not double-count as a client call site.
// ---------------------------------------------------------------------------

const SITE_KIND_EMISSION = 'emission_point';

const EMISSION_LOG_METHODS = new Set([
  'debug', 'info', 'warn', 'error', 'verbose', 'silly', 'fatal', 'trace', 'log',
]);
const CONSOLE_LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace']);
const EMISSION_TRACE_METHODS = new Set(['startSpan', 'startActiveSpan']);
const EMISSION_CAPTURE_METHODS = new Set([
  'captureException', 'captureMessage', 'captureEvent',
]);

// emissionIdentity classifies a call as an emission point, returning
// {framework, category} or null. `clientType`/`resolved` come from the same
// resolveClientType pass the G1 heuristic uses.
function emissionIdentity(receiver, method, clientType, resolved, checker) {
  const recvText = typeof receiver.getText === 'function' ? receiver.getText() : '';
  if (recvText === 'console' && CONSOLE_LOG_METHODS.has(method)) {
    return { framework: 'console', category: 'log' };
  }
  if (resolved && clientType) {
    if (
      (clientType.startsWith('winston.') || clientType === 'pino' || clientType.startsWith('pino.')) &&
      EMISSION_LOG_METHODS.has(method)
    ) {
      return { framework: clientType, category: 'log' };
    }
    if (clientType.startsWith('@opentelemetry/') && EMISSION_TRACE_METHODS.has(method)) {
      return { framework: clientType, category: 'trace' };
    }
    if (clientType.startsWith('@sentry/') && EMISSION_CAPTURE_METHODS.has(method)) {
      return { framework: clientType, category: 'error_capture' };
    }
    return null;
  }
  // Namespace imports (import * as Sentry from '@sentry/node'): the receiver
  // is a namespace whose TYPE does not resolve; attribute via the import.
  if (EMISSION_CAPTURE_METHODS.has(method)) {
    let sym;
    try {
      sym = checker.getSymbolAtLocation(receiver);
    } catch (_e) {
      sym = undefined;
    }
    const imp = packageFromImport(sym);
    if (imp && imp.pkg.startsWith('@sentry/')) {
      return { framework: imp.pkg, category: 'error_capture' };
    }
  }
  return null;
}

// enclosingCatchClause returns the catch clause LEXICALLY containing `node`,
// or null. Purely structural containment (no function-boundary stop): a log
// written inside a catch -- directly or via a callback -- is on the error
// path, and the same containment marks the catch as instrumented.
function enclosingCatchClause(node) {
  let cur = node.parent;
  while (cur && !ts.isSourceFile(cur)) {
    if (ts.isCatchClause(cur)) return cur;
    cur = cur.parent;
  }
  return null;
}

// containsThrow reports whether a catch clause re-throws: a propagating
// handler is NOT a swallow.
function containsThrow(node) {
  let found = false;
  const scan = (n) => {
    if (ts.isThrowStatement(n)) found = true;
    else ts.forEachChild(n, scan);
  };
  scan(node);
  return found;
}

// emissionRecord builds one aggregate packet. Function bodies are omitted on
// purpose (volume); the category and count ride const_args.
function emissionRecord(agg, relPath, snapshot) {
  return {
    packet_schema: PACKET_SCHEMA,
    site_key: '', // stamped in emit(), like every packet
    site_kind: SITE_KIND_EMISSION,
    snapshot_id: snapshot,
    file_path: relPath,
    line_number: agg.line,
    symbol: agg.symbol,
    func: agg.method,
    receiver: '',
    client_type: agg.framework,
    snippet: agg.snippet,
    enclosing_function_body: '',
    callers: [],
    callees: [],
    client_construction: [],
    const_args: [
      { index: 0, name: 'emission_category', value: agg.category, how: 'aggregate' },
      { index: 0, name: 'emission_count', value: String(agg.count), how: 'aggregate' },
    ],
    macro_expansion: false,
    provenance: {
      client_type_resolved:
        agg.framework !== 'catch_clause' && agg.framework !== 'console',
      confidence_tier: 'high',
      callers_total: 0,
      callers_included: 0,
      callees_total: 0,
      callees_included: 0,
    },
    lang: 'typescript',
  };
}

// ---------------------------------------------------------------------------
// Program construction + file discovery
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', 'coverage',
]);

// buildProgram creates a type-checked Program over `root`. If a tsconfig.json
// is present it is honored (files + compilerOptions); otherwise every non-.d.ts
// source under root (skipping vendored/build dirs) is a root file with
// conservative default options.
//
// JAVASCRIPT IS INCLUDED (po-av01j.137). It used to be excluded at two layers
// at once -- discoverSources took only *.ts/*.tsx and allowJs was explicitly
// false -- so identical code yielded 30 sites named .ts and 0 named .js, with
// no abstention and exit 0. Express/Node backends without TypeScript were
// simply invisible.
//
// Measured before enabling rather than assumed: on the fixture renamed to .js,
// 30 sites with 27 of 30 client types RESOLVED (pg.Pool, express.Express,
// bullmq.Queue, ioredis.Redis). Resolution survives because the client type
// comes from the DEPENDENCY's type declarations, not from annotations in the
// file, so untyped JS does not mean unresolved receivers.
//
// A tsconfig's own file list is UNIONED with discovered JS rather than
// replaced: a project may legitimately exclude .js from its build while still
// shipping .js that makes I/O calls, and this is a reliability scan, not a
// compile.
function buildProgram(root) {
  const tsconfigPath = path.join(root, 'tsconfig.json');
  if (fs.existsSync(tsconfigPath)) {
    const configFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
    const parsed = ts.parseJsonConfigFileContent(
      configFile.config || {},
      ts.sys,
      root,
    );
    const options = Object.assign({}, parsed.options, {
      noEmit: true,
      allowJs: true,
    });
    const known = new Set(parsed.fileNames);
    for (const f of discoverSources(root)) {
      if (!known.has(f)) known.add(f);
    }
    return ts.createProgram({ rootNames: Array.from(known), options });
  }
  const options = {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.NodeJs,
    allowJs: true,
    skipLibCheck: true,
    noEmit: true,
    strict: false,
  };
  const rootNames = discoverSources(root);
  return ts.createProgram({ rootNames, options });
}

// discoverSources walks root for scannable sources (never *.d.ts), skipping
// vendored and build dirs, returning absolute paths.
function discoverSources(root) {
  const out = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_e) {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) stack.push(full);
      } else if (e.isFile()) {
        if (e.name.endsWith('.d.ts')) continue;
        // JavaScript included (po-av01j.137): .js is the majority of the Node
        // ecosystem, and excluding it made those repos silently unscanned.
        if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(e.name)) out.push(full);
      }
    }
  }
  return out;
}

function siteKey(rec) {
  return `${rec.file_path}:${rec.line_number}:${rec.client_type}:${rec.func}`;
}

// ---------------------------------------------------------------------------
// Retrieval
// ---------------------------------------------------------------------------

function runRetrieve(root, snapshot, filesArg) {
  const program = buildProgram(root);
  const checker = program.getTypeChecker();
  const rootReal = fs.realpathSync(root);

  const relPathOf = (abs) => {
    let rel = path.relative(rootReal, fs.existsSync(abs) ? realOr(abs) : abs);
    return rel.split(path.sep).join('/');
  };

  // A source file we retrieve sites from: under root, not a declaration file,
  // not a default lib, not vendored.
  const isScanned = (sf) => {
    if (sf.isDeclarationFile) return false;
    if (program.isSourceFileDefaultLibrary(sf)) return false;
    const fn = sf.fileName.replace(/\\/g, '/');
    if (fn.includes('/node_modules/')) return false;
    const real = realOr(sf.fileName);
    return real.startsWith(rootReal + path.sep) || real === rootReal;
  };

  // Incremental filter: restrict emitted files to this exact-path set.
  let wanted = null;
  if (filesArg) {
    wanted = new Set(
      filesArg
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
        .map((p) => p.split(path.sep).join('/')),
    );
  }

  const records = [];
  for (const sf of program.getSourceFiles()) {
    if (!isScanned(sf)) continue;
    const relPath = relPathOf(sf.fileName);
    if (wanted && !wanted.has(relPath)) continue;

    // Per-file G4 emission state: aggregates keyed (function, framework,
    // category), plus the catch clauses seen and which of them emit.
    const aggs = new Map();
    const catchClauses = [];
    const emittingCatches = new Set();
    const aggregate = (node, framework, category, method) => {
      const enc = enclosingFunction(node);
      const key = `${enc.name}\0${framework}\0${category}`;
      let agg = aggs.get(key);
      if (!agg) {
        const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
        agg = {
          line: line + 1,
          method,
          snippet: method === 'catch' ? '' : cap(node.getText()),
          framework,
          category,
          symbol: enc.name,
          count: 0,
        };
        aggs.set(key, agg);
      }
      agg.count++;
    };

    const visit = (node) => {
      if (ts.isCatchClause(node)) catchClauses.push(node);
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)
      ) {
        // G4 (po-av01j.5): emission calls are aggregated per (function,
        // framework, category) and routed OUT of the G1 site list; anything
        // else falls through to the ordinary call-site retrieval.
        const prop = node.expression;
        const receiver = prop.expression;
        const method = prop.name.getText();
        const { clientType, resolved } = resolveClientType(receiver, checker, program);
        const em = emissionIdentity(receiver, method, clientType, resolved, checker);
        if (em) {
          let category = em.category;
          const cc = enclosingCatchClause(node);
          if (cc) {
            emittingCatches.add(cc);
            // A log emission ON an error path is the capture fact.
            if (category === 'log') category = 'error_capture';
          }
          aggregate(node, em.framework, category, method);
        } else {
          const rec = siteFromCall(node, sf, relPath, snapshot, checker, program, rootReal, relPathOf, isScanned);
          if (rec) records.push(rec);
        }
      } else if (ts.isNewExpression(node)) {
        // G3: some constructions ARE handler registrations (bullmq Worker).
        const rec = jobSiteFromNew(node, sf, relPath, snapshot, checker, program);
        if (rec) records.push(rec);
      } else if (ts.isMethodDeclaration(node)) {
        // G2: NestJS route decorators register the decorated class method.
        records.push(...nestRouteRecords(node, sf, relPath, snapshot, checker));
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);

    // Swallowed error paths: a catch that neither emits anything recognized
    // nor re-throws, aggregated per enclosing function.
    for (const cc of catchClauses) {
      if (emittingCatches.has(cc) || containsThrow(cc)) continue;
      aggregate(cc, 'catch_clause', 'error_capture', 'catch');
    }
    for (const agg of [...aggs.values()].sort((a, b) => a.line - b.line)) {
      records.push(emissionRecord(agg, relPath, snapshot));
    }
  }

  const repoConfig = collectRepoConfig(program, checker, snapshot, isScanned);
  return { records, repoConfig };
}

// collectRepoConfig walks EVERY scanned source file (repo-scoped, so never
// restricted by the incremental --files filter) for client CONSTRUCTIONS whose
// config literal sets a timeout-ish field, deduped to one `{type, fields}` entry
// per distinct constructed type (fields unioned across constructions of that
// type). Returns the repo_config packet the config lane consumes. A construction
// with no timeout-ish field is dropped; a run with none yields an empty array.
function collectRepoConfig(program, checker, snapshot, isScanned) {
  const byType = new Map(); // type -> Set(field names)
  for (const sf of program.getSourceFiles()) {
    if (!isScanned(sf)) continue;
    const visit = (node) => {
      let objArg = null;
      if (ts.isNewExpression(node)) {
        objArg = firstObjectArg(node);
      } else if (ts.isCallExpression(node) && isFactoryCall(node)) {
        objArg = firstObjectArg(node);
      }
      if (objArg) {
        const fields = new Set();
        collectTimeoutFields(objArg, 0, fields);
        if (fields.size > 0) {
          const type = constructedType(node, checker, program);
          if (type) {
            const set = byType.get(type) || new Set();
            for (const f of fields) set.add(f);
            byType.set(type, set);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
  }
  const constructions = [...byType.entries()]
    .map(([type, fields]) => ({ type, fields: [...fields] }))
    .sort((a, b) => a.type.localeCompare(b.type));
  return {
    packet_schema: PACKET_SCHEMA,
    kind: 'repo_config',
    snapshot_id: snapshot,
    constructions,
  };
}

function realOr(p) {
  try {
    return fs.realpathSync(p);
  } catch (_e) {
    return p;
  }
}

// ---------------------------------------------------------------------------
// Constant-valued arguments (schema v2).
//
// Evidence, never a verdict: the emitter reports that an argument's value is
// knowable without running the program, and how it was determined. What the
// value MEANS is spec-layer knowledge. Only literal tokens and one-hop named
// constants (a `const` with a literal initializer, an enum member the checker
// folds) are resolved — no deep constant propagation.
// ---------------------------------------------------------------------------

// literalText returns the source text of a literal expression, or null when
// the expression is not a literal. Template literals WITH substitutions are
// not literals; `-1` (a prefix minus on a numeric literal) is.
function literalText(node) {
  if (
    ts.isStringLiteralLike(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword
  ) {
    return node.getText();
  }
  if (
    ts.isPrefixUnaryExpression(node) &&
    node.operator === ts.SyntaxKind.MinusToken &&
    ts.isNumericLiteral(node.operand)
  ) {
    return node.getText();
  }
  return null;
}

// namedConstantText resolves a reference one hop to its constant value:
// an enum member access via the checker's own constant folding, or an
// identifier declared `const` with a literal initializer. Returns the value's
// source-level rendering, or null when the reference is not a constant.
function namedConstantText(node, checker) {
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    let cv;
    try {
      cv = checker.getConstantValue(node);
    } catch (_e) {
      cv = undefined;
    }
    if (cv === undefined) return null;
    return typeof cv === 'string' ? JSON.stringify(cv) : String(cv);
  }
  if (!ts.isIdentifier(node)) return null;
  let sym;
  try {
    sym = checker.getSymbolAtLocation(node);
  } catch (_e) {
    return null;
  }
  if (!sym) return null;
  const decl = sym.valueDeclaration;
  if (!decl || !ts.isVariableDeclaration(decl) || !decl.initializer) return null;
  if (!(ts.getCombinedNodeFlags(decl) & ts.NodeFlags.Const)) return null;
  return literalText(decl.initializer);
}

// constArgsOf reports the constant-valued arguments of a call, as
// {index, name, value, how}. `index` is the zero-based position as written;
// `name` is always "" (TypeScript has no keyword arguments); `how` is
// "literal" or "named_constant".
function constArgsOf(node, checker) {
  const out = [];
  const args = node.arguments || [];
  for (let i = 0; i < args.length; i++) {
    const lit = literalText(args[i]);
    if (lit !== null) {
      out.push({ index: i, name: '', value: lit, how: 'literal' });
      continue;
    }
    const named = namedConstantText(args[i], checker);
    if (named !== null) {
      out.push({ index: i, name: '', value: named, how: 'named_constant' });
    }
  }
  return out;
}

function siteFromCall(node, sf, relPath, snapshot, checker, program, rootReal, relPathOf, isScanned) {
  const prop = node.expression; // PropertyAccessExpression
  const receiver = prop.expression;
  const method = prop.name.getText();

  const { clientType, resolved, version } = resolveClientType(
    receiver,
    checker,
    program,
  );

  // G2 server-entry registrations are checked FIRST: `app.get('/x', h)` on a
  // resolved express receiver would otherwise emit as a G1 client call. A
  // matched registration emits one server_entry record and never a G1 site.
  if (resolved && isServerFrameworkType(clientType)) {
    const lower = method.toLowerCase();
    if (SERVER_ROUTE_METHODS.has(lower) || SERVER_MIDDLEWARE_METHODS.has(lower)) {
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
      const enc = enclosingFunction(node);
      return {
        packet_schema: PACKET_SCHEMA,
        site_key: '', // stamped in emit()
        snapshot_id: snapshot,
        file_path: relPath,
        line_number: line + 1,
        symbol: enc.name,
        func: method,
        receiver: receiver.getText(),
        client_type: clientType,
        client_version: version,
        snippet: cap(node.getText()),
        enclosing_function_body: enc.node ? cap(enc.node.getText()) : '',
        callers: [],
        callees: [],
        // The route path (a literal in the mainstream frameworks) rides the
        // existing const_args machinery.
        const_args: constArgsOf(node, checker),
        macro_expansion: false,
        client_construction: [],
        site_kind: SITE_KIND_SERVER_ENTRY,
        provenance: {
          client_type_resolved: true,
          confidence_tier: 'high',
          callers_total: 0,
          callers_included: 0,
          callees_total: 0,
          callees_included: 0,
        },
        lang: 'typescript',
      };
    }
  }

  // Emission decision (documented in the header):
  //   * a resolved external client emits regardless of method name, unless the
  //     method is obvious non-I/O noise (.then/.map/.on/...);
  //   * otherwise, a STRONG I/O verb emits at low confidence;
  //   * a WEAK verb on an unresolved receiver, and everything else, is dropped.
  let emit = false;
  let tier = 'low';
  if (resolved && !NOISE_METHODS.has(method)) {
    // A named I/O verb is evidence enough on its own; otherwise the call must
    // at least be awaitable to count as crossing a boundary. See
    // callReturnsThenable for why the package name cannot make this call.
    //
    // G3 background-job REGISTRATIONS are exempt: `cron.schedule(...)` and
    // friends are registrations, not I/O, and are usually synchronous. That
    // altitude has its own type-driven selection table (isJobRegistration), so
    // a G1 awaitability heuristic must not silently veto it.
    const namedIO = STRONG_IO_METHODS.has(method) || WEAK_IO_METHODS.has(method);
    if (
      namedIO ||
      isJobRegistration(clientType, method) ||
      callReturnsThenable(node, checker, clientType + '.' + method)
    ) {
      emit = true;
      tier = 'high';
    }
  } else if (STRONG_IO_METHODS.has(method)) {
    emit = true;
    tier = resolved ? 'high' : 'low';
  }
  if (!emit) return null;

  const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
  const enc = enclosingFunction(node);

  const rec = {
    packet_schema: PACKET_SCHEMA,
    site_key: '', // stamped in emit()
    snapshot_id: snapshot,
    file_path: relPath,
    line_number: line + 1,
    symbol: enc.name,
    func: method,
    receiver: receiver.getText(),
    client_type: clientType,
    client_version: version,
    snippet: cap(node.getText()),
    enclosing_function_body: enc.node ? cap(enc.node.getText()) : '',
    callers: [], // empty (no cross-module call graph yet)
    callees: [], // empty
    // Schema v2: constant-valued arguments as evidence, and the macro flag
    // (TypeScript has no macros; C/C++ sets it mechanically).
    const_args: constArgsOf(node, checker),
    macro_expansion: false,
    // G3: a resolved scheduler/queue registration is a background-job site;
    // everything else stays the classic call site.
    site_kind: resolved && isJobRegistration(clientType, method) ? 'background_job' : '',
    client_construction: constructionFor(
      receiver,
      checker,
      rootReal,
      relPathOf,
      isScanned,
    ),
    provenance: {
      client_type_resolved: resolved,
      confidence_tier: tier,
      callers_total: 0,
      callers_included: 0,
      callees_total: 0,
      callees_included: 0,
    },
    lang: 'typescript',
  };
  return rec;
}

// jobSiteFromNew emits the background-job site for a construction that IS a
// handler registration (`new Worker(name, processor)` in bullmq). The
// constructed class must RESOLVE to a known framework package; any other
// new-expression returns null and is not a site. `func` is "constructor",
// matching how enclosingFunction names constructor bodies.
function jobSiteFromNew(node, sf, relPath, snapshot, checker, program) {
  const callee = node.expression;
  if (!callee) return null;
  const { clientType, resolved, version } = resolveClientType(
    callee,
    checker,
    program,
  );
  if (!resolved || !isJobCtor(clientType)) return null;

  const { line } = sf.getLineAndCharacterOfPosition(node.getStart());
  const enc = enclosingFunction(node);
  return {
    packet_schema: PACKET_SCHEMA,
    site_key: '', // stamped in emit()
    snapshot_id: snapshot,
    file_path: relPath,
    line_number: line + 1,
    symbol: enc.name,
    func: 'constructor',
    receiver: callee.getText(),
    client_type: clientType,
    client_version: version,
    snippet: cap(node.getText()),
    enclosing_function_body: enc.node ? cap(enc.node.getText()) : '',
    callers: [],
    callees: [],
    const_args: constArgsOf(node, checker),
    macro_expansion: false,
    site_kind: 'background_job',
    client_construction: [],
    provenance: {
      client_type_resolved: true,
      confidence_tier: 'high',
      callers_total: 0,
      callers_included: 0,
      callees_total: 0,
      callees_included: 0,
    },
    lang: 'typescript',
  };
}

// nestRouteRecords emits one server-entry record per NestJS route decorator
// (`@Get('/x')`) on a class method. Conservative and typed: the decorator's
// identifier must RESOLVE to @nestjs/common through its import binding; a
// same-named local decorator abstains. The record's symbol is the decorated
// handler method; the route path rides const_args like every other literal.
function nestRouteRecords(node, sf, relPath, snapshot, checker) {
  const out = [];
  const decorators =
    typeof ts.canHaveDecorators === 'function' && ts.canHaveDecorators(node)
      ? ts.getDecorators(node)
      : node.decorators;
  if (!decorators) return out;
  for (const dec of decorators) {
    const expr = dec.expression;
    if (!ts.isCallExpression(expr) || !ts.isIdentifier(expr.expression)) {
      continue;
    }
    const name = expr.expression.text;
    if (!NEST_ROUTE_DECORATORS.has(name)) continue;
    let sym;
    try {
      sym = checker.getSymbolAtLocation(expr.expression);
    } catch (_e) {
      sym = undefined;
    }
    const imp = packageFromImport(sym);
    if (!imp || imp.pkg !== '@nestjs/common') continue;
    const { line } = sf.getLineAndCharacterOfPosition(dec.getStart());
    out.push({
      packet_schema: PACKET_SCHEMA,
      site_key: '', // stamped in emit()
      snapshot_id: snapshot,
      file_path: relPath,
      line_number: line + 1,
      symbol:
        node.name && typeof node.name.getText === 'function'
          ? node.name.getText()
          : '',
      func: name,
      receiver: '',
      client_type: '@nestjs/common.' + name,
      client_version: '',
      snippet: cap(dec.getText()),
      enclosing_function_body: cap(node.getText()),
      callers: [],
      callees: [],
      const_args: constArgsOf(expr, checker),
      macro_expansion: false,
      client_construction: [],
      site_kind: SITE_KIND_SERVER_ENTRY,
      provenance: {
        client_type_resolved: true,
        confidence_tier: 'high',
        callers_total: 0,
        callers_included: 0,
        callees_total: 0,
        callees_included: 0,
      },
      lang: 'typescript',
    });
  }
  return out;

}

// Write a string to fd 1 (stdout) SYNCHRONOUSLY and completely. process.exit()
// discards whatever process.stdout.write() has buffered, and on a PIPE (how
// rvl captures the helper via std::process .output()) large writes buffer
// heavily -- so an async write + process.exit truncates the tail
// nondeterministically (po-3t3oj.37: identical scans returned 14k/5k/2k/463
// sites). A blocking fd write with an EAGAIN retry loop cannot be truncated:
// it does not return until the pipe has taken every byte.
function writeStdoutSync(str) {
  const buf = Buffer.from(str, 'utf8');
  let off = 0;
  while (off < buf.length) {
    try {
      off += fs.writeSync(1, buf, off, buf.length - off);
    } catch (e) {
      if (e.code === 'EAGAIN') continue; // pipe momentarily full; retry
      throw e;
    }
  }
}

function emit(records, out) {
  if (out) {
    // File-stream sink (in-process test harness): its own drain is awaited.
    for (const rec of records) {
      rec.packet_schema = PACKET_SCHEMA;
      rec.site_key = siteKey(rec);
      out.write(JSON.stringify(rec));
      out.write('\n');
    }
    return;
  }
  const lines = [];
  for (const rec of records) {
    rec.packet_schema = PACKET_SCHEMA;
    rec.site_key = siteKey(rec);
    lines.push(JSON.stringify(rec));
  }
  if (lines.length) writeStdoutSync(lines.join('\n') + '\n');
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = {
    packetSchema: false,
    retrieve: false,
    root: '.',
    name: null,
    files: '',
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--packet-schema':
        args.packetSchema = true;
        break;
      case '--retrieve':
        args.retrieve = true;
        break;
      case '--root':
        args.root = argv[++i];
        break;
      case '--name':
        args.name = argv[++i];
        break;
      case '--files':
        args.files = argv[++i] || '';
        break;
      default:
        // ignore unknown flags for forward-compat with the sibling helpers
        break;
    }
  }
  return args;
}

// Workspaces that DECLARE dependencies but have none installed (po-av01j.132).
//
// Per workspace, not per repo: monorepos install per package, and the gate-set
// contract already records that infisical has six workspaces where its layout
// suggests three. One uninstalled workspace silently removes its whole subtree
// from resolution.
//
// A package.json with no dependencies and no devDependencies needs no install,
// so it is not reported. Skips node_modules itself and the usual vendored trees.
// True when `dir` or any ancestor up to (and including) `root` has an
// installed node_modules — the resolvability the TypeScript module resolver
// actually uses, which is also how hoisted monorepos are laid out.
function hasNodeModulesUpTo(dir, root) {
  let cur = path.resolve(dir);
  const stop = path.resolve(root);
  for (;;) {
    if (fs.existsSync(path.join(cur, 'node_modules'))) return true;
    if (cur === stop) return false;
    const parent = path.dirname(cur);
    if (parent === cur) return false;
    cur = parent;
  }
}

function missingDependencyTrees(root) {
  const skip = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'target', 'vendor']);
  const missing = [];
  const walk = (dir, depth) => {
    if (depth > 4) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const hasPkg = entries.some((e) => e.isFile() && e.name === 'package.json');
    if (hasPkg) {
      let declares = false;
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
        declares =
          Object.keys(pkg.dependencies || {}).length > 0 ||
          Object.keys(pkg.devDependencies || {}).length > 0;
      } catch {
        // An unreadable package.json is not evidence of anything; leave it.
        declares = false;
      }
      // Hoisting-aware: yarn/pnpm workspaces install a workspace's deps into
      // an ANCESTOR's node_modules (usually the repo root), and a local dir
      // exists only for version conflicts. Demanding node_modules per
      // declaring workspace refused medusa (98 hoisted workspaces) and Ghost
      // (.nxcache artifacts) immediately after both had installed cleanly.
      // Unresolvable means: neither this dir nor any ancestor up to the
      // scanned root has node_modules.
      if (declares && !hasNodeModulesUpTo(dir, root)) {
        missing.push(path.relative(root, dir) || '.');
      }
    }
    for (const e of entries) {
      if (e.isDirectory() && !skip.has(e.name)) walk(path.join(dir, e.name), depth + 1);
    }
  };
  walk(root, 0);
  return missing;
}

function main(argv) {
  const args = parseArgs(argv || process.argv.slice(2));

  // Let a consumer negotiate the contract before paying for a load.
  if (args.packetSchema) {
    writeStdoutSync(String(PACKET_SCHEMA) + '\n');
    return 0;
  }

  if (args.retrieve) {
    const root = path.resolve(args.root);
    const snapshot = args.name || path.basename(root) || root;

    // ABSTAIN ON AN UNINSTALLED DEPENDENCY TREE (po-av01j.132).
    //
    // tsindex resolves client types through the TypeScript compiler, which
    // reads node_modules. Without it, resolution fails SILENTLY rather than
    // erroring: the interesting receivers (axios, octokit, a query builder)
    // come back unresolved and are skipped, so the run reports a small number
    // of sites and exit 0 -- which reads as "scanned, and this repo is mostly
    // clean".
    //
    // Measured, identical source and tsconfig, only node_modules differing:
    // 0 sites without, 1 site (axios.AxiosStatic) with. On a real repo the
    // same effect returned 3 sites from 90 .ts files, and the gate-set
    // contract already records 1,911 -> 83,927 sites at one fixed commit on a
    // larger repo. A PARTIAL result that looks complete is worse than none.
    //
    // Same charter as rustindex on an unloadable cargo workspace and goindex
    // with no module: abstain rather than guess. Exit 3 is the helper ABSTAIN
    // code rvl reads (po-av01j.102), so it surfaces as a COVERAGE line.
    const missing = missingDependencyTrees(root);
    if (missing.length > 0) {
      process.stderr.write(
        `tsindex: ${missing.length} workspace(s) declare dependencies but have no ` +
          `installed node_modules (${missing.slice(0, 3).join(', ')}` +
          `${missing.length > 3 ? ', ...' : ''}). TypeScript type resolution reads ` +
          `node_modules, and without it client receivers resolve to nothing and are ` +
          `silently skipped -- so tsindex abstains rather than reporting a partial ` +
          `scan as a complete one. Install dependencies (npm ci / pnpm install ` +
          `--frozen-lockfile / yarn install --immutable) and re-run.\n`,
      );
      return 3;
    }

    const { records, repoConfig } = runRetrieve(root, snapshot, args.files);
    emit(records);
    // One repo-scoped record per run, after the site packets. rvl_core's
    // parse_stream keys on kind:"repo_config" to route it away from sites.
    writeStdoutSync(JSON.stringify(repoConfig) + '\n');
    process.stderr.write(
      `${snapshot}: ${records.length} retrieved sites, ` +
        `${repoConfig.constructions.length} config constructions\n`,
    );
    return 0;
  }

  process.stderr.write(
    'usage: tsindex --packet-schema | --retrieve --root <dir> [--name <snap>] [--files a.ts,b.ts]\n',
  );
  return 2;
}

// Exports for the in-process test harness.
module.exports = {
  PACKET_SCHEMA,
  parseArgs,
  runRetrieve,
  siteKey,
  main,
  STRONG_IO_METHODS,
  WEAK_IO_METHODS,
  NOISE_METHODS,
  isTimeoutish,
  collectTimeoutFields,
  stableTypeName,
};

if (require.main === module) {
  process.exit(main());
}
