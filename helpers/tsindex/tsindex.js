#!/usr/bin/env node
// tsindex -- TypeScript retriever helper for rvlscan.
//
// Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
// This is the TypeScript sibling of helpers/goindex and helpers/pyindex. It
// emits the SAME versioned packet stream rvlscan consumes, for TypeScript
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
// helper is a `.js` run under `node`, discovered by rvlscan the same way
// pyindex.py is discovered and run under `python3`). We deliberately use the
// stable `typescript` compiler API rather than the pre-release native port.
//
// callers/callees are empty in v1: this helper reports per-site evidence and
// in-scope construction, not a cross-module call graph. The keys are emitted
// (as empty arrays) so the packet shape is stable and a later version can fill
// them without a schema bump.

'use strict';

const ts = require('typescript');
const fs = require('fs');
const path = require('path');

// PACKET_SCHEMA is the version of the emitted packet contract. rvlscan absorbs
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
    return {
      clientType: pkgInfo.pkg + '.' + typeName,
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
    return { clientType: imp.pkg + '.' + typeName, resolved: true, version: '' };
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
// Program construction + file discovery
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'dist', 'build', 'out', 'coverage',
]);

// buildProgram creates a type-checked Program over `root`. If a tsconfig.json
// is present it is honored (files + compilerOptions); otherwise every non-.d.ts
// *.ts/*.tsx under root (skipping vendored/build dirs) is a root file with
// conservative default options.
function buildProgram(root) {
  const tsconfigPath = path.join(root, 'tsconfig.json');
  if (fs.existsSync(tsconfigPath)) {
    const configFile = ts.readConfigFile(tsconfigPath, ts.sys.readFile);
    const parsed = ts.parseJsonConfigFileContent(
      configFile.config || {},
      ts.sys,
      root,
    );
    const options = Object.assign({}, parsed.options, { noEmit: true });
    return ts.createProgram({ rootNames: parsed.fileNames, options });
  }
  const options = {
    target: ts.ScriptTarget.ES2020,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.NodeJs,
    allowJs: false,
    skipLibCheck: true,
    noEmit: true,
    strict: false,
  };
  const rootNames = discoverSources(root);
  return ts.createProgram({ rootNames, options });
}

// discoverSources walks root for *.ts/*.tsx (never *.d.ts), skipping vendored
// and build dirs, returning absolute paths. Used only when there is no tsconfig.
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
        if (e.name.endsWith('.ts') || e.name.endsWith('.tsx')) out.push(full);
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

    const visit = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression)
      ) {
        const rec = siteFromCall(node, sf, relPath, snapshot, checker, program, rootReal, relPathOf, isScanned);
        if (rec) records.push(rec);
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
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

  // Emission decision (documented in the header):
  //   * a resolved external client emits regardless of method name, unless the
  //     method is obvious non-I/O noise (.then/.map/.on/...);
  //   * otherwise, a STRONG I/O verb emits at low confidence;
  //   * a WEAK verb on an unresolved receiver, and everything else, is dropped.
  let emit = false;
  let tier = 'low';
  if (resolved && !NOISE_METHODS.has(method)) {
    emit = true;
    tier = 'high';
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

// Write a string to fd 1 (stdout) SYNCHRONOUSLY and completely. process.exit()
// discards whatever process.stdout.write() has buffered, and on a PIPE (how
// rvlscan captures the helper via std::process .output()) large writes buffer
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
};

if (require.main === module) {
  process.exit(main());
}
