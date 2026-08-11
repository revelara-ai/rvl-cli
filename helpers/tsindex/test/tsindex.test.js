// Tests for tsindex, mirroring goindex/packet_test.go and pyindex's
// test_pyindex.py. A packet stream must be self-describing and uniquely keyed:
// those two properties are what every downstream consumer (index, eval join,
// factory) depends on, and neither is recoverable after the fact.
//
// Run from the tsindex dir:  node --test
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');

const HERE = __dirname;
const TSINDEX = path.join(HERE, '..', 'tsindex.js');
const FIXTURE_ROOT = path.join(HERE, '..', 'testdata', 'fixture');

function run(...args) {
  return execFileSync('node', [TSINDEX, ...args], { encoding: 'utf8' });
}

function retrieveAll(...extra) {
  const out = run('--retrieve', '--root', FIXTURE_ROOT, ...extra);
  return out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l)); // throws if a line is not valid JSON
}

// Site packets only (the repo_config record is filtered out).
function retrieveRecords(...extra) {
  return retrieveAll(...extra).filter((r) => r.kind !== 'repo_config');
}

function repoConfig(...extra) {
  const cfgs = retrieveAll(...extra).filter((r) => r.kind === 'repo_config');
  assert.strictEqual(cfgs.length, 1, 'exactly one repo_config record per run');
  return cfgs[0];
}

test('--packet-schema prints 2', () => {
  const out = run('--packet-schema').trim();
  assert.strictEqual(out, '2');
});

test('retrieval emits records, each with schema and site_key', () => {
  const records = retrieveRecords();
  assert.ok(records.length >= 1, 'expected at least one site');
  for (const rec of records) {
    assert.strictEqual(rec.packet_schema, 2, 'packet_schema must be 2');
    assert.ok(rec.site_key, 'site_key must be stamped on every packet');
    assert.strictEqual(rec.lang, 'typescript');
  }
});

test('const_args carry literal and named-constant evidence; macro flag false', () => {
  // Schema v2 (po-av01j.19): constant-valued arguments are evidence (the TS
  // pool-timeout precision fix was exactly this shape), and every site
  // carries the macro flag (false: TypeScript has no macros).
  const records = retrieveRecords();
  for (const rec of records) {
    assert.ok(Array.isArray(rec.const_args), 'const_args must be on every packet');
    assert.strictEqual(rec.macro_expansion, false, 'macro_expansion must be false');
  }

  // A string-literal SQL argument reports as a literal const arg.
  const pool = records.find(
    (r) => r.client_type === 'pg.Pool' && r.symbol === 'loadUser',
  );
  assert.ok(pool, 'expected the loadUser pool.query site');
  const lit = pool.const_args.find((a) => a.index === 0);
  assert.ok(lit, `expected a const arg at index 0: ${JSON.stringify(pool.const_args)}`);
  assert.strictEqual(lit.how, 'literal');
  assert.ok(lit.value.includes('SELECT * FROM users'), lit.value);
  // The [id] array argument is NOT constant and must not be reported.
  assert.strictEqual(pool.const_args.some((a) => a.index === 1), false);

  // A module-level `const` resolves as a named constant, one hop, no deep
  // constant propagation.
  const status = records.find(
    (r) => r.client_type === 'ioredis.Redis' && r.symbol === 'statusOf',
  );
  assert.ok(status, 'expected the statusOf redis.get site');
  const named = status.const_args.find((a) => a.how === 'named_constant');
  assert.ok(named, `expected a named_constant arg: ${JSON.stringify(status.const_args)}`);
  assert.strictEqual(named.index, 0);
  assert.ok(named.value.includes('status:latest'), named.value);

  // A plain variable/parameter argument yields no const args.
  const raw = records.find((r) => r.func === 'execute' && r.client_type === '');
  assert.ok(raw, 'expected the cursor.execute site');
  assert.deepStrictEqual(raw.const_args, []);
});

test('site_keys are unique and equal the formula', () => {
  const records = retrieveRecords();
  for (const r of records) {
    const want = `${r.file_path}:${r.line_number}:${r.client_type}:${r.func}`;
    assert.strictEqual(r.site_key, want, 'site_key must be file:line:client_type:func');
  }
  const keys = records.map((r) => r.site_key);
  assert.strictEqual(
    new Set(keys).size,
    keys.length,
    `site_key values must be unique: ${JSON.stringify(keys)}`,
  );
});

test('a known pg client resolves high with a package-qualified type', () => {
  const records = retrieveRecords();
  const pg = records.filter(
    (r) => r.client_type === 'pg.Pool' && r.func === 'query',
  );
  assert.ok(pg.length >= 1, 'expected a resolved pg.Pool.query site');
  for (const r of pg) {
    assert.strictEqual(r.provenance.client_type_resolved, true);
    assert.strictEqual(r.provenance.confidence_tier, 'high');
  }
  // version threaded through from the package's package.json.
  assert.strictEqual(pg[0].client_version, '8.11.3');
});

test('axios and ioredis clients resolve high', () => {
  const records = retrieveRecords();
  const axios = records.filter(
    (r) => r.client_type.startsWith('axios.') && r.func === 'get',
  );
  assert.ok(axios.length >= 1, 'expected a resolved axios .get site');
  assert.strictEqual(axios[0].provenance.confidence_tier, 'high');

  const redis = records.filter((r) => r.client_type === 'ioredis.Redis');
  assert.ok(redis.length >= 1, 'expected a resolved ioredis.Redis site');
  assert.strictEqual(redis[0].provenance.client_type_resolved, true);
});

test('two calls on one line with different client types get distinct keys', () => {
  // po-3t3oj.15: file:line is NOT unique. The fixture puts redis.get and
  // axios.get on the SAME line, same method `get`, different client_type.
  const records = retrieveRecords();
  const byLine = {};
  for (const r of records) {
    (byLine[r.line_number] = byLine[r.line_number] || []).push(r);
  }
  const shared = Object.values(byLine).find((rs) => rs.length >= 2);
  assert.ok(shared, 'fixture must have two client calls sharing a line');
  const clientTypes = new Set(shared.map((r) => r.client_type));
  assert.ok(
    clientTypes.size >= 2,
    'the colliding line must carry >=2 distinct client types',
  );
  const keys = new Set(shared.map((r) => r.site_key));
  assert.strictEqual(
    keys.size,
    shared.length,
    'distinct client types on one line must yield distinct site_keys',
  );
});

test('a hoisted monorepo does not trip the missing-node_modules abstain', () => {
  // yarn/pnpm workspaces HOIST: a workspace's dependencies land in the ROOT
  // node_modules, and a per-workspace dir exists only for version conflicts.
  // The guard demanding node_modules in every declaring workspace refused
  // medusa (98 hoisted workspaces) and Ghost (.nxcache artifacts) right after
  // both had installed successfully. Resolvability is: this dir OR any
  // ancestor up to the root has node_modules.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-hoist-'));
  try {
    fs.mkdirSync(path.join(tmp, 'node_modules'));
    fs.mkdirSync(path.join(tmp, 'packages', 'app'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'packages', 'app', 'package.json'),
      JSON.stringify({ name: 'app', dependencies: { axios: '^1.0.0' } }),
    );
    const out = run('--retrieve', '--root', tmp);
    // The run must complete (no sites is fine); before the fix it exited 3.
    assert.ok(typeof out === 'string');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a repo with no node_modules anywhere still abstains', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-bare-'));
  try {
    fs.mkdirSync(path.join(tmp, 'packages', 'app'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'packages', 'app', 'package.json'),
      JSON.stringify({ name: 'app', dependencies: { axios: '^1.0.0' } }),
    );
    assert.throws(
      () => run('--retrieve', '--root', tmp),
      (e) => e.status === 3,
      'expected the abstain exit code',
    );
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a chained LLM SDK call on a constructed client resolves and emits', () => {
  // po-av01j.133.8: `const client = new OpenAI()` then
  // `client.chat.completions.create(...)`. The checker resolves the chained
  // receiver; the site was invisible because "create" was in neither method
  // allowlist. It rides the weak set, so only a RESOLVED receiver emits it.
  const records = retrieveRecords();
  const sites = records.filter(
    (r) =>
      r.func === 'create' &&
      r.client_type.startsWith('openai.') &&
      r.provenance.client_type_resolved === true,
  );
  assert.ok(sites.length >= 1, 'expected a resolved openai chained create site');
});

test('an unresolved receiver still emits a STRONG verb at low confidence', () => {
  const records = retrieveRecords();
  const raw = records.filter(
    (r) => r.func === 'execute' && r.client_type === '',
  );
  assert.ok(raw.length >= 1, 'expected the cursor.execute low-tier site');
  assert.strictEqual(raw[0].provenance.client_type_resolved, false);
  assert.strictEqual(raw[0].provenance.confidence_tier, 'low');
});

test('construction of a resolved client is retrievable', () => {
  const records = retrieveRecords();
  const pool = records.find(
    (r) => r.client_type === 'pg.Pool' && r.func === 'query',
  );
  assert.ok(pool, 'expected the pool.query site');
  const sources = pool.client_construction.map((c) => c.source);
  assert.ok(
    sources.some((s) => s.includes('new Pool(')),
    'construction of the pool client must be retrievable',
  );
});

test('background-job registrations carry site_kind', () => {
  // G3 (po-av01j.4): scheduler/queue registrations ride the same packet
  // stream marked site_kind="background_job"; classic call sites keep an
  // empty site_kind. Detection is type-driven through the checker.
  const records = retrieveRecords();
  for (const rec of records) {
    assert.ok('site_kind' in rec, 'site_kind must be on every packet');
  }
  const jobs = records.filter((r) => r.site_kind === 'background_job');

  // bullmq dispatches: the bounded one carries its timeout option in the
  // snippet, the bare one does not.
  const adds = jobs.filter(
    (r) => r.client_type === 'bullmq.Queue' && r.func === 'add',
  );
  assert.ok(adds.length >= 3, `want the bullmq add dispatches: ${JSON.stringify(jobs.map((j) => j.site_key))}`);
  assert.ok(
    adds.some((r) => r.snippet.includes('timeout: 5000')),
    'the bounded dispatch must be visible in its snippet',
  );

  // The Worker construction IS the handler registration.
  const worker = jobs.find(
    (r) => r.client_type === 'bullmq.Worker' && r.func === 'constructor',
  );
  assert.ok(worker, `new Worker(...) must be a background_job site: ${JSON.stringify(jobs.map((j) => j.site_key))}`);
  assert.strictEqual(worker.symbol, 'startWorker');
  assert.ok(worker.provenance.client_type_resolved, 'worker registration resolves');

  // node-cron schedule.
  const cronSite = jobs.find(
    (r) => r.client_type.startsWith('node-cron.') && r.func === 'schedule',
  );
  assert.ok(cronSite, `node-cron schedule must be kinded: ${JSON.stringify(jobs.map((j) => j.site_key))}`);

  // Classic sites stay classic.
  const pool = records.find((r) => r.client_type === 'pg.Pool');
  assert.strictEqual(pool.site_kind, '');
});

test('untyped job lookalikes are never guessed at', () => {
  // registry.schedule(...) on an `any` receiver: type-driven means the site
  // is not emitted at all, let alone kinded.
  const records = retrieveRecords();
  assert.ok(
    !records.some((r) => r.symbol === 'notAJob'),
    'a lookalike on an untyped receiver must not become a site',
  );
});

test('non-client noise is not emitted', () => {
  const records = retrieveRecords();
  const methods = new Set(records.map((r) => r.func));
  for (const noise of ['push', 'map', 'toString']) {
    assert.ok(!methods.has(noise), `noise method ${noise} must not be a site`);
  }
});

test('server-entry registrations are inventoried and never leak into G1', () => {
  // G2 (po-av01j.3): express route/middleware registrations and NestJS route
  // decorators emit as site_kind "server_entry" with the framework identity
  // as client_type and the route path riding const_args.
  const records = retrieveRecords();
  const entries = records.filter((r) => r.site_kind === 'server_entry');
  const g1 = records.filter((r) => !r.site_kind);
  assert.ok(g1.length >= 1, 'G1 sites must still be emitted alongside entries');

  // express app.get('/healthz', ...) on a resolved express.Express receiver.
  const health = entries.find(
    (r) => r.client_type === 'express.Express' && r.func === 'get',
  );
  assert.ok(health, `expected the app.get healthz entry: ${JSON.stringify(entries)}`);
  assert.ok(
    health.const_args.some((a) => a.value.includes('/healthz')),
    `route path must ride const_args: ${JSON.stringify(health.const_args)}`,
  );
  assert.strictEqual(health.packet_schema, 2);
  assert.ok(health.site_key, 'site_key must be stamped on server entries');

  // express middleware attachment + a Router-typed registration.
  assert.ok(
    entries.some((r) => r.client_type === 'express.Express' && r.func === 'use'),
    'expected the app.use middleware attachment',
  );
  assert.ok(
    entries.some((r) => r.client_type === 'express.Router' && r.func === 'post'),
    'expected the router.post registration',
  );

  // NestJS route decorator, attributed to @nestjs/common with the decorated
  // method as the symbol.
  const nest = entries.find((r) => r.client_type === '@nestjs/common.Get');
  assert.ok(nest, 'expected the @Get route decorator entry');
  assert.strictEqual(nest.symbol, 'list');
  assert.ok(nest.const_args.some((a) => a.value.includes('/orders')));

  // The registrations never ALSO emit as G1 client calls.
  for (const r of g1) {
    const isServerType =
      r.client_type.startsWith('express.') ||
      r.client_type.startsWith('@nestjs/common.');
    const verb = r.func.toLowerCase();
    assert.ok(
      !(isServerType && (verb === 'get' || verb === 'post' || verb === 'use')),
      `server registration leaked into G1: ${JSON.stringify(r)}`,
    );
  }
});

test('--files restricts output to the listed file (exact path)', () => {
  const records = retrieveRecords('--files', 'src/service.ts');
  assert.ok(records.length >= 1);
  for (const r of records) {
    assert.strictEqual(r.file_path, 'src/service.ts');
  }
  // a non-existent file yields no SITES (not an error, not everything). The
  // repo-scoped repo_config line is always emitted, so filter to site packets.
  const sites = retrieveRecords('--files', 'does_not_exist.ts');
  assert.strictEqual(sites.length, 0);
});

// --- G4 emission packets (po-av01j.5) ---
//
// Emission points ride the same stream as AGGREGATES — one packet per
// (enclosing function, framework, category), never one per log line — stamped
// site_kind: "emission_point" with category and count riding const_args.

function emissionRecords() {
  return retrieveRecords().filter((r) => r.site_kind === 'emission_point');
}

function constByName(rec, name) {
  const a = rec.const_args.find((x) => x.name === name);
  return a ? a.value : null;
}

test('log statements aggregate per function/framework/category', () => {
  const emissions = emissionRecords();
  assert.ok(emissions.length >= 1, 'expected emission packets from the fixture');
  const noisy = emissions.filter(
    (r) => r.symbol === 'noisy' && r.client_type === 'winston.Logger',
  );
  assert.strictEqual(
    noisy.length,
    1,
    `four logger calls in one function must be ONE aggregate: ${JSON.stringify(noisy)}`,
  );
  assert.strictEqual(constByName(noisy[0], 'emission_category'), 'log');
  assert.strictEqual(constByName(noisy[0], 'emission_count'), '4');
  // Shared packet invariants hold for emission packets too.
  assert.strictEqual(noisy[0].packet_schema, 2);
  assert.ok(noisy[0].site_key);
});

test('span instrumentation is a trace-category emission', () => {
  const emissions = emissionRecords();
  const spans = emissions.filter(
    (r) => r.symbol === 'traced' && r.client_type === '@opentelemetry/api.Tracer',
  );
  assert.strictEqual(spans.length, 1, JSON.stringify(emissions));
  assert.strictEqual(constByName(spans[0], 'emission_category'), 'trace');
});

test('a log emission inside a catch is error_capture, and not a swallow', () => {
  const emissions = emissionRecords();
  const inCatch = emissions.filter(
    (r) => r.symbol === 'catches' && r.client_type === 'winston.Logger',
  );
  assert.strictEqual(inCatch.length, 1, JSON.stringify(emissions));
  assert.strictEqual(constByName(inCatch[0], 'emission_category'), 'error_capture');
  for (const r of emissions) {
    if (r.client_type === 'catch_clause') {
      assert.notStrictEqual(r.symbol, 'catches', 'a logging catch is not a swallow');
      assert.notStrictEqual(r.symbol, 'rethrows', 'a re-throwing catch is not a swallow');
    }
  }
});

test('a catch that neither emits nor re-throws is a catch_clause swallow', () => {
  const emissions = emissionRecords();
  const swallows = emissions.filter((r) => r.client_type === 'catch_clause');
  assert.strictEqual(swallows.length, 1, JSON.stringify(swallows));
  assert.strictEqual(swallows[0].symbol, 'swallows');
  assert.strictEqual(constByName(swallows[0], 'emission_category'), 'error_capture');
});

test('console calls emit under the console identity', () => {
  const emissions = emissionRecords();
  const consoles = emissions.filter(
    (r) => r.symbol === 'consoleUser' && r.client_type === 'console',
  );
  assert.strictEqual(consoles.length, 1, JSON.stringify(emissions));
  assert.strictEqual(constByName(consoles[0], 'emission_count'), '2');
});

test('emission calls are routed OUT of the G1 site list; anchors stay in', () => {
  const g1 = retrieveRecords().filter((r) => !r.site_kind);
  // logger.info etc must not double-count as G1 client calls.
  assert.ok(
    !g1.some((r) => r.client_type === 'winston.Logger'),
    'logger calls leaked into the G1 site list',
  );
  // The LLM SDK call is a G1 anchor (the RC-061 call-site half rides G1).
  assert.ok(
    g1.some((r) => r.client_type === 'openai.Completions' && r.func === 'create'),
    `expected the openai.Completions.create G1 site: ${JSON.stringify(
      g1.map((r) => r.client_type),
    )}`,
  );
});

test('repo_config packet is emitted, well-formed, and repo-scoped', () => {
  const cfg = repoConfig();
  assert.strictEqual(cfg.kind, 'repo_config', 'kind must be the literal repo_config');
  assert.strictEqual(cfg.packet_schema, 2);
  assert.ok(cfg.snapshot_id, 'snapshot_id must be set');
  assert.ok(Array.isArray(cfg.constructions), 'constructions must be an array');
});

test('repo_config records timeout-ish constructions and skips no-timeout ones', () => {
  const cfg = repoConfig();
  const byType = new Map(cfg.constructions.map((c) => [c.type, c.fields]));

  // TypeORM DataSource with a NESTED extra.query_timeout, resolved to <pkg>.<Type>.
  const ds = byType.get('typeorm.DataSource');
  assert.ok(ds, `expected a typeorm.DataSource construction: ${JSON.stringify([...byType.keys()])}`);
  assert.ok(ds.includes('query_timeout'), 'DataSource fields must include query_timeout');

  // node-postgres Pool with a top-level connection timeout.
  const pool = byType.get('pg.Pool');
  assert.ok(pool, `expected a pg.Pool construction: ${JSON.stringify([...byType.keys()])}`);
  assert.ok(
    pool.includes('connectionTimeoutMillis'),
    'pg.Pool fields must include connectionTimeoutMillis',
  );

  // The no-timeout `new Pool({})` must NOT add a bare field-less pg.Pool entry:
  // pg.Pool is present only because a DIFFERENT construction set a timeout, and
  // its fields never include an empty/no-timeout marker.
  assert.ok(pool.length >= 1, 'a recorded construction always carries >=1 field');

  // Each construction is exactly {type, fields}.
  for (const c of cfg.constructions) {
    assert.strictEqual(typeof c.type, 'string');
    assert.ok(Array.isArray(c.fields) && c.fields.length >= 1);
  }
});

// ---------------------------------------------------------------------------
// client_type must never carry a filesystem path (po-av01j.115).
//
// site_key is `file:line:client_type:method`, so anything machine-dependent in
// client_type makes the key machine-dependent too: the same repo checked out at
// a different path yields different keys, and joins, caches and gate sets stop
// matching across hosts. Specs also key on client_type, so a path-qualified
// type can never be matched by any published spec.
//
// This only fires when node_modules is present -- on a bare clone the external
// resolution fails silently and the fallback never runs -- which is why it went
// unnoticed until a dependency-installed probe.
// ---------------------------------------------------------------------------

const { stableTypeName } = require('../tsindex.js');

test('stableTypeName leaves an ordinary type name alone', () => {
  const pkg = { pkg: 'pg', dir: '/w/node_modules/pg' };
  assert.strictEqual(stableTypeName('Pool', pkg, '/w/node_modules/pg/lib/index.d.ts'), 'Pool');
  assert.strictEqual(stableTypeName('AxiosStatic', pkg, '/w/node_modules/pg/x.d.ts'), 'AxiosStatic');
});

test('stableTypeName replaces an absolute module path with the package subpath', () => {
  // The observed real case: zod's re-export module has no nameable symbol, so
  // the checker falls back to the module's absolute path.
  const pkg = { pkg: 'zod', dir: '/home/someone/repo/backend/node_modules/zod' };
  const decl = '/home/someone/repo/backend/node_modules/zod/v3/external.d.ts';
  const got = stableTypeName('"/home/someone/repo/backend/node_modules/zod/v3/external"', pkg, decl);
  assert.strictEqual(got, 'v3/external');
});

test('stableTypeName handles the typeof import(...) spelling', () => {
  const pkg = { pkg: 'zod', dir: '/a/node_modules/zod' };
  const decl = '/a/node_modules/zod/lib/external.d.ts';
  const got = stableTypeName('typeof import("/a/node_modules/zod/lib/external")', pkg, decl);
  assert.strictEqual(got, 'lib/external');
});

test('stableTypeName is identical for the same package at different checkouts', () => {
  // The property that actually matters: the name must not depend on where the
  // repo happens to live on disk.
  const a = stableTypeName('"/tmp/scratch/x/node_modules/zod/v3/external"',
    { pkg: 'zod', dir: '/tmp/scratch/x/node_modules/zod' },
    '/tmp/scratch/x/node_modules/zod/v3/external.d.ts');
  const b = stableTypeName('"/home/ci/build/node_modules/zod/v3/external"',
    { pkg: 'zod', dir: '/home/ci/build/node_modules/zod' },
    '/home/ci/build/node_modules/zod/v3/external.d.ts');
  assert.strictEqual(a, b, 'same package+module must name identically on any host');
});

test('stableTypeName fails closed when it cannot derive a stable name', () => {
  // Better to drop the site than to emit a machine-dependent key. '' tells the
  // caller to treat the receiver as unresolved.
  assert.strictEqual(stableTypeName('"/some/where/else/mod"', null, '/some/where/else/mod.d.ts'), '');
  assert.strictEqual(
    stableTypeName('"/a/node_modules/zod/v3/x"', { pkg: 'zod', dir: '/completely/other' }, '/nope.d.ts'),
    '');
});

test('no emitted client_type contains a filesystem path', () => {
  for (const rec of retrieveAll()) {
    const ct = rec.client_type;
    if (!ct) continue;
    assert.ok(!ct.includes('/node_modules/'),
      `client_type embeds a node_modules path: ${ct}`);
    assert.ok(!/(^|[.("])\//.test(ct),
      `client_type embeds an absolute path: ${ct}`);
    assert.ok(!ct.includes('import('),
      `client_type carries an unresolved import() spelling: ${ct}`);
  }
});

// ---------------------------------------------------------------------------
// Resolving to an external package does not make a call a CLIENT call
// (po-av01j.116).
//
// The old rule was "a resolved external client emits regardless of method
// name". That holds for pg/axios/ioredis, and fails for pure-computation
// packages: on infisical, 82,645 of 83,042 resolved sites (99.5%) had no I/O
// verb, and zod + knex builders alone were 86.5% of them.
//
// A package blocklist is the wrong axis, because knex is BOTH a real query
// client and a schema builder (`knex.ColumnBuilder.notNullable`). The test that
// separates them is structural: a call that crosses a process, network or disk
// boundary is awaitable, and a synchronous fluent builder is not.
// ---------------------------------------------------------------------------

test('synchronous fluent builder calls are not emitted as client sites', () => {
  const recs = retrieveAll().filter((r) => (r.file_path || '').endsWith('schemas.ts'));
  const emitted = recs.filter((r) => !r.kind && r.client_type);
  assert.deepStrictEqual(
    emitted.map((r) => `${r.client_type}.${r.func}`),
    [],
    'schema-builder chains must not appear as client call sites',
  );
});

test('awaitable client calls are still emitted', () => {
  // The guard against over-dropping: the real clients in the fixture must
  // survive the builder exclusion untouched.
  const all = retrieveAll().filter((r) => !r.kind && r.client_type);
  const pkgs = new Set(all.map((r) => r.client_type.split('.')[0]));
  for (const want of ['pg', 'axios', 'ioredis']) {
    assert.ok(pkgs.has(want), `real client package ${want} must still be retrieved`);
  }
});

// po-av01j.137: identical code yielded 30 sites named .ts and 0 named .js, with
// no abstention and exit 0. Express/Node backends without TypeScript were
// entirely invisible. Client types survive the rename because they come from
// the DEPENDENCY's type declarations, not from annotations in the file.
test('plain JavaScript is retrieved, with client types resolved', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-js-'));
  fs.mkdirSync(path.join(dir, 'node_modules', 'pg'), { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'node_modules', 'pg', 'package.json'),
    JSON.stringify({ name: 'pg', version: '8.11.3', types: 'index.d.ts' }),
  );
  fs.writeFileSync(
    path.join(dir, 'node_modules', 'pg', 'index.d.ts'),
    'export declare class Pool { query(text: string, values?: unknown[]): Promise<unknown>; }\n',
  );
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'x', dependencies: { pg: '^8.11.3' } }));
  fs.writeFileSync(
    path.join(dir, 'server.js'),
    "import { Pool } from 'pg';\nconst p = new Pool({});\nexport async function go() { return await p.query('SELECT 1'); }\n",
  );
  const lines = run('--retrieve', '--root', dir, '--name', 'js')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const sites = lines.filter((r) => r.site_key);
  assert.ok(sites.length >= 1, 'a .js file must produce sites: ' + JSON.stringify(lines));
  assert.ok(
    sites.some((s) => s.client_type === 'pg.Pool'),
    'the client type must still resolve from the dependency types: ' + JSON.stringify(sites.map((s) => s.client_type)),
  );
});
