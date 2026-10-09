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
const crypto = require('node:crypto');

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
  // Line 1 stays the bare schema integer, so a consumer that reads only the
  // first line of the reply keeps working.
  const out = run('--packet-schema');
  assert.strictEqual(out.split('\n')[0], '2');
});

test('--packet-schema reports this file\'s content version', () => {
  // The handshake (po-8ozxg): rvl compares this value against the copy it
  // ships, and computes it for a script by hashing the file. The two must be
  // the same number or every tsindex reads as drifted.
  const want = crypto
    .createHash('sha256')
    .update(fs.readFileSync(TSINDEX))
    .digest('hex')
    .slice(0, 12);
  const out = run('--packet-schema');
  assert.strictEqual(out.split('\n')[1], 'content-version ' + want);
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

test('a repo with no node_modules no longer abstains for that alone', () => {
  // po-pk3fp.2 narrowed this. An uninstalled tree used to abstain outright,
  // which cost the fleet 68 of its 97 TypeScript repos. It now scans, because
  // an import statement names the package and the source names the type; only
  // the specifiers syntax genuinely cannot map still abstain (see the path-
  // alias test below).
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-uninstalled-'));
  try {
    fs.mkdirSync(path.join(tmp, 'packages', 'app'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'packages', 'app', 'package.json'),
      JSON.stringify({ name: 'app', dependencies: { axios: '^1.0.0' } }),
    );
    const out = run('--retrieve', '--root', tmp);
    assert.ok(typeof out === 'string');
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
  // service.ts constructs its pool in-file; crossmodule.ts imports one.
  const pool = records.find(
    (r) => r.client_type === 'pg.Pool' && r.func === 'query' && r.file_path === 'src/service.ts',
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

// --- test-path skip ---
//
// Test code is not scanned for API surfaces: on one real repo 700+ of 889
// violates were Playwright/msw calls inside E2E tests, and goindex has
// always skipped _test.go the same way. The skip is COUNTED and reported on
// the repo-scoped record, never silent, and --include-tests turns it off.

const TESTS_FIXTURE_ROOT = path.join(HERE, '..', 'testdata', 'fixture-tests');

// Every test-convention file in the fixture; each carries one strong-verb
// call, so a file that is scanned is a file that produces a site.
const FIXTURE_TEST_FILES = [
  'src/service.test.ts',
  'src/service.spec.ts',
  'src/login.cy.ts',
  'tests/helpers.ts',
  'test/unit.ts',
  '__tests__/a.ts',
  '__mocks__/client.ts',
  'e2e/login.ts',
  'spec/b.ts',
  'fixtures/c.ts',
  'testdata/d.ts',
  'cypress/support/e.ts',
  'playwright.config.ts',
  'jest.config.js',
  'vitest.setup.ts',
  'setupTests.ts',
];
const FIXTURE_PRODUCTION_FILES = [
  'lib/contest/index.ts',
  'src/attestation.ts',
  'src/service.ts',
];

function retrieveFrom(root, ...extra) {
  const out = run('--retrieve', '--root', root, ...extra);
  const all = out
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const cfgs = all.filter((r) => r.kind === 'repo_config');
  assert.strictEqual(cfgs.length, 1, 'exactly one repo_config record per run');
  return { sites: all.filter((r) => r.kind !== 'repo_config'), cfg: cfgs[0] };
}

function scannedFiles(sites) {
  return [...new Set(sites.map((r) => r.file_path))].sort();
}

test('isTestPath matches the documented conventions and nothing else', () => {
  const { isTestPath } = require('../tsindex.js');
  for (const p of FIXTURE_TEST_FILES) {
    assert.strictEqual(isTestPath(p), true, `${p} is test material`);
  }
  // Exact path segments and exact basename shapes: a substring is not a
  // convention. These are the false positives a looser rule would produce.
  for (const p of [
    ...FIXTURE_PRODUCTION_FILES,
    'src/latest.ts',
    'src/spectrum.ts',
    'src/testify.ts',
    'packages/test-utils/index.ts',
    'vite.config.ts',
    'src/e2e-client.ts',
  ]) {
    assert.strictEqual(isTestPath(p), false, `${p} is production code`);
  }
});

test('test paths are skipped by default, counted, and reported on repo_config', () => {
  const { sites, cfg } = retrieveFrom(TESTS_FIXTURE_ROOT);
  assert.deepStrictEqual(scannedFiles(sites), FIXTURE_PRODUCTION_FILES);
  assert.strictEqual(
    cfg.test_files_skipped,
    FIXTURE_TEST_FILES.length,
    `the skip must be counted, never silent: ${JSON.stringify(cfg)}`,
  );
  // NAMED as well as counted: rvl's packet index flags each skipped file so
  // a warm scan can report the repository-wide number from reused entries,
  // not just the files one invocation re-parsed.
  assert.deepStrictEqual(
    [...cfg.test_files_skipped_paths].sort(),
    [...FIXTURE_TEST_FILES].sort(),
  );
  // A construction inside a test file is not a repo-wide fact either: a
  // timeout set in test scaffolding must not credit a bound to production.
  assert.deepStrictEqual(cfg.constructions, []);
});

test('--include-tests scans test paths and reports zero skipped', () => {
  const { sites, cfg } = retrieveFrom(TESTS_FIXTURE_ROOT, '--include-tests');
  assert.deepStrictEqual(
    scannedFiles(sites),
    [...FIXTURE_PRODUCTION_FILES, ...FIXTURE_TEST_FILES].sort(),
  );
  assert.strictEqual(cfg.test_files_skipped, 0);
  assert.deepStrictEqual(cfg.test_files_skipped_paths, []);
  // With tests in scope the test-file construction IS visible.
  assert.ok(
    cfg.constructions.some((c) => c.fields.includes('connectionTimeoutMillis')),
    JSON.stringify(cfg.constructions),
  );
});

test('--files naming only a test file emits no sites and still counts the skip', () => {
  // The incremental path asks for exactly the changed files; a commit that
  // touches only a test must not produce test sites, and must not read as a
  // helper that silently dropped a requested file.
  const { sites, cfg } = retrieveFrom(TESTS_FIXTURE_ROOT, '--files', 'src/service.test.ts');
  assert.strictEqual(sites.length, 0);
  assert.strictEqual(cfg.test_files_skipped, 1);
  assert.deepStrictEqual(cfg.test_files_skipped_paths, ['src/service.test.ts']);
  const included = retrieveFrom(
    TESTS_FIXTURE_ROOT,
    '--files',
    'src/service.test.ts',
    '--include-tests',
  );
  assert.deepStrictEqual(scannedFiles(included.sites), ['src/service.test.ts']);
  assert.strictEqual(included.cfg.test_files_skipped, 0);
});

// --- resolution WITHOUT an installed node_modules (po-pk3fp.2) -------------
//
// tsindex used to abstain outright on a checkout whose workspaces declare
// dependencies but have none installed: 68 of the fleet's 97 TypeScript repos,
// every customer scanning a tree they have not installed, and every repo whose
// install cannot be made to succeed.
//
// The durable fix is that a spec key does not need the module on disk. An
// import statement names the package, and a `new Pool()`, a `db: Pool`
// annotation or a `private db: Pool` property names the type -- so
// `pg.Pool` is recoverable from syntax alone, identically to what the
// TypeChecker reports when the package IS installed.
//
// The fixture is copied WITHOUT node_modules so the two runs differ in exactly
// one thing, which is the property the whole lane turns on.

function fixtureWithoutNodeModules(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-nodeps-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.cpSync(FIXTURE_ROOT, dir, {
    recursive: true,
    filter: (src) => path.basename(src) !== 'node_modules',
  });
  assert.strictEqual(
    fs.existsSync(path.join(dir, 'node_modules')),
    false,
    'the uninstalled copy must have no node_modules',
  );
  return dir;
}

test('an uninstalled checkout scans instead of abstaining', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites, cfg } = retrieveFrom(dir);
  // Before the fix this run exited 3 and produced nothing; bypassing the
  // abstain produced 6 sites against the installed run's 32.
  assert.ok(
    sites.length >= 20,
    `an uninstalled checkout must still retrieve its client sites, got ${sites.length}`,
  );
  // The degradation is on the wire, never ambient: this run resolved from
  // syntax because the tree is uninstalled, and the record says so.
  assert.ok(cfg.dependency_trees_uninstalled >= 1, JSON.stringify(cfg));
  assert.ok(
    cfg.dependency_trees_uninstalled_paths.includes('.'),
    JSON.stringify(cfg.dependency_trees_uninstalled_paths),
  );
});

test('uninstalled resolution yields the SAME spec keys the checker does', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const bare = retrieveFrom(dir).sites;
  const installed = retrieveRecords();
  // Every type a `new Ctor()`, a type annotation or a class property names in
  // source is recoverable without the package. These are the ratified TS
  // judgment keys, so they must match EXACTLY, not merely resemble.
  for (const type of ['pg.Pool', 'ioredis.Redis', 'bullmq.Queue']) {
    const want = installed
      .filter((r) => r.client_type === type)
      .map((r) => r.site_key)
      .sort();
    const got = bare
      .filter((r) => r.client_type === type)
      .map((r) => r.site_key)
      .sort();
    assert.ok(want.length > 0, `the installed run must have ${type} sites`);
    assert.deepStrictEqual(got, want, `${type} keys must survive an uninstalled tree`);
  }
});

test('a syntactically resolved site reports tier medium, not high', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites } = retrieveFrom(dir);
  const pool = sites.filter((r) => r.client_type === 'pg.Pool');
  assert.ok(pool.length >= 1);
  for (const r of pool) {
    // Resolved: the weak-verb gate needs this, or every pool.query and
    // redis.get is dropped as container noise.
    assert.strictEqual(r.provenance.client_type_resolved, true);
    // But NOT high: the type came from import syntax, not the TypeChecker,
    // and a reader must be able to tell those apart.
    assert.strictEqual(r.provenance.confidence_tier, 'medium');
    // No package on disk means no package.json to read a version from.
    assert.strictEqual(r.client_version, '');
  }
  // The installed run is untouched: the fallback runs only after the checker.
  for (const r of retrieveRecords().filter((x) => x.client_type === 'pg.Pool')) {
    assert.strictEqual(r.provenance.confidence_tier, 'high');
  }
});

test('a module object used directly resolves to the bare import path', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites } = retrieveFrom(dir);
  // `import axios from 'axios'; axios.get(...)`. The module object's TYPE
  // name (AxiosStatic) lives in the package, so syntax cannot recover it --
  // but the import path can, and that is the key shape a spec author writes.
  const axios = sites.filter((r) => r.client_type === 'axios' && r.func === 'get');
  assert.ok(axios.length >= 1, JSON.stringify(sites.map((s) => s.client_type)));
  assert.strictEqual(axios[0].provenance.confidence_tier, 'medium');
  // A bare package name must still reach the framework tables that key on
  // `<pkg>.<Type>`: express routes and node-cron schedules are registrations
  // whether or not the type name resolved.
  assert.ok(
    sites.some((r) => r.site_kind === 'server_entry' && r.client_type === 'express'),
    'an express route registration must survive: ' +
      JSON.stringify(sites.filter((s) => s.site_kind === 'server_entry')),
  );
  assert.ok(
    sites.some((r) => r.site_kind === 'background_job' && r.client_type === 'node-cron'),
    'a node-cron schedule must survive',
  );
});

test('repo_config construction types survive an uninstalled tree', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { cfg } = retrieveFrom(dir);
  const types = cfg.constructions.map((c) => c.type);
  // Without this the config lane sees `Pool`/`DataSource`/`axios.create` --
  // bare identifier text that no ConfigSpec is keyed on, and that
  // rvl_spec::client_family cannot classify into an I/O family.
  for (const t2 of ['pg.Pool', 'ioredis.Redis', 'typeorm.DataSource']) {
    assert.ok(types.includes(t2), `${t2} missing from ${JSON.stringify(types)}`);
  }
});

test('a bare checkout with a resolvable import scans; site keys stay unique', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-bare-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'app', dependencies: { pg: '^8.0.0' } }),
    );
    fs.writeFileSync(
      path.join(tmp, 'src', 'db.ts'),
      "import { Pool } from 'pg';\n" +
        'const pool = new Pool({ connectionTimeoutMillis: 5000 });\n' +
        'export class Repo {\n' +
        '  constructor(private readonly db: Pool) {}\n' +
        '  find(sql: string) { return this.db.query(sql); }\n' +
        '}\n' +
        'export function load(id: number) { return pool.query("SELECT 1", [id]); }\n',
    );
    const { sites, cfg } = retrieveFrom(tmp);
    const keys = sites.map((r) => r.site_key);
    assert.strictEqual(new Set(keys).size, keys.length, JSON.stringify(keys));
    // Both the module-scope const and the constructor-parameter property
    // resolve: the annotation names the type, and the import names the package.
    assert.deepStrictEqual(
      sites.filter((r) => r.client_type === 'pg.Pool' && r.func === 'query').length,
      2,
      JSON.stringify(sites.map((s) => [s.client_type, s.func, s.receiver])),
    );
    assert.deepStrictEqual(cfg.constructions, [
      { type: 'pg.Pool', fields: ['connectionTimeoutMillis'] },
    ]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a tree whose only external imports are tsconfig path aliases abstains', () => {
  // The residue the syntactic path genuinely cannot cross. `@app/db` is a
  // path alias onto a workspace directory, so the specifier names no package
  // and following it needs the package CONTENTS the tree does not have.
  // Reporting a near-empty scan as a complete one is the failure the original
  // abstain existed to prevent, so this case still abstains -- and names the
  // aliases, which is the only actionable thing to say about it.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-alias-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'app', dependencies: { '@app/db': '*' } }),
    );
    fs.writeFileSync(
      path.join(tmp, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { baseUrl: '.', paths: { '@app/*': ['packages/*/src'] } },
      }),
    );
    fs.writeFileSync(
      path.join(tmp, 'src', 'use.ts'),
      "import { db } from '@app/db';\nexport function load() { return db.query('SELECT 1'); }\n",
    );
    let err;
    try {
      run('--retrieve', '--root', tmp);
    } catch (e) {
      err = e;
    }
    assert.ok(err, 'expected the abstain exit');
    assert.strictEqual(err.status, 3, String(err.stderr));
    assert.match(String(err.stderr), /@app\/db/, 'the abstain must NAME the specifier');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('an uninstalled tree does not flood with builder calls', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites } = retrieveFrom(dir);
  // The awaitability gate is a TYPE test: with no package it answers "yes" to
  // everything, so leaving it in would emit every property call in the file.
  // That is the zod/knex builder flood it exists to stop -- 99.5% of resolved
  // sites on infisical carried no I/O verb. At tier medium a named I/O verb
  // is required instead.
  const types = sites.map((r) => `${r.client_type}.${r.func}`);
  for (const noise of ['zodlike.string', 'zodlike.object', 'axios.create', 'express.Router']) {
    assert.strictEqual(
      types.includes(noise),
      false,
      `${noise} is a builder/factory call, not a site: ${JSON.stringify(types)}`,
    );
  }
  // And the real calls are still there, so this is a filter rather than a
  // retreat to the old near-empty scan.
  assert.ok(types.filter((t2) => t2 === 'pg.Pool.query').length >= 4, JSON.stringify(types));
});

test('an uninstalled tree still routes emissions out of the client lane', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites } = retrieveFrom(dir);
  // A logger reaching the G1 client lane is a wrong KIND of site, not just a
  // coarser key: `logger.error(...)` would read as an unbounded client call.
  // The emission tables key on the package, so the syntactic `winston`
  // reaches the same arm as the checker's `winston.Logger`.
  const winston = sites.filter((r) => r.client_type === 'winston');
  assert.ok(winston.length >= 1, JSON.stringify(sites.map((s) => s.client_type)));
  for (const r of winston) {
    assert.strictEqual(r.site_kind, 'emission_point');
  }
  const otel = sites.filter((r) => r.client_type === '@opentelemetry/api');
  assert.ok(otel.length >= 1, 'an otel span must stay an emission point');
  assert.strictEqual(otel[0].site_kind, 'emission_point');
});

test('path aliases beside real imports do not poison the run', () => {
  // The common monorepo shape, and the one the fleet unlock turns on: some
  // imports are packages, some are tsconfig `paths` onto workspace
  // directories. The aliases are named as unmappable and their receivers stay
  // unattributed; the packages resolve normally and the run does NOT abstain.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tsx-mixed-'));
  try {
    fs.mkdirSync(path.join(tmp, 'src'), { recursive: true });
    fs.writeFileSync(
      path.join(tmp, 'package.json'),
      JSON.stringify({ name: 'm', dependencies: { pg: '^8.0.0', axios: '^1.0.0' } }),
    );
    fs.writeFileSync(
      path.join(tmp, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { baseUrl: '.', paths: { '@app/*': ['packages/*/src'] } },
        include: ['src/**/*.ts'],
      }),
    );
    fs.writeFileSync(
      path.join(tmp, 'src', 'app.ts'),
      "import { Pool } from 'pg';\n" +
        "import axios from 'axios';\n" +
        "import { helper } from '@app/db';\n" +
        'const pool = new Pool({ connectionTimeoutMillis: 3000 });\n' +
        'export async function go(id: number) {\n' +
        "  const r = await pool.query('SELECT 1', [id]);\n" +
        "  const h = await helper.query('SELECT 2');\n" +
        "  const u = await axios.get('/x');\n" +
        '  return [r, h, u];\n' +
        '}\n',
    );
    const { sites, cfg } = retrieveFrom(tmp);
    assert.deepStrictEqual(
      sites.map((r) => `${r.client_type}.${r.func}`).sort(),
      ['axios.get', 'pg.Pool.query'],
      JSON.stringify(sites.map((r) => [r.client_type, r.func, r.receiver])),
    );
    assert.deepStrictEqual(cfg.unmappable_specifiers, ['@app/db']);
    assert.strictEqual(cfg.dependency_trees_uninstalled, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// --- following the repo's OWN modules without node_modules (po-pk3fp.10) ---
//
// A client is usually constructed in one module and imported everywhere else,
// so the specifier at the call site is `./db`, not `pg`. The TypeChecker
// follows that import whether or not node_modules exists -- the repo's own
// modules are in the program -- and syntax has to follow it too, through
// named exports, barrels and default exports, down to the import of the
// package that names the type.

function writeTree(t, prefix, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [rel, body] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), typeof body === 'string' ? body : JSON.stringify(body));
  }
  return dir;
}

test('a client imported from a sibling module keeps its key on an uninstalled tree', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const keysIn = (sites) =>
    sites
      .filter((r) => r.file_path === 'src/crossmodule.ts')
      .map((r) => r.site_key)
      .sort();
  const want = keysIn(retrieveRecords());
  // Named export, namespace import, barrel re-export, default export of a
  // construction, and a type re-exported under another name.
  assert.strictEqual(want.length, 5, JSON.stringify(want));
  assert.deepStrictEqual(keysIn(retrieveFrom(dir).sites), want);
});

test('an awaited SDK call keeps its site on an uninstalled tree', (t) => {
  const dir = fixtureWithoutNodeModules(t);
  const { sites } = retrieveFrom(dir);
  // `client.chat.completions.create(...)` carries no I/O verb, so the installed
  // run admits it through the checker's awaitability test, which cannot run
  // without the package. The source says the same thing syntactically: the
  // call's result is awaited or returned from an async function. The member
  // type (`Completions`) lives in the package, so the key is one level coarser.
  const creates = sites.filter((r) => r.func === 'create' && r.client_type === 'openai');
  assert.deepStrictEqual(
    creates.map((r) => `${r.file_path}:${r.line_number}`).sort(),
    ['src/emitters.ts:58', 'src/llm.ts:11'],
    JSON.stringify(sites.map((r) => [r.client_type, r.func, r.file_path, r.line_number])),
  );
  for (const r of creates) assert.strictEqual(r.provenance.confidence_tier, 'medium');
});

test('a wildcard re-export of a package is named, never guessed', (t) => {
  // `export * from 'ioredis'` in a local barrel: whether `Redis` comes from
  // ioredis is a fact about the package's CONTENTS, which the tree does not
  // have. Guessing would be right here and wrong beside a second `export *`,
  // so the receiver stays unattributed and the specifier is named.
  const dir = writeTree(t, 'tsx-star-', {
    'package.json': { name: 's', dependencies: { pg: '^8', ioredis: '^5' } },
    'src/clients.ts': "export * from 'ioredis';\n",
    'src/use.ts':
      "import { Pool } from 'pg';\n" +
      "import { Redis } from './clients';\n" +
      'const pool = new Pool();\n' +
      'const redis = new Redis();\n' +
      "export async function go() { return [await pool.query('x'), await redis.get('k')]; }\n",
  });
  const { sites, cfg } = retrieveFrom(dir);
  assert.deepStrictEqual(
    sites.map((r) => `${r.client_type}.${r.func}`),
    ['pg.Pool.query'],
    JSON.stringify(sites.map((r) => [r.client_type, r.func])),
  );
  assert.deepStrictEqual(cfg.unmappable_specifiers, ["export * from 'ioredis'"]);
});

test('a tree reachable only through wildcard re-exports abstains and names them', (t) => {
  const dir = writeTree(t, 'tsx-staronly-', {
    'package.json': { name: 's', dependencies: { ioredis: '^5' } },
    'src/clients.ts': "export * from 'ioredis';\n",
    'src/use.ts':
      "import { Redis } from './clients';\n" +
      'const redis = new Redis();\n' +
      "export async function go() { return redis.get('k'); }\n",
  });
  let err;
  try {
    run('--retrieve', '--root', dir);
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'expected the abstain exit');
  assert.strictEqual(err.status, 3, String(err.stderr));
  assert.match(String(err.stderr), /export \* from 'ioredis'/);
});

test('path aliases declared in a nested workspace tsconfig are unmappable', (t) => {
  // Monorepos declare `paths` per workspace. An alias the root tsconfig does
  // not know is otherwise attributed to a package named `~`, which counts as
  // attributed and can hold off the abstain on a tree that resolved nothing.
  const dir = writeTree(t, 'tsx-nested-', {
    'package.json': { name: 'root', private: true },
    'packages/api/package.json': { name: 'api', dependencies: { pg: '^8' } },
    'packages/api/tsconfig.json': {
      compilerOptions: { baseUrl: '.', paths: { '~/*': ['src/*'] } },
    },
    'packages/api/src/use.ts':
      "import { db } from '~/db';\nexport async function go() { return db.query('x'); }\n",
  });
  let err;
  try {
    run('--retrieve', '--root', dir);
  } catch (e) {
    err = e;
  }
  assert.ok(err, 'every external import is an alias, so this must abstain');
  assert.strictEqual(err.status, 3, String(err.stderr));
  assert.match(String(err.stderr), /~\/db/);
});

test('a path alias from an extended tsconfig is honored', (t) => {
  const dir = writeTree(t, 'tsx-extends-', {
    'package.json': { name: 'e', dependencies: { pg: '^8' } },
    'tsconfig.base.json': {
      compilerOptions: { baseUrl: '.', paths: { '@app/*': ['packages/*/src'] } },
    },
    'tsconfig.json': { extends: './tsconfig.base.json', include: ['src/**/*.ts'] },
    'src/use.ts':
      "import { Pool } from 'pg';\n" +
      "import { helper } from '@app/db';\n" +
      'const pool = new Pool();\n' +
      "export async function go() { return [await pool.query('x'), await helper.query('y')]; }\n",
  });
  const { sites, cfg } = retrieveFrom(dir);
  assert.deepStrictEqual(sites.map((r) => `${r.client_type}.${r.func}`), ['pg.Pool.query']);
  assert.deepStrictEqual(cfg.unmappable_specifiers, ['@app/db']);
});

test('a path alias onto in-repo source resolves through it', (t) => {
  // The alias names a workspace directory, and that directory is right here:
  // it is the package CONTENTS that are missing, not the repo's own source.
  // Following the alias into it is what the checker does too.
  const dir = writeTree(t, 'tsx-inrepo-', {
    'package.json': { name: 'i', dependencies: { pg: '^8' } },
    'tsconfig.json': {
      compilerOptions: { baseUrl: '.', paths: { '@app/*': ['packages/*/src'] } },
    },
    'packages/db/src/index.ts': "import { Pool } from 'pg';\nexport const pool = new Pool();\n",
    'src/use.ts':
      "import { pool } from '@app/db';\nexport async function go() { return pool.query('x'); }\n",
  });
  const { sites, cfg } = retrieveFrom(dir);
  assert.deepStrictEqual(
    sites.map((r) => `${r.file_path}:${r.client_type}.${r.func}`),
    ['src/use.ts:pg.Pool.query'],
    JSON.stringify(sites.map((r) => [r.file_path, r.client_type, r.func])),
  );
  assert.deepStrictEqual(cfg.unmappable_specifiers, []);
});

// --- the abstain's install advice (po-av01j.170) ---
//
// tsindex reads node_modules for TYPE RESOLUTION only: it never loads or runs
// a package. So the install it asks for must not be one that runs every
// package's install scripts. A plain `npm ci` fails outright on a repo whose
// native dependency cannot build on the user's toolchain (Online Boutique's
// `pprof` on node 24), and asks someone who only wants a SCAN to execute
// code from hundreds of packages.

// A tree that abstains (its only external import is a wildcard re-export)
// beside the package it depends on, whose install script cannot succeed.
function treeWithUnbuildableDependency(t) {
  const dir = writeTree(t, 'tsx-native-', {
    'dep/package.json': {
      name: 'nativeclient',
      version: '1.0.0',
      types: 'index.d.ts',
      scripts: { install: 'node -e "process.exit(1)"' },
    },
    'dep/index.d.ts': 'export class Client { query(sql: string): Promise<string>; }\n',
    'app/package.json': { name: 'app', dependencies: { nativeclient: 'file:../dep' } },
    'app/src/clients.ts': "export * from 'nativeclient';\n",
    'app/src/use.ts':
      "import { Client } from './clients';\n" +
      'const client = new Client();\n' +
      "export async function go() { return client.query('SELECT 1'); }\n",
  });
  return path.join(dir, 'app');
}

function abstainMessage(root) {
  try {
    run('--retrieve', '--root', root);
  } catch (e) {
    assert.strictEqual(e.status, 3, String(e.stderr));
    return String(e.stderr);
  }
  return assert.fail('expected the abstain exit');
}

test('the abstain advises the script-free install first, and says why', (t) => {
  const msg = abstainMessage(treeWithUnbuildableDependency(t));
  for (const form of [
    'npm ci --ignore-scripts',
    'pnpm install --frozen-lockfile --ignore-scripts',
    'yarn install --immutable --mode=skip-build',
  ]) {
    assert.ok(msg.includes(form), `the abstain must name \`${form}\`: ${msg}`);
  }
  // The reason, in one line: what makes skipping the scripts safe to advise.
  assert.match(msg, /only to resolve types/);
  // The plain form survives as the FALLBACK, after the script-free one.
  const plain = msg.search(/npm ci(?! --ignore-scripts)/);
  assert.ok(plain > msg.indexOf('npm ci --ignore-scripts'), msg);
});

test('a script-free install resolves the abstain where the plain install fails', (t) => {
  const app = treeWithUnbuildableDependency(t);
  const npm = (...args) => {
    try {
      execFileSync(
        'npm',
        ['install', '--install-links', '--offline', '--no-audit', '--no-fund', ...args],
        { cwd: app, encoding: 'utf8', stdio: 'pipe' },
      );
      return 0;
    } catch (e) {
      if (e.code === 'ENOENT') return null;
      return e.status;
    }
  };
  const plain = npm();
  if (plain === null) return t.skip('npm is not on PATH');
  assert.notStrictEqual(plain, 0, 'the dependency must fail to build for this to prove anything');
  abstainMessage(app);

  assert.strictEqual(npm('--ignore-scripts'), 0);
  const { sites, cfg } = retrieveFrom(app);
  assert.deepStrictEqual(
    sites.map((r) => `${r.client_type}.${r.func}`),
    ['nativeclient.Client.query'],
  );
  assert.strictEqual(cfg.dependency_trees_uninstalled, 0);
});

// --- Misuse shapes: missing_await (po-6c0v8.16) ------------------------------
//
// A call whose type is a thenable, made as a statement, is the missing_await
// fact. It rides the same stream as an AGGREGATE stamped
// site_kind: "misuse_shape": one packet per (enclosing function, class,
// identity), with the class and the count in const_args.

function misuseRecords(root) {
  const recs = root ? retrieveFrom(root).sites : retrieveRecords();
  return recs.filter((r) => r.site_kind === 'misuse_shape');
}

function misuseIn(records, symbol, identity) {
  return records.filter((r) => r.symbol === symbol && r.client_type === identity);
}

test('a floating promise is one missing_await packet per function and identity', () => {
  const misuse = misuseRecords();
  const promise = misuseIn(misuse, 'floats', 'promise');
  assert.strictEqual(promise.length, 1, JSON.stringify(misuse));
  const rec = promise[0];
  assert.strictEqual(constByName(rec, 'misuse_class'), 'missing_await');
  // save(id), audit('saved'), (save(id + 1)), and the one-argument .then
  assert.strictEqual(constByName(rec, 'misuse_count'), '4');
  for (const a of rec.const_args) assert.strictEqual(a.how, 'aggregate');
  // The line and the snippet are those of the first occurrence.
  assert.strictEqual(rec.file_path, 'src/floating.ts');
  assert.strictEqual(rec.snippet, 'save(id)');
  assert.strictEqual(rec.func, 'save');
  const src = fs.readFileSync(path.join(FIXTURE_ROOT, 'src', 'floating.ts'), 'utf8').split('\n');
  assert.strictEqual(src[rec.line_number - 1].trim(), 'save(id);');
  // An aggregate carries no body and no call graph, and it is not a client.
  assert.strictEqual(rec.receiver, '');
  assert.strictEqual(rec.enclosing_function_body, '');
  assert.deepStrictEqual(rec.callers, []);
  assert.deepStrictEqual(rec.callees, []);
  assert.deepStrictEqual(rec.client_construction, []);
  assert.strictEqual(rec.macro_expansion, false);
  assert.strictEqual(rec.packet_schema, 2);
  assert.strictEqual(rec.lang, 'typescript');
  assert.strictEqual(rec.provenance.client_type_resolved, true);
  assert.strictEqual(rec.site_key, `${rec.file_path}:${rec.line_number}:promise:save`);
});

test('a floating thenable that is not a Promise has its own identity', () => {
  const misuse = misuseRecords();
  const thenable = misuseIn(misuse, 'floats', 'thenable');
  assert.strictEqual(thenable.length, 1, JSON.stringify(misuse));
  assert.strictEqual(constByName(thenable[0], 'misuse_class'), 'missing_await');
  assert.strictEqual(constByName(thenable[0], 'misuse_count'), '1');
  assert.strictEqual(thenable[0].snippet, "rows('users')");
  assert.strictEqual(thenable[0].func, 'rows');
});

test('a floating promise from a method call is reported in its own function', () => {
  const close = misuseIn(misuseRecords(), 'close', 'promise');
  assert.strictEqual(close.length, 1);
  assert.strictEqual(constByName(close[0], 'misuse_count'), '1');
  assert.strictEqual(close[0].func, 'flush');
});

test('a promise that is awaited, returned, assigned, voided or handled is not a fact', () => {
  const misuse = misuseRecords();
  // `bounded` holds the bounded form of each identity, a call that is not a
  // thenable, and a call with no type. `settled` returns from an arrow body.
  for (const symbol of ['bounded', 'settled']) {
    assert.deepStrictEqual(misuse.filter((r) => r.symbol === symbol), []);
  }
  // The fixture has no other floating call: these four packets are all.
  assert.deepStrictEqual(
    misuse.map((r) => `${r.symbol}:${r.client_type}`).sort(),
    ['close:promise', 'floats:promise', 'floats:thenable', 'generic:promise'],
  );
});

test('a generic callee is judged at each call, not by the first call seen', () => {
  // pass(id) comes first and is not a thenable; pass(save(id)) is. An answer
  // cached for the callee would make the result depend on the order.
  const generic = misuseIn(misuseRecords(), 'generic', 'promise');
  assert.strictEqual(generic.length, 1);
  assert.strictEqual(constByName(generic[0], 'misuse_count'), '1');
  assert.strictEqual(generic[0].snippet, 'pass(save(id))');
});

test('misuse packets do not leak into the client lane or the emission lane', () => {
  const others = retrieveRecords().filter(
    (r) => r.file_path === 'src/floating.ts' && r.site_kind !== 'misuse_shape',
  );
  assert.deepStrictEqual(others, []);
});

test('an uninstalled tree reports the same floating promises of in-repo functions', (t) => {
  const got = misuseRecords(fixtureWithoutNodeModules(t));
  assert.deepStrictEqual(
    got.map((r) => `${r.symbol}:${r.client_type}:${constByName(r, 'misuse_count')}`).sort(),
    ['close:promise:1', 'floats:promise:4', 'floats:thenable:1', 'generic:promise:1'],
  );
});
