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

test('non-client noise is not emitted', () => {
  const records = retrieveRecords();
  const methods = new Set(records.map((r) => r.func));
  for (const noise of ['push', 'map', 'toString']) {
    assert.ok(!methods.has(noise), `noise method ${noise} must not be a site`);
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
