// Constructions of objects that take a bound when they are built: a pg
// connection pool and an lru-cache. Each is one unsized_construction packet
// that lists the options AS WRITTEN. The retriever decides nothing: a bounded
// construction is a packet that lists its bound.
import { Pool } from 'pg';
import * as pg from 'pg';
import { LRUCache } from 'lru-cache';
import LRU from 'lru-cache';

const POOL_MAX = 20;

interface Settings {
  poolSize: number;
  cacheOptions: { max?: number };
}

export function unsizedPool() {
  return new Pool({ connectionString: 'postgres://localhost/app' });
}

export function defaultPool() {
  return new Pool();
}

export function boundedPool() {
  return new Pool({ connectionString: 'postgres://localhost/app', max: 10 });
}

export function constantPool() {
  return new pg.Pool({ max: POOL_MAX });
}

export function namedPool(settings: Settings) {
  return new Pool({ max: settings.poolSize });
}

export function hiddenPoolOptions(base: { connectionString: string }) {
  return new Pool({ ...base });
}

export function unsizedCache() {
  return new LRUCache<string, string>({ ttl: 60000 });
}

export function boundedCache() {
  return new LRUCache<string, string>({ max: 500 });
}

export function sizedCache() {
  return new LRUCache<string, Buffer>({ maxSize: 1048576, sizeCalculation: (v) => v.length });
}

export function defaultImportCache() {
  return new LRU<string, string>();
}

export function numericCache() {
  return new LRU<string, string>(500);
}

export function passedCacheOptions(settings: Settings) {
  return new LRUCache<string, string>(settings.cacheOptions);
}

export function shorthandCache(max: number) {
  return new LRUCache<string, string>({ max });
}

// A local class that only LOOKS like a pool is never guessed at.
class Pool2 {
  constructor(public options?: { max?: number }) {}
}

export function notAConstruction() {
  class LRUCache {}
  return [new Pool2(), new LRUCache()];
}
