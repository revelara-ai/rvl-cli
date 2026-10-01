// Client calls whose receiver was imported from a SIBLING module rather than
// constructed here (po-pk3fp.10). Every shape a local module can hand a client
// across: a named export, a namespace import, a default export of a
// construction, and a type re-exported under another name.
import { boundedPool } from './dbconfig';
import * as dbconfig from './dbconfig';
import cache, { PgPool, boundedPool as viaBarrel } from './clients';

export async function countUsers(): Promise<unknown> {
  return boundedPool.query('SELECT count(*) FROM users');
}

export async function viaNamespace(): Promise<unknown> {
  return dbconfig.boundedPool.query('SELECT 1');
}

export async function viaReexport(): Promise<unknown> {
  return viaBarrel.query('SELECT 2');
}

export async function cached(key: string): Promise<unknown> {
  return cache.get(key);
}

export class Reports {
  constructor(private readonly db: PgPool) {}

  async run(): Promise<unknown> {
    return this.db.query('SELECT 3');
  }
}
