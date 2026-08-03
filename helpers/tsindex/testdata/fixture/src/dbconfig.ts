// Central client CONSTRUCTIONS with timeout-ish config, for the repo_config
// scan. No method calls here, so this file adds no per-site packets -- only the
// repo-scoped construction facts. A DI-injected DataSource/Pool built here is
// used far from these lines; only a repo-level record can carry the fact.
import { DataSource } from 'typeorm';
import { Pool } from 'pg';

// TypeORM DataSource with a NESTED `extra` bag setting query_timeout.
export const ds = new DataSource({
  type: 'postgres',
  extra: { query_timeout: 10000 },
});

// node-postgres Pool with a top-level connection timeout.
export const boundedPool = new Pool({ connectionTimeoutMillis: 5000 });

// A Pool with NO timeout-ish field: must NOT contribute a construction fact.
export const plainPool = new Pool({});
