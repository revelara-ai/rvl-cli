// A small well-typed service exercising resolvable external-client calls
// (pg, axios, ioredis) alongside non-client noise that must NOT be indexed.
import { Pool } from 'pg';
import axios from 'axios';
import Redis from 'ioredis';

// Construction-visible clients: constructed here, used in functions below. The
// construction (and any construction-time config) is retrievable per site.
const pool = new Pool({ connectionString: 'postgres://localhost/app', max: 10 });
const redis = new Redis({ host: 'localhost', port: 6379, connectTimeout: 1000 });
const api = axios.create({ timeout: 1000, baseURL: 'https://api.example.com' });

export async function loadUser(id: number): Promise<any> {
  // pg.Pool.query -- resolved external client, high confidence.
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  // noise: Array.map / Array.push must NOT be emitted as sites.
  const ids: number[] = [];
  ids.push(id);
  return result.rows.map((r) => r.id);
}

export async function fetchProfile(id: number): Promise<any> {
  // axios default import (AxiosStatic) .get -- resolved external, high.
  const resp = await axios.get(`https://api.example.com/users/${id}`);
  // noise: Object.toString must NOT be emitted.
  const label = id.toString();
  return { data: resp.data, label };
}

export async function cachedProfile(key: string): Promise<any> {
  // TWO client calls on ONE line, SAME method `get`, DIFFERENT client_type
  // (ioredis.Redis vs axios.AxiosStatic). site_key must keep both distinct by
  // client_type. This is the po-3t3oj.15 uniqueness case.
  const combo = (await redis.get(key)) ?? (await axios.get(`/refresh/${key}`)).data;
  // axios instance (AxiosInstance) via axios.create() -- resolved external.
  const viaInstance = await api.get(`/profile/${key}`);
  return { combo, viaInstance };
}

export class Repo {
  private db: Pool;

  constructor(db: Pool) {
    this.db = db;
  }

  async find(sql: string): Promise<any> {
    // pg.Pool.query on a property receiver -- resolved external, high.
    return this.db.query(sql);
  }
}

// Unresolved receiver: a STRONG I/O verb (`execute`) on an untyped cursor still
// emits, at LOW confidence with client_type "".
export async function rawQuery(cursor: any, sql: string): Promise<any> {
  return cursor.execute(sql);
}
