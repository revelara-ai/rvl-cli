import * as crypto from 'node:crypto';
import { createHash } from 'crypto';
import https from 'https';
import { Pool, Client } from 'pg';

const nodeCrypto = require('crypto');

export function weakDigest(b: string) {
  return crypto.createHash('md5').update(b).digest('hex');
}

export function strongDigest(b: string) {
  return createHash('sha256').update(b).digest('hex');
}

export function namedDigest(b: string) {
  return createHash('sha1').update(b).digest('hex');
}

export function desCipher(key: Buffer) {
  return nodeCrypto.createCipheriv('des-ede3-cbc', key, null);
}

export function agent() {
  return new https.Agent({ rejectUnauthorized: false });
}

export function db() {
  const c = new Client({ host: 'db', password: 'hunter2' });
  const p = new Pool({ connectionString: 'postgres://app:hunter2@db/app', max: 5 });
  return [c, p];
}

export function trustEverything() {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

export function notAConstruction(other: { createHash(a: string): void }) {
  other.createHash('md5');
}
