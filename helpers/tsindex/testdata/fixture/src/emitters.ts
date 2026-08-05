// G4 emission fixture (po-av01j.5): log statements, span instrumentation,
// error-capture sites, and catch clauses that log, swallow, or re-throw.
import { createLogger } from 'winston';
import { trace } from '@opentelemetry/api';
import OpenAI from 'openai';
import { Pool } from 'pg';

const logger = createLogger();
const tracer = trace.getTracer('svc');
const llm = new OpenAI();
const epool = new Pool({});

export function noisy(x: string): void {
  // Four winston.Logger calls -> ONE aggregate packet with count 4.
  logger.info('a');
  logger.warn('b');
  logger.error('c');
  logger.debug(x);
}

export async function traced(id: number): Promise<unknown> {
  const span = tracer.startSpan('load');
  const r = await epool.query('SELECT 1', [id]);
  span.end();
  return r;
}

export async function catches(sql: string): Promise<unknown> {
  try {
    return await epool.query(sql);
  } catch (err) {
    // A log emission ON the error path: category upgrades to error_capture,
    // and this catch is instrumented — never a swallow.
    logger.error('query failed', err);
    return null;
  }
}

export async function swallows(sql: string): Promise<unknown> {
  try {
    return await epool.query(sql);
  } catch (err) {
    return null; // no emission, no re-throw: the catch_clause swallow fact
  }
}

export async function rethrows(sql: string): Promise<unknown> {
  try {
    return await epool.query(sql);
  } catch (err) {
    throw err; // propagates: NOT a swallow
  }
}

export async function summarize(prompt: string): Promise<unknown> {
  // The RC-061 anchor: a G1 call site on the LLM SDK, with no surrounding
  // emission in this function.
  return llm.chat.completions.create({ model: 'gpt', input: prompt });
}

export function consoleUser(x: string): void {
  console.log('starting', x);
  console.error('oops');
}
