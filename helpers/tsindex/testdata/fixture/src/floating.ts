// Misuse-shape fixture (po-6c0v8.16): a call whose result is a thenable, made
// as a statement. Nothing awaits it, so its rejection has no handler and its
// work is not finished when the caller continues.

async function save(id: number): Promise<void> {
  if (id < 0) throw new Error('bad id');
}

async function audit(msg: string): Promise<string> {
  return msg;
}

function sync(id: number): number {
  return id + 1;
}

declare function untyped(id: number): any;

// A thenable that is not a Promise: the shape of a query builder.
class Query {
  then(resolve: (rows: number[]) => void): void {
    resolve([]);
  }
}

function rows(table: string): Query {
  void table;
  return new Query();
}

class Store {
  async flush(): Promise<void> {}

  async close(): Promise<void> {
    this.flush(); // a method call: `promise` again, in another function
  }
}

export async function floats(id: number): Promise<void> {
  // Four floating promises -> ONE `promise` aggregate with count 4.
  save(id);
  audit('saved');
  (save(id + 1));
  // The `.then` with one argument has no rejection handler.
  audit('x').then((m) => m.length);
  // One floating thenable -> ONE `thenable` aggregate with count 1.
  rows('users');
}

function pass<T>(x: T): T {
  return x;
}

export function generic(id: number): void {
  pass(id); // T is number: not a thenable
  pass(save(id)); // T is Promise<void>: the same callee, and a fact
}

// The bounded form of each: no packet from this function.
export async function bounded(id: number, store: Store): Promise<unknown> {
  await save(id);
  const pending = save(id);
  void save(id);
  void store;
  save(id).catch((err) => err);
  audit('x').then((m) => m, (err) => err);
  await rows('users');
  const q = rows('users');
  void rows('users');
  sync(id); // not a thenable
  untyped(id); // `any`: no type, so no fact
  await pending;
  await q;
  return save(id);
}

export const settled = (id: number): Promise<void> => save(id);
