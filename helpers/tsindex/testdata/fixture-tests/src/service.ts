// Production code: one strong I/O verb on an untyped receiver. Emitted at
// low confidence, which is all this fixture needs -- the question here is
// WHICH FILES are read, not how well a receiver resolves.
export function ping(client: any) {
  return client.post('/ping');
}
