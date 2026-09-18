// "test" mid-token is NOT a test convention; this file must be scanned.
export function attest(client: any) {
  return client.post('/attest');
}
