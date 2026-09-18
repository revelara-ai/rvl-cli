declare const Pool: any;
export function t(client: any) {
  const pool = new Pool({ connectionTimeoutMillis: 1 });
  return client.post('/tests/helpers.ts');
}
