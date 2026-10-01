/* No-compile-db server entry: the registration name is a unique unmangled C
 * identifier, so it is inventoried at LOW tier like the client allowlist. */
int serve(void *ctx) {
  mg_set_request_handler(ctx, "/healthz", 0, 0);
  return 0;
}
