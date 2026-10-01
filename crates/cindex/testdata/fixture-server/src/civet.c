/* civetweb fixture: planted G2 server-entry registrations. */
#include "civetweb.h"

static int health(struct mg_connection *conn, void *cbdata) {
  (void)conn;
  (void)cbdata;
  return 200;
}

static int users(struct mg_connection *conn, void *cbdata) {
  (void)conn;
  (void)cbdata;
  return 200;
}

int serve(const char *dynamic_uri) {
  struct mg_context *ctx = mg_start(0, 0, 0);
  mg_set_request_handler(ctx, "/healthz", health, 0);
  mg_set_request_handler(ctx, dynamic_uri, users, 0);
  return 0;
}
