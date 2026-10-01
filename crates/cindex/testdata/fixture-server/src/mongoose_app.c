/* mongoose fixture: the listener registration and its event handler. */
#include "mongoose.h"

static void ev_handler(struct mg_connection *c, int ev, void *ev_data) {
  struct mg_http_message *hm = (struct mg_http_message *)ev_data;
  (void)c;
  (void)ev;
  if (mg_match(hm->uri, mg_str("/api/health"), 0)) {
    return;
  }
  if (mg_http_match_uri(hm, "/api/users")) {
    return;
  }
  /* A method match is not a route: never emitted. */
  if (mg_match(hm->method, mg_str("GET"), 0)) {
    return;
  }
}

/* The same matcher outside a registered event handler is a plain glob
 * match on some string: never emitted. */
int not_a_handler(struct mg_http_message *hm) {
  return mg_match(hm->uri, mg_str("/internal/glob"), 0);
}

int run_server(struct mg_mgr *mgr) {
  mg_http_listen(mgr, "http://0.0.0.0:8000", ev_handler, 0);
  return 0;
}
