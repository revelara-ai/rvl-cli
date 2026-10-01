/* Vendored STUB of the mongoose surface the fixture exercises. */
#ifndef FIXTURE_MONGOOSE_H
#define FIXTURE_MONGOOSE_H

struct mg_str {
  const char *buf;
  unsigned long len;
};
struct mg_mgr {
  int unused;
};
struct mg_connection;
struct mg_http_message {
  struct mg_str method, uri;
};
typedef void (*mg_event_handler_t)(struct mg_connection *c, int ev,
                                   void *ev_data);

struct mg_str mg_str(const char *s);
int mg_match(struct mg_str str, struct mg_str pattern, struct mg_str *caps);
int mg_http_match_uri(const struct mg_http_message *hm, const char *glob);
struct mg_connection *mg_http_listen(struct mg_mgr *mgr, const char *url,
                                     mg_event_handler_t fn, void *fn_data);

#endif /* FIXTURE_MONGOOSE_H */
