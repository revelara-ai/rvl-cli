/* Vendored STUB of the civetweb surface the fixture exercises. */
#ifndef FIXTURE_CIVETWEB_H
#define FIXTURE_CIVETWEB_H

struct mg_context;
struct mg_connection;
typedef int (*mg_request_handler)(struct mg_connection *conn, void *cbdata);

struct mg_context *mg_start(const void *callbacks, void *user_data,
                            const char **options);
void mg_set_request_handler(struct mg_context *ctx, const char *uri,
                            mg_request_handler handler, void *cbdata);

#endif /* FIXTURE_CIVETWEB_H */
