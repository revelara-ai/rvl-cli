/* C fixture: planted G1 client-call sites for the cindex golden tests.
 * Line numbers matter to the tests only loosely (they match on method +
 * const_args), but keep the planted sites stable. */
#include "curl/curl.h"
#include "hiredis/hiredis.h"
#include "libpq-fe.h"
#include "posixnet.h"

/* A macro-wrapped call site: the perform inside expands at the use site, so
 * the emitted packet must carry macro_expansion=true (schema v2, mechanical
 * from expansion locations). */
#define CHECKED_PERFORM(h) curl_easy_perform(h)

static long fetch_users(CURL *curl, PGconn *conn, redisContext *rc, int fd) {
  curl_easy_setopt(curl, CURLOPT_URL, "https://api.example.com/users");
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
  CURLcode code = curl_easy_perform(curl);

  PGresult *res = PQexec(conn, "SELECT id FROM users");
  PQclear(res);

  void *reply = redisCommand(rc, "GET users:%d", 7);

  struct sockaddr peer = {0};
  int c = connect(fd, &peer, (socklen_t)sizeof peer);
  long n = recv(fd, &c, sizeof c, 0);

  (void)reply;
  (void)code;
  return n;
}

static int wrapped(CURL *curl) { return CHECKED_PERFORM(curl); }

int main(void) {
  CURL *h = curl_easy_init();
  PGconn *conn = PQconnectdb("dbname=fixture");
  redisContext *rc = redisConnect("127.0.0.1", 6379);
  fetch_users(h, conn, rc, 3);
  curl_easy_cleanup(h);
  return wrapped(h);
}
