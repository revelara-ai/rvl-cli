/* Vendored STUB of the hiredis surface the fixture exercises. */
#ifndef FIXTURE_HIREDIS_H
#define FIXTURE_HIREDIS_H

typedef struct redisContext {
  int err;
} redisContext;

redisContext *redisConnect(const char *ip, int port);
void *redisCommand(redisContext *c, const char *format, ...);

#endif /* FIXTURE_HIREDIS_H */
