/* A project header both TUs include. Its inline function holds a site, so
 * the site's file_path is this header and not either TU. */
#ifndef FIXTURE_PROTO_H
#define FIXTURE_PROTO_H

#include "posixio.h"

static inline long proto_ping(int sock) { return send(sock, "ping", 4, 0); }

#endif /* FIXTURE_PROTO_H */
