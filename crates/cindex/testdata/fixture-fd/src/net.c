/* fd dataflow fixture: POSIX read/write are emitted only when the fd has
 * socket evidence in the SAME function. The function names say what the
 * golden test expects of each. */
#include "proto.h"

/* Initialized from socket(): both calls are socket I/O. */
long socket_init_fd(const struct sockaddr *peer) {
  char buf[8];
  int s = socket(2, 1, 0);
  connect(s, peer, (socklen_t)sizeof *peer);
  write(s, "hello", 5);
  return read(s, buf, sizeof buf);
}

/* Assigned (not initialized) from accept(). */
long accepted_fd(int listener) {
  char buf[8];
  int c;
  c = accept(listener, 0, 0);
  return read(c, buf, sizeof buf);
}

/* A parameter that this function also hands to send(): a socket. */
long param_used_as_socket(int sock) {
  char buf[8];
  send(sock, "x", 1, 0);
  return read(sock, buf, sizeof buf);
}

/* A parameter with no evidence either way: abstain. */
long param_unknown(int fd) {
  char buf[8];
  return read(fd, buf, sizeof buf);
}

/* One variable holding a socket and then a file: conflicting, abstain. */
long reused_variable(const char *path) {
  char buf[8];
  int fd = socket(2, 1, 0);
  close(fd);
  fd = open(path, 0);
  return read(fd, buf, sizeof buf);
}

long ping(int sock) { return proto_ping(sock); }
