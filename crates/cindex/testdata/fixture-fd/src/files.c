/* The file-fd half of the fixture: nothing here is socket I/O. */
#include "proto.h"

long file_fd(const char *path) {
  char buf[8];
  int fd = open(path, 0);
  write(fd, "x", 1);
  return read(fd, buf, sizeof buf);
}

struct conn {
  int fd;
};

/* A struct member: provenance is outside local dataflow, abstain. */
long member_fd(struct conn *c) {
  char buf[8];
  return read(c->fd, buf, sizeof buf);
}
