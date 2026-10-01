/* Vendored STUB of the POSIX fd declarations the fixture exercises, so the
 * fixture parses hermetically without system headers. */
#ifndef FIXTURE_POSIXIO_H
#define FIXTURE_POSIXIO_H

typedef unsigned int socklen_t;

struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};

int socket(int domain, int type, int protocol);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long send(int sockfd, const void *buf, unsigned long len, int flags);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, unsigned long count);
long write(int fd, const void *buf, unsigned long count);
int close(int fd);

#endif /* FIXTURE_POSIXIO_H */
