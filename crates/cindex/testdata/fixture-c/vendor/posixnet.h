/* Vendored STUB of the POSIX socket declarations the fixture exercises, so
 * the fixture parses hermetically without system headers. */
#ifndef FIXTURE_POSIXNET_H
#define FIXTURE_POSIXNET_H

typedef unsigned int socklen_t;

struct sockaddr {
  unsigned short sa_family;
  char sa_data[14];
};

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
long send(int sockfd, const void *buf, unsigned long len, int flags);
long recv(int sockfd, void *buf, unsigned long len, int flags);

#endif /* FIXTURE_POSIXNET_H */
