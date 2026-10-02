/* C emission fixture: syslog() free calls. The golden test pins ONE G4
 * aggregate for `serve` (two calls), and none for functions that do not emit. */
#include "syslog.h"

static int serve(int fd) {
  syslog(LOG_INFO, "serving fd %d", fd);
  if (fd < 0) {
    syslog(LOG_ERR, "bad fd %d", fd);
    return -1;
  }
  return 0;
}

static int quiet(int fd) { return fd + 1; }

int main(void) {
  openlog("daemon", 0, 0); /* configures the logger: not an emission */
  int rc = serve(quiet(2));
  closelog();
  return rc;
}
