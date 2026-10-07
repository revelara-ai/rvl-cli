/* C fixture: the planted G3 background-job site for the cindex golden tests.
 * pthread_create is the registration; the worker loop body is NOT analyzed
 * (registrations only), and join/detach are lifecycle calls, not sites. */
#include <pthread.h>

static void *drain_queue(void *arg) {
  for (;;) {
  }
  return arg;
}

int start_workers(void) {
  pthread_t tid;
  int rc = pthread_create(&tid, 0, drain_queue, 0);
  if (rc != 0) {
    return rc;
  }
  return pthread_detach(tid);
}
