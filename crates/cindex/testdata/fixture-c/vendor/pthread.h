/* Vendored STUB of the pthread declarations the fixture exercises, so the
 * fixture parses hermetically without system headers. */
#ifndef FIXTURE_PTHREAD_H
#define FIXTURE_PTHREAD_H

typedef unsigned long pthread_t;
typedef struct pthread_attr pthread_attr_t;

int pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                   void *(*start_routine)(void *), void *arg);
int pthread_join(pthread_t thread, void **retval);
int pthread_detach(pthread_t thread);

#endif /* FIXTURE_PTHREAD_H */
