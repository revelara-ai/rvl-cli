/* Vendored STUB of <syslog.h>: what matters to the retriever is the global
 * `syslog` identity. openlog/closelog configure the logger and emit nothing. */
#pragma once

#define LOG_ERR 3
#define LOG_INFO 6

void openlog(const char *ident, int option, int facility);
void syslog(int priority, const char *format, ...);
void closelog(void);
