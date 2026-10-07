// Vendored STUB of glog's shape: LOG(severity) expands to a temporary
// `google::LogMessage` whose `.stream()` the statement writes into. That
// member call is the one identity every LOG statement resolves to.
#pragma once

namespace google {

struct LogStream {
  LogStream &operator<<(const char *s);
  LogStream &operator<<(int n);
};

class LogMessage {
 public:
  LogMessage(const char *file, int line);
  LogMessage(const char *file, int line, int severity);
  ~LogMessage();
  LogStream &stream();
};

}  // namespace google

#define COMPACT_GOOGLE_LOG_INFO google::LogMessage(__FILE__, __LINE__)
#define COMPACT_GOOGLE_LOG_ERROR google::LogMessage(__FILE__, __LINE__, 2)
#define LOG(severity) COMPACT_GOOGLE_LOG_##severity.stream()
