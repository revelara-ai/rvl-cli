// Vendored STUB of spdlog's shape: level methods on `spdlog::logger`, the
// free functions that forward to the default logger, and the SPDLOG_* macros,
// which (as in real spdlog) expand to a `logger::log` member call.
#pragma once

namespace spdlog {

namespace level {
enum level_enum { trace, debug, info, warn, err, critical, off };
}

struct source_loc {
  const char *filename;
  int line;
  const char *funcname;
};

class logger {
 public:
  template <typename... Args>
  void log(source_loc loc, level::level_enum lvl, const char *fmt, Args &&...args) {}
  template <typename... Args>
  void info(const char *fmt, Args &&...args) {}
  template <typename... Args>
  void warn(const char *fmt, Args &&...args) {}
  template <typename... Args>
  void error(const char *fmt, Args &&...args) {}
  // Configuration, not emission.
  void set_level(level::level_enum lvl);
  void flush();
};

logger *default_logger_raw();

template <typename... Args>
void info(const char *fmt, Args &&...args) {}
void set_level(level::level_enum lvl);

}  // namespace spdlog

#define SPDLOG_LOGGER_CALL(logger, level, ...) \
  (logger)->log(spdlog::source_loc{__FILE__, __LINE__, __func__}, level, __VA_ARGS__)
#define SPDLOG_INFO(...) \
  SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::info, __VA_ARGS__)
#define SPDLOG_ERROR(...) \
  SPDLOG_LOGGER_CALL(spdlog::default_logger_raw(), spdlog::level::err, __VA_ARGS__)
