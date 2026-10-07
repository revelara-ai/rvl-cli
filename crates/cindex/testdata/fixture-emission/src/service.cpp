// C++ emission fixture: spdlog member calls, spdlog free functions, the
// SPDLOG_* macros, and glog LOG(). The golden test pins one G4 aggregate per
// (enclosing function, framework), never one packet per log line.
#include "glog/logging.h"
#include "spdlog/spdlog.h"

namespace app {

// A user function that shares a name with a logging call but is neither in
// the global namespace nor a spdlog identity: must never be inventoried.
void syslog(int priority, const char *message) {}

int handle(spdlog::logger &log, int n) {
  log.info("handling {}", n);
  log.warn("slow request");
  SPDLOG_ERROR("failed {}", n);  // macro: expands to logger::log
  log.set_level(spdlog::level::debug);  // configuration: not an emission
  LOG(INFO) << "handled " << n;
  LOG(ERROR) << "bad request";
  return n;
}

void startup() {
  spdlog::set_level(spdlog::level::info);  // configuration: not an emission
  spdlog::info("starting");
}

void quiet(spdlog::logger &log) {
  log.flush();
  syslog(3, "app::syslog is not the libc one");
}

}  // namespace app
