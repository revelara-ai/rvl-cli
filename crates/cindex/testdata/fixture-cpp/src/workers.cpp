// C++ fixture: the planted G3 background-job sites for the cindex golden
// tests. Constructing a std::thread / std::jthread WITH a callable is the
// registration. The default constructor starts nothing and the move
// constructor only transfers a thread that is already running, so neither
// is a site.
#include <thread>

namespace app {

void poll_forever() {
  for (;;) {
  }
}

void start_poller() {
  std::thread worker(poll_forever);
  worker.detach();
}

void start_temporary() {
  std::thread([] { poll_forever(); }).detach();
}

void start_joining() {
  std::jthread worker(poll_forever);
}

void not_registrations(std::thread running) {
  std::thread idle;
  std::thread moved(static_cast<std::thread &&>(running));
  idle.join();
  moved.join();
}

}  // namespace app
