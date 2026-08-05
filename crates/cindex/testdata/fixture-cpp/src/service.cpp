// C++ fixture: the three typing tiers the cindex golden tests pin down.
//
//   1. virtual dispatch  -> emitted at the STATIC interface identity, mid tier
//                           (callee_candidates counts the in-TU definitions)
//   2. gRPC-style stub   -> emitted by `::Stub` type identity
//   3. uninstantiated template -> dependent callee, never emitted (abstention)
#include "rpc/greeter_stub.h"

namespace app {

class Backend {
 public:
  virtual ~Backend() = default;
  virtual int fetch(const char *key) = 0;
};

class HttpBackend : public Backend {
 public:
  int fetch(const char *key) override { return 1; }
};

class CacheBackend : public Backend {
 public:
  int fetch(const char *key) override { return 2; }
};

int read_through(Backend &b) {
  return b.fetch("users:7");  // virtual dispatch: 3 in-TU definitions
}

template <typename C>
int generic_talk(C &client) {
  return client.query("SELECT 1");  // dependent: abstain, never guessed
}

int call_stub(helloworld::Greeter::Stub &stub) {
  helloworld::Status s = stub.SayHello("hi");
  return s.code;
}

}  // namespace app
