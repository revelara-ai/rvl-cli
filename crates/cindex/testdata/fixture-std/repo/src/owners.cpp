// C++ fixture: accessors of the standard-library ownership and reference
// wrappers are not client calls. Each one below hands back what the wrapper
// already holds and does no I/O, so none is a site. std::future<T>::get
// blocks until the result is ready, so it stays a site.
//
// The standard headers sit in ../sysroot, outside the scan root, as they do
// in a real build: that is what makes the weak verb `get` a candidate.
#include <functional>
#include <future>
#include <memory>
#include <optional>

namespace app {

struct Conn {
  int fd;
};

Conn *borrow(std::unique_ptr<Conn> &p) {
  return p.get();  // accessor: not a site
}

Conn *borrow_shared(std::shared_ptr<Conn> &p) {
  return p.get();  // accessor on the __shared_ptr base: not a site
}

int upgrade(std::weak_ptr<Conn> &w) {
  return w.lock().get()->fd;  // lock and get: not sites
}

Conn &unwrap(std::reference_wrapper<Conn> &r) {
  return r.get();  // accessor: not a site
}

int unwrap_optional(std::optional<int> &o) {
  return o.value();  // accessor: not a site
}

int await_result(std::future<int> &f) {
  return f.get();  // blocks until the result is ready: a site
}

}  // namespace app
