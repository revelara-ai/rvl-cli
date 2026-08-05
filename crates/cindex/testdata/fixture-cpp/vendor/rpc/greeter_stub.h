// Vendored STUB of a gRPC-generated service stub's shape: what matters to the
// retriever is the `::Stub` nested-class identity, which generated gRPC C++
// code always carries.
#pragma once

namespace helloworld {

struct Status {
  int code;
};

class Greeter {
 public:
  class Stub {
   public:
    Status SayHello(const char *request);
  };
};

}  // namespace helloworld
