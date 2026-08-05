// G2 server-entry surface the checker resolves classpath-lessly: the JDK's own
// com.sun.net.httpserver route registration.
package com.example;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;

class Web {
    void start() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api", exchange -> exchange.close());
    }
}
