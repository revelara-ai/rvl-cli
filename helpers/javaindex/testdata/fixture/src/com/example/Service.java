// G1 client-call surfaces: JDK-platform clients (JDBC, java.net.http) that the
// checker resolves classpath-lessly, a stub-typed third-party client (okhttp3),
// an import-attributed third-party client with no stub (jedis), an unresolved
// strong-verb receiver (Session), and container/string noise that must never
// emit.
package com.example;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import redis.clients.jedis.Jedis;

class Service {
    static final int QUERY_TIMEOUT_SECONDS = 30;
    static final String REFRESH_SQL = "REFRESH MATERIALIZED VIEW users_mv";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
    private final OkHttpClient ok = new OkHttpClient.Builder()
            .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .build();
    private final Jedis jedis = new Jedis("localhost");

    String fetchUser(Connection conn, String id) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT name FROM users WHERE id = ?");
        ps.setQueryTimeout(QUERY_TIMEOUT_SECONDS);
        ResultSet rs = ps.executeQuery();
        return rs.next() ? rs.getString(1) : null;
    }

    String fetchRemote() throws Exception {
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create("https://api.example.com/u")).build();
        HttpResponse<String> resp = http.send(request, HttpResponse.BodyHandlers.ofString());
        return resp.body();
    }

    Response fetchViaOkHttp(Request request) throws Exception {
        return ok.newCall(request).execute();
    }

    String cachedUser() {
        return jedis.get("user:1");
    }

    void runUnknown(Session session) {
        session.execute(REFRESH_SQL);
    }

    String noise(String id) {
        List<String> items = new ArrayList<>();
        items.add("x");
        Map<String, String> byId = new HashMap<>();
        byId.get("k");
        return id.trim();
    }
}
