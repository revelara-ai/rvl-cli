package gw;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class Gateway {
    private final HttpClient client = HttpClient.newHttpClient();

    abstract void close();

    private static HttpRequest request(String uri) {
        return HttpRequest.newBuilder(java.net.URI.create(uri)).build();
    }

    public HttpResponse<String> execute(String uri) throws Exception {
        return client.send(request(uri), HttpResponse.BodyHandlers.ofString());
    }

    public void shutdown() {
        close();
    }
}
