// Minimal stub; see OkHttpClient.java.
package okhttp3;

public class Request {
    public static class Builder {
        public Builder url(String url) {
            return this;
        }

        public Request build() {
            return new Request();
        }
    }
}
