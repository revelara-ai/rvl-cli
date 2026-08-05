// Minimal hand-written stub (the javaindex analog of tsindex's vendored .d.ts
// stubs): enough surface for the fixture to type-check okhttp3 identities with
// zero network and no real dependency. Tracked on purpose.
package okhttp3;

public class OkHttpClient {
    public OkHttpClient() {}

    public Call newCall(Request request) {
        return new Call();
    }

    public static class Builder {
        public Builder() {}

        public Builder connectTimeout(long timeout, java.util.concurrent.TimeUnit unit) {
            return this;
        }

        public Builder readTimeout(long timeout, java.util.concurrent.TimeUnit unit) {
            return this;
        }

        public OkHttpClient build() {
            return new OkHttpClient();
        }
    }
}
