// javaindex test harness. Plain Java (no JUnit -- the helper's toolchain rule
// is "a JDK and nothing else"), run from helpers/javaindex:
//
//     java test/JavaIndexTest.java
//
// It spawns the helper as a subprocess (`java javaindex.java ...`), exactly
// the way rvl invokes it, and asserts the properties every consumer
// depends on: schema stamped, site_key unique and equal to the
// file:line:client_type:func formula, typed vs import-attributed vs
// unresolved confidence behavior, the G2/G3/G4 site kinds, const_args
// evidence, the repo_config record, and full-load vs --files retrieval
// invariance.

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

class JavaIndexTest {

    static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (!Files.isRegularFile(Paths.get("javaindex.java"))) {
            System.err.println("run from helpers/javaindex: java test/JavaIndexTest.java");
            System.exit(2);
        }

        // --packet-schema negotiation before any load.
        String schema = run("--packet-schema").trim();
        check("2".equals(schema), "--packet-schema prints 2, got " + schema);

        List<Map<String, Object>> all = retrieve("--retrieve", "--root", "testdata/fixture",
                "--name", "fx");
        List<Map<String, Object>> sites = new ArrayList<>();
        Map<String, Object> repoConfig = null;
        for (Map<String, Object> rec : all) {
            if ("repo_config".equals(rec.get("kind"))) {
                repoConfig = rec;
            } else {
                sites.add(rec);
            }
        }

        // --- shared packet invariants ---
        check(repoConfig != null, "exactly one repo_config record rides the stream");
        Set<String> keys = new HashSet<>();
        for (Map<String, Object> s : sites) {
            check(((Long) s.get("packet_schema")) == 2L,
                    "packet_schema stamped on " + s.get("site_key"));
            check("java".equals(s.get("lang")), "lang is java on " + s.get("site_key"));
            check(Boolean.FALSE.equals(s.get("macro_expansion")),
                    "macro_expansion false on " + s.get("site_key"));
            String expect = s.get("file_path") + ":" + s.get("line_number") + ":"
                    + s.get("client_type") + ":" + s.get("func");
            check(expect.equals(s.get("site_key")),
                    "site_key formula: want " + expect + " got " + s.get("site_key"));
            check(keys.add((String) s.get("site_key")),
                    "site_key unique: " + s.get("site_key"));
        }

        // --- G1: JDK platform types resolve classpath-lessly at tier high ---
        Map<String, Object> jdbc = byTypeFunc(sites, "java.sql.PreparedStatement", "executeQuery");
        check(jdbc != null, "JDBC executeQuery is a site");
        if (jdbc != null) {
            check("high".equals(tier(jdbc)), "JDBC site resolves at tier high");
            check(Boolean.TRUE.equals(prov(jdbc).get("client_type_resolved")),
                    "JDBC client_type_resolved");
            check("".equals(siteKind(jdbc)), "JDBC site is a classic G1 site");
        }
        Map<String, Object> http = byTypeFunc(sites, "java.net.http.HttpClient", "send");
        check(http != null, "java.net.http send is a site");
        if (http != null) {
            List<?> ctors = (List<?>) http.get("client_construction");
            check(!ctors.isEmpty(), "http.send cites its field construction");
            if (!ctors.isEmpty()) {
                String source = (String) ((Map<?, ?>) ctors.get(0)).get("source");
                check(source.contains("connectTimeout"),
                        "the cited construction shows the connectTimeout config");
            }
        }

        // --- G1: stub-typed third-party resolution (the tsindex .d.ts analog) ---
        Map<String, Object> okCall = byTypeFunc(sites, "okhttp3.Call", "execute");
        check(okCall != null, "stub-typed okhttp3.Call.execute is a site");
        if (okCall != null) {
            check("high".equals(tier(okCall)), "stub-typed site is tier high");
        }

        // --- G1: import attribution keeps a weak verb alive on a no-stub client ---
        Map<String, Object> jedis = byTypeFunc(sites, "redis.clients.jedis.Jedis", "get");
        check(jedis != null, "import-attributed Jedis.get survives (weak verb, resolved identity)");
        if (jedis != null) {
            check("high".equals(tier(jedis)), "import-attributed site is tier high");
            check(hasConstArg(jedis, "\"user:1\"", "literal"),
                    "jedis.get carries its literal key as a const_arg");
            check(!((List<?>) jedis.get("client_construction")).isEmpty(),
                    "jedis.get cites the new Jedis(...) construction");
        }

        // --- G1: unresolved receiver + strong verb emits at tier low ---
        Map<String, Object> unknown = byTypeFunc(sites, "", "execute");
        check(unknown != null, "unresolved strong-verb call still emits (abstain-friendly)");
        if (unknown != null) {
            check("low".equals(tier(unknown)), "unresolved site is tier low");
            check(Boolean.FALSE.equals(prov(unknown).get("client_type_resolved")),
                    "unresolved site reports client_type_resolved false");
            check(hasConstArg(unknown, "\"REFRESH MATERIALIZED VIEW users_mv\"", "named_constant"),
                    "the folded REFRESH_SQL constant rides const_args as named_constant");
        }

        // --- G1: noise never emits ---
        for (Map<String, Object> s : sites) {
            String f = (String) s.get("func");
            check(!f.equals("add") && !f.equals("trim") && !f.equals("next"),
                    "container/string noise must not emit: " + s.get("site_key"));
        }

        // --- G2 server entries ---
        Map<String, Object> spring = byTypeFunc(sites,
                "org.springframework.web.bind.annotation.GetMapping", "GetMapping");
        check(spring != null, "@GetMapping (wildcard import) is a server_entry");
        if (spring != null) {
            check("server_entry".equals(siteKind(spring)), "@GetMapping site_kind");
            check(hasConstArg(spring, "\"/users/{id}\"", "literal"),
                    "the route path rides const_args");
        }
        Map<String, Object> reqMap = byTypeFunc(sites,
                "org.springframework.web.bind.annotation.RequestMapping", "RequestMapping");
        check(reqMap != null && "server_entry".equals(siteKind(reqMap)),
                "@RequestMapping is a server_entry");
        if (reqMap != null) {
            check(hasNamedConstArg(reqMap, "path", "\"/health\""),
                    "@RequestMapping(path=...) keeps the argument NAME on const_args");
        }
        Map<String, Object> jaxrs = byTypeFunc(sites, "javax.ws.rs.GET", "GET");
        check(jaxrs != null && "server_entry".equals(siteKind(jaxrs)),
                "JAX-RS @GET (single import) is a server_entry");
        Map<String, Object> jdkServer = byTypeFunc(sites,
                "com.sun.net.httpserver.HttpServer", "createContext");
        check(jdkServer != null && "server_entry".equals(siteKind(jdkServer)),
                "HttpServer.createContext (JDK-typed) is a server_entry");

        // --- G3 background jobs ---
        Map<String, Object> ses = byTypeFunc(sites,
                "java.util.concurrent.ScheduledExecutorService", "scheduleAtFixedRate");
        check(ses != null && "background_job".equals(siteKind(ses)),
                "ScheduledExecutorService.scheduleAtFixedRate is a background_job");
        Map<String, Object> timer = byTypeFunc(sites, "java.util.Timer", "schedule");
        check(timer != null && "background_job".equals(siteKind(timer)),
                "Timer.schedule is a background_job");
        Map<String, Object> quartz = byTypeFunc(sites, "org.quartz.Scheduler", "scheduleJob");
        check(quartz != null && "background_job".equals(siteKind(quartz)),
                "quartz scheduleJob (import-attributed) is a background_job");
        List<Map<String, Object>> scheduled = allByType(sites,
                "org.springframework.scheduling.annotation.Scheduled");
        check(scheduled.size() == 2, "both @Scheduled registrations are background_job sites, got "
                + scheduled.size());
        boolean sawBounded = false;
        for (Map<String, Object> s : scheduled) {
            check("background_job".equals(siteKind(s)), "@Scheduled site_kind");
            String body = (String) s.get("enclosing_function_body");
            if (body.contains("@Transactional(timeout = 30)")) {
                sawBounded = true;
            }
        }
        check(sawBounded, "the bounded @Scheduled record carries the neighbouring "
                + "@Transactional(timeout=30) in its enclosing source");
        for (Map<String, Object> s : scheduled) {
            if (((String) s.get("enclosing_function_body")).contains("fixedRate")) {
                check(hasNamedConstArg(s, "fixedRate", "5000"),
                        "@Scheduled(fixedRate = 5000) rides const_args with its name");
            }
        }

        // --- G4 emission aggregates ---
        Map<String, Object> slf4jLog = emissionAgg(sites, "org.slf4j.Logger", "log");
        check(slf4jLog != null, "slf4j (import-attributed) aggregates under category log");
        if (slf4jLog != null) {
            check("2".equals(emissionCount(slf4jLog)),
                    "two off-error-path slf4j calls aggregate to count 2");
        }
        Map<String, Object> slf4jErr = emissionAgg(sites, "org.slf4j.Logger", "error_capture");
        check(slf4jErr != null, "a log emission ON the error path recategorizes to error_capture");
        Map<String, Object> julLog = emissionAgg(sites, "java.util.logging.Logger", "log");
        check(julLog != null, "JUL (JDK-typed) aggregates under category log");
        Map<String, Object> sentry = emissionAgg(sites, "io.sentry.Sentry", "error_capture");
        check(sentry != null, "Sentry.captureException aggregates under error_capture");
        Map<String, Object> swallow = emissionAgg(sites, "catch_clause", "error_capture");
        check(swallow != null, "the swallowing catch aggregates under catch_clause");
        if (swallow != null) {
            check("1".equals(emissionCount(swallow)), "exactly one swallowing catch in the fixture");
            check("catch".equals(swallow.get("func")), "swallow func is `catch`");
        }
        for (Map<String, Object> s : sites) {
            if ("emission_point".equals(siteKind(s))) {
                check("".equals(s.get("enclosing_function_body")),
                        "emission aggregates omit function bodies (volume control)");
            }
        }

        // --- repo_config constructions ---
        if (repoConfig != null) {
            List<?> ctors = (List<?>) repoConfig.get("constructions");
            check(hasConstruction(ctors, "java.net.http.HttpClient", "connectTimeout"),
                    "HttpClient.newBuilder().connectTimeout(...) rides repo_config");
            check(hasConstruction(ctors, "okhttp3.OkHttpClient", "readTimeout"),
                    "new OkHttpClient.Builder().readTimeout(...) rides repo_config "
                            + "(.Builder folds onto the built type)");
        }

        // --- retrieval invariance: --files emits the same packets for a file ---
        List<Map<String, Object>> onlyService = retrieve("--retrieve", "--root",
                "testdata/fixture", "--name", "fx", "--files", "src/com/example/Service.java");
        List<String> fullServiceKeys = new ArrayList<>();
        for (Map<String, Object> s : sites) {
            if ("src/com/example/Service.java".equals(s.get("file_path"))) {
                fullServiceKeys.add((String) s.get("site_key"));
            }
        }
        List<String> incServiceKeys = new ArrayList<>();
        for (Map<String, Object> s : onlyService) {
            if (s.containsKey("kind")) {
                continue; // repo_config rides every run
            }
            check("src/com/example/Service.java".equals(s.get("file_path")),
                    "--files restricts output to the listed file, got " + s.get("file_path"));
            incServiceKeys.add((String) s.get("site_key"));
        }
        check(fullServiceKeys.equals(incServiceKeys),
                "full-load and --files retrieval agree per file (invariance): full="
                        + fullServiceKeys + " inc=" + incServiceKeys);

        if (failures > 0) {
            System.err.println(failures + " assertion(s) FAILED");
            System.exit(1);
        }
        System.out.println("javaindex tests OK (" + sites.size() + " sites)");
    }

    // --- assertions and lookups ---

    static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
            System.err.println("FAIL: " + what);
        }
    }

    static Map<String, Object> byTypeFunc(List<Map<String, Object>> sites, String type,
            String func) {
        for (Map<String, Object> s : sites) {
            if (type.equals(s.get("client_type")) && func.equals(s.get("func"))
                    && !"emission_point".equals(siteKind(s))) {
                return s;
            }
        }
        return null;
    }

    static List<Map<String, Object>> allByType(List<Map<String, Object>> sites, String type) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> s : sites) {
            if (type.equals(s.get("client_type"))) {
                out.add(s);
            }
        }
        return out;
    }

    static Map<String, Object> emissionAgg(List<Map<String, Object>> sites, String framework,
            String category) {
        for (Map<String, Object> s : sites) {
            if (!"emission_point".equals(siteKind(s)) || !framework.equals(s.get("client_type"))) {
                continue;
            }
            for (Object o : (List<?>) s.get("const_args")) {
                Map<?, ?> a = (Map<?, ?>) o;
                if ("emission_category".equals(a.get("name")) && category.equals(a.get("value"))
                        && "aggregate".equals(a.get("how"))) {
                    return s;
                }
            }
        }
        return null;
    }

    static String emissionCount(Map<String, Object> agg) {
        for (Object o : (List<?>) agg.get("const_args")) {
            Map<?, ?> a = (Map<?, ?>) o;
            if ("emission_count".equals(a.get("name"))) {
                return (String) a.get("value");
            }
        }
        return null;
    }

    static boolean hasConstArg(Map<String, Object> site, String value, String how) {
        for (Object o : (List<?>) site.get("const_args")) {
            Map<?, ?> a = (Map<?, ?>) o;
            if (value.equals(a.get("value")) && how.equals(a.get("how"))) {
                return true;
            }
        }
        return false;
    }

    static boolean hasNamedConstArg(Map<String, Object> site, String name, String value) {
        for (Object o : (List<?>) site.get("const_args")) {
            Map<?, ?> a = (Map<?, ?>) o;
            if (name.equals(a.get("name")) && value.equals(a.get("value"))) {
                return true;
            }
        }
        return false;
    }

    static boolean hasConstruction(List<?> ctors, String type, String field) {
        for (Object o : ctors) {
            Map<?, ?> c = (Map<?, ?>) o;
            if (type.equals(c.get("type")) && ((List<?>) c.get("fields")).contains(field)) {
                return true;
            }
        }
        return false;
    }

    static Map<?, ?> prov(Map<String, Object> site) {
        return (Map<?, ?>) site.get("provenance");
    }

    static String tier(Map<String, Object> site) {
        return (String) prov(site).get("confidence_tier");
    }

    static String siteKind(Map<String, Object> site) {
        Object k = site.get("site_kind");
        return k == null ? "" : (String) k;
    }

    // --- subprocess plumbing ---

    static String run(String... helperArgs) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(System.getProperty("java.home") + "/bin/java");
        cmd.add("javaindex.java");
        cmd.addAll(java.util.Arrays.asList(helperArgs));
        Process p = new ProcessBuilder(cmd).start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream is = p.getInputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        }
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        try (InputStream es = p.getErrorStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = es.read(buf)) > 0) {
                err.write(buf, 0, n);
            }
        }
        int code = p.waitFor();
        if (code != 0) {
            throw new AssertionError("helper exited " + code + ": "
                    + err.toString(StandardCharsets.UTF_8.name()));
        }
        return out.toString(StandardCharsets.UTF_8.name());
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> retrieve(String... helperArgs) throws Exception {
        List<Map<String, Object>> out = new ArrayList<>();
        for (String line : run(helperArgs).split("\n")) {
            if (line.trim().isEmpty()) {
                continue;
            }
            out.add((Map<String, Object>) new Json(line).parse());
        }
        return out;
    }

    // --- a minimal JSON reader (objects, arrays, strings, numbers, bools,
    // null), enough to decode the helper's own output ---

    static class Json {
        final String s;
        int i;

        Json(String s) {
            this.s = s;
        }

        Object parse() {
            skipWs();
            Object v = value();
            skipWs();
            if (i != s.length()) {
                throw new IllegalStateException("trailing JSON at " + i + ": " + s.substring(i));
            }
            return v;
        }

        Object value() {
            skipWs();
            char c = s.charAt(i);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (c == 't') {
                expect("true");
                return Boolean.TRUE;
            }
            if (c == 'f') {
                expect("false");
                return Boolean.FALSE;
            }
            if (c == 'n') {
                expect("null");
                return null;
            }
            return number();
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (s.charAt(i) == '}') {
                i++;
                return m;
            }
            while (true) {
                skipWs();
                String k = string();
                skipWs();
                i++; // :
                m.put(k, value());
                skipWs();
                if (s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                i++; // }
                return m;
            }
        }

        List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++; // [
            skipWs();
            if (s.charAt(i) == ']') {
                i++;
                return l;
            }
            while (true) {
                l.add(value());
                skipWs();
                if (s.charAt(i) == ',') {
                    i++;
                    continue;
                }
                i++; // ]
                return l;
            }
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            i++; // "
            while (true) {
                char c = s.charAt(i++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = s.charAt(i++);
                    switch (e) {
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default:
                            sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Object number() {
            int start = i;
            while (i < s.length() && "-+.eE0123456789".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String n = s.substring(start, i);
            if (n.contains(".") || n.contains("e") || n.contains("E")) {
                return Double.parseDouble(n);
            }
            return Long.parseLong(n);
        }

        void expect(String word) {
            if (!s.startsWith(word, i)) {
                throw new IllegalStateException("bad JSON at " + i);
            }
            i += word.length();
        }

        void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }
    }
}
