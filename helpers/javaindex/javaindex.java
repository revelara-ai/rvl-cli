// javaindex -- Java retriever helper for rvlscan.
//
// Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
// This is the Java sibling of helpers/goindex, helpers/pyindex, and
// helpers/tsindex. It emits the SAME versioned packet stream rvlscan
// consumes, for Java source.
//
// The split this enforces
//
//   Per-language work is RETRIEVAL: mechanical, semantically neutral, no
//   reliability opinion. "Here is the call site." "Here is the client this
//   receiver was constructed from." That is compiler-frontend work. JUDGEMENT
//   stays semantic -- the LLM panel now, a distilled student later. Nothing
//   here decides whether a call is bounded, retried, or safe.
//
// Engine: the JDK's own javac Compiler Tree API (com.sun.source.*, exported
// by the jdk.compiler module) driven through ToolProvider's system compiler:
// JavacTask.parse() + analyze(), Trees for positions and type mirrors. The
// helper is a single .java source file run in JEP 330 source-file mode
// (`java javaindex.java ...`), discovered by rvlscan the same way pyindex.py
// runs under python3 and tsindex.js under node. No build step, no dependency
// jars; requires a JDK (11+), not just a JRE.
//
// Degradation story (classpath-less analysis, on record):
//   The run compiles the repo WITHOUT its dependency classpath. Receivers
//   whose types live in the JDK platform itself (java.sql JDBC, java.net.http
//   HttpClient, java.util.logging, java.util.concurrent schedulers) resolve
//   fully through the checker -> confidence tier "high". Third-party
//   receivers (OkHttp, Jedis, Kafka, Spring) do NOT resolve -- javac leaves
//   an error type -- and fall back to IMPORT ATTRIBUTION: the receiver's
//   declared type name (or a static-call class identifier) matched against
//   exactly one explicit single-type import yields the dotted identity
//   (okhttp3.OkHttpClient), still tier "high" because the import binding is a
//   compiler-verified per-file fact (the pyindex import-driven model, the
//   tsindex import-binding fallback). Anything else -- a wildcard-ambiguous
//   name, a `var` with an unresolvable initializer, an unknown parameter
//   type -- lands at tier "low" with an empty client_type, and is emitted
//   ONLY when its method is a strong I/O verb (the tsindex `any` rule:
//   abstain-by-omission, a site is never guessed at). If analyze() itself
//   fails, element resolution degrades to nothing and every receiver lands
//   on the strong-verb/low path -- honest, never fabricated.
//
// callers/callees are empty in v1: per-site evidence and in-scope
// construction, not a cross-module call graph. The keys are emitted (as
// empty arrays) so the packet shape is stable and a later version can fill
// them without a schema bump.

import com.sun.source.tree.AnnotationTree;
import com.sun.source.tree.AssignmentTree;
import com.sun.source.tree.CatchTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.ImportTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.Tree;
import com.sun.source.tree.UnaryTree;
import com.sun.source.tree.VariableTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.lang.model.element.VariableElement;
import javax.lang.model.type.DeclaredType;
import javax.lang.model.type.TypeKind;
import javax.lang.model.type.TypeMirror;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

class JavaIndex {

    // PACKET_SCHEMA is the version of the emitted packet contract. rvlscan
    // absorbs helper churn behind this number: a consumer that does not know a
    // version refuses the stream rather than guessing at its shape. It MUST
    // agree with goindex's PacketSchema, pyindex's and tsindex's
    // PACKET_SCHEMA, and rvl_core::PACKET_SCHEMA.
    //
    // v2 adds const_args (constant-valued arguments at the call site) and
    // macro_expansion (always false for Java, which has no macros; mechanical
    // for C/C++). v2 is a strict superset of v1.
    static final int PACKET_SCHEMA = 2;

    // Byte cap per emitted snippet, mirroring goindex's maxSnippetBytes.
    static final int MAX_SNIPPET_BYTES = 2400;

    // Construction snippets to include per site (mirrors goindex
    // maxCtorsEmitted).
    static final int MAX_CTORS_EMITTED = 2;

    // Directories never worth descending into. `target` covers Maven output,
    // `build`/`out` cover Gradle/IDE output, `generated` covers codegen.
    static final Set<String> SKIP_DIRS = new HashSet<>(Arrays.asList(
            ".git", "node_modules", "target", "build", "out", "vendor",
            ".gradle", ".idea", "generated", "__pycache__"));

    // -----------------------------------------------------------------------
    // Client-detection policy (retrieval selection, not judgment).
    //
    // Java always resolves the JDK platform, so "the receiver resolved" is
    // not by itself the external-client signal it is in TypeScript. The
    // volume-control rule, fully mechanical:
    //   * third-party (incl. import-attributed) receivers emit every
    //     non-noise method -- the tsindex rule;
    //   * JDK platform CLIENT packages (java.sql, javax.sql, java.net,
    //     com.sun.net) emit strong or weak I/O verbs;
    //   * any other platform type (collections, streams, strings) emits
    //     strong verbs only -- which in practice is none;
    //   * unresolved receivers emit strong verbs only, at tier "low";
    //   * a resolved type ending in "Builder" is client CONFIGURATION, not a
    //     client call: its timeout-ish fields ride the repo_config record.
    // -----------------------------------------------------------------------

    static final Set<String> STRONG_IO_METHODS = new HashSet<>(Arrays.asList(
            // JDBC
            "execute", "executeQuery", "executeUpdate", "executeBatch",
            "executeLargeUpdate", "executeLargeBatch",
            // HTTP
            "send", "sendAsync",
            // messaging / queues
            "enqueue", "publish", "subscribe", "poll"));

    static final Set<String> WEAK_IO_METHODS = new HashSet<>(Arrays.asList(
            "get", "set", "put", "post", "delete", "patch", "head", "options",
            "query", "exchange", "call", "run", "read", "write", "connect",
            "invoke", "fetch", "exec"));

    // Suppressed even on a resolved third-party client: object-protocol and
    // iteration methods a real client object also carries.
    static final Set<String> NOISE_METHODS = new HashSet<>(Arrays.asList(
            "toString", "equals", "hashCode", "getClass", "clone", "close",
            "iterator", "stream", "forEach", "wait", "notify", "notifyAll"));

    // -----------------------------------------------------------------------
    // G2 server-entry surfaces (po-av01j.3 conventions).
    // Call-form registrations, keyed on the resolved/attributed receiver FQN.
    // -----------------------------------------------------------------------
    static final Map<String, Set<String>> SERVER_ENTRY_CALLS = new HashMap<>();
    static {
        SERVER_ENTRY_CALLS.put("com.sun.net.httpserver.HttpServer",
                new HashSet<>(Arrays.asList("createContext")));
        SERVER_ENTRY_CALLS.put("javax.servlet.ServletContext",
                new HashSet<>(Arrays.asList("addServlet")));
        SERVER_ENTRY_CALLS.put("jakarta.servlet.ServletContext",
                new HashSet<>(Arrays.asList("addServlet")));
    }

    // Annotation-form registrations: simple name -> candidate framework
    // packages. Attribution requires the import to bind the name to one of
    // the candidate packages (single-type import, or a wildcard import of
    // exactly that package -- the dominant Spring idiom). A same-named local
    // annotation abstains.
    static final Map<String, List<String>> SERVER_ENTRY_ANNOTATIONS = new HashMap<>();
    static {
        List<String> spring = Arrays.asList("org.springframework.web.bind.annotation");
        for (String n : Arrays.asList("RequestMapping", "GetMapping", "PostMapping",
                "PutMapping", "DeleteMapping", "PatchMapping")) {
            SERVER_ENTRY_ANNOTATIONS.put(n, spring);
        }
        List<String> jaxrs = Arrays.asList("javax.ws.rs", "jakarta.ws.rs");
        for (String n : Arrays.asList("GET", "POST", "PUT", "DELETE", "PATCH",
                "HEAD", "OPTIONS")) {
            SERVER_ENTRY_ANNOTATIONS.put(n, jaxrs);
        }
    }

    // -----------------------------------------------------------------------
    // G3 background-job surfaces (po-av01j.4 conventions).
    // -----------------------------------------------------------------------
    static final Map<String, Set<String>> JOB_CALLS = new HashMap<>();
    static {
        Set<String> sched = new HashSet<>(Arrays.asList(
                "schedule", "scheduleAtFixedRate", "scheduleWithFixedDelay"));
        JOB_CALLS.put("java.util.concurrent.ScheduledExecutorService", sched);
        JOB_CALLS.put("java.util.concurrent.ScheduledThreadPoolExecutor", sched);
        JOB_CALLS.put("java.util.Timer",
                new HashSet<>(Arrays.asList("schedule", "scheduleAtFixedRate")));
        JOB_CALLS.put("org.quartz.Scheduler",
                new HashSet<>(Arrays.asList("scheduleJob")));
    }

    static final Map<String, List<String>> JOB_ANNOTATIONS = new HashMap<>();
    static {
        JOB_ANNOTATIONS.put("Scheduled",
                Arrays.asList("org.springframework.scheduling.annotation"));
    }

    // -----------------------------------------------------------------------
    // G4 emission-point surfaces (po-av01j.5 conventions). Aggregates, one
    // per (enclosing function, framework identity, category); a log emission
    // on an error path recategorizes to error_capture (the pyindex rule); a
    // catch clause with no recognized emission and no throw aggregates under
    // the `catch_clause` identity (the Java sibling of except_handler /
    // recover_block).
    // -----------------------------------------------------------------------
    static final String SITE_KIND_SERVER_ENTRY = "server_entry";
    static final String SITE_KIND_BACKGROUND_JOB = "background_job";
    static final String SITE_KIND_EMISSION = "emission_point";

    static final Set<String> EMISSION_LOG_TYPES = new HashSet<>(Arrays.asList(
            "org.slf4j.Logger", "org.apache.logging.log4j.Logger",
            "org.apache.log4j.Logger", "java.util.logging.Logger"));
    static final Set<String> EMISSION_LOG_METHODS = new HashSet<>(Arrays.asList(
            "trace", "debug", "info", "warn", "error", "fatal", "log",
            "severe", "warning", "config", "fine", "finer", "finest"));
    static final Set<String> EMISSION_TRACE_METHODS = new HashSet<>(Arrays.asList(
            "spanBuilder", "startSpan"));
    static final Set<String> EMISSION_CAPTURE_METHODS = new HashSet<>(Arrays.asList(
            "captureException", "captureMessage", "captureEvent"));

    // Timeout-ish builder/setter names for the repo_config record
    // (case-insensitive substring match, mirroring tsindex's isTimeoutish).
    static boolean isTimeoutish(String name) {
        String lower = name.toLowerCase();
        return lower.contains("timeout") || lower.contains("deadline");
    }

    // =======================================================================
    // CLI
    // =======================================================================

    public static void main(String[] args) throws Exception {
        boolean packetSchema = false;
        boolean retrieve = false;
        String root = ".";
        String name = null;
        String files = "";
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--packet-schema":
                    packetSchema = true;
                    break;
                case "--retrieve":
                    retrieve = true;
                    break;
                case "--root":
                    root = args[++i];
                    break;
                case "--name":
                    name = args[++i];
                    break;
                case "--files":
                    files = i + 1 < args.length ? args[++i] : "";
                    break;
                default:
                    // ignore unknown flags for forward-compat with siblings
                    break;
            }
        }

        if (packetSchema) {
            // Let a consumer negotiate the contract before paying for a load.
            System.out.println(PACKET_SCHEMA);
            return;
        }

        if (!retrieve) {
            System.err.println("usage: java javaindex.java --packet-schema | "
                    + "--retrieve --root <dir> [--name <snap>] [--files A.java,B.java]");
            System.exit(2);
        }

        Path rootPath = Paths.get(root).toAbsolutePath().normalize();
        String snapshot = name != null ? name
                : (rootPath.getFileName() != null ? rootPath.getFileName().toString() : "repo");
        Set<String> only = new HashSet<>();
        for (String f : files.split(",")) {
            if (!f.isEmpty()) {
                only.add(f);
            }
        }

        JavaIndex ix = new JavaIndex(rootPath, snapshot);
        List<Map<String, Object>> records = ix.run(only);

        StringBuilder sb = new StringBuilder();
        for (Map<String, Object> rec : records) {
            rec.put("packet_schema", PACKET_SCHEMA);
            rec.put("site_key", siteKey(rec));
            writeJson(sb, rec);
            sb.append('\n');
        }
        // One repo-scoped record per run, after the site packets. rvl_core's
        // parse_stream keys on kind:"repo_config" to route it away from
        // sites. Emitted even when empty, like tsindex.
        writeJson(sb, ix.repoConfigRecord());
        sb.append('\n');
        System.out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.flush();
        System.err.println(snapshot + ": " + records.size() + " retrieved sites, "
                + ix.repoConfig.size() + " config constructions");
    }

    static String siteKey(Map<String, Object> rec) {
        // MUST agree with rvl_index::site_key and the sibling helpers:
        // file:line:client_type:func. A file:line is NOT unique -- one
        // location can resolve to several sites with different client types.
        return rec.get("file_path") + ":" + rec.get("line_number") + ":"
                + rec.get("client_type") + ":" + rec.get("func");
    }

    // =======================================================================
    // Retrieval
    // =======================================================================

    final Path root;
    final String snapshot;
    // Constructed-client registry: variable element -> declaration snippet,
    // for client_construction (built across ALL units, so a field constructed
    // in another file is still found).
    final Map<Element, Map<String, Object>> constructions = new HashMap<>();
    // repo_config constructions: type FQN -> union of timeout-ish fields.
    final Map<String, TreeSet<String>> repoConfig = new TreeMap<>();

    Trees trees;
    SourcePositions positions;

    JavaIndex(Path root, String snapshot) {
        this.root = root;
        this.snapshot = snapshot;
    }

    List<Map<String, Object>> run(Set<String> only) throws Exception {
        List<Path> files = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (!dir.equals(root) && SKIP_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                if (file.toString().endsWith(".java")) {
                    files.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        files.sort(null);
        if (files.isEmpty()) {
            return new ArrayList<>();
        }

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            System.err.println("javaindex requires a JDK (no system Java compiler available)");
            System.exit(1);
        }
        DiagnosticCollector<JavaFileObject> diags = new DiagnosticCollector<>();
        StandardJavaFileManager fm =
                compiler.getStandardFileManager(diags, null, StandardCharsets.UTF_8);
        // getJavaFileObjectsFromFiles: the JDK 11-safe overload (the Paths
        // variants moved around in later JDKs).
        List<java.io.File> asFiles = new ArrayList<>();
        for (Path f : files) {
            asFiles.add(f.toFile());
        }
        Iterable<? extends JavaFileObject> units = fm.getJavaFileObjectsFromFiles(asFiles);
        // -proc:none: never run annotation processors over scanned code.
        JavacTask task = (JavacTask) compiler.getTask(
                new PrintWriter(Writer.nullWriter()), fm, diags,
                Arrays.asList("-proc:none"), null, units);
        List<CompilationUnitTree> parsed = new ArrayList<>();
        for (CompilationUnitTree cu : task.parse()) {
            parsed.add(cu);
        }
        try {
            // Attribution over ALL units, classpath-less: platform types
            // resolve, third-party types become error types. Diagnostics are
            // collected and discarded -- they are expected, not failures.
            task.analyze();
        } catch (Throwable t) {
            // Degrade honestly: with no attribution, receivers land on the
            // strong-verb/low path (see the header's degradation story).
        }
        trees = Trees.instance(task);
        positions = trees.getSourcePositions();

        // Pass A: constructions (client_construction registry + repo_config).
        for (CompilationUnitTree cu : parsed) {
            String rel = relPath(cu);
            String src = sourceOf(cu);
            UnitImports imps = importsOf(cu);
            new ConstructionScanner(cu, rel, src, imps).scan(cu, null);
        }

        // Pass B: sites. ALL units stay in the analysis (that is what keeps
        // full-load and --files retrieval identical per file); `only` filters
        // which files' packets are EMITTED.
        List<Map<String, Object>> out = new ArrayList<>();
        for (CompilationUnitTree cu : parsed) {
            String rel = relPath(cu);
            if (!only.isEmpty() && !only.contains(rel)) {
                continue;
            }
            String src = sourceOf(cu);
            UnitImports imps = importsOf(cu);
            SiteScanner scanner = new SiteScanner(cu, rel, src, imps);
            scanner.scan(cu, null);
            out.addAll(scanner.sites);
            out.addAll(scanner.emissionRecords());
        }
        return out;
    }

    Map<String, Object> repoConfigRecord() {
        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("packet_schema", PACKET_SCHEMA);
        rec.put("kind", "repo_config");
        rec.put("snapshot_id", snapshot);
        List<Object> ctors = new ArrayList<>();
        for (Map.Entry<String, TreeSet<String>> e : repoConfig.entrySet()) {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("type", e.getKey());
            c.put("fields", new ArrayList<>(e.getValue()));
            ctors.add(c);
        }
        rec.put("constructions", ctors);
        return rec;
    }

    String relPath(CompilationUnitTree cu) {
        Path p = Paths.get(cu.getSourceFile().toUri());
        return root.relativize(p).toString().replace('\\', '/');
    }

    final Map<String, String> sourceCache = new HashMap<>();

    String sourceOf(CompilationUnitTree cu) {
        String key = cu.getSourceFile().toUri().toString();
        return sourceCache.computeIfAbsent(key, k -> {
            try {
                return cu.getSourceFile().getCharContent(true).toString();
            } catch (Exception e) {
                return "";
            }
        });
    }

    String cap(String s) {
        if (s.length() > MAX_SNIPPET_BYTES) {
            return s.substring(0, MAX_SNIPPET_BYTES) + "\n// ... truncated";
        }
        return s;
    }

    String text(CompilationUnitTree cu, Tree tree, String src) {
        long start = positions.getStartPosition(cu, tree);
        long end = positions.getEndPosition(cu, tree);
        if (start < 0 || end < 0 || end <= start || end > src.length()) {
            return "";
        }
        return cap(src.substring((int) start, (int) end));
    }

    long lineOf(CompilationUnitTree cu, Tree tree) {
        long start = positions.getStartPosition(cu, tree);
        if (start < 0) {
            return 0;
        }
        return cu.getLineMap().getLineNumber(start);
    }

    // --- imports ---

    static class UnitImports {
        final Map<String, String> single = new HashMap<>();   // Simple -> FQN
        final Set<String> wildcards = new HashSet<>();        // package names
        final Map<String, String> statics = new HashMap<>();  // member -> owner FQN
        final Set<String> staticWildcards = new HashSet<>();  // owner FQNs
    }

    UnitImports importsOf(CompilationUnitTree cu) {
        UnitImports imps = new UnitImports();
        for (ImportTree imp : cu.getImports()) {
            String q = imp.getQualifiedIdentifier().toString();
            int dot = q.lastIndexOf('.');
            if (dot < 0) {
                continue;
            }
            String head = q.substring(0, dot);
            String tail = q.substring(dot + 1);
            if (imp.isStatic()) {
                if (tail.equals("*")) {
                    imps.staticWildcards.add(head);
                } else {
                    imps.statics.put(tail, head);
                }
            } else if (tail.equals("*")) {
                imps.wildcards.add(head);
            } else {
                imps.single.put(tail, q);
            }
        }
        return imps;
    }

    // attributeType maps a source-level type name to a dotted identity via the
    // unit's imports. Conservative: a wildcard-ambiguous simple name abstains
    // (returns null) rather than guessing -- misattributing a same-package
    // class to a wildcard package would poison the site_key identity.
    static String attributeType(String raw, UnitImports imps) {
        if (raw == null || raw.isEmpty()) {
            return null;
        }
        raw = raw.replaceAll("<.*>", "").trim();
        if (raw.isEmpty() || raw.endsWith("[]") || raw.equals("var")) {
            return null;
        }
        int dot = raw.indexOf('.');
        if (dot >= 0) {
            String first = raw.substring(0, dot);
            if (!first.isEmpty() && Character.isLowerCase(first.charAt(0))) {
                // Written fully qualified in source (org.slf4j.Logger).
                return raw;
            }
            // A nested-class reference (OkHttpClient.Builder): map the outer
            // name through the imports and keep the nesting.
            String outer = imps.single.get(first);
            return outer != null ? outer + raw.substring(dot) : null;
        }
        return imps.single.get(raw);
    }

    // --- receiver resolution ---

    static class Resolved {
        final String clientType; // "" when unresolved
        final boolean resolved;  // checker-resolved OR import-attributed
        final String tier;       // "high" | "low"

        Resolved(String clientType, boolean resolved, String tier) {
            this.clientType = clientType;
            this.resolved = resolved;
            this.tier = tier;
        }
    }

    static final Resolved UNRESOLVED = new Resolved("", false, "low");

    // checkerFqn: the fully-qualified name of a checker-resolved declared
    // type, or null for error/primitive/unqualified types.
    String checkerFqn(TypeMirror t) {
        if (t == null || t.getKind() != TypeKind.DECLARED) {
            return null;
        }
        Element e = ((DeclaredType) t).asElement();
        if (!(e instanceof TypeElement)) {
            return null;
        }
        String q = ((TypeElement) e).getQualifiedName().toString();
        return q.indexOf('.') >= 0 ? q : null;
    }

    Resolved resolveReceiver(TreePath recvPath, UnitImports imps) {
        TypeMirror t = null;
        try {
            t = trees.getTypeMirror(recvPath);
        } catch (Throwable ignore) {
            // no attribution: fall through to the raw-name path
        }
        String fqn = checkerFqn(t);
        if (fqn != null) {
            return new Resolved(fqn, true, "high");
        }
        // Import attribution (the classpath-less third-party path).
        String raw = null;
        Element el = null;
        try {
            el = trees.getElement(recvPath);
        } catch (Throwable ignore) {
            // no attribution
        }
        if (el instanceof VariableElement) {
            Tree decl = trees.getTree(el);
            if (decl instanceof VariableTree && ((VariableTree) decl).getType() != null) {
                raw = ((VariableTree) decl).getType().toString();
            }
            if (raw == null || raw.equals("var")) {
                TypeMirror vt = el.asType();
                raw = vt != null ? vt.toString() : null;
            }
        } else if (el instanceof TypeElement) {
            // Static call on a class reference (Sentry.captureException).
            raw = ((TypeElement) el).getQualifiedName().toString();
        } else if (t != null && t.getKind() == TypeKind.ERROR) {
            raw = t.toString();
        }
        String attributed = attributeType(raw, imps);
        if (attributed != null) {
            return new Resolved(attributed, true, "high");
        }
        return UNRESOLVED;
    }

    static boolean isPlatform(String fqn) {
        return fqn.startsWith("java.") || fqn.startsWith("javax.")
                || fqn.startsWith("jdk.") || fqn.startsWith("com.sun.")
                || fqn.startsWith("sun.");
    }

    static boolean isPlatformClient(String fqn) {
        return fqn.startsWith("java.sql.") || fqn.startsWith("javax.sql.")
                || fqn.startsWith("java.net.") || fqn.startsWith("com.sun.net.");
    }

    // --- const args (schema v2) ---

    // literalText: the source text of a literal token (string literals keep
    // their quotes, matching the sibling helpers), or null. A substitution:
    // -1 rides UnaryTree with a literal operand.
    String literalText(CompilationUnitTree cu, ExpressionTree e, String src) {
        if (e instanceof LiteralTree) {
            return text(cu, e, src);
        }
        if (e instanceof UnaryTree
                && (e.getKind() == Tree.Kind.UNARY_MINUS || e.getKind() == Tree.Kind.UNARY_PLUS)
                && ((UnaryTree) e).getExpression() instanceof LiteralTree) {
            return text(cu, e, src);
        }
        return null;
    }

    // namedConstantText: the checker-folded constant value of an identifier /
    // member-select argument (a static final with a constant initializer), or
    // null. Evidence, never a verdict; no deep constant propagation.
    String namedConstantText(TreePath argPath, ExpressionTree e) {
        if (!(e instanceof IdentifierTree) && !(e instanceof MemberSelectTree)) {
            return null;
        }
        Element el = null;
        try {
            el = trees.getElement(argPath);
        } catch (Throwable ignore) {
            return null;
        }
        if (!(el instanceof VariableElement)) {
            return null;
        }
        Object cv = ((VariableElement) el).getConstantValue();
        if (cv == null) {
            return null;
        }
        return cv instanceof String ? "\"" + jsonEscape((String) cv) + "\"" : String.valueOf(cv);
    }

    List<Object> constArgsOf(CompilationUnitTree cu, TreePath callPath,
            List<? extends ExpressionTree> args, String src) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < args.size(); i++) {
            ExpressionTree a = args.get(i);
            String name = "";
            ExpressionTree value = a;
            if (a instanceof AssignmentTree) {
                // Annotation arguments carry names (fixedRate = 5000) --
                // Java's only named-argument surface.
                AssignmentTree as = (AssignmentTree) a;
                name = as.getVariable().toString();
                value = as.getExpression();
            }
            String lit = literalText(cu, value, src);
            if (lit != null) {
                out.add(constArg(i, name, lit, "literal"));
                continue;
            }
            String named = namedConstantText(new TreePath(callPath, value), value);
            if (named != null) {
                out.add(constArg(i, name, named, "named_constant"));
            }
        }
        return out;
    }

    static Map<String, Object> constArg(int index, String name, String value, String how) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", index);
        m.put("name", name);
        m.put("value", value);
        m.put("how", how);
        return m;
    }

    // --- pass A: constructions ---

    class ConstructionScanner extends TreePathScanner<Void, Void> {
        final CompilationUnitTree cu;
        final String rel;
        final String src;
        final UnitImports imps;
        final Deque<String> methodStack = new ArrayDeque<>();

        ConstructionScanner(CompilationUnitTree cu, String rel, String src, UnitImports imps) {
            this.cu = cu;
            this.rel = rel;
            this.src = src;
            this.imps = imps;
        }

        @Override
        public Void visitMethod(MethodTree node, Void p) {
            methodStack.push(node.getName().toString());
            try {
                return super.visitMethod(node, p);
            } finally {
                methodStack.pop();
            }
        }

        @Override
        public Void visitVariable(VariableTree node, Void p) {
            // Register declarations whose initializer constructs something,
            // so a site on this receiver can cite where its client was
            // configured (client_construction).
            ExpressionTree init = node.getInitializer();
            if (init instanceof NewClassTree || init instanceof MethodInvocationTree) {
                Element el = null;
                try {
                    el = trees.getElement(getCurrentPath());
                } catch (Throwable ignore) {
                    // unattributed declaration: no registry entry
                }
                if (el != null) {
                    Map<String, Object> snip = new LinkedHashMap<>();
                    snip.put("file", rel);
                    snip.put("line", lineOf(cu, node));
                    snip.put("symbol", node.getName().toString());
                    snip.put("source", text(cu, node, src));
                    constructions.put(el, snip);
                }
            }
            return super.visitVariable(node, p);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void p) {
            String type = constructedType(node);
            recordBuilderChain(node, type);
            return super.visitNewClass(node, p);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            // Factory chain roots: X.newBuilder() / X.builder().
            if (node.getMethodSelect() instanceof MemberSelectTree) {
                MemberSelectTree ms = (MemberSelectTree) node.getMethodSelect();
                String m = ms.getIdentifier().toString();
                if (m.equals("newBuilder") || m.equals("builder")) {
                    TreePath msPath = new TreePath(getCurrentPath(), ms);
                    Resolved r = resolveReceiver(new TreePath(msPath, ms.getExpression()), imps);
                    if (r.resolved) {
                        recordBuilderChain(node, r.clientType);
                    }
                }
            }
            return super.visitMethodInvocation(node, p);
        }

        // constructedType: the FQN of `new X(...)` / `new X.Builder()`, via
        // the checker when it resolves, via imports otherwise; null when
        // neither works (abstain).
        String constructedType(NewClassTree node) {
            String fqn = null;
            try {
                fqn = checkerFqn(trees.getTypeMirror(getCurrentPath()));
            } catch (Throwable ignore) {
                // unattributed construction
            }
            if (fqn == null) {
                fqn = attributeType(node.getIdentifier().toString(), imps);
            }
            return fqn;
        }

        // recordBuilderChain walks UP from a construction/factory node
        // through the enclosing fluent chain (`.connectTimeout(...)
        // .readTimeout(...).build()`), recording timeout-ish link names on
        // the built type for the repo_config record. Inline chains only --
        // a builder handed around as a variable is not traced (documented
        // limitation, the tsindex options-variable analog).
        void recordBuilderChain(Tree node, String type) {
            if (type == null) {
                return;
            }
            // The nested-builder convention: new OkHttpClient.Builder()
            // configures an OkHttpClient.
            if (type.endsWith(".Builder")) {
                type = type.substring(0, type.length() - ".Builder".length());
            }
            TreeSet<String> fields = new TreeSet<>();
            TreePath p = getCurrentPath();
            Tree current = node;
            while (p.getParentPath() != null) {
                Tree parent = p.getParentPath().getLeaf();
                if (parent instanceof MemberSelectTree
                        && ((MemberSelectTree) parent).getExpression() == current) {
                    Tree grand = p.getParentPath().getParentPath() != null
                            ? p.getParentPath().getParentPath().getLeaf()
                            : null;
                    if (grand instanceof MethodInvocationTree
                            && ((MethodInvocationTree) grand).getMethodSelect() == parent) {
                        String m = ((MemberSelectTree) parent).getIdentifier().toString();
                        if (isTimeoutish(m)) {
                            fields.add(m);
                        }
                        current = grand;
                        p = p.getParentPath().getParentPath();
                        continue;
                    }
                }
                break;
            }
            if (!fields.isEmpty()) {
                repoConfig.computeIfAbsent(type, k -> new TreeSet<>()).addAll(fields);
            }
        }
    }

    // --- pass B: sites ---

    class SiteScanner extends TreePathScanner<Void, Void> {
        final CompilationUnitTree cu;
        final String rel;
        final String src;
        final UnitImports imps;
        final List<Map<String, Object>> sites = new ArrayList<>();
        final Deque<MethodTree> methodStack = new ArrayDeque<>();
        // Innermost-catch bookkeeping for the swallow fact.
        final Deque<CatchFrame> catchStack = new ArrayDeque<>();
        // (symbol|framework|category) -> aggregate.
        final Map<String, Agg> aggs = new LinkedHashMap<>();

        SiteScanner(CompilationUnitTree cu, String rel, String src, UnitImports imps) {
            this.cu = cu;
            this.rel = rel;
            this.src = src;
            this.imps = imps;
        }

        class CatchFrame {
            final CatchTree node;
            boolean emits;
            boolean rethrows;

            CatchFrame(CatchTree node) {
                this.node = node;
            }
        }

        class Agg {
            final long line;
            final String symbol;
            final String method;
            final String framework;
            final String category;
            final String snippet;
            int count;

            Agg(long line, String symbol, String method, String framework,
                    String category, String snippet) {
                this.line = line;
                this.symbol = symbol;
                this.method = method;
                this.framework = framework;
                this.category = category;
                this.snippet = snippet;
            }
        }

        String symbol() {
            return methodStack.isEmpty() ? "" : methodStack.peek().getName().toString();
        }

        String enclosingBody() {
            return methodStack.isEmpty() ? "" : text(cu, methodStack.peek(), src);
        }

        @Override
        public Void visitMethod(MethodTree node, Void p) {
            // Annotation-form registrations (G2 routes, G3 schedulers) hang
            // off the method's modifiers; scan them against the tables before
            // descending into the body.
            for (AnnotationTree ann : node.getModifiers().getAnnotations()) {
                annotationRecord(node, ann);
            }
            methodStack.push(node);
            try {
                return super.visitMethod(node, p);
            } finally {
                methodStack.pop();
            }
        }

        @Override
        public Void visitCatch(CatchTree node, Void p) {
            CatchFrame frame = new CatchFrame(node);
            catchStack.push(frame);
            try {
                super.visitCatch(node, p);
            } finally {
                catchStack.pop();
            }
            if (!frame.emits && !frame.rethrows) {
                // A handled error path with no recognized emission and no
                // rethrow: the swallow fact RC-027's question needs.
                aggregate("catch_clause", "error_capture", "catch", node, "");
            }
            return null;
        }

        @Override
        public Void visitThrow(com.sun.source.tree.ThrowTree node, Void p) {
            if (!catchStack.isEmpty()) {
                catchStack.peek().rethrows = true;
            }
            return super.visitThrow(node, p);
        }

        void aggregate(String framework, String category, String method, Tree at, String snippet) {
            String sym = symbol();
            String key = sym + "|" + framework + "|" + category;
            Agg agg = aggs.get(key);
            if (agg == null) {
                agg = new Agg(lineOf(cu, at), sym, method, framework, category, snippet);
                aggs.put(key, agg);
            }
            agg.count++;
        }

        List<Map<String, Object>> emissionRecords() {
            List<Agg> ordered = new ArrayList<>(aggs.values());
            ordered.sort((a, b) -> Long.compare(a.line, b.line));
            List<Map<String, Object>> out = new ArrayList<>();
            for (Agg a : ordered) {
                Map<String, Object> rec = baseRecord(a.line, a.symbol, a.method, "",
                        a.framework, a.snippet, "");
                rec.put("site_kind", SITE_KIND_EMISSION);
                List<Object> ca = new ArrayList<>();
                ca.add(constArg(0, "emission_category", a.category, "aggregate"));
                ca.add(constArg(0, "emission_count", String.valueOf(a.count), "aggregate"));
                rec.put("const_args", ca);
                rec.put("provenance", provenance(
                        !a.framework.equals("catch_clause"), "high"));
                out.add(rec);
            }
            return out;
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            ExpressionTree select = node.getMethodSelect();
            if (select instanceof MemberSelectTree) {
                memberCall(node, (MemberSelectTree) select);
            } else if (select instanceof IdentifierTree) {
                // A bare call is a local method -- except when a static
                // import binds it to a telemetry surface (import static
                // io.sentry.Sentry.captureException).
                String m = ((IdentifierTree) select).getName().toString();
                String owner = imps.statics.get(m);
                if (owner == null && EMISSION_CAPTURE_METHODS.contains(m)) {
                    for (String w : imps.staticWildcards) {
                        owner = w;
                        break;
                    }
                }
                if (owner != null && EMISSION_CAPTURE_METHODS.contains(m)) {
                    markCatchEmits();
                    aggregate(owner, "error_capture", m, node, text(cu, node, src));
                }
            }
            return super.visitMethodInvocation(node, p);
        }

        void markCatchEmits() {
            if (!catchStack.isEmpty()) {
                catchStack.peek().emits = true;
            }
        }

        void memberCall(MethodInvocationTree node, MemberSelectTree ms) {
            String method = ms.getIdentifier().toString();
            TreePath msPath = new TreePath(getCurrentPath(), ms);
            TreePath recvPath = new TreePath(msPath, ms.getExpression());
            Resolved r = resolveReceiver(recvPath, imps);

            // G2 call-form registrations are checked FIRST: a matched
            // registration emits one server_entry record, never a G1 site.
            Set<String> serverMethods = SERVER_ENTRY_CALLS.get(r.clientType);
            if (r.resolved && serverMethods != null && serverMethods.contains(method)) {
                Map<String, Object> rec = classicRecord(node, ms, method, r, recvPath);
                rec.put("site_kind", SITE_KIND_SERVER_ENTRY);
                sites.add(rec);
                return;
            }

            // G3 call-form registrations: scheduler/queue surfaces ride the
            // stream as background_job sites. Type-driven: an unresolved or
            // same-named local method is never guessed at.
            Set<String> jobMethods = JOB_CALLS.get(r.clientType);
            if (r.resolved && jobMethods != null && jobMethods.contains(method)) {
                Map<String, Object> rec = classicRecord(node, ms, method, r, recvPath);
                rec.put("site_kind", SITE_KIND_BACKGROUND_JOB);
                sites.add(rec);
                return;
            }

            // G4 emission points are routed OUT of the G1 list (a log.info
            // must not double-count as a client call).
            String category = emissionCategory(r, method);
            if (category != null) {
                markCatchEmits();
                // A log emission ON an error path is the capture fact.
                if (category.equals("log") && !catchStack.isEmpty()) {
                    category = "error_capture";
                }
                aggregate(r.clientType, category, method, node, text(cu, node, src));
                return;
            }

            // G1 emission decision (documented in the header).
            boolean emit;
            if (r.resolved) {
                if (r.clientType.endsWith("Builder")) {
                    // Client configuration, inventoried by repo_config.
                    emit = false;
                } else if (isPlatform(r.clientType)) {
                    emit = isPlatformClient(r.clientType)
                            ? STRONG_IO_METHODS.contains(method) || WEAK_IO_METHODS.contains(method)
                            : STRONG_IO_METHODS.contains(method);
                } else {
                    emit = !NOISE_METHODS.contains(method);
                }
            } else {
                emit = STRONG_IO_METHODS.contains(method);
            }
            if (!emit) {
                return;
            }
            sites.add(classicRecord(node, ms, method, r, recvPath));
        }

        String emissionCategory(Resolved r, String method) {
            if (!r.resolved) {
                return null;
            }
            if (EMISSION_LOG_TYPES.contains(r.clientType)
                    && EMISSION_LOG_METHODS.contains(method)) {
                return "log";
            }
            if (r.clientType.startsWith("io.opentelemetry.")
                    && EMISSION_TRACE_METHODS.contains(method)) {
                return "trace";
            }
            if (r.clientType.equals("io.sentry.Sentry")
                    && EMISSION_CAPTURE_METHODS.contains(method)) {
                return "error_capture";
            }
            return null;
        }

        Map<String, Object> classicRecord(MethodInvocationTree node, MemberSelectTree ms,
                String method, Resolved r, TreePath recvPath) {
            Map<String, Object> rec = baseRecord(lineOf(cu, node), symbol(), method,
                    text(cu, ms.getExpression(), src), r.clientType,
                    text(cu, node, src), enclosingBody());
            rec.put("const_args",
                    constArgsOf(cu, getCurrentPath(), node.getArguments(), src));
            rec.put("client_construction", constructionFor(recvPath));
            rec.put("provenance", provenance(r.resolved, r.tier));
            return rec;
        }

        List<Object> constructionFor(TreePath recvPath) {
            List<Object> out = new ArrayList<>();
            Element el = null;
            try {
                el = trees.getElement(recvPath);
            } catch (Throwable ignore) {
                return out;
            }
            Map<String, Object> snip = el != null ? constructions.get(el) : null;
            if (snip != null && out.size() < MAX_CTORS_EMITTED) {
                out.add(snip);
            }
            return out;
        }

        void annotationRecord(MethodTree method, AnnotationTree ann) {
            Tree annType = ann.getAnnotationType();
            String simple;
            String fq = null;
            if (annType instanceof IdentifierTree) {
                simple = ((IdentifierTree) annType).getName().toString();
            } else if (annType instanceof MemberSelectTree) {
                simple = ((MemberSelectTree) annType).getIdentifier().toString();
                fq = annType.toString();
            } else {
                return;
            }
            String kind;
            List<String> pkgs = SERVER_ENTRY_ANNOTATIONS.get(simple);
            if (pkgs != null) {
                kind = SITE_KIND_SERVER_ENTRY;
            } else {
                pkgs = JOB_ANNOTATIONS.get(simple);
                if (pkgs == null) {
                    return;
                }
                kind = SITE_KIND_BACKGROUND_JOB;
            }
            String clientType = attributeAnnotation(simple, fq, pkgs);
            if (clientType == null) {
                return; // a same-named local annotation abstains
            }
            Map<String, Object> rec = baseRecord(lineOf(cu, ann),
                    method.getName().toString(), simple, "", clientType,
                    text(cu, ann, src), text(cu, method, src));
            rec.put("site_kind", kind);
            rec.put("const_args", constArgsOf(cu,
                    new TreePath(getCurrentPath(), ann), ann.getArguments(), src));
            rec.put("provenance", provenance(true, "high"));
            sites.add(rec);
        }

        // attributeAnnotation: the annotation identity, iff its name binds to
        // one of the candidate framework packages -- written fully qualified,
        // via a single-type import, or via a wildcard import of exactly that
        // package (the dominant Spring idiom).
        String attributeAnnotation(String simple, String fq, List<String> pkgs) {
            for (String p : pkgs) {
                String candidate = p + "." + simple;
                if (candidate.equals(fq)
                        || candidate.equals(imps.single.get(simple))
                        || (fq == null && imps.single.get(simple) == null
                                && imps.wildcards.contains(p))) {
                    return candidate;
                }
            }
            return null;
        }

        Map<String, Object> baseRecord(long line, String symbol, String func,
                String receiver, String clientType, String snippet, String body) {
            Map<String, Object> rec = new LinkedHashMap<>();
            rec.put("packet_schema", PACKET_SCHEMA);
            rec.put("site_key", ""); // stamped in main(), like every packet
            rec.put("snapshot_id", snapshot);
            rec.put("file_path", rel);
            rec.put("line_number", line);
            rec.put("symbol", symbol);
            rec.put("func", func);
            rec.put("receiver", receiver);
            rec.put("client_type", clientType);
            // No manifest resolution in v1: kept a stable empty field, like
            // the site_key formula, so a later version can fill it from
            // pom.xml/gradle metadata without a schema bump.
            rec.put("client_version", "");
            rec.put("snippet", snippet);
            rec.put("enclosing_function_body", body);
            rec.put("callers", new ArrayList<>());
            rec.put("callees", new ArrayList<>());
            rec.put("const_args", new ArrayList<>());
            rec.put("macro_expansion", false);
            rec.put("site_kind", "");
            rec.put("client_construction", new ArrayList<>());
            rec.put("provenance", provenance(false, "low"));
            rec.put("lang", "java");
            return rec;
        }

        Map<String, Object> provenance(boolean resolved, String tier) {
            Map<String, Object> prov = new LinkedHashMap<>();
            prov.put("client_type_resolved", resolved);
            prov.put("confidence_tier", tier);
            prov.put("callers_total", 0);
            prov.put("callers_included", 0);
            prov.put("callees_total", 0);
            prov.put("callees_included", 0);
            return prov;
        }
    }

    // =======================================================================
    // JSON writer (no dependencies; the helper must stay a single source
    // file runnable in JEP 330 mode).
    // =======================================================================

    static String jsonEscape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    static void writeJson(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            sb.append('"').append(jsonEscape((String) v)).append('"');
        } else if (v instanceof Boolean || v instanceof Integer || v instanceof Long) {
            sb.append(v);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                sb.append('"').append(jsonEscape(e.getKey())).append("\":");
                writeJson(sb, e.getValue());
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object o : (List<Object>) v) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJson(sb, o);
            }
            sb.append(']');
        } else {
            sb.append('"').append(jsonEscape(String.valueOf(v))).append('"');
        }
    }
}
