# javaindex — Java retriever helper

Emits the versioned packet stream rvl consumes, for Java source. The Java
sibling of `goindex`, `pyindex`, and `tsindex`. Retrieval only: this helper
decides nothing about reliability, it only says what the code is.

    java javaindex.java --retrieve --root <repo> --name <snapshot>      # full load
    java javaindex.java --retrieve --root <repo> --files A.java,B.java  # incremental reload
    java javaindex.java --packet-schema                                 # negotiate before loading

## Engine: the JDK's own javac Compiler Tree API, in source-file mode

The deliberate, on-record engine choice (po-av01j.9): **javac's Compiler Tree
API** (`com.sun.source.*`, exported by the `jdk.compiler` module) driven
through `ToolProvider.getSystemJavaCompiler()` — `JavacTask.parse()` +
`analyze()`, `Trees` for positions and type mirrors. The helper is a single
`.java` source file run in **JEP 330 source-file mode** (`java
javaindex.java …`): in-memory compile, no build step, no dependency jars, the
same scripted-helper shape as `pyindex.py` under `python3` and `tsindex.js`
under `node`. Discovery is env override (`RVL_JAVAINDEX`) → a
`javaindex.java` next to the rvl binary → `PATH`.

Rejected alternatives: Eclipse JDT (a dependency jar and a build system in
the toolchain for capability the JDK already ships), and a javac *plugin*
(wrong lifecycle — we drive the compiler as a library over the repo, we do
not hook someone's build). Requires a **JDK 11+** (not a JRE): source-file
mode and the system compiler both live in the JDK.

## Degradation story (classpath-less analysis, on record)

The run compiles the repo **without its dependency classpath**:

- **JDK platform receivers** (`java.sql` JDBC, `java.net.http` HttpClient,
  `java.util.logging`, `java.util.concurrent` schedulers,
  `com.sun.net.httpserver`) resolve fully through the checker →
  `confidence_tier: "high"`, `client_type_resolved: true`.
- **Third-party receivers** (OkHttp, Jedis, Kafka, Spring) do NOT resolve —
  javac leaves an error type — and fall back to **import attribution**: the
  receiver's declared type name (or a static-call class identifier) matched
  against exactly one explicit single-type import yields the dotted identity
  (`okhttp3.OkHttpClient`), still tier `high` because the import binding is a
  compiler-verified per-file fact. This is the pyindex import-driven model
  and the tsindex import-binding fallback.
- **Everything else** — a wildcard-ambiguous simple name, a `var` whose
  initializer does not resolve, an unknown parameter type — lands at tier
  `"low"` with an empty `client_type` and is emitted **only** when its method
  is a strong I/O verb (the tsindex `any` rule): abstain-by-omission, a site
  is never guessed at. If `analyze()` itself fails, element resolution
  degrades to nothing and every receiver lands on the strong-verb/low path —
  honest, never fabricated.

Documented abstention classes: wildcard type imports (`import okhttp3.*`)
abstain rather than risk misattributing a same-package class; a
`printStackTrace`-only catch reads as a swallow (stderr is not centralized
monitoring — RC-027's bar is a capture or structured log emission);
`client_version` is always `""` (no pom/gradle manifest resolution in v1,
kept as a stable field like the sibling helpers).

## What it emits

One JSON object per line (JSONL). Every record carries `packet_schema`
(currently `2`, agreeing with `rvl_core::PACKET_SCHEMA` and the sibling
helpers), `site_key` (`file:line:client_type:method`, the downstream join
key), `snapshot_id`, root-relative forward-slashed `file_path`, 1-based
`line_number`, `symbol` (enclosing method), `func`, `receiver`,
`client_type`, `client_version` (`""`), `snippet`,
`enclosing_function_body`, empty `callers`/`callees` (no cross-module call
graph in v1), `client_construction` (best-effort in-scope construction
snippets), `const_args` + `macro_expansion: false` (schema v2; Java has no
macros), `site_kind`, `provenance`
(`client_type_resolved`/`confidence_tier`), and `lang: "java"`.

`const_args` carries literal tokens (`how: "literal"`, source-level
rendering with string quotes) and checker-folded constants — a
`static final` with a constant initializer — as `how: "named_constant"`.
Annotation arguments are Java's only named-argument surface, so
`@Scheduled(fixedRate = 5000)` rides with `name: "fixedRate"` (the implicit
single element is `value`). Evidence, never a verdict; no deep constant
propagation.

### Site kinds (the G2/G3/G4 extensions, cross-language conventions)

- **`server_entry`** — Spring `@RequestMapping`/`@GetMapping`-family and
  JAX-RS `@GET`-family method annotations (attributed via a single-type
  import or a wildcard import of exactly the framework package — the
  dominant Spring idiom), plus call-form registrations
  (`HttpServer.createContext`, `ServletContext.addServlet`).
- **`background_job`** — `@Scheduled` (Spring), and call-form registrations:
  `ScheduledExecutorService.schedule*`, `java.util.Timer.schedule*`,
  `org.quartz.Scheduler.scheduleJob`. Type-driven; a same-named local method
  or annotation abstains.
- **`emission_point`** — AGGREGATES, one per (enclosing function, framework,
  category), category and count riding `const_args`
  (`emission_category`/`emission_count`, `how: "aggregate"`), never one
  packet per log line. Frameworks: slf4j/log4j/JUL (`log`), OpenTelemetry
  spans (`trace`), Sentry captures (`error_capture`). A log emission ON an
  error path recategorizes to `error_capture` (the pyindex rule); a catch
  clause with no recognized emission and no `throw` aggregates under the
  `catch_clause` identity (the Java sibling of `except_handler` /
  `recover_block`), `func: "catch"`.

### Client-detection policy (volume control, fully mechanical)

Java always resolves the JDK platform, so "the receiver resolved" is not by
itself the external-client signal it is in TypeScript: third-party (incl.
import-attributed) receivers emit every non-noise method; JDK platform
CLIENT packages (`java.sql`, `javax.sql`, `java.net`, `com.sun.net`) emit
strong or weak I/O verbs; any other platform type (collections, strings)
emits strong verbs only; unresolved receivers emit strong verbs only, at
tier `low`. A resolved type ending in `Builder` is client CONFIGURATION, not
a client call — its timeout-ish fields ride the `repo_config` record.

## The `repo_config` record (one per run)

Mirrors tsindex/goindex: one repo-scoped line, `kind: "repo_config"`, with
deduped `constructions` `{type, fields}` — one entry per constructed client
type whose **inline builder chain** sets at least one timeout-ish name
(case-insensitive substring `timeout`/`deadline`):
`HttpClient.newBuilder().connectTimeout(…)` →
`{"type":"java.net.http.HttpClient","fields":["connectTimeout"]}`;
`new OkHttpClient.Builder().readTimeout(…)` folds the nested `.Builder` onto
the built type. Emitted even when empty. Detection limit (documented, the
tsindex options-variable analog): only inline chains — a builder handed
around as a variable is not traced.

## Tests

From this directory, with a JDK:

    java test/JavaIndexTest.java

Plain Java, no JUnit (the helper's toolchain rule is "a JDK and nothing
else"). It spawns the helper as a subprocess exactly the way rvl does
and asserts: schema negotiation, `site_key` formula + uniqueness, the
typed/attributed/unresolved tier behavior, noise suppression, all three site
kinds, `const_args` evidence, the `repo_config` constructions, and
**retrieval invariance** — a full load and a `--files` incremental reload
emit identical packets for the same file (all units stay in the analysis in
both modes; `--files` only filters emission).

`testdata/fixture/` is a small Java app whose `stubs/okhttp3/` are
hand-written minimal source stubs (the analog of tsindex's vendored `.d.ts`
stubs): they let the checker exercise the fully-typed third-party path with
zero network, while `jedis`/`quartz`/`slf4j`/Spring imports are deliberately
stub-less to exercise the import-attribution path.
