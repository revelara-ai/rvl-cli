# How a scan finds your code

With no `--retrieved`, `rvl` detects the languages under `PATH`, runs the
matching retriever helper itself, and feeds the packets into the pipeline.
Multiple detected languages run each helper and concatenate their packets.

`brew install --cask revelara-ai/tap/rvl` (the tap ships `rvl` as a cask)
gives you a working scan for six of the seven supported languages with no
further setup:

| Retriever | How it arrives | Runtime prerequisite |
| --- | --- | --- |
| `pyindex.py` | embedded in the binary | `python3` |
| `tsindex.js` | embedded in the binary | `node` + a TypeScript 5.x compiler¹ |
| `javaindex.java` | embedded in the binary | a JDK 11+ (JEP 330 source mode) |
| `goindex` | in the release archive | the `go` tool |
| `cindex` | in the release archive, with its pinned `libclang` | none in a release; a system `libclang` in a source build² |
| `rustindex` | in the release archive | `rust-analyzer` |
| `csindex` | not shipped: it pulls ~9 MB of Roslyn | a .NET 8 SDK³ |

¹ `rvl` points `NODE_PATH` at the repository being scanned, so a project with
`typescript` in its own `node_modules` needs nothing. Otherwise tsindex prints
the one command to run and that language degrades rather than failing the
scan. The pin matters: npm's `typescript` now resolves to the 7.x native port,
whose JS API this helper cannot drive.

² `cindex` dlopens libclang at run time. A release archive carries a pinned,
checksummed libclang (LLVM 18.1.1) in `libclang/` beside `cindex`, and a
release `cindex` uses only that one, so C/C++ results do not depend on the
machine. A source build uses the system library instead. `LIBCLANG_PATH`
overrides both. Where no library can be loaded, `cindex` fails closed with
actionable guidance. `cindex --engine-check` prints the version it resolved
and which engine it was (`[vendored ...]`, `[system]` or `[LIBCLANG_PATH ...]`).

³ Build it once from a clone; the output directory is a location `rvl`
searches, so there is no separate install step:
`dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex`.

Ask what is missing before the first scan on a new machine:

```sh
rvl doctor [PATH]            # repo-aware: only the languages this tree has
rvl doctor --fix             # close what can be closed safely
```

`doctor` names, per language lane, which retriever resolved, from which
slot, and whether the runtime it drives is installed. When that retriever is
not the build `rvl` ships, the same line says `helper drift` (see
[Helper drift](#helper-drift)). It also reports
credentials, spec-cache freshness, and git-hook wiring. `--fix` performs only
safe, idempotent, local repairs, announcing each one first; anything needing a
system package manager or `sudo` is printed, never run. Exit codes: `0`
everything this repo needs is in place, `1` a gap remains, `2` usage error.
`--format=json` emits the same checks for scripts.

One caveat before trusting a green `doctor`: it reports the
three compiled helpers (`goindex`, `cindex`, `rustindex`) as
`native — no runtime prereq`, because it checks that the helper itself is
resolvable and does not probe the toolchain that helper drives. So a machine
with no `go`, no `libclang` or no `rust-analyzer` still shows `PASS` on that
lane. This bites hardest on fresh CI runners and new build images, where the
helper arrived with the archive but the toolchain never did. A green
`doctor` there does not prove the lane can read code. `cindex --engine-check`
prints the libclang it resolved, and the scan's own `COVERAGE` block is the
authority on whether a lane actually read anything (see
[Gating commits and CI](gating.md) for the coverage assertion that catches
this in CI).

## Resolution slots

Helpers are resolved in this order, and the scan's `retrievers:` line names
both the path and the slot it came from (`env:VAR` / `bundled` / `embedded` /
`installed` / `PATH`):

1. an env override: `RVL_GOINDEX` / `RVL_PYINDEX` / …;
2. a helper packaged with the binary, next to `rvl` or in the `share/rvl`
   directory a package manager files an archive's non-binary members into;
3. the copy `rvl` carries inside itself and writes out on first use;
4. a helper you built into `~/.revelara/helpers/<name>`;
5. a helper on `PATH`.

Slot 4 is why no install instruction in this tool ends with an `RVL_…`
export: every suggested command writes to a location resolution already
checks, so building a helper also installs it.

The embedded scripts are written to `~/.revelara/helpers/<rvl version>/` on
first use, and rewritten whenever their contents no longer hash to the
embedded text, so an edited or truncated copy is restored instead of
silently scanning wrong. `RVL_HELPER_DIR` relocates that directory.

### Helper drift

A helper found in slot 1, 2, 4 or 5 can be a different build from the one
this `rvl` ships. The usual cause is an old `pyindex.py` left beside the
binary by an earlier `make install`, or an `RVL_…` export that a shell profile
still carries. The scan then describes an older scanner than the one you think
you ran.

When the helper that ran has a shipped sibling (a bundled helper, otherwise
the embedded copy), the scan compares their content versions and adds one
line to `COVERAGE` if they do not agree:

```text
  retrievers: Python /home/u/.local/bin/pyindex.py (bundled)
  helper drift: Python /home/u/.local/bin/pyindex.py (bundled) differs from the copy embedded in this rvl (content 3fa91c0b77de, shipped 9c41d2e07a15)
```

The content version is the second line of a helper's `--packet-schema` reply:
the first 12 hex digits of a sha256 of the helper's own source. A version is
an identity, not an age, so two different versions are reported as `differs`.
A helper that reports no version was built before this handshake existed, and
that one is reported as `older`.

This is a warning only. The scan runs the helper it resolved and its exit code
does not change, because a different helper is often deliberate. To clear the
line, remove or rebuild the named file, or unset the override. `--out` carries
the same text in `coverage.retrievers[].drift`. `rustindex` and `cindex` do
not report a content version yet, so they are never compared.

Per-language toolchain setup and the full hook workflow are covered in
[Local scanning](https://app.revelara.ai/help/local-scanning).

## Client constructions and config specs

Every call-site packet carries `client_construction`: the snippets where the
receiver was built, as `{file, line, symbol, source}`. `symbol` is the
constructed TYPE (`net/http.Client`) and `source` is the literal or statement
that built it (`http.Client{Timeout: 10 * time.Second}`), so a
construction-time timeout is visible to the scan without the retriever
judging it.

A `client_config` spec keys on that type and says where the bound comes
from: `fields` names the fields whose being set carries it (`["Timeout"]` for
`net/http.Client`), and `default_bound` records a bound the library applies on
its own (`{"kind": "seconds", "seconds": 100}` for .NET's `HttpClient`). The
scan credits a whole-call `this_client` spec on one of those two grounds: the
type bounds by default, or a construction attached to the site sets one of
the named fields, in `symbol` or in `source`. An `http.Client{}` with no
`Timeout` is the classic hang and never passes on the type match alone. A
spec that says neither cannot be checked against any construction, so the
site abstains with `client config <type> names no bounding field or default`
(counted under `unresolved bounds` in COVERAGE) until the spec is re-authored
or a bound is [declared](scanning.md#suppressing-bounding-waiving) in
`.revelara.yaml`. Declared bounds are exempt: they are an operator's claim
about the type as deployed, not about a field, and a declaration replaces
the served spec for that type whatever the served spec's confidence.

Only the construction's own fields count. A field is read at most one
literal deep and one argument list deep in `source`, which is where every
retriever puts the client's fields (the literal itself, the whole assignment
or declaration statement, or the options object inside the constructor
call). A field of a nested literal belongs to the nested type:
`http.Client{Transport: &http.Transport{DialContext: (&net.Dialer{Timeout:
30 * time.Second}).DialContext}}` bounds only the dial, and the scan does
not read the dialer's `Timeout` as the client's.

A spec can also list `unbounded_sentinels`, the values of a named field that
mean no bound (`"0"` for `net/http.Client`'s `Timeout`, `"None"` for a
Python keyword, `"Duration.ZERO"` for a Java builder), the same idea as the
call-argument sentinels. A construction that sets the field to one of them
is positive evidence the bound was switched off, so the site violates with
the value cited, unless another construction of the type sets a real value.
A spec that lists none credits any set value.

Decorators get the same treatment through their own spec section. A bound
on a decorator, such as `@shared_task(time_limit=120)`, covers every call in
the function, so the site's API spec can't say which values switch it off. A
`decorators` entry does that instead. It names the decorator's identity
(`celery.shared_task`), the written names it governs, matched on the last
dotted segment (`shared_task`, `task`), and its `unbounded_sentinels`. A
bound key set to one of those values (`time_limit=0`, `time_limit=None`)
earns no credit. The scan then keeps looking for other bounds instead of
reporting a violation, because the call can still carry its own. With no
matching decorator spec, any value earns credit, as before.

An API spec can name a `capacity_arg`, the constructor argument that gives
the receiver a finite capacity (`{"name": "maxsize", "position": 0}` for
`queue.Queue.put`). Such a call blocks only when the receiver can fill, so
the scan reads the constructions that reach the receiver before it reports
the call:

- Every construction leaves the argument out, or sets it to zero or a
  negative number: the call cannot block, and the site is `not_applicable`
  with the construction cited.
- A construction sets a positive integer: the site is judged as usual, so a
  `put` with no timeout on a `queue.Queue(maxsize=10)` violates.
- No construction was found, the construction was not traced to the
  receiver, or the value is not an integer literal: a site that would
  violate abstains instead. A bound that was found still satisfies.

A spec with no `capacity_arg` is read as before. pyindex attaches to a local
receiver only the constructions in its own function, so a same-named queue
in another function does not change the answer.

One limit to know: goindex attaches every construction of a type in the
module to every site using it, so one `Timeout`-bearing literal is evidence
for every `http.Client` call in the repo. The reason names the file and line
it came from.

## Unsized constructions

Some objects take a bound when they are built: a connection pool has a
maximum size, a queue has a capacity, a cache has a size limit or an expiry,
and a read of a whole body has a size limit. A retriever reports each such
construction as one packet with `site_kind: "unsized_construction"`. The
packet is not a call site. It is not counted in COVERAGE, and it is not a row
in `--out`.

The packet lists what the retriever saw, in `const_args`:

| Entry | `how` | Meaning |
| --- | --- | --- |
| `bound_class` | `aggregate` | `pool`, `queue`, `cache`, or `read`. |
| A constructor argument (`arg0`, or its keyword) or a method called on the value (`SetMaxOpenConns`) | `literal` or `named_constant` | The value is a constant. The packet carries the value. |
| The same | `name` | The value is not a constant (`cfg.Max`). The packet carries the source text. The scanner credits it as a bound and never resolves it. |
| A call that the argument of a read passes through (`io.LimitReader`) | `call` | Go reads only. |
| A method called on the same type somewhere else in the module | `type` | Only on a value that leaves the function. |
| `bound_escapes` | `aggregate` | The value leaves the constructing function: it is returned, stored, passed to a call, or has no name. |
| `bound_opaque` | `aggregate` | Some options are not written out (`Queue(**opts)`). |

A retriever does not decide which entry is a bound. A `construction_bounds`
spec does. For one type and class, the spec gives the names that bound the
object (`bounded_by`), the values that mean "no limit" (`unbounded_values`),
whether the default of the library is finite (`default_bounded`), and the
control. A construction that no spec names is not judged.

The verdict for one construction:

1. A name in `bounded_by` is seen in scope. If its value is a constant in
   `unbounded_values`, the construction has no bound. If not, it is bounded.
2. No such name is seen, and `default_bounded` is true. It is bounded.
3. No such name is seen, and `bound_opaque` is present. The scanner abstains.
4. No such name is seen, and the value stays in the function. It has no bound.
5. No such name is seen, and the value leaves the function. If a `bounded_by`
   name is called on the type somewhere else, the scanner abstains. If not, it
   has no bound.

A finding is advisory. It has the class `unsized.<class>` (`unsized.pool`),
and the control that the spec gives. The scan reports one finding for each
class and control, with at most five sites.

| Retriever | Emits |
| --- | --- |
| `goindex` | `pool`: `database/sql` `Open`, `OpenDB`. `cache`: `github.com/patrickmn/go-cache` `New`. `read`: `io.ReadAll`, `io/ioutil.ReadAll`. The list is `bound_constructors` in `helpers/goindex/extractor_corpus.json`. |
| `pyindex` | `queue`: the `queue` and `asyncio` queue classes, `multiprocessing.Queue`, `collections.deque`. `pool`: `redis.ConnectionPool`, `redis.BlockingConnectionPool`, `sqlalchemy.create_engine`, `psycopg_pool.ConnectionPool`. `cache`: `functools.lru_cache`, `functools.cache`. |
| The other retrievers | Nothing yet. |

Three limits:

- `goindex` does not report `make(chan T)`. A Go channel with no capacity
  blocks the sender until a receiver is ready. It is not an unbounded queue.
- `pyindex` does not report reads. It has no receiver types, so it cannot tell
  `response.read()` from a read that has a limit.
- The retriever reads one function. For a value that leaves the function, the
  only other evidence is a method call on the same type in the same module.

## What a retriever skips

A retriever reads production code. Two kinds of file are left out, and
both are counted in COVERAGE rather than dropped in silence, because a file
excluded without saying so reads as a file that was scanned:

- **Machine-generated files**, decided by the banner in the file (`Code
  generated ... DO NOT EDIT`), never by the path. `rvl` drops their packets
  after retrieval and prints `N machine-generated files excluded`; `--out`
  carries `coverage.generated_skipped`.
- **Test files**, decided by path convention inside the helper. `goindex`
  has always skipped `_test.go` and `vendor/`. `pyindex` and `tsindex` skip
  the conventions below, count what they skipped, and report the count on
  the repo-scoped record every helper writes (`test_files_skipped`, with
  the paths beside it as `test_files_skipped_paths`, on tsindex's
  `repo_config` and pyindex's `retrieval_stats`). `rvl` prints one
  COVERAGE line per language, `TypeScript: 12 test files skipped (tests are
  not scanned for API surfaces)`, and `--out` carries the total as
  `coverage.test_files_skipped`. A zero prints nothing. The packet index
  flags each named file, so a warm scan reports the repository-wide count
  from reused entries rather than the files it happened to re-parse.

`cindex` writes one `tu_includes` record per translation unit it parsed:
the in-repo headers that unit includes. The packet index stores the list
with the unit's packets, together with the packets found in those headers.
A warm scan re-parses a C or C++ source file when the file changed or when
a header it includes changed. `rvl index reindex --files` accepts a header
and re-parses the source files that include it.

`cindex` also names, on its `retrieval_stats` record, the translation units
that parsed with errors (`tus_incomplete_paths`). The packet index flags each
one, so a warm scan that reuses the entry still prints `C/C++: 1 file
INCOMPLETE: ...` in COVERAGE and `--out` carries
`coverage.parse_incomplete_files`. Without the flag the unit was reused as a
clean parse with zero sites. The flag describes the last parse. A header that
was not found is not a recorded dependency, so to install the header does not
clear the flag: the unit is parsed again only when the file or a header it
includes changes. A full `rvl scan` (without `--incremental`) parses every
unit and shows the current state. An index entry for a C or C++ file that
was written before the flag existed is parsed again one time.

`tsindex` also reports, on the same `repo_config` record, the workspaces
that declare dependencies with no installed tree
(`dependency_trees_uninstalled`, with the directories beside it as
`dependency_trees_uninstalled_paths`). It resolves those from import syntax
rather than abstaining, and `rvl` prints `TypeScript: 2 workspaces without
installed dependencies (client types resolved from import syntax: medium
tier, no client versions)` in COVERAGE; `--out` carries the total as
`coverage.dependency_trees_uninstalled`.

| Retriever | Skipped by default |
| --- | --- |
| `goindex` | `*_test.go`, anything under `vendor/` |
| `pyindex` | a path segment named `tests`, `test`, `testing` or `fixtures`; `conftest.py`; `test_*.py`; `*_test.py` |
| `tsindex` | a path segment named `tests`, `test`, `__tests__`, `__mocks__`, `e2e`, `spec`, `fixtures`, `testdata` or `cypress`; `*.test.*`, `*.spec.*`, `*.cy.*`; `playwright.config.*`, `cypress.config.*`, `vitest.config.*`, `vitest.workspace.*`, `vitest.setup.*`, `jest.config.*`, `jest.setup.*`, `setupTests.*` |

Segments and basenames match exactly, never as substrings: `attestation.ts`,
`lib/contest/`, `packages/test-utils/` and `src/latest.py` are production
code. The segment rule has one known false positive: a directory literally
named `spec` is treated as test material, so an `openapi/spec/` tree of
TypeScript is skipped and counted. `--include-tests` is the escape hatch.

A deliberate change to bound crediting rides along in tsindex: a test
file's client constructions are left out of the repo-scoped construction
facts too, so a timeout set in test scaffolding cannot credit a bound to a
production call. A repo whose only `new Pool({ connectionTimeoutMillis })`
lives under `tests/` used to have its production `pool.query` calls
credited as bounded; it now abstains on them, which is the honest answer.

A retriever is not started at all for a language that is found only in
test material while another language is really present; the roll-call
names it as `skipped`. See [scanning.md](scanning.md) for the rule.

`rvl scan --include-tests` turns that language skip off and lifts the
file skip for the Python and TypeScript
lanes on a full scan (`goindex` is unchanged). It is refused together with
`--incremental`: the packet index is built with the skip in place, so a warm
scan could only honor the flag for the files it re-parsed and would report
that partial answer as the repository's.

## Misuse shapes

Some shapes of code are wrong where they stand: shapes of error handling, of
async code, of a retry, of a query call, of output, and of a metric. One
function is enough to see them, and no call graph is necessary. A
retriever reports them as packets with `site_kind: "misuse_shape"`. The packet
is not a call site. It is not counted in COVERAGE, and it is not a row in
`--out`.

A misuse packet is an aggregate, like an emission point. There is one packet
for each enclosing function, class, and identity. The class and the count are
in `const_args`, with `how: "aggregate"`:

| Entry | Meaning |
| --- | --- |
| `misuse_class` | The class of the shape. See the table below. |
| `misuse_count` | The number of times the shape occurs in the function. |

The identity is in `client_type`. The line and the snippet are those of the
first occurrence.

| Class | Shape | Identity |
| --- | --- | --- |
| `overbroad_catch` | A handler catches the root exception type and does not raise again. | The type that is caught (`Exception`, `BaseException`), or `bare` for `except:`. |
| `discarded_error` | A call result of type error is assigned to a discard (`_ = f.Close()`). | The callee: `os.Remove`, `os.File.Close`. `func value` when the call goes through a function value. |
| `blocking_in_async` | A blocking function is called in the text of an async function. | The callee: `time.sleep`, `requests.get`. |
| `sync_over_async` | An async function waits synchronously for async work. | The call that waits: `asyncio.run`. |
| `fire_and_forget` | A task is started as a statement. Nothing holds the task. | The call that starts it: `asyncio.create_task`. |
| `missing_await` | A coroutine function is called as a statement, or its result is assigned to a name that nothing reads. | `coroutine`. |
| `retry_shape` | A wait on the failure path of an attempt loop, or the configuration of a retry library. | The shape: `constant_delay`, `no_jitter`, or `unbounded_attempts`. |
| `loop_variable_query` | A query method is called on a relation of a loop variable (`for c in customers: c.orders.all()`). | The method: `all`, `filter`, `first`. |
| `sql_concat_in_call` | A query call has SQL text that is built in the argument: a concatenation, a format call, or an f-string. | The query method: `database/sql.DB.Query`, `execute`. |
| `print_logging` | Output goes through a print function to a standard stream. | The callee: `fmt.Println`, `fmt.Fprintf(os.Stderr)`, `print`. |
| `latency_scalar_metric` | A Prometheus gauge or counter is registered with a name that contains `latency`, `duration`, `response_time`, or `elapsed`. | The constructor: `prometheus_client.Gauge`. |

Each of the last five classes has the name of the shape that the retriever
reads. The name is not the name of a defect, because the retriever cannot see
the defect:

- `retry_shape` is read from the delay expression. The retriever does not
  decide from the intent of a loop that it is a retry. An attempt loop is a
  `for` or `while` loop with no collection (`for {}`, `for i := 0; i < n; i++`,
  `while`, `for attempt in range(n)`). A loop over a collection gives each
  item one attempt, and is not reported. The wait must be on the failure
  path: in Go, below an `err != nil` test or after an `err == nil` test that
  leaves the iteration; in Python, in an `except` handler or after a `try`
  that leaves the loop. A sleep at another position is a poll interval.
  `constant_delay` is a delay in which nothing changes between attempts.
  `no_jitter` is a delay that changes and has no random term.
  `unbounded_attempts` is a loop with no condition and no counter test that
  leaves it. A delay that a function computes (`time.Sleep(backoff(n))`) has
  no shape in the expression, and is not reported.
- `loop_variable_query` is not the N+1 defect. It is the one form of an N+1
  that one function shows. A query in a function that the loop calls is not
  seen, and this lane does not report it with any name.
- `sql_concat_in_call` is not SQL injection. It is the one form that one
  expression shows. SQL text that one statement builds and another statement
  runs is not seen: that needs data flow.
- `print_logging` does not include the standard log package of a language
  (`log.Printf`, `logging.info`). The emission lane counts those calls as log
  emissions, and one line cannot be a log emission and a missing one.

A swallowed error is not in this table. It is an emission-point fact
(`except_handler`, `catch_clause`, `recover_block`), and the emission lane
reports it. A handler that the emission lane counts as a swallow is not
reported again as an overbroad catch.

A retriever does not decide that a shape is a finding. A `misuse_shapes` spec
does. Each entry has a class, a type, a role, and a control:

- `type` is one identity, or `*` for all identities of the class. An entry
  for one identity has priority over a `*` entry.
- `role: "violates"` makes the shape a finding for the control of the entry.
- `role: "allowed"` makes the shape legitimate for that identity. This is the
  list of legitimate suppressions. A discarded `Close` on a file that was only
  read is an example.
- `severity` is optional: `low` or `medium`. Without it, the class has its
  default severity.

A class that no spec names is not judged.

These shapes are frequent, and a report with one line for each occurrence is
a report that nobody reads. The retriever does not report fewer shapes to
prevent this. The volume is controlled in three other places:

1. The scan reports one finding for each class and control, with a maximum of
   five sites.
2. The finding gives the total count, so that the exposure tier of the report
   applies to it.
3. A finding is always advisory. The default severity is `low` for
   `overbroad_catch`, `discarded_error`, `fire_and_forget`,
   `loop_variable_query`, `print_logging`, and `latency_scalar_metric`. It is
   `medium` for `blocking_in_async`, `sync_over_async`, `missing_await`,
   `retry_shape`, and `sql_concat_in_call`. A spec can
   set `low` or `medium`. It cannot set `high`.

The finding has the class `misuse.<class>` (`misuse.discarded_error`). A
waiver or `rvl suppress` uses that name.

| Retriever | Emits |
| --- | --- |
| `goindex` | `discarded_error`, `retry_shape`, `sql_concat_in_call`, `print_logging`, `latency_scalar_metric`. Go has no typed catch and no async functions, and a Go ORM does not load a relation through the receiver, so it has no other class. |
| `pyindex` | `overbroad_catch`, `blocking_in_async`, `sync_over_async`, `fire_and_forget`, `missing_await`, `retry_shape`, `loop_variable_query`, `sql_concat_in_call`, `print_logging`, `latency_scalar_metric`. |
| The other retrievers | Nothing yet. |

Limits:

- `goindex` reports an assignment to `_` only. It does not report a call
  statement that ignores all its results (`f.Close()`), and it does not
  report `_ = err` on a variable.
- `pyindex` has no types. For `blocking_in_async` it reports module-level
  functions from a fixed table (`time.sleep`, `requests.get`,
  `subprocess.run`). It does not report a blocking method on a client object.
- `pyindex` knows that a callee is a coroutine function only when the same
  module defines it with `async def`, at module level or on the enclosing
  class. It does not see a coroutine function that is imported.
- A call in a lambda or in a nested function that is not async is not
  reported as `blocking_in_async`. It runs where that function is called, for
  example in a worker thread.
- For `retry_shape`, `goindex` reads loops only. It does not read the
  configuration of a retry library. `pyindex` reads loops and `tenacity`
  configurations. In Python, the failure path is an exception: a loop that
  tests a result and sleeps is not reported.
- For `sql_concat_in_call`, `goindex` knows the handle types of
  `database/sql`, `sqlx`, and `pgx`. `pyindex` has no types, so it reports
  the methods `execute`, `executemany`, and `executescript` on any receiver.
- For `loop_variable_query`, `pyindex` has no types. The method name is the
  only evidence that the call is a query. `count` and `get` are not in the
  list, because `str.count` and `dict.get` are more frequent.
- For `latency_scalar_metric`, the retrievers know the Prometheus client
  only, and the name of the metric must be a string constant.

## Scanning a prebuilt packet stream

To scan a prebuilt packet stream instead of running a helper, pass the escape
hatch; `explain` and `report` take the same inputs:

```sh
rvl scan --retrieved packets.jsonl
rvl explain <id> --retrieved packets.jsonl
```

The signed spec cache is used by default (`rvl sync` populates it,
`rvl cache import` loads it air-gapped). `--specs-file` is a loudly-announced
dev override.

## See also

- [Releasing](releasing.md): how each helper reaches a released `rvl`
- [Gating commits and CI](gating.md): what a lane that reads nothing does to
  your gate
- [Configuration](configuration.md): the `RVL_*INDEX` overrides and
  `RVL_HELPER_DIR`
