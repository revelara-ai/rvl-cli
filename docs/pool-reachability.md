# Can goindex say which entry points reach a pool? (spike)

RC-067 v2 cell M5 asks whether one pool for a dependency serves both request
paths and background work: the same `*sql.DB`, `*pgxpool.Pool` or
`*http.Client` value reaches an HTTP or RPC handler and also a job, worker or
cron entry point. Today the site packet carries only one-hop facts: the client
type, up to 3 construction refs, the construction scope, const args, and up to
3 callers of the enclosing function. Nothing in it says which entry points
reach the pool, so the judge cannot answer M5 from it.

This note records what goindex's existing call graph can resolve toward that
fact. It is a measurement. No feature code was written.

## Method

A throwaway probe, not committed, compiled goindex's own sources and called
`reachIndex` (`trace.go`) and the pass-2 caller edges (`retrieve.go`)
directly. It then did three things:

1. **Forward value flow.** It inverted `reachIndex.values` alias edges
   (`b = a`, `T{f: a}`, `x.f = a`, an argument bound to a parameter by
   `bindParams`). Starting from the variables assigned at the seed line, it
   collected every variable, field and parameter the pool reaches. A "user"
   is a function whose body names one of those variables. Closures are part
   of the declaration they sit in, as they are in goindex.
2. **Upward walk.** From the users it walked the static caller edges, with
   no depth cap, and recorded entry points:
   - **handler**: a function or method value passed as an argument to a
     registration that `serverEntryClientType` recognizes; or a method of a
     type whose value is passed to `Register*Server(s, v)` (gRPC), to
     `http.Handle`/`ListenAndServe`, or to `http.Server{Handler: v}`.
   - **job**: a call made by a `go` statement or inside one; an argument to
     a `jobFrameworks` registration; or a function that calls
     `time.NewTicker`/`time.Tick`.
3. **Back to the seed.** For each G1 call whose receiver is a flow variable,
   it ran goindex's own `reach.trace` on the receiver and checked whether the
   trace reaches the seed's construction. That check is the site-to-pool join
   a per-site fact depends on.

Two optional extensions measure what the existing graph is missing:
`+iface` adds CHA edges, so a call through an interface method reaches every
in-repo method that implements it. `+wrap` makes `x := f(..., pool, ...)`,
with `f` in the repository, carry the pool into `x`.

The probe ran on 2026-11-02 against these repository heads: heroiclabs/nakama
`f794398`, nkanaev/yarr `a87e819` and crowdsecurity/crowdsec `849c7a2`. It used
goindex from this repository at `51d3b9a` and Go 1.27.1.

## Results

M5 resolves when the pool reaches at least one handler and at least one job.

| Repo, seed | Variant | Flow vars | Users | Handler entries | Job entries | M5 |
| --- | --- | --- | --- | --- | --- | --- |
| nakama `main.go:159` (`db := server.DbConnect`) | base | 185 | 876 | 167 | 5 | yes |
| | +iface +wrap | 1323 | 1115 | 185 | 24 | yes |
| yarr `cmd/yarr/main.go:187` (`store, err := storage.New(db)`) | base | 7 | 12 | 0 | 5 | **no** |
| | +iface | 7 | 12 | 14 | 5 | yes |
| | +wrap | 11 | 18 | 14 | 5 | yes |
| crowdsec `pkg/apiserver/apiserver.go:128` (`dbClient`) | base | 14 | 54 | 24 | 5 | yes |
| | +iface +wrap | 28 | 64 | 24 | 5 | yes |

"base" here already includes the handler and job joins described above, and
goindex does none of them today. With goindex exactly as it is, **none of
the three resolves**. The upward walk stops at `roots` and classifies none of
them. The `server_entry` and job-framework records exist, but they are call
sites. Nothing links them to the functions they register.

What each repository needed:

- **nakama.** 166 of the 167 handler entries come from the gRPC rule:
  methods of the `ApiServer` and `ConsoleServer` types, whose values are
  passed to `RegisterNakamaServer` and `RegisterConsoleServer`. Neither the
  route table nor a static edge reaches them. The jobs found are the
  leaderboard scheduler's goroutines and ticker
  (`server/leaderboard_scheduler.go`), the rank-cache init worker, a
  notification goroutine, and the metrics ticker.
- **yarr.** `storage.New` returns the `storage.Storage` interface, and the
  server reaches it through a second interface (`StorageProvider.GetStorage`).
  Static edges stop at `localStorage.GetStorage`, which has no static caller.
  CHA or `+wrap` connects the 14 `routes.go` handlers. The worker's goroutines
  and tickers resolve in base.
- **crowdsec.** The 24 gin routes in `controllers/controller.go` resolve
  through the route join. The jobs found are the APIC `Pull`, `SendMetrics`
  and `SendUsageMetrics` ticker loops. The **flush scheduler is missed**: it
  registers `c.FlushAlerts` with `go-co-op/gocron/v2`, which is not in
  `jobFrameworks`. The rule also classes `go apiServer.Run()`
  (`cmd/crowdsec/api.go:54`) as a job, but that is the HTTP server started in
  a goroutine, not background work.

### Seeding at the construction itself

The seeds above are the caller's assignment, the line the key cites. If the
probe is seeded at the actual construction inside the constructor, the result
changes:

| Seed | Base | +iface +wrap |
| --- | --- | --- |
| nakama `server/db.go:122` (`stdlib.OpenDB`) | 1 user, 0 handlers | same |
| crowdsec `pkg/database/database.go:46` (`sql.Open`) | 1 user, 0 handlers | same |
| yarr `src/storage/sqlite/storage.go:31` (`sql.Open`) | 26 users, 0 handlers, 0 jobs | 15 handlers, 7 jobs |

`reachIndex` records no return flow (`return db` to `x := f()`), so the
forward trace stops at the constructor's `return`. yarr survives only because
the pool goes into a struct field (`&SQLiteStorage{db: db}`), and that
field's methods are users.

### With return flow

`reachIndex` now records return flow. Each value a `return` statement hands
back reaches the function's declared result, and a call's result reaches the
variable it is assigned to (`trace.go`, `returns` and `forward`). The
fixture test is `TestForwardTraceLeavesTheConstructorThroughItsReturn`.

The probe was written again for this measurement, and it ran against the same
heads with Go 1.27.1. It counts distinct handler functions. The first probe
counted route registrations, so a function registered twice, like crowdsec's
`FindAlerts` for GET and HEAD, counted twice there. The table gives both
probes' numbers at the caller's seed so that the two can be compared.

| Seed | Variant | Flow vars | Users | Handler functions | Job entries |
| --- | --- | --- | --- | --- | --- |
| nakama `main.go:159` (caller) | base | 185 | 876 | 166 (first probe: 167) | 5 |
| nakama `server/db.go:122` | base | 2 | 1 | 0 | 1 |
| | return flow | 190 | 877 | 166 | 6 |
| crowdsec `pkg/apiserver/apiserver.go:128` (caller) | base | 14 | 54 | 18 (first probe: 24 routes) | 5 |
| crowdsec `pkg/database/database.go:46` | base | 1 | 1 | 0 | 1 |
| | return flow | 1 | 1 | 0 | 1 |

- **nakama** now resolves from the construction. The pool leaves
  `dbConnect` through its return, then leaves `DbConnect` through its return,
  and reaches `main.go:159`. From there the result is the same as seeding the
  caller. The 5 extra flow variables are the two returns and the locals
  along the way. The extra job is `dbConnect` itself: it starts a
  goroutine with a `time.NewTicker` that rescans the database's DNS, so the
  ticker rule counts it. That is the precision risk named under Answers, a
  constructor that starts a ticker.
- **crowdsec** does not change. `getEntDriver` hands the pool to
  `entsql.OpenDB(dbdialect, db)`, which is a dependency's function, and
  returns that function's driver, not the pool. Return flow carries the
  driver, which does not hold the seed. To reach the caller, the trace needs
  the pool-wrapping rule (`+wrap`) extended to a dependency's function that
  takes the pool and returns a value of its own type. The job counted at
  the construction is `reloadHandler`. It is called from a goroutine, and it
  is a caller, several levels up, of `getEntDriver`.

### The site-to-pool join

A per-site fact first has to know which pool the site's receiver is. That is
the existing backward `reach.trace`:

| Repo | G1 sites on a flow variable | Traced back to the seed | Why the rest are not |
| --- | --- | --- | --- |
| nakama | 193 | 67 | 126 `traceNone`: a parameter of a function with unseen callers (an exported method, a function used as a value) |
| yarr (seed `sql.Open`) | 24 | 24 | none |
| crowdsec | 0 | 0 | the queries are ent builder chains on `c.Ent`, where `c` is the receiver of exported `database.Client` methods |

## Answers

1. **Construction to users.** It works through struct fields, parameters
   (closed-world, through `bindParams`) and closures (a captured variable is
   the same object), and now through function results (return flow). It
   does not work through interface values, channels, maps or slices, or
   through a dependency's function that wraps the pool. Return flow was the
   gap that mattered, because the pool is almost always built inside a
   constructor and returned.
2. **Handler or job.** The caller graph can carry the classification. The
   facts needed are not joined today. A `go` call is a plain caller edge, and
   a route registration's handler argument is a reference with no edge. gRPC
   needs a rule at the level of the registered type, and yarr needs interface
   dispatch. Users were at most 8 levels below an entry point, inside the
   default `-max-depth` of 12. Precision risks: a server started with `go`
   reads as a job, and a constructor that starts a metrics ticker reads as
   one too.
3. **Cost.** The forward walk and the upward walk took 13 ms (yarr),
   661 ms (nakama) and 506 ms (crowdsec) on top of the shared package load.
   A warm `goindex -retrieve` took 1.0 s, 7.7 s and 4.1 s, so the added time
   is at most about 10%. The work is one walk per pool, and each repository
   here has one pool. The repositories have 70, 320 and 194 call-site packets
   on pool types (`sql.DB`, `sql.Tx`, `pgx`, ent), with an average size of
   2.9 KB, 11.1 KB and 3.3 KB.
   - **Per-site fact (A).** Each such packet carries the pool's construction
     ref, handler and job counts, up to 3 sample entries per class, and the
     incomplete flags. That is about 300 bytes per packet, or about 96 KB
     on nakama's 10.0 MB stream (1%), 21 KB on yarr's 0.65 MB (3%) and
     58 KB on crowdsec's 4.2 MB (1.4%). Every site on one pool repeats the
     same value. Coverage is bounded by the join above.
   - **Per-pool row (B).** One record per pool. It can carry the full entry
     lists, which were 14 to 185 handlers here. It needs a new record kind,
     and rvl has to join a site's `client_construction` to the row before
     the judge sees it. That join has the same coverage as A, because it is
     the same trace.

## Recommendation

**A**, computed once per pool and memoized, then attached to each site that
traces to that pool. The judge reads site packets, so B would still have to
be inlined into the packet on rvl's side. B adds a record kind and a second
join without improving coverage, because both options depend on the same
backward trace. A's duplication costs 1% to 3% of the stream on these
repositories.

Either option is blocked by the same groundwork. The list is in the order
measured above:

1. Add return-flow edges to `reachIndex`, so a seed at the construction
   reaches the caller. Done: see "With return flow". crowdsec still needs
   item 4's wrapping rule, extended to a dependency's wrapper.
2. Link registration arguments to functions, and mark `go` edges.
3. Add gRPC `Register*Server` and `http.Handler` values as handler entries.
4. Add interface dispatch (CHA), or the pool-wrapping rule.
5. Add `go-co-op/gocron` to `jobFrameworks`. Done: the row is
   `gocron.NewTask`, whose argument is the job function, so
   `gocron.NewTask(c.FlushAlerts)` is the job site.
6. Raise the backward join above 67/193 on nakama and 0 on crowdsec.

Before any decision moves on these facts, adjudicate how often a server
started with `go`, or a metrics ticker, is misclassed as a job.

## Built: the per-site fact

The operator chose A. goindex now computes the walk once per pool and puts
the result on every call site whose receiver traces to that pool, as
`pool_reach` in the site packet (`helpers/goindex/poolreach.go`). The field
is additive within the v2 packet train. rvl does not read it yet.

```json
"pool_reach": [{"file": "server/db.go", "line": 122, "symbol": "database/sql.DB",
  "handlers": 177, "jobs": 20,
  "handler_entries": [{"symbol": "GetAccount", "file": "server/api_account.go", "line": 30, "via": "grpc"}, ...],
  "job_entries": [{"symbol": "main", "file": "main.go", "line": 213, "via": "go_literal"}, ...],
  "users": 1301, "unclassified_roots": 694}]
```

The entry lists are a sample of 3 per class. The counts cover the whole
walk. `via` names the rule that classed each entry. `join_open` is set when a
parameter between the site and the pool belongs to a function with callers
this repository does not show.

What was built, in the order of the recommendation above:

- **Registrations and go statements.** A function value passed to a route
  registration is a handler (`route`), and so is a function literal passed to
  one (`route_literal`). A function started by `go` is a job (`go`), and so is
  a literal started by one (`go_literal`). A function or literal passed to a
  `jobFrameworks` registration is a job too (`job_framework`,
  `job_literal`). The upward walk stops at these entries. It does not cross
  from a literal to the function the literal is written in, because the
  framework or the goroutine runs the literal, not that function.
- **gRPC and http.Handler.** A method of a repository type passed to
  `Register*Server` is a handler (`grpc`) when the interface that parameter
  takes names the method. `ServeHTTP` of a type passed as an `http.Handler`
  (a parameter or `http.Server{Handler: ...}`) is a handler, and so is a
  function converted to `http.HandlerFunc` (`http_handler`).
- **Interfaces.** A call through an interface this repository declares
  reaches every method of a repository type that implements it (CHA).
  Interfaces from dependencies are left out, so that `io.Writer` does not
  join every `Write` method.
- **Wrapping.** A call whose result is a value of the callee's own type
  wraps its receiver and its arguments: `entsql.OpenDB(dialect, db)` wraps
  `db`, and `ent.NewClient(ent.Driver(drv))` wraps `drv`. Basic values,
  errors, contexts and functions are not wrapped. The forward walk follows
  wraps into the result. A function literal passed as an argument is now
  bound too, so `ExecuteInTx(ctx, db, func(tx *sql.Tx) error {...})` reaches
  `tx`. `trace` reads neither, so `client_construction` and its scope are
  unchanged.
- **The join.** The search starts from the receiver, or from the first
  variable it is selected from that leads to a pool. For `c.Ent.Alert.Query()`
  that is `Ent`. It follows copies, parameters (every visible call),
  return flow, wraps and literal bindings back to the constructions. A
  construction is a value of a type declared outside this repository. A
  repository type only holds a pool, so its operands are followed instead.
  Nil and the zero value of a pointer are not constructions.
- **Tickers.** A function is a ticker job when it receives from a
  `time.Ticker`'s channel or from `time.Tick` in its own body. Calling
  `time.NewTicker` is not enough. This drops constructors that only store a
  ticker, such as nakama's `NewMatchHandler`. The loop that reads the ticker
  is still found, as a `go_literal`.

Measured on 2026-11-04 at the heads above (nakama `f794398`, crowdsec
`849c7a2`, Go 1.27.1):

| | nakama | crowdsec |
| --- | --- | --- |
| DB call sites (`database/sql`, pgx, ent) | 320 | 230 |
| with `pool_reach` | 312 | 61 |
| with a handler and a job entry | 301 | 61 |
| pool at | `server/db.go:122` | `pkg/database/database.go:46` |
| handler entries | 177 (175 `grpc`, 2 `route`) | 18 (`route`) |
| job entries | 20 (6 `go`, 14 `go_literal`) | 10 (3 `go_literal`, 4 `job_framework`, 3 `ticker`) |
| G1 sites on the earlier flow / joined back to the seed | 194 / 194 (strict `trace`: 67) | 0 / 0 |
| G1 sites on the new flow / joined back to the seed | 336 / 336 | 106 / 106 |
| `pool_reach` bytes / stream | 292 KB / 10.5 MB (2.8%) | 109 KB / 4.5 MB (2.4%) |
| `goindex -retrieve`, fastest of 6, before / after | 5.87 s / 6.23 s (+6%) | 3.39 s / 3.53 s (+4%) |
| peak RSS before / after | 1.10 GB / 1.19 GB | 1.44 GB / 1.53 GB |

167 of crowdsec's 169 DB sites without the fact are in ent's generated
code (`pkg/database/ent`), such as `_d.Exec(ctx)` inside `ExecX`. There the
receiver is the receiver of a generated method. The join does not bind a
method's receiver to the values it is called on, so the search has nowhere
to go.

The earlier probe gave the wrong cause for the 126 nakama sites that `trace`
does not resolve. They are not parameters with unseen callers. They hit
`traceMaxAlias`, the cap of 3 copies. With no cap, `trace` resolves all but 4
of them. The pool join does not use that cap. Its search keeps a visited set
instead.

### Job precision

Every job entry on the two pools, read against the source:

- **nakama, 16 of 20 are background work.** These are the leaderboard
  scheduler and its goroutines, the rank-cache workers, the matchmaker loop
  and its fan-out, the match loop, the party, status and tracker loops,
  `NotificationSendAll`'s goroutine, the startup storage-index load and the
  console's refresh loop. `dbConnect`'s DNS rescan is also background work:
  it drains the pool with `db.Conn`. Three of the misclassed entries are
  goroutines started for one websocket connection, on the request path:
  `SingleSession`, `processOutgoing` and `Close`. The fourth is
  `HandleShutdown`'s shutdown goroutine.
- **crowdsec, 7 of 10 are background work.** These are the APIC `Pull`,
  `SendMetrics` and `SendUsageMetrics` ticker loops and the four flush jobs
  that the gocron row now finds. The three misclassed entries are the
  goroutine that runs `apiServer.Run` (the `go server.Run()` case), the one
  that runs `servePrometheus`, and the signal handler `HandleSignals`.
- **Metrics tickers.** crowdsec's `SendMetrics` and `SendUsageMetrics` are
  ticker loops that read the database and send to CAPI. They are background
  work on the pool, not a misclassification. None of nakama's job entries
  is a metrics ticker.

So 23 of 30 job entries are right. Every error is a goroutine that serves,
or lives as long as, a server, a connection or a signal. None of them is a
false handler. A judge that reads `via` can tell `ticker` and
`job_framework`, which were all right here, from `go` and `go_literal`, which
were 16 of 23.
