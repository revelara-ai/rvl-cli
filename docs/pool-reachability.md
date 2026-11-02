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
   the same object). It does not work through function results, interface
   values, channels, maps or slices. Return flow is the gap that matters: the
   pool is almost always built inside a constructor and returned.
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
   reaches the caller.
2. Link registration arguments to functions, and mark `go` edges.
3. Add gRPC `Register*Server` and `http.Handler` values as handler entries.
4. Add interface dispatch (CHA), or the pool-wrapping rule.
5. Add `go-co-op/gocron` to `jobFrameworks`.
6. Raise the backward join above 67/193 on nakama and 0 on crowdsec.

Before any decision moves on these facts, adjudicate how often a server
started with `go`, or a metrics ticker, is misclassed as a job.
