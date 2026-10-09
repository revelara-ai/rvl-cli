# csindex

C# retriever helper for rvl. Emits the same versioned JSONL packet stream
as `goindex` / `pyindex` / `tsindex` (packet schema v2), for C# source.
Retrieval only, no verdicts.

## Engine

Roslyn (`Microsoft.CodeAnalysis.CSharp`): syntax trees plus a semantic model
over an **ad hoc compilation** — every discovered `.cs` file under `--root`
plus the trusted platform assemblies of the running runtime. csindex never
performs an MSBuild project load, so it needs no NuGet restore of the target
repository and cannot be wedged by a non-loading project.

## Honest degradation

The ad hoc compilation resolves the BCL (`HttpClient`, `ActivitySource`, ...)
and any types declared in the target tree itself. Types from **unrestored
NuGet packages do not resolve semantically**. Then:

- a **strong I/O verb** (`SendAsync`, `ExecuteReaderAsync`, `ProduceAsync`,
  ...) still emits the site; `client_type` comes from syntactic construction
  tracking when available, and `provenance.client_type_resolved` stays
  `false` — the low-confidence tier the panel discounts and specs abstain on;
- a **weak verb** (`Get`, `Send`, `Read`, ... — names that collide with
  non-I/O surfaces) abstains by omission unless the receiver resolved
  semantically;
- a catch clause containing an emission-shaped call on an **unresolved**
  receiver is never counted as a swallow (fail toward abstention, never
  toward accusation);
- a `Task` type that does not resolve emits **no** `sync_over_async` packet;
- a catch of the written name `Exception` or `System.Exception` that does not
  resolve (a project with `ImplicitUsings` has no `using System;`) still
  emits `overbroad_catch`, with `provenance.client_type_resolved` `false`;
- apart from that one written name, there is **no heuristic tier**: nothing
  here invents an identity from a name match.

## Lanes

- **G1** client calls: HttpClient family, ADO.NET command execution, EF Core
  `SaveChanges*` + materializing LINQ terminals, StackExchange.Redis,
  Kafka/RabbitMQ, the `Grpc.Core.CallInvoker` surface.
- **G2** `server_entry`: `Map*` route registrations and `Use*` middleware on
  resolved ASP.NET Core hosting surfaces; `[HttpGet]`-family controller
  attributes (route template rides `const_args`).
- **G3** `background_job`: `AddHostedService`, Hangfire
  (`RecurringJob.AddOrUpdate`, `BackgroundJob.Enqueue/Schedule`), Quartz
  `ScheduleJob`, plus `BackgroundService`/`IHostedService` implementations
  (the class declaration is the inventoried surface).
- **G4** `emission_point` aggregates (one per enclosing function × framework
  × category, count in `const_args`): `ILogger`, Serilog, `ActivitySource`
  (trace), Sentry (error_capture), and `catch_clause` swallow facts.
- **Unsized constructions** (`unsized_construction`, one per construction):
  `Channel.CreateUnbounded` (queue), `File.ReadAllText` and
  `File.ReadAllBytes` (read), and a `MemoryCache` whose options set no
  `SizeLimit`, built with `new MemoryCache(...)` or registered with
  `AddMemoryCache(...)` (cache). Resolved symbols only. The bounded form of
  each gives no packet. See "Unsized constructions" in `docs/retrievers.md`.

## Misuse shapes

`site_kind: "misuse_shape"` aggregates, one per enclosing function × class ×
identity, with `misuse_class` and `misuse_count` in `const_args`. The contract
and the list of identities are in "Misuse shapes" in `docs/retrievers.md`.

- `overbroad_catch`: `catch (Exception)` (identity `System.Exception`) and a
  bare `catch` (identity `bare`). Not emitted for a handler that throws again,
  a handler with a `when` filter, or a handler that the G4 lane already
  reports as a `catch_clause` swallow.
- `sync_over_async`: `.Result`, `.Wait()` with no argument, and
  `.GetAwaiter().GetResult()` on a `Task` or a `ValueTask`. The identity is
  the task type and the member, for example
  `System.Threading.Tasks.Task.Result`.

## Usage

```
csindex --packet-schema
csindex --retrieve --root <repo> --name <snapshot> [--files a.cs,b.cs]
```

`--packet-schema` prints two lines: the contract version, then
`content-version <12 hex digits>`, the start of a sha256 of `Program.cs`, which the assembly embeds. The first
line is what a consumer negotiates on. The second identifies this build of the
helper: rvl compares it with the copy it ships and warns in `COVERAGE` when
the two differ (see "Helper drift" in `docs/retrievers.md`).

Build requires a .NET 8 SDK and NuGet access for the Roslyn package:

```
dotnet build -c Release
```

rvl discovers the helper via `RVL_CSINDEX` (pointing at either a
published `csindex` executable or a framework-dependent `csindex.dll`, which
runs under `dotnet`), a `csindex`/`csindex.dll` adjacent to the rvl
binary, or `PATH`.

## Fixture

`testdata/fixture_misuse/` holds one function per identity of the misuse
lane, and one per form that the lane does not report.

`testdata/fixture/` is a minimal compilable app exercising all four lanes and the
unsized-construction inventory (`Bounds.cs`).
Third-party surfaces (Redis, Kafka, gRPC, Hangfire, ASP.NET Core, ...) are
**vendored interface stubs** in `Stubs.cs`, so the fixture compiles — and
csindex resolves its receivers semantically — without any package restore.
