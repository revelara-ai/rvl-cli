# goindex — Go retriever helper

Emits the versioned packet stream rvl consumes. Retrieval only: this
helper decides nothing about reliability, it only says what the code is.

    goindex -root <repo> -retrieve -name <snapshot>     # full load
    goindex -root <repo> -retrieve -files a.go,b.go     # incremental reload
    goindex -packet-schema                              # negotiate before loading

`-packet-schema` prints two lines: the contract version, then
`content-version <12 hex digits>`, the start of a sha256 of the helper's Go sources, which the binary embeds. The first
line is what a consumer negotiates on. The second identifies this build of the
helper: rvl compares it with the copy it ships and warns in `COVERAGE` when
the two differ (see "Helper drift" in `docs/retrievers.md`).

Every emitted record carries:

- `packet_schema` — the contract version (currently `2`). rvl absorbs
  helper churn behind this number; a consumer that does not know a version
  refuses the stream rather than guessing at its shape. It agrees with
  pyindex's and tsindex's `PACKET_SCHEMA` and `rvl_core::PACKET_SCHEMA`.
- `site_key` — `file:line:client_type:method`. A file:line is **not** unique:
  one location can resolve to several sites with different client types and
  different verdicts. Measured on a 1528-site corpus: 1528 distinct site keys
  vs 1526 distinct file:line pairs. Downstream indexes and joins key on
  `site_key`, and `rvl_index::site_key` must agree with `siteKey` here.
- `lang` — always `"go"`. Named the same way the sibling helpers name theirs
  (`"python"`, `"typescript"`, `"csharp"`, `"java"`, `"rust"`, `"c_cpp"`), and
  stamped in `encodeRetrieved` next to `packet_schema` and `site_key` so every
  record kind carries it. Go emitted nothing here until po-av01j.63, which made
  a Go site indistinguishable from one whose language could not be resolved —
  and a consumer that cannot tell those apart has to treat both as unknown.
- `const_args` (v2) — constant-valued arguments at the call site, as
  `{index, name, value, how}`. Literal tokens report `how: "literal"`;
  constants the Go type checker folds for free (a named `const`, a folded
  constant expression like `2*time.Second`) report `how: "named_constant"`.
  Go calls are purely positional, so `name` is always absent. Evidence, never
  a verdict — what a value MEANS is spec-layer knowledge, and there is no deep
  constant propagation.
- `macro_expansion` (v2) — whether the site sits inside a macro expansion.
  Always `false` for Go (no macros); mechanical for C/C++ retrievers.

The candidate-extractor tables -- the G1 I/O method names and the G4 emission
framework list -- are corpus data in `extractor_corpus.json`, embedded at build
time, not code constants (po-av01j.219). Its `known_unretrieved` list names I/O
the tables do not retrieve yet (it is empty now), and every `-retrieve`
run counts those calls on the `repo_config` record's `retrieval` census beside
`candidates` (call sites emitted) and `calls_resolved` (every call whose callee
type-resolved). That census is the retrieval denominator: coverage is
resolution over what these tables retrieve, and the census is how much they
retrieve. It is computed before any `-files` filter, so it is always whole-repo.

`reader_calls` in the same file lists package functions that read from the
reader they are given: `io.ReadAll` and `io/ioutil.ReadAll`. Each call is a
call site with `client_type` the package path (`io`), `func` `ReadAll`, and
`receiver` the reader expression (`resp.Body`). The call names no client, and
the reader is what bounds the read, so the record also carries
`framework_type`: where the reader comes from. A reader is followed back
through a local that is assigned once and through a call that takes one reader
(`bufio.NewReader(resp.Body)`, `io.LimitReader(resp.Body, n)`). The origin is
then the concrete type (`os.File`), or the owner type and field for an
interface held in a struct field (`net/http.Response.Body`,
`net/http.Request.Body`). The field is absent when the origin is not known,
for example an `io.Reader` parameter. rvl looks an API spec up by
`framework_type` first and then by `client_type`, so a spec keyed on
`net/http.Response.Body` and `ReadAll` covers a response body read and does
not cover a file read. `client_construction` holds the values that reach the
variable the reader comes from, such as the call that returned the response.
`framework_type` is not part of `site_key`.

`construction_calls` and `construction_fields` in the same file select the
constructions emitted as call sites: a cipher, a hash or a database opened
from a DSN (a package function; the package is the `client_type`), and a
`crypto/tls.Config` field set in a composite literal or an assignment (the
struct is the `client_type`, the field is `func`, and its value is the one
`const_args` entry). See "Constructions that are call sites" in
`docs/retrievers.md`.

The same file holds `bound_constructors`: the functions whose calls are
emitted as `site_kind: "unsized_construction"` packets (a connection pool, a
cache, a read of a whole body). The packet lists the setters and options seen
in the constructing function. It does not say which one is a bound. See
"Unsized constructions" in `docs/retrievers.md`.

A discarded error (`_ = f.Close()`, `n, _ := strconv.Atoi(s)`) rides the same
stream as an aggregate with `site_kind: "misuse_shape"`: one packet per
function and callee, with `misuse_class: discarded_error` and `misuse_count`
in `const_args` (`misuse.go`). It is not a call site and is not in the census.
Whether a discard is legitimate is spec knowledge, so every one is emitted.
Four more classes ride the same kind (`misuse_shapes.go`): `retry_shape` (a
wait on the failure path of an attempt loop, keyed by the shape of its delay),
`sql_concat_in_call` (SQL text built in the argument of a query call),
`print_logging` (`fmt.Print*`, the print builtins, `fmt.Fprint*` to a standard
stream; never the `log` package) and `latency_scalar_metric` (a Prometheus
gauge or counter with a latency name). Each is named for the shape, not for a
defect. See "Misuse shapes" in `docs/retrievers.md`.

A cold full load is paid at explicit init, never on the hook path; the
incremental path (`-files`) reloads only what changed.

## Retrieval budgets

Five flags bound how much of the search reaches a packet. Each is a sweep
axis, and the defaults stay where they are until the precision of a raise is
measured:

| Flag | Default | What it caps |
| --- | --- | --- |
| `-max-callers` | 4 | ancestors emitted per site (`provenance.hit_caller_budget`) |
| `-max-callees` | 4 | in-repo callees emitted per site |
| `-max-snippet` | 2400 | bytes per snippet (`// ... truncated`) |
| `-max-depth` | 12 | levels of the upward walk (`provenance.hit_depth_cap`) |
| `-max-ctors` | 2 | constructions emitted per site |

The walk itself and its counts (`ancestors_traced`, `ancestors_with_deadline`,
`direct_callers`, `direct_callers_passing_bounded_ctx`) do not depend on
`-max-callers`: that flag decides how many ancestors are shown, and whether
the search counts as complete. rvl reasons from "no bound found" only on a
complete search, so a raise that makes a site complete turns an `unresolved
bounds` abstain into a decision. Which way the decision goes is the
precision question. Raising the budgets on a corpus the rulesets were
authored against closed most of its `unresolved bounds` abstains, and it also
removed 6 advisory findings. Nothing measured whether those 6 were false
positives.

Measured on 2026-10-29: goindex built from this repository at `a8a1893` (Go
1.27.3), with `-retrieve` on two public comparator repositories. Each flag was
raised alone, then together. A site is a call-site packet (no `site_kind`).
"Incomplete" means `hit_caller_budget` or `hit_depth_cap`.

| authelia/authelia `e5b644b` (211 sites) | incomplete | callee cut | snippet cut | stream |
| --- | --- | --- | --- | --- |
| defaults 4/4/2400/12 | 47 | 42 | 44 | 2.3 MB |
| `-max-callers 8` | 28 | 42 | 49 | 2.5 MB |
| `-max-callers 16` | 14 | 42 | 50 | 2.8 MB |
| `-max-callers 24` | 10 | 42 | 50 | 2.9 MB |
| `-max-callees 16` | 47 | 39 | 44 | 2.4 MB |
| `-max-snippet 12000` | 47 | 42 | 3 | 2.6 MB |
| `-max-depth 32` | 47 | 42 | 44 | 2.3 MB |
| 24/16/12000/32 | 10 | 39 | 7 | 3.5 MB |

| argoproj/argo-cd `e1a6522` (1967 sites) | incomplete | callee cut | snippet cut | stream |
| --- | --- | --- | --- | --- |
| defaults 4/4/2400/12 | 124 (4 at the depth cap) | 163 | 223 | 11.7 MB |
| `-max-callers 8` | 83 | 163 | 235 | 12.5 MB |
| `-max-callers 16` | 67 | 163 | 241 | 13.4 MB |
| `-max-callers 24` | 59 | 163 | 242 | 14.5 MB |
| `-max-callees 16` | 124 | 153 | 223 | 12.2 MB |
| `-max-snippet 12000` | 124 | 163 | 57 | 14.0 MB |
| `-max-depth 32` | 124 (0 at the depth cap) | 163 | 223 | 11.7 MB |
| 24/16/12000/32 | 59 | 153 | 82 | 19.3 MB |

What this shows:

- Only `-max-callers` changes whether a search is complete. Callees, snippet
  bytes and depth change what the packet shows but complete no site. On
  argo-cd, the 4 sites at the depth cap were also over the caller budget, so
  `-max-depth 32` alone completes none of them.
- The knee is the caller budget. An incomplete site needs `-max-callers` at
  least equal to its `ancestors_traced`. At `-max-callers 24`, authelia keeps
  10 incomplete sites (25 to 78 ancestors). argo-cd keeps 59: 10 with 26 to 95
  ancestors and 49 with 121 to 392, which is fan-in to shared server code that
  no emitted-caller budget reaches.
- At the defaults, every site that the raise completes has a
  `none_bounded` dataflow verdict, except 1 `all_bounded` and 3 `mixed` sites
  on argo-cd. Where the API's spec needs a bound, a complete search over
  `none_bounded` evidence is a finding. On these two repositories, the raise
  therefore moves toward more findings, not fewer. That is the opposite of
  the earlier 6 advisory findings removed. If a drop appears here, the
  structural evidence did not cause it. The cause is what the decision model
  read in the extra caller text, and only adjudication can say whether that
  reading is right.
- The full raise costs +52% (authelia) and +65% (argo-cd) of packet stream.
  `-max-callers 24` alone costs +26% and +24%, and makes as many sites
  complete.

This is a retrieval measurement, not a coverage one. It counts which sites a
raise would let rvl decide, not which of those sites have a spec that would
decide them. Choosing values needs the per-site precision of the decisions
that flip, adjudicated on a development repository and then confirmed once
on a held-out gate set. Re-run the sweep for each language.
