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
| `cindex` | in the release archive | a system `libclang`² |
| `rustindex` | in the release archive | `rust-analyzer` |
| `csindex` | not shipped: it pulls ~9 MB of Roslyn | a .NET 8 SDK³ |

¹ `rvl` points `NODE_PATH` at the repository being scanned, so a project with
`typescript` in its own `node_modules` needs nothing. Otherwise tsindex prints
the one command to run and that language degrades rather than failing the
scan. The pin matters: npm's `typescript` now resolves to the 7.x native port,
whose JS API this helper cannot drive.

² `cindex` dlopens libclang at run time, so the binary installs everywhere and
fails closed with actionable guidance where the library is absent.
`cindex --engine-check` prints the version it resolved.

³ Build it once from a clone; the output directory is a location `rvl`
searches, so there is no separate install step:
`dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex`.

Ask what is missing before the first scan on a new machine:

```sh
rvl doctor [PATH]            # repo-aware: only the languages this tree has
rvl doctor --fix             # close what can be closed safely
```

`doctor` names, per language lane, which retriever resolved, from which
slot, and whether the runtime it drives is installed. A stale helper
shadowing the shipped one is only visible here. It also reports
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

One limit to know: goindex attaches every construction of a type in the
module to every site using it, so one `Timeout`-bearing literal is evidence
for every `http.Client` call in the repo. The reason names the file and line
it came from.

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

`rvl scan --include-tests` lifts the skip for the Python and TypeScript
lanes on a full scan (`goindex` is unchanged). It is refused together with
`--incremental`: the packet index is built with the skip in place, so a warm
scan could only honor the flag for the files it re-parsed and would report
that partial answer as the repository's.

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
