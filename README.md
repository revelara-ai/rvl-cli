# rvl

The Revelara reliability scanner.

`rvl` analyzes codebases for reliability risks and grounds its findings in
the Revelara controls catalog and incident corpus. The scan is deterministic
and makes no model calls: it resolves the API surfaces your code actually
calls, matches them against a signed spec cache, and returns a blocking /
advisory ladder with an exit code a git hook or CI job can gate on.

Customer code never leaves the machine. See [Privacy](#privacy).

## Install

```sh
brew install revelara-ai/tap/rvl
```

That is the whole install: the cask ships `rvl` plus the `goindex`, `cindex`
and `rustindex` retriever helpers, and the remaining helpers are carried
inside the binary.

Or download a release archive for your platform from the
[releases page](https://github.com/revelara-ai/rvl-cli/releases) and put its
contents on your `PATH`.

## Quick start

```sh
rvl login                  # store API credentials in ~/.revelara/config.yaml
rvl init                   # write .revelara.yaml, install the agent skills
rvl doctor                 # what is missing on this machine, for THIS repo
rvl scan                   # scan the current directory
rvl hook install           # gate `git commit` on the scan
```

A scan prints a finding ladder with a short id per finding:

```
■ BLOCKING (base severity elevated by incident evidence)
  svc/main.py:4 — requests.get has no timeout or deadline — not at the call,
  not on a client or session it is built from, and not anywhere up the call
  chain, and requests applies no default of its own; it can hang indefinitely
    severity: high
    control RC-019 · explain: rvl explain bfyx
```

Follow a finding from there:

```sh
rvl explain bfyx                        # the sites, the control, the fix
rvl suppress bfyx --reason="…"          # waive it in .revelara.yaml
```

`suppress` writes `scanner.waivers` into `./.revelara.yaml`, so a waiver is a
committed, reviewable decision your team shares through git rather than a
setting on one laptop.

## Commands

### Scanning

| Command | What it does |
| --- | --- |
| `rvl scan [PATH]` | Scan a repo against the signed spec cache: spec matching, propagation, triage. Deterministic, no model calls. |
| `rvl explain <ID> [PATH]` | Explain one finding as an evidence block: the sites it covers, the control, and the fix. |
| `rvl suppress <ID> [PATH]` | Waive a finding: append a rule waiver to `./.revelara.yaml` under `scanner.waivers`. |
| `rvl report [PATH]` | Show EXACTLY what a scan would report about unknown API surfaces — shape only. See [Privacy](#privacy). |
| `rvl index <init\|reindex\|status>` | Incremental-scan packet index (content-hash keyed). |
| `rvl sync` | Refresh the spec cache from the Revelara API (async-safe, never blocks a scan). |
| `rvl cache <import\|status>` | Spec-cache maintenance, including air-gapped import of a signed artifact. |

### Setting up a repo and a machine

| Command | What it does |
| --- | --- |
| `rvl init` | Initialize Revelara for this repository: write `.revelara.yaml`, install the plugin skills, check credentials. |
| `rvl doctor [PATH]` | Diagnose (and with `--fix`, repair) this machine's ability to scan THIS repository. |
| `rvl hook <install\|doctor>` | Install or check the git-hook scan gate. |
| `rvl skills <install\|update\|status>` | Install the Revelara workflow skills and lenses into your coding-agent harness. |
| `rvl plugin <install\|update\|list\|remove\|editors\|agents>` | The same machinery under rvl-cli's plugin vocabulary, per harness. |
| `rvl config <show\|set>` | View and edit CLI configuration (`~/.revelara/config.yaml`). |
| `rvl login` / `rvl logout` | Configure or remove Revelara API credentials. |
| `rvl status` | Check connection and authentication status. |
| `rvl completion <bash\|zsh\|fish>` | Generate shell completion scripts. |
| `rvl version` | Print the version (`--version` also works). |

### Querying the Revelara platform

These talk to the Revelara API and need credentials.

| Command | What it does |
| --- | --- |
| `rvl risk <list\|ready\|show\|context\|stale\|resolve\|accept>` | Manage risk lifecycle. |
| `rvl control <list\|show>` | Query the reliability controls catalog. |
| `rvl evidence <submit\|list\|verify>` | Manage control evidence. |
| `rvl compliance report` | Compliance readiness scorecard for a framework. Readiness framing only, never certification. |
| `rvl knowledge <search\|facts\|procedures\|patterns\|graph\|foresight\|enrich\|health\|…>` | Query the organizational knowledge base. |
| `rvl incident search` | Search indexed incident postmortems. |
| `rvl stpa <submit\|list-ucas>` | STPA-inspired safety analysis. Findings are candidates for engineer review, not a substitute for expert hazard analysis. |
| `rvl feedback` / `rvl bugreport` | Send feedback or a bug report to the Revelara team. |

Every command takes `--help`, and most of the platform commands take
`--format json`.

## Gating commits and CI

```sh
rvl hook install --pre-commit    # gate `git commit`
rvl hook install --pre-push      # gate `git push`
rvl hook doctor                  # read-only preflight
```

`hook install` writes a shim into `.git/hooks`; with lefthook present it
prints a snippet to paste into `lefthook.yml` instead. The pre-commit shim is
four lines:

```sh
#!/bin/sh
# Installed by `rvl hook install`: Revelara deterministic scan gate.
# Exit 3 means BLOCKING findings remain; 0 is clean. No model calls.
exec rvl scan . --incremental --changed-only --hook pre-commit
```

`--changed-only` scopes both the report and the gate to the files this change
touched, so a one-file docs commit does not surface the whole repository.
It requires `--incremental`, and the changed set comes from git, never from
the packet index.

### Exit codes

`rvl scan` sits on a hook or in a CI gate, so its exit code **is** the gate:

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed; nothing blocking remains after waivers (`commit clean`). |
| `1` | Scan could not complete — no verifiable spec cache, a retriever error under `--strict`, an IO failure. The scanner broke; your code was never judged. |
| `2` | Usage error: unknown or invalid flag/argument. |
| `3` | Scan completed and **BLOCKING** findings remain (`✗ blocked`). Fix them, or waive them in `.revelara.yaml`. |

Blocked has its own code so a hook can tell "your code has a problem" (`3`)
from "the scanner is broken" (`1`) — a broken scanner must not be silently
read as a clean tree. Advisory findings never affect the exit code. Do not
write a gate that only checks for non-zero.

**Exit `0` means nothing blocking was found, not that your code was scanned.**
A scan whose retrievers produced nothing still exits `0`. Read the `COVERAGE`
block, which names the per-language site count and any lane that failed:
`languages: Go 0 sites` on a Go repository means the gate passed over
unread code. The next section covers how to catch that in CI.

To get past a blocked commit deliberately, `RVL_FORCE=1 git commit …` or arm
a one-shot override with `rvl scan force-next`.

### In CI

Credentials come from the environment, so CI needs no `rvl login`:

```sh
export RVL_API_KEY="$REVELARA_API_KEY"
rvl scan . --incremental --changed-only --strict
```

`--base` sets the ref `--changed-only` diverges from, and it is the top of a
chain: `--base`, `RVL_BASE_REF`, `GITHUB_BASE_REF`,
`CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, then `.revelara.yaml`
`scanner.base_ref`. A GitHub pull-request event already exports
`GITHUB_BASE_REF`, so a PR job usually needs no flag at all.

`--strict` matters more than it looks. By default a scan **fails open**: when
a retriever errors, the scan degrades to whatever it did read, prints
`NOT CLEAN — nothing was scanned (see COVERAGE)`, and still exits `0` so a
commit is not held hostage to a broken toolchain. That is the right default on
a laptop and the wrong one on a build runner, where an image missing a
language toolchain would otherwise produce a green gate forever. `--strict`
turns that case into exit `1`.

`--strict` is not a complete backstop, because it only catches a retriever
that **errors**. A retriever that exits cleanly having read nothing is not an
error, so it is reported as a genuine empty result and `--strict` passes it.
The Go lane does exactly this when the `go` tool is absent: `goindex` exits
`0` with zero packets, the scan prints `languages: Go 0 sites` and
`✓ commit clean`, and both plain and `--strict` runs exit `0`. Until that is
fixed, a CI job that must not silently pass over unread code should assert on
coverage as well as on the exit code. `--out` writes a
`coverage.lang_status` array (`state`, and `detail` carrying the site count on
a scanned lane or the error on a failed one), which makes that one command:

```sh
rvl scan . --strict --out findings.json
jq -e '.coverage.lang_status
       | all(.state == "scanned" and ((.detail | tonumber?) // 0) > 0)' \
  findings.json
```

That fails the job on a lane that errored *and* on a lane that read zero
sites, which is the gap `--strict` leaves open.

A repository with no supported language — docs, Terraform, config — produces
`lang_status: []`, and `all` over an empty array is `true`, so it passes
rather than failing the job. That is deliberate: the check asks "did every
lane rvl claimed to scan actually read something", not "does this repo have
code". Do not "fix" it into a false alarm on your docs repos.

## How a scan finds your code

With no `--retrieved`, `rvl` detects the languages under `PATH`, runs the
matching retriever helper itself, and feeds the packets into the pipeline.
Multiple detected languages run each helper and concatenate their packets.

`brew install revelara-ai/tap/rvl` gives you a working scan for six of the
seven supported languages with no further setup:

| Retriever | How it arrives | Runtime prerequisite |
| --- | --- | --- |
| `pyindex.py` | embedded in the binary | `python3` |
| `tsindex.js` | embedded in the binary | `node` + a TypeScript 5.x compiler¹ |
| `javaindex.java` | embedded in the binary | a JDK 11+ (JEP 330 source mode) |
| `goindex` | in the release archive | the `go` tool |
| `cindex` | in the release archive | a system `libclang`² |
| `rustindex` | in the release archive | `rust-analyzer` |
| `csindex` | **not shipped** — it drags ~9 MB of Roslyn | a .NET 8 SDK³ |

¹ `rvl` points `NODE_PATH` at the repository being scanned, so a project with
`typescript` in its own `node_modules` needs nothing. Otherwise tsindex prints
the one command to run and that language degrades rather than failing the
scan. The pin matters: npm's `typescript` now resolves to the 7.x native port,
whose JS API this helper cannot drive.

² `cindex` dlopens libclang at run time, so the binary installs everywhere and
fails closed with actionable guidance where the library is absent.
`cindex --engine-check` prints the version it resolved.

³ Build it once from a clone, and that is the whole install — the output
directory is a location `rvl` searches:
`dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex`.

Ask what is missing before the first scan on a new machine:

```sh
rvl doctor [PATH]            # repo-aware: only the languages this tree has
rvl doctor --fix             # close what can be closed safely
```

`doctor` names, per language lane, which retriever resolved, **from which
slot**, and whether the runtime it drives is installed — a stale helper
shadowing the shipped one is visible here and nowhere else. It also reports
credentials, spec-cache freshness, and git-hook wiring. `--fix` performs only
safe, idempotent, local repairs, announcing each one first; anything needing a
system package manager or `sudo` is printed, never run. Exit codes: `0`
everything this repo needs is in place, `1` a gap remains, `2` usage error.
`--format=json` emits the same checks for scripts.

One caveat worth knowing before you trust a green `doctor`: it reports the
three compiled helpers (`goindex`, `cindex`, `rustindex`) as
`native — no runtime prereq`, because it checks that the helper itself is
resolvable and does not probe the toolchain that helper drives. So a machine
with no `go`, no `libclang` or no `rust-analyzer` still shows `PASS` on that
lane. `cindex --engine-check` prints the libclang it resolved, and the scan's
own `COVERAGE` block is the authority on whether a lane actually read
anything.

Helpers are resolved in this order, and the scan's `retrievers:` line names
both the path and the slot it came from (`env:VAR` / `bundled` / `embedded` /
`installed` / `PATH`):

1. an env override — `RVL_GOINDEX` / `RVL_PYINDEX` / …;
2. a helper packaged with the binary — next to `rvl`, or in the `share/rvl`
   directory a package manager files an archive's non-binary members into;
3. the copy `rvl` carries inside itself and writes out on first use;
4. a helper you built into `~/.revelara/helpers/<name>`;
5. a helper on `PATH`.

Slot 4 is why no install instruction in this tool ends with "now export
`RVL_…`": every command it suggests writes somewhere resolution already
looks, so building the helper *is* installing it.

The embedded scripts are written to `~/.revelara/helpers/<rvl version>/` on
first use, and rewritten whenever their contents no longer hash to the
embedded text — so an edited or truncated copy heals instead of silently
scanning wrong. `RVL_HELPER_DIR` relocates that directory.

Per-language toolchain setup and the full hook workflow are covered in
[Local scanning](https://app.revelara.ai/help/local-scanning).

To scan a prebuilt packet stream instead of running a helper, pass the escape
hatch — `explain` and `report` take the same inputs:

```sh
rvl scan --retrieved packets.jsonl
rvl explain <id> --retrieved packets.jsonl
```

The signed spec cache is used by default (`rvl sync` populates it,
`rvl cache import` loads it air-gapped). `--specs-file` is a loudly-announced
dev override.

## Coding-agent skills and lenses

`rvl skills` installs the Revelara workflow skills and lenses (the `/rvl:scan`
lens set, CAST/STPA interrogatory workflows, assessment skills) into your
coding-agent harness:

```sh
rvl skills install            # install into every detected harness
rvl skills install claude     # or name one
rvl skills update             # refresh previously installed harnesses
rvl skills status             # installed vs served versions (drift)
rvl plugin editors            # every supported harness, with tier
```

Once installed, harnesses with slash commands expose `/rvl:scan`, `/rvl:fix`,
`/rvl:ask`, `/rvl:risks`, `/rvl:review`, `/rvl:evidence`, `/rvl:status` and
the interview-driven `/rvl:assess-*` process assessments. Harnesses without
slash commands discover the same content through the managed context block
below.

Content is served by the Revelara plugin system, verified (transport checksum
+ signed integrity manifest), and cached under `~/.revelara/cache/skills` so
installs keep working offline (`RVL_OFFLINE=1` or a network failure fall back
to the verified cached copy). This surface only downloads; it never uploads
anything.

Verification is fail-closed: a server with no signing key configured (a
self-hosted deployment, typically) refuses the install rather than installing
unverified content. Set **`RVL_ALLOW_UNSIGNED_PLUGIN=1`** to opt out — the
same variable name rvl-cli used, so existing self-hosted CI keeps working
unchanged.

`rvl init` and `rvl plugin install`/`update` also maintain a **managed context
block** in your repository's `AGENTS.md` (and `CLAUDE.md` once skills are
installed), delimited by
`<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->` /
`<!-- END REVELARA MANAGED BLOCK -->`. That block is how a harness with no
slash commands discovers `rvl` at all. It is created when the file is missing,
appended when the file exists without it, and **replaced in place** otherwise
— so re-running never duplicates it, and edits made INSIDE the markers do not
survive the next run. Everything outside the markers is left alone. Pass
`--no-context-files` to skip the step entirely.

## Configuration

Credentials live in `~/.revelara/config.yaml` (`rvl login`, or
`rvl config set <api_url|api_key|org_name> <value>`). The CLI never exposes
credentials to LLM contexts.

Project configuration lives in `.revelara.yaml` at your repo root, written by
`rvl init` and meant to be committed. The full field reference is in the
[project configuration guide](https://app.revelara.ai/help/revelara-config).
The keys this binary reads are:

| Key | Purpose |
| --- | --- |
| `project`, `components`, `team`, `criticality` | Service naming and ownership for submitted findings. |
| `scanner.waivers` | Rule waivers, written by `rvl suppress`. |
| `scanner.base_ref` | Fallback base ref for `--changed-only`. |
| `scanner.use_agent` | `allow` opts the repo into hook-mode agent adjudication. Absent means deny: consent is a committed act, never a default. |
| `scanner.agent_hooks.<hook>.enabled` | Per-hook opt-in for that lane. |
| `scanner.agent_verdicts` | `gate` promotes agent `violates` verdicts into the BLOCKING section; anything else keeps them advisory. |

Unknown keys are tolerated everywhere, so the same file can carry settings for
other consumers.

### Environment variables

Environment variables win over `~/.revelara/config.yaml`, which is what makes
headless and CI use work with no config file at all.

| Variable | Purpose |
| --- | --- |
| `RVL_API_KEY` | API key (config `api_key`) |
| `RVL_API_URL` | API endpoint (config `api_url`) |
| `RVL_ORG_NAME` | Organization name (config `org_name`) |
| `RVL_OFFLINE=1` | Kill switch for every network fetch |
| `RVL_BASE_REF` | Base ref for `--changed-only` (below `--base`, above CI's own vars) |
| `RVL_FORCE=1` | Commit despite blocking findings |
| `RVL_SCAN_TIMEOUT` | HTTP timeout for submission mode (default 60s) |
| `RVL_HELPER_DIR` | Relocate the extracted-helper directory |
| `RVL_GOINDEX`, `RVL_PYINDEX`, `RVL_TSINDEX`, `RVL_JAVAINDEX`, `RVL_CINDEX`, `RVL_RUSTINDEX`, `RVL_CSINDEX` | Point a lane at a specific helper (slot 1) |
| `RVL_CACHE_DIR`, `RVL_INDEX_DIR`, `RVL_SKILLS_CACHE_DIR` | Relocate the spec cache, packet index, skills cache |
| `RVL_ALLOW_UNSIGNED_PLUGIN=1` | Accept plugin content from a server with no signing key |
| `RVL_ALLOW_MISSING_HELPERS=1` | Scan the remaining lanes when a helper is absent |
| `NO_COLOR` | Honored, as is `--color auto|always|never` |

There are no `RVLSCAN_*` variables. The names are not aliases and are not
read.

### Compatibility flags

`rvl scan` accepts several flags from the previous Go CLI so that hook files
already on disk keep working after an upgrade, since no human is present when
git runs them. None of these is the recommended spelling, and each prints a
notice naming the repair:

| Flag | Behavior now |
| --- | --- |
| `--agent` | Runs the ordinary deterministic scan. It never invokes a model. |
| `--staged` | Alias for `--incremental --changed-only --hook pre-commit`. |
| `--pre-push` | Alias for `--incremental --changed-only --hook pre-push`. |
| `--mode enforce\|eval` | `enforce` is the only mode; `eval` reports without blocking. |
| `--ci` | Alias for `--format json`. |
| `--auto-infer` | No-op: submission is always non-interactive. |

`rvl hook install` repairs a hook shim written by the old CLI in place,
without `--force`, so a repo takes this path once and never again.

## Privacy

**Customer code never leaves the machine.** `rvl` is open source so this is
true and auditable by construction, not aspiration. When a scan reports the
unknown API surfaces it could not decide (no spec exists yet), the payload
carries ONLY the API SHAPE — `client_type`, `method`, the `lang` it was
written in, and a `site_count` — and nothing else: no source snippets, no
enclosing function bodies, no file paths (paths leak repo structure), no line
numbers, nothing repo-identifying beyond the public API identity, its
language, and a count.

`lang` is a language NAME ("go", "python", "csharp", …), not source: it is a
property of the language the public API belongs to, at the same altitude as
`client_type`, and it is normalized to a short identifier before it can ride,
so nothing free-form can use it as a side channel. It is there because a
factory that cannot tell which language a surface came from has to guess one,
and a confidently wrong language is a worse answer than none. Empty means no
language is being claimed — either the scanner could not resolve one, or the
shape was seen in more than one language.

The shape-only report type (`ReportSurface`) is structurally incapable of
carrying source; audit tests build a report from source-bearing sites and
assert the source never appears in the serialized payload.

Use `rvl report` to see EXACTLY what would ever be transmitted:

```sh
rvl report [PATH]                   # human-readable table of shape + counts
rvl report [PATH] --json            # the exact JSON payload the wire would carry
rvl report [PATH] --out shape.json  # write that JSON payload to a file
```

Reporting is local-only today: `rvl report` shows or writes the payload, it
does not transmit it.

## Development

This is a Cargo workspace. The `rvl` binary lives in `crates/rvl`.

```sh
make build          # cargo build
make test lint      # cargo test; clippy -D warnings
make dev            # build + install helpers next to the binary
```

A locally built `rvl scan <path>` already resolves the scripted retrievers
from the copies embedded in the binary, so `make helpers` is only needed for
`goindex` (which cargo cannot build) and when **developing** a scripted
helper: it copies `pyindex.py` / `javaindex.java` next to the binary, and the
adjacent slot outranks the embedded one, so an edit takes effect without
re-embedding. On a gvm box with a mismatched `GOROOT`, override the Go
invocation: `make helpers GO='env -u GOROOT go'`. Raw `cargo` still works for
anything the Makefile does not wrap.

## Releases

Releases are cut by pushing a v-prefixed semver tag (e.g. `v1.0.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew cask to `revelara-ai/homebrew-tap`.

### Shipping the retriever helpers

Each helper reaches a released `rvl` by the cheapest route its nature allows,
so a fresh install scans with no setup:

- **`pyindex.py` / `tsindex.js` / `javaindex.java`** are platform-independent
  text. They are `include_str!`d into the binary
  (`crates/rvl/src/embedded_helpers.rs`) and written to
  `~/.revelara/helpers/<version>/` on first use — one build carries them for
  every target, and there is nothing to package.
- **`cindex` / `rustindex`** are bin targets of the `rvl` package
  (`crates/rvl/src/bin/`), so `[package.metadata.dist] binaries` in
  `crates/rvl/Cargo.toml` packs them into the **same** archive as `rvl` (each
  was previously its own dist app, archive and formula), and the generated
  cask installs each as its own `binary` stanza.
- **`goindex`** is a compiled Go binary that cargo cannot build. Release CI
  cross-compiles it per target triple into `crates/rvl/dist-extras/`
  (`.github/workflows/build-setup.yml`, spliced into dist's build job via
  `github-build-setup`), and `[package.metadata.dist] include` packs it.
- **`csindex`** is deliberately not shipped: the assembly is ~39 KB but pulls
  ~9 MB of `Microsoft.CodeAnalysis` behind it, more than the rest of the
  archive combined. Scanning a C# repo without it fails closed with the one
  `dotnet build` command that installs it into `~/.revelara/helpers/csindex`,
  where resolution finds it — no environment variable at any point. A future
  `rvl-csindex` cask should install into that same directory so the two routes
  compose.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
