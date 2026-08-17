# rvl

The Revelara reliability scanner.

`rvl` analyzes codebases for reliability risks and grounds its findings in
the Revelara controls catalog and incident corpus.

> Status: v1.0.0. Renamed from `rvlscan` at this release; there is no
> transitional `rvlscan` alias, so update any script or hook that invoked the
> old name.

## Install

Via Homebrew (once a release is published):

```sh
brew install revelara-ai/tap/rvl
```

Or download a release archive from the
[releases page](https://github.com/revelara-ai/rvl-cli/releases).

## Usage

Scan a repository with a single command:

```sh
rvl scan [PATH]              # PATH defaults to the current directory
```

With no `--retrieved`, rvl detects the languages under `PATH` (Go via
`go.mod` or any `*.go`; Python via `pyproject.toml`/`setup.py` or any `*.py`),
runs the matching retriever helper (`goindex` / `pyindex`) itself, and feeds the
packets into the scan pipeline. Multiple detected languages run each helper and
concatenate their packets.

Helpers are discovered in this order:

1. an env override — `RVL_GOINDEX` / `RVL_PYINDEX` / … (path to the
   helper binary, or, for Python, the `pyindex.py` script);
2. a helper packaged with the binary — next to `rvl`, or in the
   `share/rvl` directory a package manager files an archive's non-binary
   members into;
3. the copy `rvl` **carries inside itself** and writes out on first use
   (`pyindex.py`, `tsindex.js`, `javaindex.java` — see below);
4. a helper you built into the canonical helper directory —
   `~/.revelara/helpers/<name>` (a file) or `~/.revelara/helpers/<name>/`
   (a directory, for builds like `dotnet -o` that emit several files);
5. a helper on `PATH` (`goindex`; for Python, `pyindex` or `pyindex.py`).

The scan's `retrievers:` line names the resolved path and which of those five
slots answered (`env:VAR` / `bundled` / `embedded` / `installed` / `PATH`), so a
stale helper shadowing a fresh one is visible.

Slot 4 is why no install instruction in this tool ends with "now export
`RVL_…`": every command it suggests writes somewhere resolution already
looks, so building the helper *is* installing it.

### First run: `rvl doctor`

Before the first scan on a new machine, ask what is missing:

```sh
rvl doctor [PATH]            # PATH defaults to the current directory
rvl doctor --fix             # close what can be closed safely
```

`doctor` is REPO-AWARE: it reports only on the languages this tree actually
contains, using the same detection the scan uses, so a Go shop is never told
about .NET. Per lane it names which retriever resolved, **from which slot**
(`env:` / `bundled` / `embedded` / `installed` / `PATH`) and whether the
runtime it drives is installed — a stale helper shadowing the shipped one via
`PATH` is visible here and nowhere else. It also reports credentials, spec
cache freshness, and git-hook wiring (folding in `rvl hook doctor`).

`--fix` performs only safe, idempotent, local repairs, announcing each one
before it runs: extract the embedded helpers, `npm install` the **pinned**
`typescript` into the helper dir, build `csindex` when a .NET SDK and the
project source are both already present, and refresh the spec cache when
credentials are already configured. Anything needing a system package manager
or `sudo` is printed, never run, and `RVL_OFFLINE=1` stops it reaching the
network. Re-running `--fix` on a healthy machine does nothing.

Exit codes: `0` everything this repo needs is in place, `1` a gap remains, `2`
usage error. `--format=json` emits the same checks for scripts.

### What arrives with an install, and what does not

`brew install revelara-ai/tap/rvl` gives you a working scan for six of the
seven languages with no further setup:

| Retriever | How it arrives | Runtime prerequisite |
| --- | --- | --- |
| `pyindex.py` | embedded in the binary | `python3` |
| `tsindex.js` | embedded in the binary | `node` + a TypeScript 5.x compiler¹ |
| `javaindex.java` | embedded in the binary | a JDK 11+ (JEP 330 source mode) |
| `cindex` | in the release archive | a system `libclang` |
| `rustindex` | in the release archive | `rust-analyzer` |
| `goindex` | in the release archive | the `go` tool |
| `csindex` | **not shipped** — it drags ~9 MB of Roslyn | a .NET 8 SDK² |

¹ rvl points `NODE_PATH` at the repository being scanned, so a project with
`typescript` in its own `node_modules` needs nothing. Otherwise tsindex prints
the one command to run (`npm install --prefix ~/.revelara/helpers/<version>
"typescript@^5.9.3"`) and that language degrades rather than failing the scan.
The pin matters: npm's `typescript` now resolves to the 7.x native port, whose
JS API this helper cannot drive.

² Build it once from a clone, and that is the whole install — the output
directory is a location rvl searches:
`dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex`.

The embedded scripts are written to `~/.revelara/helpers/<rvl version>/` on
first use, and rewritten whenever their contents no longer hash to the embedded
text — so an edited or truncated copy heals instead of silently scanning wrong.
`RVL_HELPER_DIR` relocates that directory.

To scan a prebuilt packet stream instead of running a helper, pass the escape
hatch:

```sh
rvl scan --retrieved packets.jsonl
```

`explain` takes the same inputs plus a finding id:

```sh
rvl explain <id> [PATH]
rvl explain <id> --retrieved packets.jsonl
```

The signed spec cache is used by default (run `rvl sync` to populate it).
`--specs-file` is a loudly-announced dev override.

### Exit codes

`rvl scan` is meant to sit on a pre-commit hook or in a CI gate, so its
exit code is the gate:

| Code | Meaning |
| ---- | ------- |
| `0`  | Scan completed; nothing blocking remains after waivers (`commit clean`). |
| `1`  | Scan could not complete — no verifiable spec cache, a retriever error under `--strict`, an IO failure. The scanner broke; your code was never judged. |
| `2`  | Usage error: unknown or invalid flag/argument. |
| `3`  | Scan completed and **BLOCKING** findings remain (`✗ blocked`). Fix them, or waive them in `.revelara.yaml`. |

Blocked has its own code so a hook can tell "your code has a problem" (`3`)
from "the scanner is broken" (`1`) — a broken scanner must not be silently
read as a clean tree. Advisory findings never affect the exit code.

Any non-zero exit fails the gate, so the simple form is enough for most CI:

```sh
rvl scan .          # non-zero => the job fails
```

### Workflow skills and lenses

`rvl skills` installs the Revelara workflow skills and lenses (the
`/rvl:scan` lens set, CAST/STPA interrogatory workflows, assessment skills)
into your coding-agent harness, so agentic scans and analyses keep working
without `rvl-cli`:

```sh
rvl skills install            # install into every detected harness
rvl skills install claude     # or name one: claude, codex, gemini,
                                  # cursor, copilot, windsurf
rvl skills update             # refresh previously installed harnesses
rvl skills status             # installed vs served versions (drift)
```

Content is served by the Revelara plugin system (the same content
`rvl plugin install` ships), verified (transport checksum + signed integrity
manifest), and cached under `~/.revelara/cache/skills` so installs keep
working offline (`RVL_OFFLINE=1` or network failure fall back to the
verified cached copy). This surface only downloads; it never uploads
anything.

Verification is fail-closed: a server with no signing key configured (a
self-hosted deployment, typically) refuses the install rather than
installing unverified content. Set **`RVL_ALLOW_UNSIGNED_PLUGIN=1`** to opt
out — the same variable name rvl-cli used, so existing self-hosted CI keeps
working unchanged.

`rvl init` and `rvl plugin install`/`update` also maintain a **managed
context block** in your repository's `AGENTS.md` (and `CLAUDE.md` once skills
are installed), delimited by
`<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->` /
`<!-- END REVELARA MANAGED BLOCK -->`. That block is how a harness with no
slash commands discovers `rvl` at all. It is created when the file is
missing, appended when the file exists without it, and **replaced in place**
otherwise — so re-running never duplicates it, and edits made INSIDE the
markers do not survive the next run. Everything outside the markers is left
alone. Pass `--no-context-files` to skip the step entirely.

## Privacy

**Customer code never leaves the machine.** `rvl` is open source so this is
true and auditable by construction, not aspiration. When a scan reports the
unknown API surfaces it could not decide (no spec exists yet), the payload
carries ONLY the API SHAPE — `client_type`, `method`, the `lang` it was written
in, and a `site_count` — and nothing else: no source snippets, no enclosing
function bodies, no file paths (paths leak repo structure), no line numbers,
nothing repo-identifying beyond the public API identity, its language, and a
count.

`lang` is a language NAME ("go", "python", "csharp", …), not source: it is a
property of the language the public API belongs to, at the same altitude as
`client_type`, and it is normalized to a short identifier before it can ride, so
nothing free-form can use it as a side channel. It is there because a factory
that cannot tell which language a surface came from has to guess one, and a
confidently wrong language is a worse answer than none. Empty means no language
is being claimed — either the scanner could not resolve one, or the shape was
seen in more than one language.

The shape-only report type (`ReportSurface`) is structurally incapable of
carrying source; audit tests build a report from source-bearing sites and assert
the source never appears in the serialized payload.

Use `rvl report` to see EXACTLY what would ever be transmitted:

```sh
rvl report [PATH]                 # human-readable table of shape + counts
rvl report [PATH] --json          # the exact JSON payload the wire would carry
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
`goindex` (which cargo cannot build) and when **developing** a scripted helper:
it copies `pyindex.py` / `javaindex.java` next to the binary, and the adjacent
slot outranks the embedded one, so an edit takes effect without re-embedding.
On a gvm box with a mismatched `GOROOT`, override the Go invocation:
`make helpers GO='env -u GOROOT go'`. Raw `cargo` still works for anything the
Makefile does not wrap.

## Releases

Releases are cut by pushing a v-prefixed semver tag (e.g. `v1.0.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew formula to `revelara-ai/homebrew-tap`.

### Shipping the retriever helpers

Each helper reaches a released `rvl` by the cheapest route its nature
allows, so a fresh install scans with no setup:

- **`pyindex.py` / `tsindex.js` / `javaindex.java`** are platform-independent
  text. They are `include_str!`d into the binary
  (`crates/rvl/src/embedded_helpers.rs`) and written to
  `~/.revelara/helpers/<version>/` on first use — one build carries them for
  every target, and there is nothing to package.
- **`cindex` / `rustindex`** are workspace binaries. `[package.metadata.dist]
  binaries` in `crates/rvl/Cargo.toml` packs them into the **same** archive
  as `rvl` (each was previously its own dist app, its own archive, and its
  own Homebrew formula), and the generated formula `bin.install`s all three.
- **`goindex`** is a compiled Go binary that cargo cannot build. Release CI
  cross-compiles it per target triple into `crates/rvl/dist-extras/`
  (`.github/workflows/build-setup.yml`, spliced into dist's build job via
  `github-build-setup`), and `[package.metadata.dist] include` packs it. It is
  not a cargo bin target, so Homebrew files it under `<prefix>/share/rvl`
  rather than in `bin` — which is why resolution checks that directory too.
  **This CI path has not yet run against a real release**: validate it on the
  next tag (`dist build` fails loudly if `dist-extras/goindex` is missing, so
  it cannot ship silently broken).
- **`csindex`** is deliberately not shipped: the assembly is ~39 KB but pulls
  ~9 MB of `Microsoft.CodeAnalysis` behind it, more than the rest of the
  archive combined. Scanning a C# repo without it fails closed with the one
  `dotnet build` command that installs it into `~/.revelara/helpers/csindex`,
  where resolution finds it — no environment variable at any point. A future
  `rvl-csindex` Homebrew formula should install into that same directory so
  the two routes compose.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
