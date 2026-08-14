# rvlscan

The Revelara reliability scanner.

`rvlscan` analyzes codebases for reliability risks and grounds its findings in
the Revelara controls catalog and incident corpus.

> Status: early development (0.x). Interfaces and output formats are unstable
> until v1.0.0.

## Install

Via Homebrew (once a release is published):

```sh
brew install revelara-ai/tap/rvlscan
```

Or download a release archive from the
[releases page](https://github.com/revelara-ai/rvlscan/releases).

## Usage

Scan a repository with a single command:

```sh
rvlscan scan [PATH]        # PATH defaults to the current directory
```

With no `--retrieved`, rvlscan detects the languages under `PATH` (Go via
`go.mod` or any `*.go`; Python via `pyproject.toml`/`setup.py` or any `*.py`),
runs the matching retriever helper (`goindex` / `pyindex`) itself, and feeds the
packets into the scan pipeline. Multiple detected languages run each helper and
concatenate their packets.

Helpers are discovered in this order:

1. an env override — `RVLSCAN_GOINDEX` / `RVLSCAN_PYINDEX` / … (path to the
   helper binary, or, for Python, the `pyindex.py` script);
2. a helper packaged with the binary — next to `rvlscan`, or in the
   `share/rvlscan` directory a package manager files an archive's non-binary
   members into;
3. the copy `rvlscan` **carries inside itself** and writes out on first use
   (`pyindex.py`, `tsindex.js`, `javaindex.java` — see below);
4. a helper on `PATH` (`goindex`; for Python, `pyindex` or `pyindex.py`).

The scan's `retrievers:` line names the resolved path and which of those four
slots answered, so a stale helper shadowing a fresh one is visible.

### What arrives with an install, and what does not

`brew install revelara-ai/tap/rvlscan` gives you a working scan for six of the
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

¹ rvlscan points `NODE_PATH` at the repository being scanned, so a project with
`typescript` in its own `node_modules` needs nothing. Otherwise tsindex prints
the one command to run (`npm install --prefix ~/.revelara/helpers/<version>
"typescript@^5.9.3"`) and that language degrades rather than failing the scan.
The pin matters: npm's `typescript` now resolves to the 7.x native port, whose
JS API this helper cannot drive.

² Build it once from a clone:
`dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex`, then
set `RVLSCAN_CSINDEX=~/.revelara/helpers/csindex/csindex.dll`.

The embedded scripts are written to `~/.revelara/helpers/<rvlscan version>/` on
first use, and rewritten whenever their contents no longer hash to the embedded
text — so an edited or truncated copy heals instead of silently scanning wrong.
`RVLSCAN_HELPER_DIR` relocates that directory.

To scan a prebuilt packet stream instead of running a helper, pass the escape
hatch:

```sh
rvlscan scan --retrieved packets.jsonl
```

`explain` takes the same inputs plus a finding id:

```sh
rvlscan explain <id> [PATH]
rvlscan explain <id> --retrieved packets.jsonl
```

The signed spec cache is used by default (run `rvlscan sync` to populate it).
`--specs-file` is a loudly-announced dev override.

### Exit codes

`rvlscan scan` is meant to sit on a pre-commit hook or in a CI gate, so its
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
rvlscan scan .          # non-zero => the job fails
```

### Workflow skills and lenses

`rvlscan skills` installs the Revelara workflow skills and lenses (the
`/rvl:scan` lens set, CAST/STPA interrogatory workflows, assessment skills)
into your coding-agent harness, so agentic scans and analyses keep working
without `rvl-cli`:

```sh
rvlscan skills install            # install into every detected harness
rvlscan skills install claude     # or name one: claude, codex, gemini,
                                  # cursor, copilot, windsurf
rvlscan skills update             # refresh previously installed harnesses
rvlscan skills status             # installed vs served versions (drift)
```

Content is served by the Revelara plugin system (the same content
`rvl plugin install` ships), verified (transport checksum + signed integrity
manifest), and cached under `~/.revelara/cache/skills` so installs keep
working offline (`RVLSCAN_OFFLINE=1` or network failure fall back to the
verified cached copy). This surface only downloads; it never uploads
anything.

## Privacy

**Customer code never leaves the machine.** `rvlscan` is open source so this is
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

Use `rvlscan report` to see EXACTLY what would ever be transmitted:

```sh
rvlscan report [PATH]                 # human-readable table of shape + counts
rvlscan report [PATH] --json          # the exact JSON payload the wire would carry
rvlscan report [PATH] --out shape.json  # write that JSON payload to a file
```

Reporting is local-only today: `rvlscan report` shows or writes the payload, it
does not transmit it.

## Development

This is a Cargo workspace. The `rvlscan` binary lives in `crates/rvlscan`.

```sh
make build          # cargo build
make test lint      # cargo test; clippy -D warnings
make dev            # build + install helpers next to the binary
```

A locally built `rvlscan scan <path>` already resolves the scripted retrievers
from the copies embedded in the binary, so `make helpers` is only needed for
`goindex` (which cargo cannot build) and when **developing** a scripted helper:
it copies `pyindex.py` / `javaindex.java` next to the binary, and the adjacent
slot outranks the embedded one, so an edit takes effect without re-embedding.
On a gvm box with a mismatched `GOROOT`, override the Go invocation:
`make helpers GO='env -u GOROOT go'`. Raw `cargo` still works for anything the
Makefile does not wrap.

## Releases

Releases are cut by pushing a v-prefixed semver tag (e.g. `v0.1.0`).
[cargo-dist](https://github.com/axodotdev/cargo-dist) builds the release
archives and publishes the Homebrew formula to `revelara-ai/homebrew-tap`.

### Shipping the retriever helpers

Each helper reaches a released `rvlscan` by the cheapest route its nature
allows, so a fresh install scans with no setup:

- **`pyindex.py` / `tsindex.js` / `javaindex.java`** are platform-independent
  text. They are `include_str!`d into the binary
  (`crates/rvlscan/src/embedded_helpers.rs`) and written to
  `~/.revelara/helpers/<version>/` on first use — one build carries them for
  every target, and there is nothing to package.
- **`cindex` / `rustindex`** are workspace binaries. `[package.metadata.dist]
  binaries` in `crates/rvlscan/Cargo.toml` packs them into the **same** archive
  as `rvlscan` (each was previously its own dist app, its own archive, and its
  own Homebrew formula), and the generated formula `bin.install`s all three.
- **`goindex`** is a compiled Go binary that cargo cannot build. Release CI
  cross-compiles it per target triple into `crates/rvlscan/dist-extras/`
  (`.github/workflows/build-setup.yml`, spliced into dist's build job via
  `github-build-setup`), and `[package.metadata.dist] include` packs it. It is
  not a cargo bin target, so Homebrew files it under `<prefix>/share/rvlscan`
  rather than in `bin` — which is why resolution checks that directory too.
  **This CI path has not yet run against a real release**: validate it on the
  next tag (`dist build` fails loudly if `dist-extras/goindex` is missing, so
  it cannot ship silently broken).
- **`csindex`** is deliberately not shipped: the assembly is ~39 KB but pulls
  ~9 MB of `Microsoft.CodeAnalysis` behind it, more than the rest of the
  archive combined. Env override / `PATH` only, with a one-command install hint
  when a C# repo is scanned without it.

The spec-cache version is independent of the binary version and is not coupled
to this repo's release CI.

## License

Apache-2.0. See [LICENSE](LICENSE).
