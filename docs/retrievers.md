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
