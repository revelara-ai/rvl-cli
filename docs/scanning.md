# Scanning your repo with rvl

`rvl` is a deterministic reliability scanner. Per-language retrievers read
your code, the results are matched against signed rulesets (the "spec
cache"), and the scanner reports where reliability problems live: missing
timeouts and deadlines, unbounded calls, secrets in the tree, risky CI and
infrastructure configuration. No account is required, nothing about your
code leaves your machine, and a scan makes zero model calls, so the same
input produces the same output.

This page covers install, scanning without an account, reading the output,
wiring the git hooks, and using a coding agent with the scanner. Reference
detail lives in the pages linked throughout; see [docs/README.md](README.md)
for the map.

## Install

```sh
brew install --cask revelara-ai/tap/rvl
```

`rvl` ships as a Homebrew cask, not a formula, so the `--cask` flag is
required. The cask installs `rvl` plus the three compiled retriever helpers
(`goindex`, `cindex`, `rustindex`). Alternatively, download a release
archive for your platform from the
[releases page](https://github.com/revelara-ai/rvl-cli/releases) and put its
contents on your `PATH`, keeping the helper binaries next to `rvl`.

The Python, TypeScript, and Java retrievers are embedded in the `rvl` binary
and need nothing beyond their runtimes (`python3`, `node` plus a TypeScript
5.x compiler, a JDK 11+). The C#/.NET retriever (`csindex`) is not shipped:
it pulls about 9 MB of Roslyn behind a roughly 39 KB assembly, so you build
it yourself, and only if you scan C#. One command from a clone of this repo
installs it where `rvl` already looks:

```sh
dotnet build helpers/csindex -c Release -o ~/.revelara/helpers/csindex
```

Verify and diagnose:

```sh
rvl version
rvl doctor        # what is missing on THIS machine, for THIS repo
rvl doctor --fix  # perform the safe local repairs; print the rest
```

`doctor` is repo-aware: it reports only on the languages your tree actually
contains. One caveat: it reports the compiled helpers (`goindex`, `cindex`,
`rustindex`) as resolvable without probing the toolchains they drive (`go`,
`libclang`, `rust-analyzer`), so a green `doctor` on a fresh machine does
not prove those lanes can read code. See
[How a scan finds your code](retrievers.md).

## Quickstart, no key required

```sh
rvl sync          # pull the free OSS ruleset - no API key needed
rvl scan          # deterministic scan of the current directory
```

`rvl sync` with no credentials installs the OSS vocabulary tier and says so:

```
oss tier: installed spec cache 2026-08-17.1
note: no API key; the commercial judgment lanes were not synced.
      Set RVL_API_KEY (or `api_key` in ~/.revelara/config.yaml) to layer them.
```

Everything local works without credentials: `rvl scan`, `rvl doctor`,
`rvl explain`, `rvl suppress`, `rvl report`, `rvl index`, `rvl hook`. Once
synced, a scan works offline; `RVL_OFFLINE=1` disables all network fetches
if you want to guarantee it.

To set a repo up properly, run `rvl init` once. It writes `.revelara.yaml`
(project name, and the committed home for waivers and declared bounds) and
installs the coding-agent skills covered in [the agent loop](#the-agent-loop)
below.

### What the free tier contains

The OSS artifact carries the vocabulary rulesets: server entry patterns,
emission patterns (logging, tracing, error handling), and configuration
knowledge for the config/IaC lane (Kubernetes, Terraform, GitHub Actions,
GitLab CI, Prometheus rules, Argo/Flux, dependency manifests). These are
enumerable facts about ecosystems.

It does not contain the judgment rulesets: the per-API verdicts about
blocking behavior, boundedness, and severity that grade API-surface
findings. Those are commercial-only. In practice the free tier finds and
names reliability-relevant surfaces in your code and configuration, and the
commercial tier additionally judges the API surfaces, which is what lets
those findings gate a commit. Lanes that carry their own severity still
gate on the free tier; secret detection is the main one.

The free ruleset is licensed
[CDLA-Permissive-2.0](https://cdla.dev/permissive-2-0/), embedded in the
artifact so every copy self-describes. Your scan results carry no
obligations under it, and redistribution only requires retaining the
license text. Both tiers are signed with the same pinned keyset, and `rvl`
verifies signatures on every fetch and every load regardless of whether a
key is configured.

### Adding a key later

```sh
rvl login       # or: export RVL_API_KEY=...
rvl sync        # now syncs both tiers
```

The commercial tier layers over the free baseline at load time. Same
binary, nothing to uninstall, no migration. The OSS store lives in an
`oss/` subdirectory beside the commercial one under the cache root, so the
two never conflict. Remove the key and the scanner falls back to the free
tier.

## Reading the output

A scan report is a ladder with three printed sections and a footer:

```
■ BLOCKING   (base severity elevated by incident evidence)
■ ADVISORY
■ COVERAGE
✗ blocked — fix or suppress 1 blocking finding to commit
```

Each finding looks like:

```
  app.py:4 — requests.get has no timeout or deadline — it can hang indefinitely
    severity: high
    control RC-019 · explain: rvl explain bfyx
```

That is: the site (`file:line`, or a repo-level site), a description, the
severity, the mapped reliability control (`RC-XXX`), and a short finding
id. Feed the id to `rvl explain <id>` for the full evidence block (every
site, the control, the fix) or to `rvl suppress <id>` to waive it.

Three things about severity:

- Severity is a property of the ruleset's judgment about the API, not a
  guess about your code, which is why it is consistent across languages.
  Findings can be elevated by incident evidence from the public corpus: a
  row carrying `evidence: N corpus incidents, M critical` is blocking even
  when its base severity alone would not be.
- A finding marked `severity: not yet graded (advisory)` means the surface
  is recognized but not yet judged. It ranks by exposure (site count, the
  one signal available without a judge) and never blocks. Un-triaged never
  gates a commit.
- Waived findings are not deleted. The footer counts them
  (`… · 2 suppressed`) and the machine-readable `--out` document carries
  them flagged.

### The COVERAGE section

```
  47/91 API surfaces resolved (51%)
  12 abstain — 8 no spec · 2 unresolved bounds · 1 need per-site judge · 1 other
  3 sites block by design — uvicorn.run (server main loop) — waiting is the contract, so no deadline is expected
```

The scanner reports what it did not decide, and why. Exit 0 means "nothing
blocking was found", not "your code was scanned"; COVERAGE is where the
difference shows up. Each abstain names what would close it:

- `no spec`: no ruleset entry for that API yet. These are what the Revelara
  spec factory mints next (see [Privacy](#privacy) for what a shape-only
  report is).
- `unresolved bounds`: the call may be bounded in a way no retrieval can
  see. [Declare the bound](#suppressing-bounding-waiving) in
  `.revelara.yaml`.
- `need per-site judge`: the API sometimes blocks and only the call site
  settles it. Closable by the
  [hook-time agent lane](#hook-time-agent-adjudication-opt-in).

Sites that resolved correctly to no finding, like a server main loop that
blocks by design, are named so you can challenge the call if you disagree.

Check the per-language roll-call: a lane that ran and read nothing is
different from a lane with nothing to find. A helper that exits cleanly
having emitted nothing is reported as a failed lane, the report prints
`NOT CLEAN — nothing was scanned (see COVERAGE)` when no code was read at
all, and `--strict` turns a degraded lane into exit 1. Details, and the CI
assertion that closes the remaining gap, are in
[Gating commits and CI](gating.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed; nothing blocking remains after waivers |
| 1 | Scan could not complete; your code was never judged |
| 2 | Usage error |
| 3 | Scan completed; blocking findings remain |

`3` is deliberately distinct from `1` so a hook can tell "your code has a
problem" from "the scanner is broken." Advisory findings never affect the
exit code. Do not write a gate that only checks for non-zero.

## The commit and push gates

```sh
rvl hook install               # pre-commit (the default; lefthook-aware)
rvl hook install --pre-push    # and/or the pre-push hook
rvl hook doctor                # read-only preflight of the wiring
```

The installed shim runs
`rvl scan . --incremental --changed-only --hook <name>`:

- pre-commit scans exactly your staged changes. It reuses the incremental
  packet index and re-reads only files whose content hash changed, under a
  10-second retrieval budget (fail-open; `--strict` makes it fail closed).
- pre-push scans the pushed range against a base ref. The base resolves
  through a chain (`--base`, `RVL_BASE_REF`, `GITHUB_BASE_REF`,
  `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`, then `scanner.base_ref` in
  `.revelara.yaml`), so a GitHub PR job usually needs no flag at all.

`rvl index init/reindex/status` manages the incremental index directly.
`rvl index reindex --detach` rebuilds it in the background, which is useful
from your own post-commit hook to keep the next pre-commit scan warm.

With lefthook present, `hook install` prints a snippet to paste into
`lefthook.yml` instead of writing `.git/hooks`, so it never fights lefthook
for the hook file.

A blocked commit prints what to do:

```
✗ blocked — fix or suppress 1 blocking finding to commit
commit blocked; use RVL_FORCE=1 or 'rvl scan force-next' to override
```

## Suppressing, bounding, waiving

- `rvl suppress <id> --reason "..." [--expires YYYY-MM-DD]` appends a
  waiver to `.revelara.yaml` under `scanner.waivers`. The waiver key is the
  finding's class (`client_type.method`), and because the file is
  committed, the waiver is reviewable and shared with the team rather than
  living on one laptop.
- Declared bounds close `unresolved bounds` abstains when you know a client
  is bounded in a way the scanner cannot see (a `statement_timeout` on the
  production database, an infra-level deadline):

  ```yaml
  scanner:
    bounds:
      - client_type: db.Pool
        bounds: whole_call
        reason: statement_timeout=30s enforced on every prod role
        expires: "2027-01-01"   # optional; empty is open-ended
  ```

  A declaration is the strongest possible claim, so it is deliberately
  narrow: exact `client_type`, `whole_call` only.
- Suppressed findings stay accounted for in the footer count and in
  `--out`, flagged rather than dropped.

## The escape hatch (audited)

When you must get a commit through:

```sh
RVL_FORCE=1 git commit ...     # env var, for shells and CI
rvl scan force-next            # arms a one-shot bypass for the next gate run
                               # (exists for GUI git clients that can't set env vars)
```

A force-through skips the scan entirely; it is the emergency path for
shipping a lesser risk to fix a greater one. Every force-through is
recorded in `.git/rvl-audit.jsonl` with a timestamp and the mechanism used
(the armed marker also records who armed it and when). This differs from
`git commit --no-verify`, which skips every hook and leaves no record. The
`force-next` marker is one-shot and per-worktree: the next gate run
consumes it, so it cannot silently apply to a later one.

## The agent loop

The scan engine never calls a model; your coding agent does. Used together,
reliability issues get found and fixed while you are still working, and the
commit gate becomes a backstop that rarely fires.

```sh
rvl init            # writes .revelara.yaml AND installs the agent skills
```

`rvl init` (or `rvl skills install` / `rvl plugin install`) installs the
Revelara skills into your coding-agent harness. Claude Code, Codex, Cursor,
Copilot, Gemini, and Windsurf are among the supported harnesses;
`rvl plugin editors` lists them all. It also maintains a managed block in
your repo's `AGENTS.md`/`CLAUDE.md` so harnesses without slash commands
discover the same capabilities. Asking naturally ("scan this codebase for
reliability risks") works too. See
[Coding-agent skills and lenses](agent-skills.md).

The loop is three skills:

1. `/rvl:scan` is engine-first: the deterministic scanner settles every
   surface it has rulesets for, and the agent's expert lenses work only on
   what the engine left undecided (the abstains and the classes with no
   ruleset yet). The machine contract between them is the
   [`--out` scan document](out-contract.md). Nothing is scanned twice, and
   agent time goes where determinism cannot reach.
2. `/rvl:fix` takes a finding (or a risk from the register, with a key),
   builds a codebase-specific remediation plan, applies it with your
   approval, and re-scans.
3. `/rvl:ask` routes a question ("should this retry have backoff?") to a
   reliability domain expert with your risk context. Guidance only, no
   file changes.

Beyond those three, the interview-driven `/rvl:assess-*` skills assess
process controls that code scanning cannot see (postmortem practice,
incident readiness, alert hygiene, recovery readiness, governance) and
record the evidence.

When the hook does fire, the finding id in the block message feeds straight
back into `rvl explain` / `/rvl:fix`.

There is also a compounding effect worth knowing about: the `no spec`
abstains from real scans are what the Revelara ruleset factory mints next,
so each `rvl sync` tends to resolve more of your codebase than the last
one.

### Hook-time agent adjudication (opt-in)

Some abstains say `need per-site judge`: the ruleset knows the API
sometimes blocks, and only looking at the call site settles it. If you opt
in, the hook can ask your own already-configured coding agent to make that
per-site call during the gate, under a time budget:

```yaml
# .revelara.yaml
scanner:
  use_agent: allow
  agent_hooks:
    pre-commit:
      enabled: true
      budget_seconds: 30    # optional; defaults: pre-commit 30s, pre-push 120s
```

How this is built: rvl shells out to an agent you already approved (Claude
Code or Copilot on `PATH`, an `agent:` selection in
`~/.revelara/config.yaml`, or an explicit `RVL_AGENT_CMD`), so there are no
new endpoints, keys, or data flows. Consent is off by default at every
layer and every layer must say yes; `RVL_NO_AGENT=1` is a hard kill switch.
The hook makes one batched invocation per run, capped at 10 sites; a
timeout or malformed output fails open and the sites stay undecided.
Verdicts are asymmetric: `satisfies` clears a site, while `violates` is an
agent-tagged warning. Blocking stays deterministic-only unless the repo
commits `scanner.agent_verdicts: gate`. Agent verdicts never enter the eval
rows or the shape-only report.

## Privacy

The deterministic scan runs entirely locally and your code never leaves the
machine. The scanner is open source, so you can verify this in the code
rather than take it on trust. The only thing a scan could ever report to
Revelara is the shape of unknown API surfaces: exactly four fields per
surface (client type, method name, language name, and a count of sites).
No source snippets, no file paths, no line numbers, nothing that identifies
your repository. You can see the exact payload any time:

```sh
rvl report            # human-readable table
rvl report --json     # the exact JSON the wire would carry
```

Reporting is local-only today: `rvl report` shows or writes the payload, it
does not transmit it. `RVL_OFFLINE=1` disables every network fetch.

Separately, `rvl scan --service <name>` is an explicit submission mode that
sends findings, including file paths and repo metadata, to your
organization's risk register. It is a deliberate, flag-gated operation on a
different channel with a different contract, and it only makes sense once
you have an account and choose to use it. [Privacy](privacy.md) scopes both
channels precisely.

## Everyday commands

| Command | What it does |
|---|---|
| `rvl scan [path]` | Full deterministic scan |
| `rvl scan --incremental` | Warm re-scan from the packet index |
| `rvl explain <id>` | Expand one finding: sites, control, fix |
| `rvl suppress <id>` | Waive a finding into `.revelara.yaml` |
| `rvl report [--json]` | Privacy preview: the exact shape-only payload |
| `rvl doctor [--fix]` | Machine/repo readiness |
| `rvl sync` | Refresh rulesets (both tiers if keyed) |
| `rvl cache status` | Installed ruleset versions and staleness |
| `rvl index init\|reindex\|status` | The incremental packet index |
| `rvl hook install\|doctor` | The git-hook gates |
| `rvl completion bash\|zsh\|fish` | Shell completion |

The full surface, including the platform commands that need credentials, is
in the [command reference](commands.md).
