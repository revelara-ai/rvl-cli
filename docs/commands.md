# Command reference

Every command takes `--help`, and most of the platform commands take
`--format json`.

## Scanning

| Command | What it does |
| --- | --- |
| `rvl scan [PATH]` | Scan a repo against the signed spec cache: spec matching, propagation, triage. Deterministic, no model calls. |
| `rvl scan force-next [--target <dir>]` | Arm a one-shot gate bypass for the next hook run (for GUI git clients that cannot set `RVL_FORCE=1`). Audited in `.git/rvl-audit.jsonl`. |
| `rvl scan digest <ENGINE_DOC>` | Print the residual-scoping digest of a scan document (`scan --out`). See [Orchestrated scans](#orchestrated-scans). |
| `rvl scan finalize <SCAN_DIR>` | Rebuild the findings files of a submit directory from the lens outputs. See [Orchestrated scans](#orchestrated-scans). |
| `rvl scan report <ENGINE_DOC>` | Print the sections of the scan report that are pure data, as Markdown. See [Orchestrated scans](#orchestrated-scans). |
| `rvl explain <ID> [PATH]` | Explain one finding as an evidence block: the sites it covers, the control, and the fix. |
| `rvl suppress <ID> [PATH] [--reason …] [--expires YYYY-MM-DD]` | Waive a finding: append a rule waiver to `./.revelara.yaml` under `scanner.waivers`. |
| `rvl report [PATH]` | Show exactly what a scan would report about unknown API surfaces (shape only). See [Privacy](privacy.md). |
| `rvl index <init\|reindex\|status>` | Incremental-scan packet index (content-hash keyed). `reindex --detach` rebuilds in the background. |
| `rvl sync` | Refresh the spec cache from the Revelara API (async-safe, never blocks a scan). With no key, syncs the OSS vocabulary tier; with a key, both tiers. Rarely needed by hand: `init` syncs, and scans start a background check every six hours. An HTTP 404 is reported as "the server has not published a spec cache", separate from `fetch failed` (network or server error). |
| `rvl cache <import\|status\|keys>` | Spec-cache maintenance, including air-gapped import of a signed artifact. `keys` lists every config key the retrievers emit and where it stands against the installed specs: specced, awaiting a spec, or vocabulary only (emitted as evidence, never judged). |

`scan`, `explain`, `suppress`, and `report` all take the same input escape
hatches: `--retrieved <packets.jsonl>` scans a prebuilt retriever packet
stream instead of running helpers, and `--specs-file` is a loudly-announced
dev-only bypass of the signed cache (`--judgments` likewise overrides the
cache's judgment corpus).

`scan` and `report` also take `--oss-only`, which loads the OSS tier alone
even when a commercial tier is installed, so the result matches a no-key
install. It is a load filter (`rvl sync` is unchanged), it is announced on
stderr, and it cannot be combined with `--specs-file` or `--judgments`. See
[Scanning](scanning.md#scanning-with-the-free-tier-only).

### Submission mode

`rvl scan` doubles as the rvl-cli-compatible submission command: when
`--service`, `--scan-dir`, `--file`, or `--stdin` is present, it submits risk
findings to your organization's risk register instead of running the local
deterministic scan (see [Privacy](privacy.md) for what that sends). The flag
set is rvl-cli parity:

| Flag | Meaning |
| --- | --- |
| `--service <name>` / `-s` | Service the findings belong to (selects submission mode with an input flag). |
| `--scan-dir <dir>` | Merge all `*.json` part files from a directory. |
| `--file <path>` / `-f` | Read findings JSON from a file. |
| `--stdin` | Read findings JSON from stdin. |
| `--target <dir>` / `-t` | Project directory the scan describes (default: cwd); `git_commit`/`git_branch` metadata come from here. |
| `--team <name>` | Owning team for the whole submission; overrides `.revelara.yaml` `team:` values and creates the team on first sight. |
| `--dry-run` | Validate, normalize, and print the submit summary without submitting. |
| `--cleanup-on-success` | Remove `--scan-dir` contents after a successful submit. |
| `--timeout <dur>` | HTTP submission timeout (e.g. `90`, `90s`, `2m`; default 60s or `RVL_SCAN_TIMEOUT`). |
| `--format <text\|json>` | `json` is the CI contract: response JSON on stdout, and exit 1 when the server reports critical or high findings. `--ci` is a compatibility alias for `--format json`. |
| `--review` | Send rvl-cli's interactive-run wire value (`scan_mode: "review"`); `--ci`/`--auto-infer` win over it. |
| `--cs-file <path>` | Attach a control structure from a separate JSON file to the submission (not `stpa submit`, which ingests a full STPA model). |

### Orchestrated scans

The `/rvl:scan` skill runs the deterministic scan, then a pass of expert
lenses, and submits both. `digest`, `finalize` and `report` are its mechanical
steps. They read and write local files only: no scan, no spec cache, no
network. A failure prints one line on stderr and exits 1. All three need rvl
1.4.0 or later (see the [release notes](release-notes.md)).

`rvl scan digest <ENGINE_DOC>` reads the document that `rvl scan --out` wrote
and prints, as text:

- `ENGINE_DIGEST`: the exit code, the counts, and one line for each blocking
  and each advisory finding.
- `COVERED_CLASSES`: the API classes the engine judges in this repo. A lens
  must not report these again.
- `UNDECIDED` and `UNDECIDED_CLASS_CENSUS`: the sites the engine abstained
  on, by scope, by lever, and by class (runtime sites, the 10 largest
  classes).
- `ADJUDICATION_LIST`: the sites a lens gives a verdict on. Runtime sites
  only, lever `judge` first, then `bounds`, then `no_spec`, 20 sites at most.

It refuses a document whose `schema` is not `rvl-scan/v1` (see
[The `--out` document contract](out-contract.md)).

`rvl scan finalize <SCAN_DIR>` builds what `rvl scan --scan-dir <SCAN_DIR>`
submits. It reads the lens outputs in `<SCAN_DIR>.lens/*.json` (a directory
beside the submit directory, so the raw outputs are never submitted) and
writes one `03-findings-<lens>.json` for each, plus `03-findings-engine.json`
when `--engine` is given. Each run removes the old `03-findings-*.json` files
and starts from the lens outputs again, so you can run it before grounding and
again with a patch. It reads and checks every input before it removes
anything: a run that fails leaves the directory as it was.

| Flag | Meaning |
| --- | --- |
| `--engine <doc>` | The scan document. Its findings become `03-findings-engine.json` with title and control unchanged. Suppressed findings are left out, and a finding with no control sends no control code. |
| `--patch <file>` | Judgments to apply (see below). |
| `--register <file>` | The risk register, from `rvl risk list --service <name> --format=json`. Needed for `extends`. |
| `--mode <quick\|deep>` | Written to every findings file as `scan_mode` (default `quick`). |
| `--crit <n>` | Business criticality, 0.0 to 1.0 (default 0). Written to every findings file, and a factor of each lens score. |

The patch is a JSON object. It names a lens finding by `<lens>#<n>`: the file
name without `.json`, and the position of the finding in that file, from 1.

| Key | Meaning |
| --- | --- |
| `findings` | A map from `<lens>#<n>` to `control_codes`, `corroboration`, `corroboration_strength`, `substantiation_strength`, `graph_evidence` and `extends`. |
| `drop` | A list of `<lens>#<n>` to leave out. |
| `control_categories` | A map from a control code to its catalog category, for the engine rows. |
| `catalog_meta` | Copied to every findings file. |

`extends: "R-038"` says that the finding is register risk R-038, found again.
The finding takes the title and the control codes of that risk, which is what
the server matches on, and keeps its own text in the narrative. A second
finding that extends the same risk is dropped (`DUP`), and a risk code that
the register file does not hold changes nothing (`UNKNOWN`).

For each lens finding, `finalize` also sets `provenance` (`agent:<lens>`) and
`component` (the component of `01-stack.json` with the longest path that
contains the finding), removes retired control codes, and computes
`risk_score` and `priority`. Corroboration comes from the patch only: what a
lens wrote in that field is not submitted. It prints one `Written:` line for
each file, then `LENS_DIGEST`, the lens findings by score.

`rvl scan report <ENGINE_DOC> [--scan-dir <SCAN_DIR>]` prints the sections of
the scan report that are data, as Markdown. The skill adds the sections that
need judgment (the lens findings, the adjudicated sites, the recommended
actions) and does not change these:

- `### Gate (deterministic engine) — exit <n>`: each finding of the scan
  document under `BLOCKING`, `ADVISORY` or `SUPPRESSED`, as
  `[id] class — site · control · fix: fix`, with the text of the engine
  unchanged. The section is the `severity` of the finding. A blocking row has
  a second line that tells how to waive it. No row is left out: a row under
  `SUPPRESSED` ends with `(suppressed)` when a waiver suppressed it and with
  `(low value)` when the engine keeps it out of the gate, and a gate-exempt
  row ends with `(gate-exempt)`. A finding with another `severity` is an
  error.
- `### Coverage`: the `Engine:` line (resolved and total retrieved API
  surfaces, the percentage, and the abstain count of each lever) and the
  `Languages:` line, which is the roll-call of `coverage.lang_status` in the
  words of the COVERAGE block of `rvl scan`.
- `### Not Assessable From Code`, with `--scan-dir` only: one line for each
  `/rvl:assess-*` skill whose practice controls are among the `control_codes`
  of `<SCAN_DIR>/03-findings-*.json`, with those control codes. Run
  `rvl scan finalize` first: a directory with no findings file is an error.
  The section is not printed when no practice control is touched. The skill
  adds the reason to each line.

It refuses a document whose `schema` is not `rvl-scan/v1`, and then prints
nothing.

`digest`, `finalize` and `report` are subcommand names, so to scan a directory
with one of those names, write it as a path: `rvl scan ./digest`.

## Setting up a repo and a machine

| Command | What it does |
| --- | --- |
| `rvl init` | Initialize Revelara for this repository: write `.revelara.yaml`, install the plugin skills, check credentials, sync the spec cache. |
| `rvl doctor [PATH]` | Diagnose (and with `--fix`, repair) this machine's ability to scan this repository. |
| `rvl hook <install\|doctor>` | Install or check the git-hook scan gate. |
| `rvl skills <install\|update\|status>` | Install the Revelara workflow skills and lenses into your coding-agent harness. |
| `rvl plugin <install\|update\|list\|remove\|editors\|agents>` | The same machinery under rvl-cli's plugin vocabulary, per harness. |
| `rvl config <show\|set>` | View and edit CLI configuration (`~/.revelara/config.yaml`). |
| `rvl login` / `rvl logout` | Configure or remove Revelara API credentials. |
| `rvl status` | Check connection and authentication status. |
| `rvl completion <bash\|zsh\|fish>` | Generate shell completion scripts. |
| `rvl version` | Print the version (`--version` also works). |

## Querying the Revelara platform

These talk to the Revelara API and need credentials.

| Command | What it does |
| --- | --- |
| `rvl risk <list\|ready\|show\|context\|stale\|resolve\|accept>` | Manage risk lifecycle. |
| `rvl control <list\|show>` | Query the reliability controls catalog. |
| `rvl factor list [--category <1-7>] [--top10]` | List the causal factor catalog: the contributing conditions found in public incident reports. |
| `rvl factor show <CODE>` | Show one causal factor: its quotes, its controls by relation, and the related risks of your organization. |
| `rvl risk list --factor <CODE>` | List the risks of your organization that are related to one causal factor. The server does the filtering. |
| `rvl evidence <submit\|list\|verify>` | Manage control evidence. |
| `rvl compliance report` | Compliance readiness scorecard for a framework. Readiness framing only, never certification. |
| `rvl knowledge <search\|graph-search\|facts\|procedures\|patterns\|relationships\|graph\|foresight\|enrich\|health>` | Query the organizational knowledge base. |
| `rvl incident search` | Search indexed incident postmortems. |
| `rvl stpa <submit\|list-ucas>` | STPA-inspired safety analysis. Findings are candidates for engineer review, not a substitute for expert hazard analysis. |
| `rvl feedback` / `rvl bugreport` | Send feedback or a bug report to the Revelara team. |

## See also

- [Scanning your repo with rvl](scanning.md): the user guide these commands serve
- [Gating commits and CI](gating.md): `rvl hook`, exit codes, CI usage
- [Configuration](configuration.md): `.revelara.yaml`, environment variables
- [How a scan finds your code](retrievers.md): retriever resolution
