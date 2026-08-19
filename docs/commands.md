# Command reference

Every command takes `--help`, and most of the platform commands take
`--format json`.

## Scanning

| Command | What it does |
| --- | --- |
| `rvl scan [PATH]` | Scan a repo against the signed spec cache: spec matching, propagation, triage. Deterministic, no model calls. |
| `rvl scan force-next [--target <dir>]` | Arm a one-shot gate bypass for the next hook run (for GUI git clients that cannot set `RVL_FORCE=1`). Audited in `.git/rvl-audit.jsonl`. |
| `rvl explain <ID> [PATH]` | Explain one finding as an evidence block: the sites it covers, the control, and the fix. |
| `rvl suppress <ID> [PATH] [--reason …] [--expires YYYY-MM-DD]` | Waive a finding: append a rule waiver to `./.revelara.yaml` under `scanner.waivers`. |
| `rvl report [PATH]` | Show EXACTLY what a scan would report about unknown API surfaces — shape only. See [Privacy](privacy.md). |
| `rvl index <init\|reindex\|status>` | Incremental-scan packet index (content-hash keyed). `reindex --detach` rebuilds in the background. |
| `rvl sync` | Refresh the spec cache from the Revelara API (async-safe, never blocks a scan). With no key, syncs the OSS vocabulary tier; with a key, both tiers. |
| `rvl cache <import\|status>` | Spec-cache maintenance, including air-gapped import of a signed artifact. |

`scan`, `explain`, `suppress`, and `report` all take the same input escape
hatches: `--retrieved <packets.jsonl>` scans a prebuilt retriever packet
stream instead of running helpers, and `--specs-file` is a loudly-announced
dev-only bypass of the signed cache (`--judgments` likewise overrides the
cache's judgment corpus).

### Submission mode

`rvl scan` doubles as the rvl-cli-compatible **submission** command: when
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
| `--format <text\|json>` | `json` is the CI contract: response JSON on stdout, and **exit 1 when the server reports critical or high findings**. `--ci` is a compatibility alias for `--format json`. |
| `--review` | Send rvl-cli's interactive-run wire value (`scan_mode: "review"`); `--ci`/`--auto-infer` win over it. |
| `--cs-file <path>` | Attach a control structure from a separate JSON file to the submission (not `stpa submit`, which ingests a full STPA model). |

## Setting up a repo and a machine

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

## Querying the Revelara platform

These talk to the Revelara API and need credentials.

| Command | What it does |
| --- | --- |
| `rvl risk <list\|ready\|show\|context\|stale\|resolve\|accept>` | Manage risk lifecycle. |
| `rvl control <list\|show>` | Query the reliability controls catalog. |
| `rvl evidence <submit\|list\|verify>` | Manage control evidence. |
| `rvl compliance report` | Compliance readiness scorecard for a framework. Readiness framing only, never certification. |
| `rvl knowledge <search\|graph-search\|facts\|procedures\|patterns\|relationships\|graph\|foresight\|enrich\|health>` | Query the organizational knowledge base. |
| `rvl incident search` | Search indexed incident postmortems. |
| `rvl stpa <submit\|list-ucas>` | STPA-inspired safety analysis. Findings are candidates for engineer review, not a substitute for expert hazard analysis. |
| `rvl feedback` / `rvl bugreport` | Send feedback or a bug report to the Revelara team. |

## See also

- [Scanning your repo with rvl](scanning.md) — the user guide these commands serve
- [Gating commits and CI](gating.md) — `rvl hook`, exit codes, CI usage
- [Configuration](configuration.md) — `.revelara.yaml`, environment variables
- [How a scan finds your code](retrievers.md) — retriever resolution
