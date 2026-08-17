# Command reference

Every command takes `--help`, and most of the platform commands take
`--format json`.

## Scanning

| Command | What it does |
| --- | --- |
| `rvl scan [PATH]` | Scan a repo against the signed spec cache: spec matching, propagation, triage. Deterministic, no model calls. |
| `rvl explain <ID> [PATH]` | Explain one finding as an evidence block: the sites it covers, the control, and the fix. |
| `rvl suppress <ID> [PATH]` | Waive a finding: append a rule waiver to `./.revelara.yaml` under `scanner.waivers`. |
| `rvl report [PATH]` | Show EXACTLY what a scan would report about unknown API surfaces — shape only. See [Privacy](privacy.md). |
| `rvl index <init\|reindex\|status>` | Incremental-scan packet index (content-hash keyed). |
| `rvl sync` | Refresh the spec cache from the Revelara API (async-safe, never blocks a scan). |
| `rvl cache <import\|status>` | Spec-cache maintenance, including air-gapped import of a signed artifact. |

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
| `rvl knowledge <search\|facts\|procedures\|patterns\|graph\|foresight\|enrich\|health\|…>` | Query the organizational knowledge base. |
| `rvl incident search` | Search indexed incident postmortems. |
| `rvl stpa <submit\|list-ucas>` | STPA-inspired safety analysis. Findings are candidates for engineer review, not a substitute for expert hazard analysis. |
| `rvl feedback` / `rvl bugreport` | Send feedback or a bug report to the Revelara team. |

## See also

- [Gating commits and CI](gating.md) — `rvl hook`, exit codes, CI usage
- [Configuration](configuration.md) — `.revelara.yaml`, environment variables
- [How a scan finds your code](retrievers.md) — retriever resolution
