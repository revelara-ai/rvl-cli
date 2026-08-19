# Configuration

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
| `scanner.bounds` | Declared whole-call bound assertions (`client_type`, `bounds: whole_call`, `reason`, `expires`); each closes an `unresolved bounds` abstain. |
| `scanner.base_ref` | Fallback base ref for `--changed-only`. |
| `scanner.use_agent` | `allow` opts the repo into hook-mode agent adjudication. Absent means deny: consent is a committed act, never a default. |
| `scanner.agent_hooks.<hook>.enabled` | Per-hook opt-in for that lane. |
| `scanner.agent_verdicts` | `gate` promotes agent `violates` verdicts into the BLOCKING section; anything else keeps them advisory. |

Unknown keys are tolerated everywhere, so the same file can carry settings for
other consumers.

## Environment variables

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
| `RVL_RUST_ANALYZER` | Path to the `rust-analyzer` binary the Rust lane drives (`RVL_RUST_ANALYZER_SHA256` optionally pins its checksum) |
| `RVL_CACHE_DIR`, `RVL_INDEX_DIR`, `RVL_SKILLS_CACHE_DIR` | Relocate the spec cache, packet index, skills cache |
| `RVL_ALLOW_UNSIGNED_PLUGIN=1` | Accept plugin content from a server with no signing key |
| `RVL_ALLOW_MISSING_CHECKSUM=1` | Accept a skills/plugin download whose server sent no transport-checksum header (self-hosted servers) |
| `RVL_ALLOW_MISSING_HELPERS=1` | Scan the remaining lanes when a helper is absent |
| `RVL_NO_AGENT=1` | Hard kill switch for hook-mode agent adjudication; overrides every opt-in |
| `RVL_AGENT_CMD` | Explicit command for the hook-adjudication agent adapter (otherwise `agent:` in `~/.revelara/config.yaml`, else claude/copilot on `PATH`) |
| `RVL_SRC` | Point `doctor` at an rvl source clone so `--fix` can find `helpers/csindex` to build |
| `NO_COLOR` | Honored, as is `--color auto\|always\|never` |

There are no `RVLSCAN_*` variables. The names are not aliases and are not
read.

## The tiered spec cache

The spec cache root defaults to `~/.revelara/cache/specs`; `RVL_CACHE_DIR`
relocates it. Under that root live two independent stores:

- the **commercial tier** in the root itself (`current/`, `last-good/`,
  `rejected/`), synced only with an API key;
- the **OSS vocabulary tier** in the `oss/` subdirectory, which `rvl sync`
  fetches with **no credentials at all** — a keyless `rvl sync` is not an
  error, it is the OSS-only install.

Both artifacts are signature-verified against the same pinned keyset at fetch
and at load. At scan time the two layer: the OSS tier is the base payload and
the commercial tier the overlay, so a keyed install adds the judgment lanes
on top of the public vocabulary baseline, and removing the key falls back to
the baseline. The judgments corpus (what grades a finding) rides only in the
commercial tier. See [Scanning your repo with rvl](scanning.md) for the
user-facing story.

## Compatibility flags

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

## See also

- [Gating commits and CI](gating.md) — where `scanner.base_ref`, `RVL_FORCE`
  and `--strict` come into play
- [How a scan finds your code](retrievers.md) — what the `RVL_*INDEX`
  overrides displace
