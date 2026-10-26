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
| `scanner.use_agent` | `allow` opts the repo into hook-mode agent adjudication. Absent means deny; opting in requires committing this key. |
| `scanner.agent_hooks.<hook>.enabled` | Per-hook opt-in for that lane. |
| `scanner.agent_verdicts` | `gate` promotes agent `violates` verdicts into the BLOCKING section; anything else keeps them advisory. |
| `scanner.model_threads` | CPU threads for local model inference (default 4, at least 1). Verdicts do not depend on it; it trades scan time for CPU. |

Unknown keys are tolerated everywhere, so the same file can carry settings for
other consumers.

## Named contexts

One `~/.revelara/config.yaml` can hold more than one server or organization
as named contexts, like kubectl:

```yaml
current_context: prod
contexts:
  prod:
    api_url: https://api.revelara.ai
    api_key: pk_...
    org_name: example.com
  staging:
    api_url: https://staging.example.com
    api_key: pk_...
    org_name: example.com
```

A file from before named contexts, with only the top-level `api_url`,
`api_key` and `org_name` keys, needs no change: `rvl` reads it as a context
named `default` and selects it. A file with no `api_url` keeps the
production URL. Commands that only read the file (`scan`, `status`,
`config show`, `config get-contexts`) never rewrite it. The first command
that writes the file anyway (`login`, `config set`, `config set-context`,
`config use-context`) stores it in the contexts form. Other keys, such as
`agent`, stay as they are. `rvl` 1.6.0 and earlier read no credentials from
a file in the contexts form.

Every command uses the same selection, highest first:

1. the global `--context <name>` flag, on any command (`rvl --context staging scan`);
2. `RVL_CONTEXT`;
3. `current_context` in the file.

`RVL_API_KEY`, `RVL_API_URL` and `RVL_ORG_NAME` still win over the values of
the selected context. A name that is not in `contexts` is an error that lists
the known contexts; `rvl` never falls back to another context or to the
production URL. A context with no `api_url` is an error too. A malformed
config file is an error for every command.

| Command | What it does |
| --- | --- |
| `rvl config get-contexts` | List the contexts: name, API URL, organization. `*` marks the selected one. A key is never printed. |
| `rvl config use-context <name>` | Write `current_context`. No other key changes. |
| `rvl config set-context <name> [--url <url>] [--key <key>] [--org <org>]` | Create or update one context. A new context needs `--url`. The URL must be `https://`, or `http://` to a loopback host; to use another `http://` server, edit the file. |

`rvl config set`, `rvl config show` and `rvl login` work on the selected
context. When no context is selected, `rvl login` and `rvl config set` write
the context `default`. A write into a context selects it when the file
selects none. `rvl status` prints `Context: <name>` on its second line when
a context is selected.
`rvl logout` removes the whole file, every context included.

## Environment variables

Environment variables win over `~/.revelara/config.yaml`, which is what makes
headless and CI use work with no config file at all.

| Variable | Purpose |
| --- | --- |
| `RVL_API_KEY` | API key (config `api_key`) |
| `RVL_API_URL` | API endpoint (config `api_url`) |
| `RVL_ORG_NAME` | Organization name (config `org_name`) |
| `RVL_CONTEXT` | Named context to use (below `--context`, above `current_context`); see [Named contexts](#named-contexts) |
| `RVL_OFFLINE=1` | Kill switch for every network fetch, including the background spec-cache check |
| `RVL_SPEC_VERSION` | Pin the spec cache content_version for `scan` (same as `--spec-version`); see below |
| `CI` | When set (and not `0`/`false`), a scan does not start the background spec-cache check |
| `RVL_BASE_REF` | Base ref for `--changed-only` (below `--base`, above CI's own vars) |
| `RVL_FORCE=1` | Commit despite blocking findings |
| `RVL_SCAN_TIMEOUT` | HTTP timeout for submission mode (default 60s) |
| `RVL_HELPER_DIR` | Relocate the extracted-helper directory |
| `RVL_GOINDEX`, `RVL_PYINDEX`, `RVL_TSINDEX`, `RVL_JAVAINDEX`, `RVL_CINDEX`, `RVL_RUSTINDEX`, `RVL_CSINDEX` | Point a lane at a specific helper (slot 1) |
| `RVL_NODE_MAX_OLD_SPACE_MB` | V8 heap limit, in MB, for the `node` that runs the TypeScript helper. Default: half of physical memory, at most 16384. `0` leaves node's own default (about 4 GB). A `NODE_OPTIONS` that sets `--max-old-space-size` is respected when this is unset |
| `RVL_RUST_ANALYZER` | Path to the `rust-analyzer` binary the Rust lane drives (`RVL_RUST_ANALYZER_SHA256` optionally pins its checksum) |
| `RVL_ONNXRUNTIME` | The ONNX Runtime library local model inference loads (the file, or a directory holding it), instead of the pinned one a release carries in `onnxruntime/` beside `rvl` |
| `RVL_RUSTINDEX_MAX_CRATES` | Largest cargo workspace (crates, dependencies included) the Rust lane hands to `rust-analyzer`; a bigger one is not indexed and the lane is reported partial. Default 600, which keeps `rust-analyzer` under about 8 GB |
| `RVL_CACHE_DIR`, `RVL_INDEX_DIR`, `RVL_SKILLS_CACHE_DIR` | Relocate the spec cache, packet index, skills cache |
| `RVL_ALLOW_UNSIGNED_PLUGIN=1` | Accept plugin content from a server with no signing key |
| `RVL_TRUST_PLUGIN_SIGNING_KEY=<fingerprint>` | Trust a changed plugin signing key. The value must be the `sha256:…` fingerprint of the key the server serves; see [agent-skills](agent-skills.md#the-signing-key-is-trusted-on-first-use) |
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
  fetches with no credentials. A keyless `rvl sync` is not an error; it
  installs this tier alone.

Both artifacts are signature-verified against the same pinned keyset at fetch
and at load. At scan time the two layer: the OSS tier is the base payload and
the commercial tier the overlay, so a keyed install adds the judgment lanes
on top of the public vocabulary baseline, and removing the key falls back to
the baseline. The judgments corpus (what grades a finding) rides only in the
commercial tier. See [Scanning your repo with rvl](scanning.md) for the
user-facing guide.

### Keeping the cache current

You do not need to run `rvl sync` by hand:

- `rvl init` syncs both tiers (the commercial one only with a key) before it
  finishes. A failed fetch does not fail init; it says to run `rvl sync`.
- A scan on the signed cache starts at most one background check every six
  hours, after the scan has finished. The scan never waits for it, and a
  failed check is silent. The last check time is `auto-sync.stamp` in the
  cache root; `rvl sync` and `rvl init` reset it.
- A cache the check installs applies from the NEXT scan, never the running
  one, so a single scan always runs on one corpus. When a repo's scan runs on
  a different corpus than its previous scan, stderr says so:
  `spec cache updated since this repo's last scan: <old> -> <new>`. A result
  that changed with no code change is then visibly the corpus, not the code.

The background check is off with `RVL_OFFLINE=1`, in CI (`CI` set), and when
the scan is pinned. To make a CI gate reproducible across time, pin the
corpus with `--spec-version <content_version>` or `RVL_SPEC_VERSION` (a
comma-separated list gives one version per tier; `rvl cache status` prints
them). A pinned scan refuses to run on any other installed version; install
the pinned artifact with `rvl cache import`.

## Compatibility flags

`rvl scan` accepts several flags from the previous Go CLI so that hook files
already on disk keep working after an upgrade, since no human is present when
git runs them. None of these is the recommended spelling, and each prints a
notice naming the repair:

| Flag | Behavior now |
| --- | --- |
| `--agent` | Runs the ordinary deterministic scan. It never invokes a model. To blend in your agent, use `--blend` (manual scans only). |
| `--staged` | Alias for `--incremental --changed-only --hook pre-commit`. |
| `--pre-push` | Alias for `--incremental --changed-only --hook pre-push`. |
| `--mode enforce\|eval` | `enforce` is the only mode; `eval` reports without blocking. |
| `--ci` | Alias for `--format json`. |
| `--auto-infer` | No-op: submission is always non-interactive. |

`rvl hook install` repairs a hook shim written by the old CLI in place,
without `--force`, so a repo takes this path only once.

## See also

- [Gating commits and CI](gating.md): where `scanner.base_ref`, `RVL_FORCE`
  and `--strict` come into play
- [How a scan finds your code](retrievers.md): what the `RVL_*INDEX`
  overrides displace
