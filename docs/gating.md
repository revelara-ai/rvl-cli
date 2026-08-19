# Gating commits and CI

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

## Exit codes

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

## In CI

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

A retriever that **errors** is not the only way a lane can read nothing. A
helper can also exit `0` having emitted no packets at all — the Go lane did
exactly this when the `go` tool was absent, and the scan printed
`✓ commit clean` over unread code. That hole is now guarded structurally: a
language that was detected, whose helper exited `0`, and whose stream carried
nothing rvl recognizes (not even the repo-scoped record every helper writes
on a successful run) is degraded as a **failed** lane, whatever the exit code
claimed. The guard lives at the one place every helper's output passes
through, so it does not depend on any individual helper's exit-code hygiene.
A degraded lane renders `NOT CLEAN — nothing was scanned (see COVERAGE)`
under the default fail-open policy and turns into exit `1` under `--strict`.

A CI job that wants belt and braces can still assert on coverage as well as
on the exit code. `--out` writes a `coverage.lang_status` array (`state`, and
`detail` carrying the site count on a scanned lane or the reason otherwise),
which makes that one command:

```sh
rvl scan . --strict --out findings.json
jq -e '.coverage.lang_status
       | all(.state == "scanned" and ((.detail | tonumber?) // 0) > 0)' \
  findings.json
```

That fails the job on a lane that errored *and* on a lane that read zero
sites.

Two shapes produce `lang_status: []`, and `all` over an empty array is
`true`, so both pass the assertion rather than failing the job:

- A repository with no supported language — docs, Terraform, config. That is
  deliberate: the check asks "did every lane rvl claimed to scan actually
  read something", not "does this repo have code". Do not "fix" it into a
  false alarm on your docs repos.
- An `--incremental` scan that reused the index: the incremental path runs no
  helper roll-call, so it emits an empty `lang_status` (except in the
  no-supported-sources case). The coverage assertion above only bites on
  **full** scans — run it against a plain `rvl scan . --strict --out …`, not
  against the hook's incremental invocation.

## See also

- [The `--out` document contract](out-contract.md) — the full schema behind
  `coverage.lang_status` and the rest of `--out`
- [How a scan finds your code](retrievers.md) — why a lane reads nothing
- [Configuration](configuration.md) — `scanner.waivers`, `scanner.base_ref`,
  and the environment variables named above
- [Local scanning](https://app.revelara.ai/help/local-scanning) — the
  end-user walkthrough of the same hook workflow
