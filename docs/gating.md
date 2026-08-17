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

`--strict` is not a complete backstop, because it only catches a retriever
that **errors**. A retriever that exits cleanly having read nothing is not an
error, so it is reported as a genuine empty result and `--strict` passes it.
The Go lane does exactly this when the `go` tool is absent: `goindex` exits
`0` with zero packets, the scan prints `languages: Go 0 sites` and
`✓ commit clean`, and both plain and `--strict` runs exit `0`. Until that is
fixed, a CI job that must not silently pass over unread code should assert on
coverage as well as on the exit code. `--out` writes a
`coverage.lang_status` array (`state`, and `detail` carrying the site count on
a scanned lane or the error on a failed one), which makes that one command:

```sh
rvl scan . --strict --out findings.json
jq -e '.coverage.lang_status
       | all(.state == "scanned" and ((.detail | tonumber?) // 0) > 0)' \
  findings.json
```

That fails the job on a lane that errored *and* on a lane that read zero
sites, which is the gap `--strict` leaves open.

A repository with no supported language — docs, Terraform, config — produces
`lang_status: []`, and `all` over an empty array is `true`, so it passes
rather than failing the job. That is deliberate: the check asks "did every
lane rvl claimed to scan actually read something", not "does this repo have
code". Do not "fix" it into a false alarm on your docs repos.

## See also

- [The `--out` document contract](out-contract.md) — the full schema behind
  `coverage.lang_status` and the rest of `--out`
- [How a scan finds your code](retrievers.md) — why a lane reads nothing
- [Configuration](configuration.md) — `scanner.waivers`, `scanner.base_ref`,
  and the environment variables named above
- [Local scanning](https://app.revelara.ai/help/local-scanning) — the
  end-user walkthrough of the same hook workflow
