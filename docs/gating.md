# Gating commits and CI

rvl gates a change in two places, and they are not equal:

1. **The CI check is the guard.** A required status check runs `rvl scan` on
   the pull request's merge ref, and on the merge queue's candidate when you
   use one. It judges a commit: the content that lands. Nothing an author
   does locally can change what it reads.
2. **The hook is the fast path.** The pre-commit and pre-push hooks give the
   same verdict in seconds, before the code leaves the laptop. They are a
   convenience, not a control.

The order matters because a local hook checks first and git acts second.
`git commit --no-verify` skips the hook. A squash-merge creates a commit on
the default branch that no hook ever saw. A hook that is not installed does
not run. Only a check on the commit itself closes those paths, so make the
CI job below a required check before you rely on the gate.

## The hook: the fast path

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

The pre-commit scan reads working-tree files, not the staged blobs. When a
staged file also has unstaged edits (`git add -p`, or an edit after
`git add`), those two differ, and a verdict on one says nothing about the
other. The scan refuses that case with exit `1` and names the files:

```
error: pre-commit: 1 staged file(s) also have unstaged edits (half.py).
```

Stage the rest of the file, or set the unstaged edits aside for the commit
with `git stash --keep-index` and restore them with `git stash pop`.

## Exit codes

`rvl scan` sits on a hook or in a CI gate, so its exit code is the gate:

| Code | Meaning |
| ---- | ------- |
| `0` | Scan completed; nothing blocking remains after waivers (`commit clean`). |
| `1` | Scan could not complete: no verifiable spec cache, a retriever error under `--strict`, an IO failure. The scanner broke; your code was never judged. |
| `2` | Usage error: unknown or invalid flag/argument. |
| `3` | Scan completed and BLOCKING findings remain (`✗ blocked`). Fix them, or waive them in `.revelara.yaml`. |

Blocked has its own code so a hook can tell "your code has a problem" (`3`)
from "the scanner is broken" (`1`). A broken scanner must not be read as a
clean tree. Advisory findings never affect the exit code. Do not write a
gate that only checks for non-zero.

Exit `0` means nothing blocking was found, not that your code was scanned.
A scan whose retrievers produced nothing still exits `0`. Read the `COVERAGE`
block, which names the per-language site count and any lane that failed:
`languages: Go 0 sites` on a Go repository means the gate passed over
unread code. The next section covers how to catch that in CI.

To get past a blocked commit deliberately, `RVL_FORCE=1 git commit …` or arm
a one-shot override with `rvl scan force-next`.

## In CI: the guard

Ship this job and make `rvl-gate` a required check on your default branch.
It is [`docs/examples/rvl-gate.yml`](examples/rvl-gate.yml):

```yaml
# Reference job: rvl as the authoritative gate. Copy to
# .github/workflows/rvl-gate.yml and mark the `rvl-gate` check as required in
# the branch protection rule (or ruleset) for your default branch.
#
# A pre-commit hook judges the working tree and can be skipped with
# `git commit --no-verify`. This job judges a commit: the pull request's merge
# ref, and the merge queue's candidate when you use one. That is the content
# that lands, so this check is the guard and the hook is the fast path.
name: rvl-gate

on:
  pull_request:
  merge_group:

permissions:
  contents: read

jobs:
  rvl-gate:
    runs-on: ubuntu-latest
    steps:
      # On pull_request this checks out refs/pull/N/merge: the PR head merged
      # with the current base, not the PR head alone. Full history, so the
      # base ref that --changed-only diverges from is reachable.
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0

      # Put `rvl` on PATH here, pinned to a version. See "Install" in the rvl
      # README for the supported channels.

      # The verdict. Exit 3 is blocking findings; exit 1 under --strict is a
      # lane that could not read the code. Both fail the job. A pull_request
      # event exports GITHUB_BASE_REF; a merge_group event does not, so the
      # base is passed in.
      - name: Gate the change
        env:
          RVL_API_KEY: ${{ secrets.REVELARA_API_KEY }}
          RVL_BASE_REF: ${{ github.event.merge_group.base_sha }}
        run: rvl scan . --incremental --changed-only --strict

      # The coverage assertion: every lane rvl claimed to scan read at least
      # one site. A full scan, because the incremental path has no roll-call.
      # Exit 3 is tolerated here: this step asks "was the code read", and the
      # step above already gave the verdict on the change.
      - name: Assert coverage
        env:
          RVL_API_KEY: ${{ secrets.REVELARA_API_KEY }}
        run: |
          rvl scan . --strict --out findings.json || [ "$?" -eq 3 ]
          jq -e '.coverage.lang_status
                 | all(.state == "scanned" and ((.detail | tonumber?) // 0) > 0)' \
            findings.json
```

The rest of this section explains each line of it.

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

`--strict` matters more than it looks. By default a scan fails open: when
a retriever errors, the scan degrades to whatever it did read, prints
`NOT CLEAN — nothing was scanned (see COVERAGE)`, and still exits `0` so a
commit is not held hostage to a broken toolchain. That is the right default on
a laptop and the wrong one on a build runner, where an image missing a
language toolchain would otherwise produce a green gate forever. `--strict`
turns that case into exit `1`.

A retriever that errors is not the only way a lane can read nothing. A
helper can also exit `0` having emitted no packets at all. The Go lane did
exactly this when the `go` tool was absent, and the scan printed
`✓ commit clean` over unread code. That hole is now guarded structurally: a
language that was detected, whose helper exited `0`, and whose stream carried
nothing rvl recognizes (not even the repo-scoped record every helper writes
on a successful run) is degraded as a failed lane, whatever the exit code
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

- A repository with no supported language (docs, Terraform, config). That is
  deliberate: the check asks "did every lane rvl claimed to scan actually
  read something", not "does this repo have code". Do not "fix" it into a
  false alarm on your docs repos.
- An `--incremental` scan that reused the index: the incremental path runs no
  helper roll-call, so it emits an empty `lang_status` (except in the
  no-supported-sources case). The coverage assertion above only bites on
  full scans: run it against a plain `rvl scan . --strict --out …`, not
  against the hook's incremental invocation.

## See also

- [The `--out` document contract](out-contract.md): the full schema behind
  `coverage.lang_status` and the rest of `--out`
- [How a scan finds your code](retrievers.md): why a lane reads nothing
- [Configuration](configuration.md): `scanner.waivers`, `scanner.base_ref`,
  and the environment variables named above
- [Local scanning](https://app.revelara.ai/help/local-scanning): the
  end-user walkthrough of the same hook workflow
