# Release notes

This page records what a release adds or changes for a program that calls
`rvl`: a skill, a hook, or a CI job that must know which version it needs.
The full list of changes in a release is on its
[GitHub release](https://github.com/revelara-ai/rvl-cli/releases).

To read the installed version, run `rvl --version` or `rvl version`.

## After 1.4.0 (not released yet)

### `scope` on each `sites` row of the `rvl scan --out` document

**Minimum version to probe for: the first release after 1.4.0.** `rvl` 1.4.0
and earlier do not write the field, so a consumer must treat a row without it
as "not classified", not as `runtime`.

Each row of `sites` has a `scope`: `runtime`, `migration`, `test_support`,
`dev_only` or `backfill`. It is the same value that an `undecided` row has for
the site. `undecided` has only the sites the engine abstained on, so until now
a consumer that sampled the resolved rows could not tell a migration from
request-path code. A row of `structure` has no `scope`, because it is about
the repository and not about a file. See
[the out contract](out-contract.md) for the field. The addition is additive:
the schema stays `rvl-scan/v1`.

### `coverage.config.by_key` in the `rvl scan --out` document

**Minimum version to probe for: the first release after 1.4.0.** `rvl` 1.4.0
and earlier do not write the field, so a consumer must treat a document
without it as "not measured", not as zero.

`coverage.config.by_key` has one row for each `(format, key)` the config lane
found a setting for, with the counts `violates`, `satisfies`, `abstain` and
`not_applicable`. A finding names only the violating sites of a config class.
With this block, the fire rate of a config spec is
`violates / (violates + satisfies)`, computed from the scan document alone.
The counts of all rows sum to `coverage.config.total`. See
[the out contract](out-contract.md) for the field. The addition is additive:
the schema stays `rvl-scan/v1`.

### The config key `dep-manifests dockerfile.final_stage_user`

**Minimum version to probe for: the first release after 1.4.0.**

The config lane reads the `USER` instructions of a Dockerfile and emits one
setting for each file: the user that the built image starts as. The value is
one of three classes:

- `root`: the last `USER` of the final stage is `root`, UID `0`, or
  `ContainerAdministrator`.
- `non-root`: the last `USER` of the final stage is a different user.
- `absent`: the final stage has no `USER`, and the earlier stages it is built
  `FROM` have none. The base image then sets the user. `rvl` does not read
  the base image, so `absent` is not a verdict that the container runs as
  root.

A `USER` that reads a build argument with no default in the file, or an
`ENV`, has no value: the lane abstains.

No spec judges the key in the current artifact, so a scan counts it in
`coverage.config.abstain.no_spec` and lists it in `no_spec_keys`, and
`rvl cache keys` shows it as awaiting a spec. A scan of a repository with a
Dockerfile gets one more row in `coverage.config.by_key` and a
`coverage.config.total` that is higher by one for each Dockerfile. No finding
changes.

A Dockerfile line that continues an instruction (after a trailing `\`), and a
line in the body of a heredoc, are no longer read as instructions. Before, a
continuation line that started with `FROM` was read as a build stage.

### `rvl factor list` and `rvl factor show`

**Minimum version to probe for: the first release after 1.4.0.** `rvl` 1.4.0
and earlier do not have the command: `rvl factor --help` exits 2 there and
exits 0 on a version that has it.

The two commands read the causal factor catalog of the Revelara platform, in
the same form as `rvl control list` and `rvl control show`.

- `rvl factor list [--category <1-7>] [--top10] [--format table|json]` lists
  the factors with the Top 10 slot, the public incident count, the public
  organization count, the category number and the name.
- `rvl factor show <CODE> [--format table|json]` shows one factor: the
  definition, the public counts, the quotes, the controls by relation
  (prevents, detects, mitigates, can induce), the tell and the guards when the
  entry has them, and the related risks of your organization. The code is
  accepted in any case. A merged code prints `Merged into <code>` and exits 0.

A public count is the number of public reports that describe the condition.
It is not a rate of occurrence. `--format=json` prints the response of the
server unchanged. A `--category` outside 1 to 7 exits 2 with no request. The
commands need a server that has the causal factor endpoints; an older server
answers 404, and the command exits 1.

The embedded context block that `rvl init` writes to `AGENTS.md` and
`CLAUDE.md` has a new "Causal factors" list with the two commands. The
addition is additive: no command or field changed.

### `--factor` on `rvl risk list`

**Minimum version to probe for: the first release after 1.4.0.** `rvl` 1.4.0
and earlier do not have the flag: the output of `rvl risk list --help` has
the text `--factor` only on a version that has it.

`rvl risk list --factor <CODE>` lists the risks of your organization that are
related to one causal factor. These are the same risks that
`rvl factor show <CODE>` shows as related risks. The code goes to the server
as the query parameter `factor`, and the server does the filtering. You can
use the flag together with `--status`, `--category`, `--service` and `--team`.

A value that is not a code form (`CF-XXXX`) exits 1 with the message of the
server. A code that no catalog entry has prints `No risks found.` and exits 0.
An empty value (`--factor=`) is not a filter. The flag needs a server that has
the `factor` filter; an older server does not know the parameter and can
return the list without the filter.

The embedded context block that `rvl init` writes to `AGENTS.md` and
`CLAUDE.md` has a new line for the flag in the "Causal factors" list. The
addition is additive: no command or field changed.

## 1.4.0

The first release after `v1.3.0`.

### `rvl scan digest` and `rvl scan finalize`

**Minimum version to probe for: 1.4.0.** `rvl` 1.3.0 and earlier do not have
these subcommands.

The `/rvl:scan` skill had two Python scripts in its text, and wrote them out
again on each scan. The two subcommands replace them:

| The skill ran | Run this |
| --- | --- |
| The residual-scoping script (Step 2): `python3 - "{ENGINE_DOC}"` | `rvl scan digest "{ENGINE_DOC}"` |
| The finalize script (Step 5C and Step 6): `python3 "{SCAN_TMPDIR}.finalize.py" "{SCAN_TMPDIR}" ...` | `rvl scan finalize "{SCAN_TMPDIR}" ...` with the same flags: `--engine`, `--patch`, `--register`, `--mode`, `--crit` |

The output lines are the same (`ENGINE_DIGEST`, `COVERED_CLASSES`,
`UNDECIDED`, `UNDECIDED_CLASS_CENSUS`, `ADJUDICATION_LIST`; `Written:`,
`UNKNOWN`, `DUP`, `INVALID`, `LENS_DIGEST`), and so are the findings files.
See [Orchestrated scans](commands.md#orchestrated-scans) for the full
description.

How to probe. Do not use a failed run as the probe:

- `rvl scan digest --help` exits 0 on 1.4.0 and later.
- On 1.3.0 and earlier, `digest` and `finalize` are read as the path of a
  directory to scan. `rvl scan digest --help` also exits 0 there, and prints
  the help of `rvl scan` with no `digest` in it. Compare the version number,
  or look for `ENGINE_DOC` in the help text.

What is different from the scripts:

- `finalize` reads and checks the patch, the register and the scan document
  before it removes the old `03-findings-*.json` files. The script wrote the
  lens files first, so a scan document of an unknown schema left a submit
  directory with no engine file in it. Now that run changes nothing.
- An input that is not what the command expects (a file that does not exist,
  a scan document with a field missing) gives one line on stderr and exit
  code 1, not a Python traceback. The message for a lens file that is not
  valid JSON (`INVALID <file>: ...`) has the same start and a different
  parser message.
- `--mode` accepts `quick` and `deep` only, and `--crit` must be a number.
  Another value is a usage error, exit code 2.
- A lens file whose name starts with a dot is not read.
- The findings files hold the same JSON values. The order of the keys in an
  object is different.

A directory named `digest`, `finalize` or `report` is now scanned as
`rvl scan ./digest`.

### `rvl scan report`

**Minimum version to probe for: 1.4.0.** `rvl` 1.3.0 and earlier do not have
this subcommand.

The `/rvl:scan` skill had a report template, and the model copied the engine
rows into it by hand. `rvl scan report "{ENGINE_DOC}" --scan-dir "{SCAN_TMPDIR}"`
prints the sections of that report that are data: the Gate section, the
`Engine:` and `Languages:` lines of the Coverage section, and the lines of the
"Not Assessable From Code" section. The skill writes the other sections. See
[Orchestrated scans](commands.md#orchestrated-scans) for the full description.

To probe, `rvl scan report --help` exits 0 on 1.4.0 and later and has
`ENGINE_DOC` in its text. On 1.3.0 and earlier, `report` is read as the path
of a directory to scan.

What is different from the template:

- A row under `SUPPRESSED` is a full row with a flag, `(suppressed)` or
  `(low value)`. The template had a list of ids.
- The "Not Assessable From Code" lines have the skill and the control codes.
  They do not have the one-line reason, which the skill adds.
