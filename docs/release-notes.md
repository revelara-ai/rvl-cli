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
