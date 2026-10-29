# Release notes

This page records what a release adds or changes for a program that calls
`rvl`: a skill, a hook, or a CI job that must know which version it needs.
The full list of changes in a release is on its
[GitHub release](https://github.com/revelara-ai/rvl-cli/releases).

To read the installed version, run `rvl --version` or `rvl version`.

## After 1.6.0 (not released yet)

### `rvl explain` says what a judgment was authored from

A judgment in the spec cache may name what it was authored from: a pattern,
an incident or documentation, the refs to it, and a note. `rvl explain`
prints them in an `authored from:` block after the fix, and prints nothing
when the judgment names none.

- Added: `--out` `findings[].source_kind`, `source_refs` and `source_note`,
  each absent when empty. They never change `severity`, the gate or `exit`.
- The refs are printed as the cache gives them; `rvl` looks nothing up.
- An older `rvl` reads a cache with these fields and ignores them.

### Construction rules judge crypto, TLS and database call sites

A `config_keys` spec with the format `construction` judges a construction
call site against its control, without the decision model: a TLS config
that skips verification, TLS below 1.2, a DES, RC4 or ECB cipher,
`ssl.CERT_NONE`, `verify=False`, `rejectUnauthorized: false` (RC-059), and a
literal password in a DSN or a password argument (RC-056). See
"Construction rules" in `docs/retrievers.md`.

- New: findings with the class `construction.<key>`, such as
  `construction.crypto/tls.Config.InsecureSkipVerify(InsecureSkipVerify)`.
  A rule with a severity of `high` blocks.
- New: the config-key expectation `absent`, and the patterns
  `no_literal_credential` and `no_weak_cipher`. An older `rvl` abstains on
  a spec that uses them.
- The rules arrive in the spec cache. Until it carries them, nothing
  changes.

### The decision model runs each input at its own length, under a budget you set

The decision model ran every input padded to the model's maximum length.
It now runs each input at its own token length: about 2.5 times as many
inputs a second for typical inputs, measured on a model of the same shape,
so more of a medium repository's questions fit in the default budget.

- Changed: `--out` `decision_model.sites` `confidence` values and the model
  records change for every input, once; the same input still gives the
  same bytes on the same machine.
- Added: `scanner.decision_model_budget` in `.revelara.yaml` (default
  `60s`). A hook and `--changed-only` hold it to at most `60s`.
- Added: when the budget cuts the lane short, a COVERAGE line (also in
  `--out` `decision_model.coverage`) says how many questions it cut, in how
  many files, from which file on, and names the setting.
- Fixed: on macOS the decision model ran on Core ML, which ONNX Runtime
  chose by default; it now runs on the CPU, as on Linux and Windows.

### Credential values are redacted as sites are read

A site's `const_args`, snippet, enclosing body, callers, callees and client
construction can quote a literal credential, such as a DSN password or a
`password='...'` argument. `rvl` now replaces the value with `<redacted>`
when it reads a site, and keeps what is around it:
`postgres://u:<redacted>@host`, `password='<redacted>'`,
`Server=h;Password=<redacted>;`.

- Changed: a `--retrieved` stream and the packet index give the redacted
  text to every lane, so the decision model, the agent prompt and the
  rendered output never hold the value.
- Changed: `--out` `config_sites` rows redact `value` and `rule` the same
  way, and a setting whose key names a credential has `value` `<redacted>`.
- Changed: submission mode (`rvl scan --service`) redacts every string in
  the findings before it posts them, so the idempotency key is computed from
  the redacted findings.

### Crypto, TLS and database constructions are call sites

The Go, Python and TypeScript retrievers report constructions whose
arguments are the security setting as classic call sites: `des.NewCipher`,
`md5.Sum`, a `tls.Config` literal's `InsecureSkipVerify`, `sql.Open`,
`hashlib.md5`, `ssl.CERT_NONE`, `ctx.check_hostname = ...`,
`crypto.createHash('md5')`, `rejectUnauthorized`, `new pg.Pool(...)`, and
others. The list is in "Constructions that are call sites" in
`docs/retrievers.md`.

- Changed: `--out` `.sites` has rows of these classes (`crypto/md5.Sum`,
  `ssl.CERT_NONE`, `pg.Pool.constructor`), and COVERAGE counts them. Until a
  spec names a class, its sites abstain as `no spec`.

### Claude Code reminds the agent to look up causal factors

The Claude Code plugin that `rvl plugin install claude` (and
`rvl skills install claude`) writes now has a `hooks/hooks.json` with a
`UserPromptSubmit` hook. On each prompt it adds one sentence to the agent's
context: the first line of the "Causal factors" block in the managed
`AGENTS.md` block, which tells the agent to run
`rvl factor lookup "<what the change does>"` before it changes a file.

- New: the hook only reminds. It never blocks a prompt or an edit, makes no
  network call and runs no `rvl` process: it echoes a fixed JSON line
  (`hookSpecificOutput.additionalContext`).
- Only Claude Code gets the hook. The other harnesses keep the instruction
  in the `AGENTS.md` context block.
- When the downloaded plugin ships its own `hooks/hooks.json`, the reminder
  is added to it; its other hooks stay.

### No more releases for Intel macOS

Releases no longer include an `x86_64-apple-darwin` archive. Intel Macs
get no new `rvl` releases. 1.7.1 is the last release that runs there, and its
archive stays downloadable from its
[GitHub release](https://github.com/revelara-ai/rvl-cli/releases/tag/v1.7.1).
The Homebrew cask now requires an Apple silicon Mac.

The reason: local model inference needs ONNX Runtime, and ONNX Runtime
publishes no Intel macOS build after 1.23.2. A release carries a pinned ONNX
Runtime so that a scan gives the same results on every machine, and that
runtime does not exist for Intel macOS.

- New: each release archive carries the pinned ONNX Runtime (1.31.0) in
  `onnxruntime/` beside `rvl`. `RVL_ONNXRUNTIME` overrides it with another
  library file or a directory holding one.
- New: `scanner.model_threads` in `.revelara.yaml` sets the CPU threads for
  local model inference (default 4). See [Configuration](configuration.md).

### Agent gate rows carry a control

Under `scanner.agent_verdicts: gate`, a ladder row from an agent `violates`
verdict (`agent.<type>.<method>`) now has the `control` of the site's class
judgment in `--out` and in `rvl explain`. Before, the field was empty.

- Changed: a gate row whose class maps to no control is advisory, and
  `COVERAGE` prints
  `<n> agent violation(s) advisory, not blocking — no control maps to the site's API class, ...`.
  Before, every gate row blocked.

### Named contexts in `~/.revelara/config.yaml`

**Minimum version to probe for: the first release after 1.6.0.**
`rvl config get-contexts --help` exits 0 on a version that has the feature
and exits 2 on an earlier one.

- The config file can hold named `contexts` and a `current_context`. A file
  with only the top-level `api_url`, `api_key` and `org_name` keys needs no
  change: `rvl` reads it as the context `default` and selects it. No command
  that only reads the file rewrites it. The first `login`, `config set`,
  `config set-context` or `config use-context` stores it in the contexts
  form, and after that `rvl` 1.6.0 and earlier read no credentials from it.
- `rvl login` and `rvl config set` with no context selected write the
  context `default`. A write into a context selects it when the file selects
  none.
- The global flag `--context <name>` and the variable `RVL_CONTEXT` select a
  context for any command. `RVL_API_KEY`, `RVL_API_URL` and `RVL_ORG_NAME`
  still win over the context's values.
- An unknown context name is an error:
  `unknown context "<name>"; known contexts: <names>`.
- New commands: `rvl config get-contexts`, `rvl config use-context <name>`
  and `rvl config set-context <name> --url --key --org`.
- `rvl status` prints `Context: <name>` on its second line when a context is
  selected.
- Changed: a malformed config file now fails `scan`, `sync` and the other
  scan commands with an error. Before, they ignored the file.
- Changed: `rvl status`, `rvl config show`, `rvl config set api_key` and
  `rvl login` no longer print any characters of the API key. They print
  `(set)` or `(not set)`. Before, they printed the first and last characters.

See [Configuration](configuration.md#named-contexts).

### Causal factor codes on findings

**Minimum version to probe for: the first release after 1.6.0.** Probe
for the `factors` key on a `findings[]` row of an `--out` document; an
earlier release writes no such key.

- Each `--out` finding has `factors`, the list of causal factor codes
  (`CF-0007`) of its control, read from the spec cache's `control_factors`
  section. It is `[]` when the cache has no factor for the control or has
  no such section.
- The ladder's detail line shows the codes after the control:
  `control RC-019 (factors CF-0007, CF-0021)`. `rvl explain` prints them
  on a `factors:` line. Only the codes are shown, not the factor names.

See [the `--out` contract](out-contract.md).

### `config_sites` in the `rvl scan --out` document

**Minimum version to probe for: the first release after 1.6.0.** A document
from an earlier version has no `config_sites` key. Read that as "not
reported", not as "no config settings".

- `config_sites[]` has one row for each config setting the config lane read,
  whatever its verdict: `format`, `file`, `line`, `resource`, `key`,
  `value`, `verdict`, `control` and `rule`. These are the settings that
  `coverage.config.by_key` counts.
- `line` is `0` when the retriever records no line. Today only Dockerfile
  rows have a line.
- `value` and `rule` are cut at 200 characters.
- A scan lists at most 5000 rows. `config_sites_overflow` counts the
  settings that the cap left out.

The schema is still `rvl-scan/v1`; the fields are additive. See
[the `--out` contract](out-contract.md#field-semantics).

## 1.6.0 (2026-10-15)

The first release after `v1.5.0`.

### `rvl factor lookup`

**Minimum version to probe for: 1.6.0.** `rvl` 1.5.0
and earlier do not have the subcommand: `rvl factor lookup --help` exits 2
there and exits 0 on a version that has it.

`rvl factor lookup "<what the change does>" [--limit <1-5>] [--format table|json]`
is the command a coding agent runs before it changes a file. It sends the
description to the causal factor catalog of the Revelara platform and prints
the factors that apply to the change, best match first.

- The text output is plain text for an agent to read. A factor that has a
  card prints the card text. Each other factor prints `<CODE> - <name>` and
  then its definition. One blank line separates the factors. There is no
  table and no header.
- When no factor matches, the command prints
  `No causal factor matches this description.` and exits 0.
- `--limit` is 1 to 5, and the default is 5. A value outside the range exits
  2 with no request.
- An empty description exits 2 with no request.
- `--format=json` prints the response of the server unchanged: `edition` and
  `factors`. Each factor has `code`, `name`, `category`, `score`,
  `public_incidents` and `public_organizations`, and either `card` or
  `definition`.

The request body has the description and the limit, and no other key. The
command sends no file content, no path and no repository data. See
[Privacy](privacy.md#platform-queries). The command needs a server that has
the lookup endpoint; an older server answers 404, and the command exits 1.

The embedded context block that `rvl init` writes to `AGENTS.md` and
`CLAUDE.md` has a new first line in the "Causal factors" list, which tells
an agent to run the command before it changes a file. The addition is
additive: no command or field changed.

### The config key `kubernetes container.run-as-user-class`

**Minimum version to probe for: 1.6.0.**

The config lane reads `runAsUser` and `runAsNonRoot` in a Kubernetes manifest
and emits one setting for each container: the user that the container is
declared to run as. Kubernetes takes each of the two fields from the
`securityContext` of the container and, when the container does not set it,
from the `securityContext` of the pod. The value is one of three classes:

- `root`: the effective `runAsUser` is `0`.
- `non-root`: the effective `runAsUser` is a different UID. With no
  `runAsUser`, the effective `runAsNonRoot` is `true`.
- `absent`: no field decides, so the image sets the user. `rvl` does not read
  the image, so `absent` is not a verdict that the container runs as root.

`runAsUser` decides before `runAsNonRoot`. A container with `runAsUser: 0`
and `runAsNonRoot: true` does not start, and its class is `root`.

A `runAsUser` that is not a UID, or a `runAsNonRoot` that is not a boolean,
has no value: the lane abstains.

The keys `container.security-context` and `pod.security-context` do not
change. They report that a security context is present, and a manifest that
sets one and runs as UID 0 satisfies them. The new key reports that case.

No spec judges the key in the current artifact, so a scan counts it in
`coverage.config.abstain.no_spec` and lists it in `no_spec_keys`, and
`rvl cache keys` shows it as awaiting a spec. A scan of a repository with a
Kubernetes workload gets one more row in `coverage.config.by_key` and a
`coverage.config.total` that is higher by one for each container. No finding
changes.

## 1.5.0 (2026-10-11)

The first release after `v1.4.0`.

### `rvl report --queue`, and `routing` on `rvl cache keys --json`

**Minimum version to probe for: 1.5.0.**

`rvl report --queue` lists every finding with no spec, with a computed
`routing`: the two gates `deterministic` and `transferable`, the `quadrant`
they make, and the `lane` (`api_spec`, `config_key_spec` or `agent`). The
view is local and is not the report payload, which does not change. See
[Privacy](privacy.md#the-spec-authoring-queue).

In `rvl cache keys --json`, a key whose `state` is `mint_queue` has the same
`routing` object. A key in a different state does not have the field. The
text output shows the route at the end of each key that awaits a spec.

### `rvl report` leaves out repo-internal surfaces, and `--combine` ranks across repositories

**Minimum version to probe for: 1.5.0.**

The `rvl report` payload has two new fields, `repo_internal_surfaces` and
`repo_internal_sites`. A surface that the scanned repository declares itself
is not in `surfaces`; it is in these counts. The Go and Java retrievers mark
such a call with `provenance.api_in_repo: true` on the packet. The field is
additive and is absent when false, so the packet schema stays `2`. A
consumer that reads `surfaces` sees fewer rows for a Go or Java repository
and must not read the missing rows as "now covered by a spec".

`rvl report --combine <FILE>...` reads report payloads and writes a combined
list. Each row has `client_type`, `method`, `lang`, `repo_count` and
`site_count`, in the order `repo_count` then `site_count`. See
[Privacy](privacy.md#combine-the-reports-of-several-repositories).

### `scope` on each `sites` row of the `rvl scan --out` document

**Minimum version to probe for: 1.5.0.** `rvl` 1.4.0
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

**Minimum version to probe for: 1.5.0.** `rvl` 1.4.0
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

**Minimum version to probe for: 1.5.0.**

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

**Minimum version to probe for: 1.5.0.** `rvl` 1.4.0
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

**Minimum version to probe for: 1.5.0.** `rvl` 1.4.0
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

### Related causal factors in `rvl risk context` and `rvl control show`

**Minimum version to probe for: 1.5.0.** `rvl` 1.4.0
and earlier do not print the section. To probe, run `rvl control show <CODE>`
or `rvl risk context <CODE>` and look for the heading
`Related Causal Factors:`. The heading is absent on an older `rvl`. It is also
absent when the server sends no factors, so read the `factors` key of
`--format=json` to tell the two apart.

The text output of three commands shows the causal factors of the catalog
that the server now sends in the `factors` array.

- `rvl risk context <CODE>` has a section `Related Causal Factors:` directly
  after the causal analysis. Each line has the factor code, the name, the
  control the relation came through, the relation, the public counts, and the
  Top 10 slot when the factor has one. The factors are derived from the mapped
  controls. They are not a classification of the risk.
- `rvl control show <CODE>` has a block `Related Causal Factors:` after
  `Related Risks`. The group `Addresses:` has the factors the control
  prevents, detects or mitigates. The group `Can induce:` has the factors the
  control can cause. A link that the adjudication did not agree on has the
  mark `(contested)`.
- `rvl risk show <CODE>` has one new last line when the risk has mapped
  controls: `Related causal factors: run 'rvl risk context <CODE>'.` The
  command makes no new request.

`--format=json` did not change: it prints the `factors` key as the server
sends it. A server that does not send `factors` gives the same text output as
before, apart from the new line of `rvl risk show`. The addition is additive:
no line or field was removed.

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
