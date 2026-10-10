# Privacy

Code never leaves the machine. `rvl` is open source, so this claim
can be verified in the code. This page covers the two channels that exist
and what each can carry: the shape-only report attached to the deterministic
scan, and the explicitly separate, flag-gated
[submission mode](#submission-mode).

When a scan reports the unknown API surfaces it could not decide (no spec
exists yet), the payload carries only the API shape (`client_type`,
`method`, the `lang` it was written in, and a `site_count`) and nothing
else: no source snippets, no enclosing function bodies, no file paths
(paths leak repo structure), no line numbers, nothing repo-identifying
beyond the public API identity, its language, and a count.

`lang` is a language name ("go", "python", "csharp", …), not source: it is
a property of the language the public API belongs to, at the same altitude
as `client_type`, and it is normalized to a short identifier before it can
ride, so nothing free-form can use it as a side channel. It is there
because a factory that cannot tell which language a surface came from has
to guess one, and a confidently wrong language is a worse answer than none.
Empty means no language is being claimed: either the scanner could not
resolve one, or the shape was seen in more than one language.

The shape-only report type (`ReportSurface`) is structurally incapable of
carrying source; audit tests build a report from source-bearing sites and
assert the source never appears in the serialized payload.

Use `rvl report` to see exactly what would ever be transmitted:

```sh
rvl report [PATH]                   # human-readable table of shape + counts
rvl report [PATH] --json            # the exact JSON payload the wire would carry
rvl report [PATH] --out shape.json  # write that JSON payload to a file
```

Reporting is local-only today: `rvl report` shows or writes the payload, it
does not transmit it.

### What the report leaves out

Two kinds of unknown surface are not in the payload. The report gives a
count for each, and never a name.

- **Repo-internal surfaces.** When a retriever marks a call as a call to a
  function that the scanned repository declares
  (`provenance.api_in_repo`), the surface is the repository's own code. A
  spec for it helps no other repository, and its name identifies the
  repository. The payload has `repo_internal_surfaces` and
  `repo_internal_sites` in place of the surfaces. The Go and Java retrievers
  set the mark. A surface from a retriever that does not set it is reported
  as before.
- **Unresolved client types.** A site with an empty client type has no API
  identity to report. The payload has `unresolved_sites` in place of those
  sites. A large number tells you that retrieval did not resolve receivers.

The table that `rvl report` prints states both counts below the surfaces.

### The spec-authoring queue

```bash
rvl report [PATH] --queue          # table: one row per finding with no spec
rvl report [PATH] --queue --json   # the same rows as JSON
```

`--queue` shows every finding with no spec, and where it goes. It is a local
view and it is not the payload: it names the repo-internal surfaces that the
payload only counts, and `rvl` never sends it. You cannot use `--queue` with
`--out` or `--combine`. The JSON has `"local_only": true`.

A finding becomes a spec only if it passes two gates. `rvl` computes both
from facts that the retriever states:

- **Deterministic.** The client type resolved, so a rule has an identity to
  key on.
- **Transferable.** The retriever did not mark the called API as declared in
  the scanned repository (`provenance.api_in_repo`). A retriever that does not
  set the mark is read as "not in the repository".

| deterministic | transferable | `quadrant` | `lane` |
| --- | --- | --- | --- |
| yes | yes | `deterministic_transferable` | `api_spec` (an API spec, lane G1) |
| yes | no | `deterministic_not_transferable` | `agent` (no spec) |
| no | yes | `transferable_not_deterministic` | `agent` (no spec) |
| no | no | `neither` | `agent` (no spec) |

The rows in the `api_spec` lane are the surfaces of the payload. A function
that one repository declares and calls from many sites is deterministic and
not transferable: a rule can decide each site, and no other repository has a
site for the spec to judge. Such a finding is not waiting for a spec. It
stays with the agent lenses.

Each row has `client_type`, `method`, `lang`, `site_count` and `routing`.
`routing` has `deterministic`, `transferable`, `quadrant` and `lane`. The
table shows an unresolved client type as `(unresolved)`.

### Combine the reports of several repositories

```sh
rvl report repo-a --out a.json
rvl report repo-b --out b.json
rvl report --combine a.json b.json          # ranked table
rvl report --combine a.json b.json --json   # the combined list as JSON
```

`--combine` does not scan. It reads report payloads and lists each surface
with `repo_count`, the number of payloads that have the surface, and
`site_count`, the sum of the sites. The order is `repo_count` first, then
`site_count`. One repository that calls an API many times cannot push that
API above an API that many repositories share. The combined list also sums
the three counts above. If a file is not a report payload, the command
fails and names the file.

The "code never leaves" claim above is scoped to the deterministic scan and
this report preview. The one surface that deliberately sends more is below.

## Submission mode

`rvl scan --service <name>` (with `--scan-dir`, `--file`, or `--stdin`) is
**submission mode**: it posts risk findings to your organization's risk
register at the Revelara API. This is a deliberate, flag-gated operation:
it never happens as a side effect of a local scan, and it requires an API
key. Its payload is intentionally richer than the shape-only report: the
findings themselves (titles, descriptions, severities, file paths),
service/team/component attribution, and repo metadata (`git_commit`,
`git_branch` from the `--target` directory), optionally plus a control
structure (`--cs-file`). That is the point of the feature: a risk register
needs to say where the risk lives.

Use `--dry-run` to validate and print the exact submit summary without
sending anything. The shape-only report contract above is unaffected:
nothing from submission mode feeds it, and nothing in the deterministic
scan feeds submission mode.
