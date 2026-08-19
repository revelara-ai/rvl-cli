# Privacy

**Customer code never leaves the machine.** `rvl` is open source so this is
true and auditable by construction, not aspiration. This page covers the two
channels that exist and what each can carry: the shape-only report attached
to the deterministic scan, and the explicitly separate, flag-gated
[submission mode](#submission-mode-a-different-channel-by-design).

When a scan reports the
unknown API surfaces it could not decide (no spec exists yet), the payload
carries ONLY the API SHAPE — `client_type`, `method`, the `lang` it was
written in, and a `site_count` — and nothing else: no source snippets, no
enclosing function bodies, no file paths (paths leak repo structure), no line
numbers, nothing repo-identifying beyond the public API identity, its
language, and a count.

`lang` is a language NAME ("go", "python", "csharp", …), not source: it is a
property of the language the public API belongs to, at the same altitude as
`client_type`, and it is normalized to a short identifier before it can ride,
so nothing free-form can use it as a side channel. It is there because a
factory that cannot tell which language a surface came from has to guess one,
and a confidently wrong language is a worse answer than none. Empty means no
language is being claimed — either the scanner could not resolve one, or the
shape was seen in more than one language.

The shape-only report type (`ReportSurface`) is structurally incapable of
carrying source; audit tests build a report from source-bearing sites and
assert the source never appears in the serialized payload.

Use `rvl report` to see EXACTLY what would ever be transmitted:

```sh
rvl report [PATH]                   # human-readable table of shape + counts
rvl report [PATH] --json            # the exact JSON payload the wire would carry
rvl report [PATH] --out shape.json  # write that JSON payload to a file
```

Reporting is local-only today: `rvl report` shows or writes the payload, it
does not transmit it.

The "code never leaves" claim above is scoped to the deterministic scan and
this report preview. The one surface that deliberately sends more is below.

## Submission mode: a different channel, by design

`rvl scan --service <name>` (with `--scan-dir`, `--file`, or `--stdin`) is
**submission mode**: it posts risk findings to your organization's risk
register at the Revelara API. This is a deliberate, flag-gated operation —
it never happens as a side effect of a local scan, it requires an API key,
and its payload is intentionally richer than the shape-only report: the
findings themselves (titles, descriptions, severities, **file paths**),
service/team/component attribution, and repo metadata (`git_commit`,
`git_branch` from the `--target` directory), optionally plus a control
structure (`--cs-file`). That is the point of the feature — a risk register
needs to say where the risk lives.

Use `--dry-run` to validate and print the exact submit summary without
sending anything. The shape-only report contract above is unaffected:
nothing from submission mode feeds it, and nothing in the deterministic scan
feeds submission mode.
