# Privacy

**Customer code never leaves the machine.** `rvl` is open source so this is
true and auditable by construction, not aspiration. When a scan reports the
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
