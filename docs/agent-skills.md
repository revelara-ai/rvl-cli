# Coding-agent skills and lenses

`rvl skills` installs the Revelara workflow skills and lenses (the `/rvl:scan`
lens set, CAST/STPA interrogatory workflows, assessment skills) into your
coding-agent harness:

```sh
rvl skills install            # install into every detected harness
rvl skills install claude     # or name one
rvl skills update             # refresh previously installed harnesses
rvl skills status             # installed vs served versions (drift)
rvl plugin editors            # every supported harness, with tier
```

Once installed, harnesses with slash commands expose `/rvl:scan`, `/rvl:fix`,
`/rvl:ask`, `/rvl:risks`, `/rvl:review`, `/rvl:evidence`, `/rvl:status` and
the interview-driven `/rvl:assess-*` process assessments. Harnesses without
slash commands discover the same content through the managed context block
below.

Content is served by the Revelara plugin system, verified (transport checksum
+ signed integrity manifest), and cached under `~/.revelara/cache/skills` so
installs keep working offline (`RVL_OFFLINE=1` or a network failure fall back
to the verified cached copy). This surface only downloads; it never uploads
anything.

Verification is fail-closed: a server with no signing key configured (a
self-hosted deployment, typically) refuses the install rather than installing
unverified content. Set **`RVL_ALLOW_UNSIGNED_PLUGIN=1`** to opt out — the
same variable name rvl-cli used, so existing self-hosted CI keeps working
unchanged.

## The managed context block

`rvl init` and `rvl plugin install`/`update` also maintain a **managed context
block** in your repository's `AGENTS.md` (and `CLAUDE.md` once skills are
installed), delimited by
`<!-- BEGIN REVELARA MANAGED BLOCK - DO NOT EDIT -->` /
`<!-- END REVELARA MANAGED BLOCK -->`. That block is how a harness with no
slash commands discovers `rvl` at all. It is created when the file is missing,
appended when the file exists without it, and **replaced in place** otherwise
— so re-running never duplicates it, and edits made INSIDE the markers do not
survive the next run. Everything outside the markers is left alone. Pass
`--no-context-files` to skip the step entirely.

## See also

- [Command reference](commands.md) — `rvl skills` and `rvl plugin` subcommands
- [Configuration](configuration.md) — `RVL_OFFLINE`, `RVL_SKILLS_CACHE_DIR`,
  `RVL_ALLOW_UNSIGNED_PLUGIN`
