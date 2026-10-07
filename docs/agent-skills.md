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

The server filters the content by your organization's intelligence tier, so
the cached copy belongs to the API key and server that fetched it. An online
install with a different key or server fetches again, also when the served
version is the same. An offline install uses the cached copy and prints a
warning when a different key or server fetched it.

Verification is fail-closed: a server with no signing key configured (a
self-hosted deployment, typically) refuses the install rather than installing
unverified content. Set **`RVL_ALLOW_UNSIGNED_PLUGIN=1`** to opt out — the
same variable name rvl-cli used, so existing self-hosted CI keeps working
unchanged.

### The signing key is trusted on first use

The server serves the key that verifies its own content, so a signature alone
does not protect you from a compromised server or connection. `rvl` therefore
pins the key. The first verified install from a server records that server's
Ed25519 key in `~/.revelara/trusted_keys.json`, one entry per server URL, and
prints its fingerprint. Each later download must come with the same key.

When the key is different, `rvl` installs nothing, leaves the cache and the
installed skills as they were, and prints the two fingerprints:

```text
the plugin signing key for https://api.revelara.ai changed: expected sha256:1f0c…, got sha256:9ab2…
```

**Key rotation.** A rotation does not need a new `rvl` release. It needs one
deliberate step on each machine:

1. Get the new fingerprint from a source that is not the server itself, for
   example Revelara support or the operator of your self-hosted server.
2. Make sure that it is the same as the `got` fingerprint in the error.
3. Run the install again with
   **`RVL_TRUST_PLUGIN_SIGNING_KEY=<the new fingerprint>`**. `rvl` replaces
   the pinned key and prints a warning with the old and the new fingerprint.

The variable is accepted only when its value is the fingerprint of the key
that the server serves. A value such as `1` trusts nothing. Unset it after
the install.

A server with a pinned key cannot go back to unsigned content:
`RVL_ALLOW_UNSIGNED_PLUGIN=1` is refused for it. If you stopped signing on a
self-hosted server, delete that server's entry from `trusted_keys.json`. A
`trusted_keys.json` that `rvl` cannot parse stops the install; `rvl` does not
treat it as empty.

The first install has no earlier key to compare with. To check it, compare
the printed fingerprint with one from the same kind of source. An offline install does not
fetch a key and uses the cached copy, which was verified when it was fetched.

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
