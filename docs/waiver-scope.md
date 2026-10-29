# Waiver scope: from one value to a whole class

Status: design, not built. This page proposes how a waiver can say *which*
instance of a finding it waives. It is written to be argued with before any
code changes. Each part names what it chose, why, and the trade-off it
accepts.

## The problem

A waiver in `.revelara.yaml` today is `{matcher, paths, expires, reason}`
(`crates/rvl/src/waiver.rs`, `struct Waiver`). That gives two grains:

- **class**: `paths` empty. Every site of the class, in every file, now and
  later.
- **file/glob**: `paths` set. Every site of the class in the matching files,
  now and later.

Neither grain can tell *this* key from the *next* key. A file-scoped waiver on
`secret.github_token` for `deploy/values.yaml` says "this token is fine". It
also hides the real token someone pastes into the same manifest next month.
That manifest is exactly where a real key would land. For secrets, a waiver
that hides too much means a leak goes out unseen. A waiver that hides too
little only means re-waiving after an edit. The design takes churn over a
missed secret wherever the two conflict.

`rvl suppress <id>` makes this worse than it has to be: it always writes the
coarsest grain, a class-wide waiver (`run_suppress` in `crates/rvl/src/main.rs`
builds the `Waiver` with `paths: vec![]`).

### A defect the design depends on

Waivers are matched against a ladder **row**, not a site. A row rolls up every
site of a class, and the scan tests a waiver's `paths` against the row's first
example site only (`waiver::is_waived(&f.class_rule,
waiver::site_path(&f.site), ...)` in `render_scan_output`). So a file waiver scoped to
one file hides the class's sites in *other* files whenever that file happens
to sort first. Reproduced on this tree:

```
a.toml: GITHUB_TOKEN = "ghp_…"   (one key)
b.toml: GITHUB_TOKEN = "ghp_…"   (a different key)

waiver {matcher: secret.github_token, paths: ["a.toml"]}  -> exit 0, "1 suppressed"
waiver {matcher: secret.github_token, paths: ["b.toml"]}  -> exit 3, blocked
```

With `paths: ["a.toml"]` the scan exits clean, so the `b.toml` key is never
reported. Every grain below needs waivers matched per site, before the rollup,
so this fix comes first (implementation item 1).

## The four grains

Finest to coarsest. A finer grain waives a subset of what a coarser one does.

| Grain | Waives | A new instance in the same file | Applies to |
| --- | --- | --- | --- |
| 1. value fingerprint | the one secret value, wherever it appears | blocks | content-lane secrets |
| 2. site | one call site or setting, pinned to its content, not its line number | blocks | every other finding with a file location |
| 3. file/glob | every instance of the class in matching files | waived | everything (today's `paths`) |
| 4. class | every instance of the class anywhere | waived | everything (today's empty `paths`) |

Grains 3 and 4 stay as they are on disk and in meaning. Grains 1 and 2 are
new.

### 1. Value fingerprint (secrets)

The waiver carries a one-way, truncated hash of the matched secret value. It
waives that value and nothing else: a different key on the same line, in the
same file, under the same matcher still blocks. That is the property the
problem asks for.

**The hash.** SHA-256 (already in the workspace as `sha2`, and wrapped by
`rvl_cache::sha256_hex`), over a domain-separated input, truncated to its
first 64 bits:

```
fingerprint = "v1:" + hex( SHA-256( "rvl-waiver-fp/v1" 0x00 rule_id 0x00 value )[0..8] )
            = "v1:" + 16 lowercase hex characters
```

- The `rvl-waiver-fp/v1` prefix and the rule id are there so that published
  tables of plain SHA-256 hashes of leaked tokens are useless against the
  fingerprint. The same value under two rules gets two fingerprints.
- The `v1:` tag lets a later version change the hash or the length without
  guessing which form an entry is.
- The file path is **not** in the input. A fingerprint waiver asserts
  something about the *value* ("this token is revoked", "this is the vendor's
  documented test key"), and that stays true when the file is moved or the
  value is copied. Leaving the path out means a rename does not churn the
  waiver.

**Why 64 bits: the two failure modes.**

- *Too sticky (a false waive).* A new, different secret is waived only if its
  64-bit fingerprint collides with a waived one under the same rule. With `W`
  fingerprint waivers that chance is `W / 2^64` per new secret: about
  `5 × 10^-17` for a thousand waivers. That never happens in practice.
  Truncating to 32 bits would make it `2 × 10^-7` per secret per thousand
  waivers. That is small, but nothing is gained by it.
- *Recovering the value (brute force).* An attacker who reads the fingerprint
  can only test guesses. The work is the size of the value's search space,
  not the hash length:
  - The provider-token rules (`github_token`, `gcp_api_key`,
    `stripe_secret_key`, `slack_token`, `aws_access_key_id`,
    `aws_secret_access_key`) match values the provider generated at random.
    A `ghp_` token has 36 base-62 characters, about 214 bits. A GCP key has 35
    base-64url characters, about 210 bits. A Stripe key has at least 20 base-62
    characters, about 119 bits. Even `AKIA` ids (16 of `[0-9A-Z]`, about 82
    bits, and not secret on their own) are out of reach. 2^80 guesses at
    10^11 SHA-256 a second, a large GPU rig, is about 380,000 years. There is
    a second guarantee too. A 64-bit fingerprint of a value with more than 64
    bits of entropy *cannot identify it*, even with unlimited compute: about
    2^150 different `ghp_` tokens share each fingerprint. Truncation is what
    makes the fingerprint non-identifying for these values.
  - `slack_token`'s pattern accepts as few as 10 characters after the
    prefix. That is the regex's lower limit, not Slack's: real tokens are
    much longer. To keep the argument above true, fingerprint grain needs at
    least 24 characters of payload for this rule. A shorter match falls back
    to site grain.
  - `generic_api_key` is gated at 3.5 bits/char Shannon entropy and 16 to 80
    characters, so at least about 56 estimated bits. It is not proven random,
    though: a human passphrase can pass the gate, and Shannon entropy
    overrates the strength of human-chosen text. This is the residual risk of
    the design (see "Low-entropy values" below).
  - `weak_default_credential` matches values that are weak *by definition*:
    the rule fires only when the value matches its vocabulary of known
    defaults (`admin`, `changeit`, `*password*`, four-digit suffixes). A
    dictionary attack recovers any of them instantly, at any truncation
    length. Truncation does not protect these values, and no truncation that
    keeps false waives rare could.

**Low-entropy values and the "no value on disk" stance.** The content lane's
privacy contract (the `rvl-content` module doc) is that the raw value never
leaves the matcher. A fingerprint keeps that contract for random values: it is
not the value and cannot become it. For a weak or human-chosen value it does
not: the fingerprint of `password1234` *is* `password1234` to anyone with a
wordlist. The design still uses fingerprints for these values, for these
reasons:

1. A waiver is only ever written for a value that is in the repository's
   working tree. The plaintext is committed in the same repository's history,
   readable by everyone who can read `.revelara.yaml`. So a fingerprint
   exposes nothing that a reader of the repository cannot already read.
2. The alternative for these rules is site grain with the value blanked out
   of the anchor (see grain 2). That is too sticky in exactly the case that
   matters here: `admin_password = changeme` becoming
   `admin_password = <the real one>` on the same line would stay waived.
3. When a waived value is removed, the fingerprint becomes **stale** and the
   scan reports it (see "Stale waivers"). `rvl suppress --prune` deletes stale
   instance waivers, so a fingerprint does not stay behind after its value is
   gone.

The cost to state plainly: if a team scrubs a leaked value from git history,
it must also scrub that value's fingerprint from `.revelara.yaml`'s history.
`scanning.md` should say so where it covers suppressing secrets.

**Where it is computed.** Only inside `rvl-content`, at match time, next to
`mask()`. `ContentFinding` gains `fingerprint: Option<String>`, and the module
privacy contract gains one sentence: the fingerprint is the only derivative of
the value that may leave the matcher, and it only goes to the local last-scan
state and to `.revelara.yaml`. It never goes on the wire. The shape-only
report, submission mode and the `--out` document's `sites` rows do not carry
it. The existing audit tests that plant tokens and assert the raw token never
appears get a sibling: the fingerprint appears only where listed above.

**Not every secret rule can be fingerprinted.** `private_key_pem` matches the
`-----BEGIN … PRIVATE KEY-----` header only, and the header is identical for
every key. A fingerprint of it would waive *every* PEM private key in the
repository: the stickiest waiver possible. This rule uses site grain until the
matcher reads the key body. A Slack token under 24 payload characters also
falls back to site grain, as above.

### 2. Site (every other finding)

Spec, API, config and model findings have no secret value to hash. Their
instance is the place in the code: the site.

A bare `file:line` is fragile, because any edit above the site moves it. A
site waiver is therefore **content-anchored**:

```
anchor = "v1:" + hex( SHA-256( "rvl-waiver-site/v1" 0x00 class_rule 0x00 normalized_line )[0..8] )
```

`normalized_line` is the site's source line with leading and trailing
whitespace trimmed and each internal run of whitespace collapsed to one space.
The waiver matches a site when the file path, the class and the anchor all
match. The line number is written to the entry as a hint for readers and is
never matched.

| Edit | Effect | Failure mode |
| --- | --- | --- |
| Lines inserted or removed above the site | still waived | none: this is the drift a bare line number gets wrong |
| Re-indenting or reformatting whitespace on the line | still waived | none |
| Changing the waived line itself | waiver goes stale, finding fires | churn: the line changed, so a second look is warranted |
| Renaming or moving the file | waiver goes stale, finding fires | churn |
| Adding a new site of the class on a different line | fires | the intended outcome |
| Adding an identical line (same text, same class) in the same file | **waived** | sticky, accepted: it is the same call written the same way, so the waiver's reason applies to it as well |

The last row is a choice. The alternative is to record which occurrence of
the anchor in the file is meant (`occurrence: 2`). That turns an insertion
*above* the site into churn again, which was the point of anchoring on
content, so it is not proposed.

Sites without a source line:

- **config lane** rows are `path (unit)`. The unit (the resource or key
  identity the lane already prints) replaces `normalized_line` in the anchor.
  It is a better anchor than a line, because it survives reformatting the
  whole file.
- **repo-structure** rows judge the repository, not a location (`site_id` is
  `repo`). They have no site grain, and `rvl suppress` writes their class
  waiver as it does today. A structure class is one row per repository, so
  class grain is already the finest grain there is.
- **Site grain for a secret rule** (`private_key_pem`, short Slack tokens)
  uses the same anchor, with the matched span replaced by a fixed
  placeholder before normalizing. This keeps any value-bearing text out of
  the hash.

Privacy: for a non-secret site, the anchor hashes a source line that is
committed in the same repository. It stays local exactly as the fingerprint
does.

### 3. File/glob and 4. Class

No change on disk or in meaning: `scanner.waivers` entries with and without
`paths`. They are kept because there are legitimate wide waivers (a fixtures
tree, a vendored SDK, a class the team has decided not to enforce). They stop
being the *default*. For a secret class, file grain is now the deliberate,
visible choice it should be (see "What `rvl suppress` writes").

## On disk

The new grains go in a **new list**, `scanner.instance_waivers`, not new
fields on `scanner.waivers` entries:

```yaml
scanner:
  waivers:                       # unchanged: grains 3 and 4
    - matcher: secret.github_token
      paths: ["testdata/**"]
      reason: recorded fixtures, every token revoked
  instance_waivers:              # new: grains 1 and 2
    - matcher: secret.github_token
      fingerprint: v1:9c1e4f0a2b7d3e65
      reason: vendor's published sandbox key
      expires: 2027-03-31
    - matcher: db.RLSPool.QueryRow
      site:
        file: internal/store/tenant.go
        anchor: v1:4be0a91c37d25f08
        line: 88                 # hint only, never matched
      reason: bounded by the pool's statement_timeout
```

Each entry has exactly one of `fingerprint` and `site`. `expires` and `reason`
mean what they mean on `scanner.waivers`, and use the same `expiry_active`.

**Why a separate list: what an older binary does.** Old and new `rvl`
binaries share one committed file: a teammate's hook binary is often a
release or two behind. Today's parser ignores keys it does not know.
`WaiverFile`, `ScannerSection` and `Waiver` in `crates/rvl/src/waiver.rs`
derive `Deserialize` *without* `#[serde(deny_unknown_fields)]`. That is
serde's default, and it means an unknown key is skipped, not an error.
`docs/configuration.md` states the same contract for the whole file ("Unknown
keys are tolerated everywhere"). New keys are therefore additive. The open
question is what an old binary *does* with an entry it half-understands:

- If `fingerprint`/`site` were new fields on a `scanner.waivers` entry, an old
  binary would drop the unknown field and read `{matcher, reason}` with empty
  `paths`, which is a **class-wide** waiver. The finest waiver would turn into
  the coarsest one on every laptop that has not upgraded. That is the worst
  possible failure for this design.
- In a separate list, an old binary skips `scanner.instance_waivers` as one
  unknown key and waives **nothing** from it. The finding blocks on that
  laptop until the binary is upgraded. That is churn, not a missed secret,
  which is the direction the design prefers.

`append_waiver` already round-trips the whole document through
`serde_yaml::Value`, so an old binary's `rvl suppress` keeps the new list it
does not understand when it writes.

**The Go reader.** The `.revelara.yaml` file is also read by the Go `rvl-cli`
(`internal/project/config.go`, `internal/agentscan/waiver.go`). Its source is
not in this repository, so its tolerance of an unknown `scanner` key has not
been checked here. `gopkg.in/yaml.v3` ignores unknown fields unless the
decoder sets `KnownFields(true)`. Implementation item 2 has to confirm that
the Go side does not set it before the new list ships. Because the Go reader
matches only its own matcher namespace (the `mapWaivers` note in
`waiver.rs`), it would never act on these entries even if it parsed them.

## What `rvl suppress` writes

`rvl suppress <id>` defaults to the finest safe grain. `--path` and `--class`
widen it, and only when asked:

| Finding | Default | `--path <glob>` | `--class` |
| --- | --- | --- | --- |
| content-lane secret (fingerprintable rule) | **value fingerprint**, one entry per distinct value | file/glob waiver | class waiver |
| `private_key_pem`, short Slack token | **site** (value-blanked anchor) | file/glob waiver | class waiver |
| any other finding with a file location | **site**, one entry per site | file/glob waiver | class waiver |
| repo-structure finding | class (its finest grain) | n/a | class waiver |

A ladder row is a class that rolls up `site_count` sites. `suppress <id>`
waives **the instances that row showed in the last scan**, one entry each,
and prints how many it wrote. Instances that appear later still fire. A
`--site <path:line>` flag narrows the waiver to one instance of the row.
`--path` and `--class` print a line naming what they now cover, for example
`waived secret.github_token in deploy/** — new keys in these files will NOT
be reported`, so a coarse waiver is never written silently.

This needs the last-scan state to keep every site's fingerprint or anchor.
Today it keeps `render::Finding`, whose `example_sites` holds at most three
sites. The state file is local, under the cache directory, and the
fingerprints in it follow the same privacy rule as above.

## Stale waivers

A waiver that matches nothing is either a fixed finding or a waiver gone
wrong. Neither should go unnoticed. After a full scan (not `--changed-only`,
which sees only part of the tree), COVERAGE counts instance waivers that
matched no site: `waivers: 2 stale (rvl suppress --prune)`. `--prune` deletes
exactly those entries. Stale class and file waivers are counted too, but not
pruned automatically, because a wide waiver that matches nothing today may be
waiting for the next file in a fixtures tree.

## Inline allow-comments

The content lane already honors an inline pragma: `rvl:allow`, the older
`rvlscan:allow`, and `gitleaks:allow` anywhere on the line suppress every
content rule on that line (`inline_allow` in `crates/rvl-content/src/lib.rs`).
The design keeps that behavior and adds three things:

1. **A targeted form**: `rvl:allow <matcher>`, for example
   `# rvl:allow secret.generic_api_key`, waives only that class on the line.
   The bare form keeps its current meaning, all content rules on the line, so
   repos that migrated from gitleaks keep working.
2. **Accounting.** Today an allowed line is skipped before any rule runs
   (`continue` at the top of `scan_bytes`). So an allowed secret appears
   nowhere, not even in the Suppressed count, and the
   suppression-without-accounting guard on the Coverage section cannot see
   it. Allowed findings should be counted as suppressed, with the reason
   `inline allow`.
3. **The config lane.** YAML, TOML, HCL, `.ini` and `.env` support comments,
   and the config lane reads these files itself (`rvl-config`). It should honor the same
   pragma on the setting's line.

The limits are stated rather than designed away. A pragma works only in
formats with comments. A bare JSON value cannot carry one, which is why
pragmas complement the `.revelara.yaml` list and do not replace it. A pragma
is also line-grain and value-agnostic: if the value on a pragma'd line is
replaced, the new value is allowed too. That is acceptable only because the
pragma sits in the diff hunk that changes the value, where a reviewer sees
both. Code lanes read through index helpers that do not keep comments, so
they do not honor pragmas. Their instance grain is the site waiver.

## Out of scope

- Waivers keyed on a git commit (gitleaks' `.gitleaksignore` fingerprints are
  `commit:file:rule:line`): `rvl` scans a working tree, not history.
- Changing `rvl-cli`'s Go waiver engine. It keeps reading `scanner.waivers`
  and does not need to read the new list.
- A slow (memory-hard) fingerprint hash to protect low-entropy values. That
  costs every scan time for a protection that, by the argument above, guards
  nothing a reader of the repository cannot already read.

## Implementation items

To be filed as separate pieces of work, in this order:

1. **Match waivers per site, before the rollup.** Fix the defect above: test
   `paths` against each site's path, so a file waiver no longer hides the
   class's sites in other files, and so a row is suppressed only when every
   site in it is waived. A partly waived row shows its unwaived sites. This
   is a bug fix that stands on its own, and items 2 and 3 depend on it.
2. **Value-fingerprint waivers for secrets.** Compute `fingerprint` in
   `rvl-content` (rule eligibility as above), add `scanner.instance_waivers`
   with `fingerprint` entries, keep every site's fingerprint in the last-scan
   state, make fingerprint the `rvl suppress` default for secrets, and add
   `--path`, `--class`, `--site`, stale counting and `--prune`. Also confirm
   that the Go `rvl-cli` reader tolerates the new key.
3. **Content-anchored site waivers.** The `site` entry, its anchor (line,
   config unit, value-blanked line for secret rules), and site grain as the
   `rvl suppress` default for every non-secret finding with a location.
4. **Targeted and counted inline allow-comments.** `rvl:allow <matcher>`,
   counting allowed findings as suppressed, and the pragma in the config lane.
