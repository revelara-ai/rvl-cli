# `rvl scan --out`: the structured scan document (v1)

The machine contract between the binary and any orchestrator, emitted by
`rvl scan --out <file>`. The implementation is
`crates/rvl/src/out_doc.rs`; this page is its external spec, and the two are
updated in the same change. Validated end-to-end on a real backend repo
(4078 sites) and consumed by the engine-first scan pipeline A/B: -65% output
tokens, -25% cost, 17 net-new findings vs the agentic-scan baseline at equal
lens count.

## Why

The deep-scan orchestration skill (`/rvl:scan`) needs a machine contract
covering everything the human ladder and COVERAGE block already say: the
findings themselves, coverage with abstains by lever, the undecided sites,
and which classes the engine covers in this repo. All of it exists internally
(`render::Coverage`, `ConfigCoverage.no_spec_keys`, the persisted last-scan
ladder); the document is serialization work, not new analysis.

The orchestrator uses it to:

1. Scope the semantic (lens) pass away from what the engine resolved, so
   nothing is scanned twice and engine results are not crowded out.
2. Hand undecided sites to lens adjudication (report-only verdicts, same
   asymmetry rules as the hook lane: an agent verdict never mutates engine
   state).
3. Render the merged developer report with engine rows verbatim.

## Example

```json
{
  "schema": "rvl-scan/v1",
  "exit": 3,
  "findings": [
    {
      "id": "2ben",
      "class": "net/http.Client.Do",
      "severity": "blocking",
      "base_severity": "high",
      "site": "internal/x/y.go:45",
      "description": "http.Client.Do has no timeout or deadline — it can hang indefinitely",
      "control": "RC-019",
      "fix": "wrap in context.WithTimeout",
      "site_count": 3,
      "suppressed": false,
      "gate_exempt": false
    }
  ],
  "coverage": {
    "resolved": 1614,
    "total": 1780,
    "abstain": { "no_spec": 90, "bounds": 40, "judge": 30, "other": 6 },
    "generated_skipped": 3,
    "test_files_skipped": 12,
    "dependency_trees_uninstalled": 0,
    "degraded_note": null,
    "lang_status": [ { "lang": "go", "state": "scanned", "detail": "1240" } ],
    "by_language": [
      { "lang": "Go", "resolved": 1614, "total": 1780, "no_spec": 90,
        "corpus_gap": false }
    ],
    "retrievers": [ { "lang": "go", "path": "...", "source": "bundled" } ],
    "degraded": [
      { "lang": "python", "abstained": false, "not_installed": true,
        "reason": "python3 not found on PATH" }
    ],
    "config": {
      "resolved": 120, "total": 140,
      "abstain": { "no_spec": 15, "outside_repo": 3, "other": 2,
                   "vocabulary_only": 4 },
      "no_spec_keys": ["github_actions permissions"],
      "unparseable_files": 0
    },
    "retrieval": [
      { "lang": "go", "calls_resolved": 18233, "candidates": 412,
        "unretrieved": { "io.ReadAll": 3 } }
    ],
    "structure": { "total": 6, "violates": 1, "satisfies": 3, "abstain": 1,
                   "not_applicable": 1 }
  },
  "sites": [
    { "site_id": "...", "snapshot_id": "...", "verdict": "violates",
      "reason": "no bound anywhere", "class": "net/http.Client.Do" }
  ],
  "undecided": [
    { "site": "queue/worker.go:88", "class": "redis.pipeline",
      "lever": "judge", "scope": "runtime" }
  ],
  "covered_classes": ["net/http.Client.Do", "redis.pipeline"],
  "structure": [
    { "site_id": "repo", "snapshot_id": "...", "verdict": "violates",
      "reason": "no test files for go", "class": "repo_structure.RC-033" }
  ],
  "hook_agent": null,
  "blend": null
}
```

## Field semantics

- `findings` is the ladder, post-waiver: every row the human sees, including
  suppressed and gate-exempt rows (flagged, never dropped). `severity` is the
  section the row renders in (`blocking` | `advisory` | `suppressed`),
  derived by the same `classify` the exit code uses; `base_severity` carries
  the judgment's raw grade (`high` | `medium` | `low` | `""` for a
  not-yet-graded class). `description` is the human one-liner from the
  ladder, `site` the primary `path:line`, and `site_count` how many sites the
  finding rolls up. `id` is the stable finding id that `explain`/`suppress`
  resolve.
- `sites` is every per-site eval row (`site_id`, `snapshot_id`, `verdict`,
  `reason`, `class`): the pre-v1 top-level array verbatim, one level down.
  The eval harness' per-site (verdict, reason) contract lives here;
  `undecided` and `covered_classes` are precomputed projections of these rows
  so an orchestrator never needs to know which verdict strings count as
  resolved.
- `coverage` mirrors the COVERAGE block one-to-one, abstains broken out by
  the lever that closes each (no-spec = mint, bounds = retrieval
  depth/declared bounds, judge = per-site judge). The roll-calls are included
  so a consumer can report which lanes ran, failed, or read nothing without
  parsing stdout:
  - `lang_status[]`: one row per detected language. `state` is `scanned` |
    `partial` | `abstained` | `failed` | `unsupported` | `not_installed` |
    `skipped`; `detail` carries the site count on a scanned lane or the
    reason otherwise. `skipped` means the language was found only in test
    material and no retriever ran for it; `detail` is the file count
    (`1 file`), and the row has no `degraded[]` entry because nothing failed. `partial` means the helper ran but some units parsed only
    partly (for C/C++, usually a header that is not installed), so the site
    count is a floor: `detail` reads `<n> sites, INCOMPLETE: <why>`.
  - `by_language[]`: `resolved`, `total` and `no_spec` split by the language
    of the file each site is in (`other` when no retriever claims the
    extension). `corpus_gap` is true when the language resolves almost
    nothing and missing specs are the cause: the ruleset has no specs for
    that ecosystem. It is a hint, and it never changes `exit`.
  - `retrievers[]`: which helper served each lane and from which resolution
    slot.
  - `degraded[]`: one row per degraded lane (`lang`, `abstained`,
    `not_installed`, `reason`); empty on a fully healthy scan.
  - `generated_skipped` and `test_files_skipped`: files the scan declined to
    read, so a consumer can tell "no sites in tests" from "tests were not
    looked at". The first counts banner-declared machine-generated files
    dropped after retrieval; the second counts test files the Python and
    TypeScript retrievers skipped by path convention, summed across
    languages (the per-language split is printed in COVERAGE). Both are
    repository-wide on every path: a warm (`--incremental`) scan counts the
    test files its packet index flagged when they were first retrieved as
    well as the ones it re-parsed this pass. `rvl scan --include-tests`
    makes the second zero by scanning them.
  - `retrieval[]`: the retrieval denominator, one row per language whose
    helper measures it (Go today). `resolved`/`total` is resolution over the
    sites the extractor RETRIEVED, and the extractor's tables decide what is
    retrieved, so never quote that percentage without this row.
    `candidates` is the call sites the extractor retrieved; `calls_resolved`
    is every call in non-test code whose callee the type checker resolved
    (crude by design: most are not I/O); `unretrieved` counts calls the
    helper's corpus knows are I/O and its tables do not retrieve, keyed by
    surface (`io.ReadAll`). The counts are whole-repo even under
    `--incremental`, but a warm pass that re-parsed no file of a language has
    no row for it: absent means not measured this run, never zero.
  - `dependency_trees_uninstalled`: workspaces that declare dependencies
    with no installed tree, summed across languages. Non-zero means the
    TypeScript retriever resolved those workspaces' client types from import
    syntax: the packets are tier `medium`, carry no `client_version`, and
    are not filtered by awaitability. `lang_status` still says `scanned`,
    so this is the field that tells such a scan from a fully resolved one.
    On a warm (`--incremental`) scan it counts what the retrievers that ran
    this pass reported; the packet index does not record the dependency
    state behind a reused packet.
  - `config.abstain.vocabulary_only`: config settings whose key is emitted
    as evidence and deliberately never judged. They have no spec by design,
    so they are counted apart from `no_spec` and never appear in
    `no_spec_keys`. `rvl cache keys` lists which keys carry the marker and
    why.
  - `structure`: the repo-structure lane's verdict counts (`total`,
    `violates`, `satisfies`, `abstain`, `not_applicable`), one control each.
    It mirrors the `structure:` line of the COVERAGE block. Null when the
    lane did not run.
- `structure` is the repo-structure lane: one eval row per control (RC-033,
  RC-057, RC-058, RC-034, RC-070, RC-006) in that order, with the same five
  fields as a `sites` row. `site_id` is always `repo`, because the lane
  judges the repository and not a location, so `class`
  (`repo_structure.RC-XXX`) is the key of a row. Every verdict is present,
  `satisfies`, `abstain` and `not_applicable` included, and the rows are
  pre-waiver engine truth. The violations among them are also ladder rows in
  `findings`, post-waiver. The rows are kept out of `sites` on purpose:
  `coverage.resolved`, `coverage.total`, `undecided` and `covered_classes`
  count call sites only. The array is empty when the lane did not run
  (`--changed-only`, or a `--retrieved` stream with no `repo_structure`
  record). An empty array never means that the repository satisfies the
  controls. To score the lane, run
  `rvl-eval score --lane structure --findings <scan.json> --gold <gold.json>`;
  a gold case id is a control code (`RC-033`) or the full class.
- `undecided` lists each site the engine reached and abstained on, with its
  lever and its path-derived scope (`runtime` | `migration` | `test_support`
  | `dev_only` | `backfill`). Scope exists so a consumer can rank runtime
  abstains above test scaffolding without re-deriving path heuristics: on the
  first real dogfood, 2761 undecided read as alarming until scope showed most
  were test_support (playwright/msw). This plus `covered_classes` is the
  abstain manifest: an orchestrator points semantic lenses at runtime-scoped
  `undecided` rows and away from `covered_classes`.
- `covered_classes` is the class-key list the loaded spec cache judges in
  this repo (classes with at least one matched site). Consumers must treat
  classes absent from this list as "not the engine's problem", never as
  "clean".
- `hook_agent` is the hook-adjudication block as rendered text, present when
  `--hook` ran with the agent lane enabled and verdicts to show (verdicts are
  provenance-tagged and separate, exactly as rendered). Null otherwise.
- `blend` is present when `rvl scan --blend` ran, null otherwise. It is a
  status report, not findings: `complete` (bool), `reason` (why the blend
  is incomplete, else null), `agent` (the agent consulted, else null), the
  counts `in_scope`, `sent`, `cleared`, `warned`, `undecided` and
  `out_of_scope`, and `block`, the BLEND section as rendered text.
  `complete: false` means the report is the deterministic half alone.
  Nothing in `findings`, `sites` or `undecided` changes because of it.
- `exit` duplicates the process exit code so a consumer holding only the file
  knows whether the gate fired (`0` clean, `3` blocking).

## Compatibility

- No separate eval-rows output: the eval rows ride inside the document at
  `.sites`, field-for-field identical to the pre-v1 format; harness consumers
  migrate by indexing one level deeper.
- Additive evolution only within v1: new fields may appear, existing fields
  never change meaning. Breaking changes bump `schema`.
- `findings[].class` is a contract field with lane-dependent meaning: for
  spec-lane findings it is the producing spec's identity
  (`client_type.method`, the waiver key, e.g. `net/http.Client.Do`); for
  vocabulary/structure lanes it keeps a fixed prefix (`server_entry.`,
  `emission.`, `unsized.`, `repo_structure.`, `config.`). The server's precision arm
  (fleet FP evidence) attributes findings to specs through this field.
- Consumers MUST ignore unknown fields.

## What this contract deliberately excludes

- No source content, no secret values: sites are `path:line` references. The
  document stays within the same privacy posture as the ladder itself. (The
  shape-only factory report remains a separate channel with a stricter
  contract; nothing here feeds it.)
- No agent/lens findings: this document is deterministic-engine truth only.
  Merging with semantic findings happens in the orchestrator,
  provenance-tagged, and engine rows are authoritative there (dedup key:
  `(control, file)` or same `class` at same site; a duplicate lens finding is
  dropped and recorded as lens corroboration of the engine row).
