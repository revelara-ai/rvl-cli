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

1. Scope the semantic (lens) pass AWAY from what the engine resolved: no
   double-scan, no crowd-out.
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
    "degraded_note": null,
    "lang_status": [ { "lang": "go", "state": "scanned", "detail": "1240" } ],
    "retrievers": [ { "lang": "go", "path": "...", "source": "bundled" } ],
    "degraded": [
      { "lang": "python", "abstained": false, "not_installed": true,
        "reason": "python3 not found on PATH" }
    ],
    "config": {
      "resolved": 120, "total": 140,
      "abstain": { "no_spec": 15, "outside_repo": 3, "other": 2 },
      "no_spec_keys": ["github_actions permissions"],
      "unparseable_files": 0
    }
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
  "hook_agent": null
}
```

## Field semantics

- `findings` is the LADDER, post-waiver: every row the human sees, including
  suppressed and gate-exempt rows (flagged, never dropped). `severity` is the
  SECTION the row renders in (`blocking` | `advisory` | `suppressed`),
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
  so a consumer can render the silence-is-never-ambiguous story without
  stdout parsing:
  - `lang_status[]` — one row per detected language: `state` is `scanned` |
    `abstained` | `failed` | `unsupported` | `not_installed`, `detail`
    carries the site count on a scanned lane or the reason otherwise.
  - `retrievers[]` — which helper served each lane and from which resolution
    slot.
  - `degraded[]` — one row per degraded lane (`lang`, `abstained`,
    `not_installed`, `reason`); empty on a fully healthy scan.
- `undecided` lists each site the engine reached and abstained on, with its
  lever and its path-derived scope (`runtime` | `migration` | `test_support`
  | `dev_only` | `backfill`). Scope exists so a consumer can rank runtime
  abstains above test scaffolding without re-deriving path heuristics: on the
  first real dogfood, 2761 undecided read as alarming until scope showed most
  were test_support (playwright/msw). This plus `covered_classes` IS the
  abstain manifest: an orchestrator points semantic lenses at runtime-scoped
  `undecided` rows and away from `covered_classes`.
- `covered_classes` is the class-key list the loaded spec cache judges in
  this repo (classes with at least one matched site). Consumers must treat
  classes absent from this list as "not the engine's problem", never as
  "clean".
- `hook_agent` is the hook-adjudication block as rendered text, present when
  `--hook` ran with the agent lane enabled and verdicts to show (verdicts are
  provenance-tagged and separate, exactly as rendered). Null otherwise.
- `exit` duplicates the process exit code so a consumer holding only the file
  knows whether the gate fired (`0` clean, `3` blocking).

## Compatibility

- No separate eval-rows output: the eval rows ride inside the document at
  `.sites`, field-for-field identical to the pre-v1 format; harness consumers
  migrate by indexing one level deeper.
- Additive evolution only within v1: new fields may appear, existing fields
  never change meaning. Breaking changes bump `schema`.
- `findings[].class` is a CONTRACT field with lane-dependent meaning: for
  spec-lane findings it is the producing spec's identity
  (`client_type.method`, the waiver key — e.g. `net/http.Client.Do`); for
  vocabulary/structure lanes it keeps a fixed prefix (`server_entry.`,
  `emission.`, `repo_structure.`, `config.`). The server's precision arm
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
