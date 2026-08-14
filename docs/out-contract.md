# `rvlscan scan --out`: the structured scan document (v1)

Status: IMPLEMENTED 2026-08-12 (this branch). Supersedes the eval-rows-only
`--out` format. Validated end-to-end on a real backend repo (4078 sites) and
consumed by the engine-first scan pipeline A/B: -65% output tokens, -25% cost,
17 net-new findings vs the agentic-scan baseline at equal lens count.

Two fields were added by that validation (design vetting working as intended):

- `sites`: the first prototype dropped the per-site eval rows entirely; six
  e2e tests failed because the eval harness is a REAL consumer of per-site
  (verdict, reason). The rows now live at `.sites`, verbatim, one level down.
- `undecided[].scope`: 2761 undecided on the first dogfood read as alarming
  until path scope showed most were test_support (playwright/msw). Consumers
  rank runtime abstains first without re-deriving path heuristics.

## Why

`--out` today writes per-site eval rows (`site_id, snapshot_id, verdict, reason,
class`). That was built for eval harnesses. The deep-scan orchestration skill
(`/rvl:scan`) needs a machine contract covering everything the human ladder and
COVERAGE block already say: the findings themselves, coverage with abstains by
lever, the undecided sites, and which classes the engine covers in this repo.
All of it exists internally (`render::Coverage`, `ConfigCoverage.no_spec_keys`,
the persisted last-scan ladder); this is serialization work, not new analysis.

The document is the single machine contract between the binary and any
orchestrator. The orchestrator uses it to:

1. Scope the semantic (lens) pass AWAY from what the engine resolved: no
   double-scan, no crowd-out.
2. Hand undecided sites to lens adjudication (report-only verdicts, same
   asymmetry rules as the hook lane: an agent verdict never mutates engine
   state).
3. Render the merged developer report with engine rows verbatim.

## Schema

```json
{
  "schema": "rvl-scan/v1",
  "exit": 0,
  "findings": [
    {
      "id": "2ben",
      "class": "gcp.storage.write",
      "severity": "blocking",
      "site": "internal/x/y.go:45",
      "scope": "Runtime",
      "control": "RC-019",
      "fix": "wrap in context.WithTimeout",
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
    "lang_status": [ { "lang": "go", "state": "scanned", "detail": "1240 sites" } ],
    "retrievers": [ { "lang": "go", "path": "...", "source": "bundled" } ],
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
  "covered_classes": ["gcp.storage.write", "redis.pipeline"],
  "hook_agent": null
}
```

## Field semantics

- `findings` is the LADDER, post-waiver: every row the human sees, including
  suppressed and gate-exempt rows (flagged, never dropped). `severity` is the
  SECTION the row renders in (`blocking` | `advisory` | `suppressed`), derived
  by the same `classify` the exit code uses; `base_severity` carries the
  judgment's raw grade. `id` is the stable finding id that `explain`/`suppress`
  resolve.
- `sites` is every per-site eval row (site_id, snapshot_id, verdict, reason,
  class): the old top-level array verbatim, one level down. The eval harness'
  per-site (verdict, reason) contract lives here; migration is reading
  `.sites` instead of the document root, nothing else. `undecided` and
  `covered_classes` are precomputed projections of these rows so an
  orchestrator never needs to know which verdict strings count as resolved.
- `coverage` mirrors the COVERAGE block one-to-one, abstains broken out by the
  lever that closes each (no-spec = mint, bounds = retrieval depth, judge =
  per-site judge). Language and retriever roll-calls are included so a consumer
  can render the silence-is-never-ambiguous story without stdout parsing.
- `undecided` lists each site the engine reached and abstained on, with its
  lever and its path-derived scope (`runtime` | `migration` | `test_support` |
  `dev_only` | `backfill`). This plus `covered_classes` IS the abstain
  manifest: an orchestrator points semantic lenses at runtime-scoped
  `undecided` rows and away from `covered_classes`.
- `covered_classes` is the class-key list the loaded spec cache judges in this
  repo (classes with at least one matched site). Consumers must treat classes
  absent from this list as "not the engine's problem", never as "clean".
- `hook_agent` carries the hook-adjudication block when `--hook` ran (verdicts
  are provenance-tagged and separate, exactly as rendered). Null otherwise.
- `exit` duplicates the process exit code so a consumer holding only the file
  knows whether the gate fired.

## Compatibility

- DECIDED at implementation: no separate `--out-format eval-rows` flag. The
  eval rows ride inside the document at `.sites`, field-for-field identical;
  harness consumers migrate by indexing one level deeper (the in-repo e2e
  suite migrated with a mechanical one-line-per-site shift, 49/49 green).
- Additive evolution only within v1: new fields may appear, existing fields
  never change meaning. Breaking changes bump `schema`.
- Consumers MUST ignore unknown fields.

## What this contract deliberately excludes

- No source content, no secret values: sites are `path:line` references. The
  document stays within the same privacy posture as the ladder itself. (The
  shape-only factory report remains a separate channel with a stricter
  contract; nothing here feeds it.)
- No agent/lens findings: this document is deterministic-engine truth only.
  Merging with semantic findings happens in the orchestrator, provenance-tagged,
  and engine rows are authoritative there (dedup key: `(control, file)` or
  same `class` at same site; a duplicate lens finding is dropped and recorded
  as lens corroboration of the engine row).
