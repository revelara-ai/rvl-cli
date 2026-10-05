# The ranked top-20 lens candidates, reconciled against the scanner

The specialist lenses claim 155 problem classes. The lens taxonomy of
2026-08-06 ranked the 20 classes that are high value and deterministically
reachable, and the porting epic (`po-6c0v8`) ports them into the scanner in
ranked order. This page is the first step of that epic. It is not a port. It
records, for each of the 20, whether the scanner already answers the question,
so that no class is built twice.

Snapshot: 2026-10-04, repository at `d4f339e`. This page is a dated record.
Read [How the evidence was collected](#how-the-evidence-was-collected) before
you rely on a row after that date.

## Statuses

| Status | Meaning |
| --- | --- |
| SHIPPED | A retriever emits the fact, the installed corpus has a spec for it, and a scan can report a finding. Nothing to build. |
| LANE-WIRED-NEEDS-CORPUS | A retriever emits the fact, but no spec judges it, so the lane abstains. The work is a corpus entry, not a detector. The row names the corpus bead. |
| GENUINELY-NEW | No retriever emits the fact. The work is retrieval first. The row names the bead that owns it. |

A candidate that holds classes with different statuses is split into lettered
rows (8a, 8b). A split row is the most useful result on this page: it shows
the part that must not be built again.

## The reconciled list

| Rank | Class | Status | Evidence | Bead | Notes |
| --- | --- | --- | --- | --- | --- |
| 1 | A1: outbound call with no timeout | SHIPPED | `crates/rvl-propagate/src/lib.rs:649`, `crates/rvl-spec/src/lib.rs:42` | Corpus growth: `po-av01j.8` | This is the G1 lane's own question. The installed corpus has 534 blocking API specs and 18 class judgments, all on RC-019. More libraries is corpus work. |
| 2 | M6: connection pool unbounded or unsized | GENUINELY-NEW | `crates/rvl-core/src/lib.rs:316`, `crates/rvl-spec/src/lib.rs:439` | `po-6c0v8.2` | No pool fact is emitted. Reuse, do not rebuild: a G1 site already carries the client's construction snippet, which is where a pool setter would be read. |
| 3 | Q1/Q2: hardcoded secret | SHIPPED | `crates/rvl-content/src/lib.rs:79`, `crates/rvl/src/main.rs:3472` | None needed | The G5 content lane. Nine rules, in-process, every finding maps to RC-043. |
| 4 | Q4: SQL injection through concatenation | GENUINELY-NEW | `crates/rvl-core/src/lib.rs:292` | `po-6c0v8.4` | A site packet has no field for the shape of a query argument. Only the same-expression form is in scope. |
| 5 | B1/B2: retry with no backoff, cap, or jitter | GENUINELY-NEW | `crates/rvl-propagate/src/lib.rs:1231` | `po-6c0v8.4` | G3 applies timeout and retry judgment to a background job as a whole. It does not read the shape of a delay expression. |
| 6 | D2: unbounded queue, channel, or mailbox | GENUINELY-NEW | `crates/rvl-spec/src/lib.rs:316` | `po-6c0v8.2` | The engine already reads a queue constructor's capacity, but only to remove a false deadline finding on a queue that can never be full. D2 asks the opposite question of the same fact. |
| 7a | M1: container without requests, or without a memory limit | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:352`, `crates/rvl-config/src/key_ledger.rs:136` | None needed | `kubernetes container.resources.requests.cpu` and `kubernetes container.resources.requests.memory` on RC-024, `kubernetes container.resources.limits.memory` on RC-067. All expect `present`. |
| 7b | M1: container without a CPU limit | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:354`, `crates/rvl-config/src/key_ledger.rs:135` | `po-av01j.44` | `kubernetes container.resources.limits.cpu` is emitted and has no spec. A CPU limit is contested practice, so this needs a decision before a spec. |
| 8a | H1: swallowed error | SHIPPED | `helpers/goindex/emission.go:360`, `crates/rvl-emission/src/lib.rs:109` | None needed | The G4 emission lane. The Go, Python, and TypeScript helpers emit swallow aggregates, and three `violates` specs map them to RC-027. The finding is one advisory row per control with at most five evidence sites. |
| 8b | H2/H3: overbroad catch, discarded error value | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:831`, `helpers/goindex/misuse.go:127`, `crates/rvl-misuse/src/lib.rs:132` | `po-6c0v8.10` | Updated 2026-10-04 by `po-6c0v8.3`. The Python helper emits `overbroad_catch` and the Go helper emits `discarded_error`, as `misuse_shape` aggregates. No `misuse_shapes` spec is in the corpus, so the lane judges nothing yet. A handler that 8a counts as a swallow is not reported again. The other helpers do not emit the packet. |
| 9 | F2: cache with no eviction, TTL, or size cap | GENUINELY-NEW | `crates/rvl-core/src/lib.rs:316` | `po-6c0v8.2` | Same mechanism as M6: the construction snippet is retrieved, no bound is read from it. |
| 10a | K2: container without a liveness or readiness probe | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:368`, `crates/rvl-config/src/key_ledger.rs:133` | None needed | `kubernetes container.liveness-probe` and `kubernetes container.readiness-probe` on RC-020. |
| 10b | K2: container without a startup probe | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:370`, `crates/rvl-config/src/key_ledger.rs:140` | `po-av01j.44` | `kubernetes container.startup-probe` is emitted and has no spec. |
| 10c | K3: liveness probe whose handler touches a dependency | GENUINELY-NEW | `crates/rvl-spec/src/lib.rs:754` | `po-6c0v8.5` | G2 knows health paths and G6 knows a probe exists. Nothing carries the probe path or joins the two. |
| 11 | F3: unbounded read of a body, file, or result set | GENUINELY-NEW | `crates/rvl-core/src/lib.rs:670` | `po-6c0v8.2` | The Go helper already counts `io.ReadAll` as I/O that its tables do not retrieve. It is a census entry, not a site. |
| 12a | Q25: mutable image tag | SHIPPED | `crates/rvl-config/src/dep_manifests.rs:768`, `crates/rvl-config/src/kubernetes/manifest.rs:390` | None needed | `dep-manifests dockerfile.base_image_pin` and `kubernetes container.image.pin` on RC-041. Both expect `digest` or `tag`. |
| 12b | Q26: container with no security context | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:377`, `crates/rvl-config/src/key_ledger.rs:139` | None needed | `kubernetes container.security-context` on RC-044, presence only. This is not a root-container check: see 12c. |
| 12c | Q26: container runs as root, fat base image | GENUINELY-NEW | `crates/rvl-config/src/dep_manifests.rs:674` | `po-6c0v8.6` | The Dockerfile retriever reads `FROM` only. Nothing reads `USER`, the value of `runAsNonRoot`, or the size class of a base image. |
| 13 | I1: unstructured or print-style logging | GENUINELY-NEW | `helpers/goindex/emission.go:56` | `po-6c0v8.4` | G4 counts log-framework calls, not `fmt.Println`. It also lets stdlib `log.Print*` satisfy RC-027, so I1 must be arbitrated against that before it ships. |
| 14 | J7: average latency in place of a histogram | GENUINELY-NEW | `crates/rvl-spec/src/lib.rs:510` | `po-6c0v8.4` | Emission categories are `log`, `trace`, and `error_capture`. There is no metric-registration category. |
| 15 | G5/G6: sync-over-async, blocking in async | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:831`, `crates/rvl-misuse/src/lib.rs:132` | `po-6c0v8.10` | Updated 2026-10-04 by `po-6c0v8.3`. The Python helper emits `blocking_in_async` and `sync_over_async` for a table of module-level functions. A blocking method on a client object is not emitted. Go has no async functions. |
| 16 | E5/E6: fire-and-forget async, missing await | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:831`, `crates/rvl-misuse/src/lib.rs:132` | `po-6c0v8.10` | Updated 2026-10-04 by `po-6c0v8.3`. The Python helper emits `fire_and_forget` and `missing_await`. A coroutine function is known only when the same module defines it. The TypeScript helper, which has the types for a floating promise, does not emit the packet yet. |
| 17 | L5: alert with no runbook link | SHIPPED | `crates/rvl-config/src/prometheus.rs:318`, `crates/rvl-config/src/key_ledger.rs:154` | None needed | `prometheus-rules rule.annotations.runbook` on RC-006. Ships in the OSS tier. |
| 18a | Q29: action not pinned to a commit SHA | SHIPPED | `crates/rvl-config/src/github_actions.rs:315`, `crates/rvl-config/src/key_ledger.rs:125` | None needed | `github-actions step.uses.ref` and `github-actions job.uses.ref` on RC-042, pattern `sha40`. |
| 18b | Q21/Q22: no dependency scanning, no SAST in CI | GENUINELY-NEW | `crates/rvl-config/src/key_ledger.rs:122` | `po-6c0v8.7` | Every GitHub Actions key is per job or per step. A whole-tree absence needs a repo-level fact, which is a G7 inventory shape. |
| 19a | O8: single replica | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:263`, `crates/rvl-config/src/key_ledger.rs:148` | None needed | `kubernetes workload.replicas` on RC-017, at least 2. `kubernetes hpa.min-replicas` has the same spec. |
| 19b | O8: PodDisruptionBudget values | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:228`, `crates/rvl-config/src/key_ledger.rs:143` | `po-av01j.44` | `kubernetes pdb.min-available` and `kubernetes pdb.max-unavailable` are emitted and have no spec. |
| 19c | O8: workload with no PDB, no anti-affinity | GENUINELY-NEW | `crates/rvl-config/src/kubernetes/manifest.rs:228` | `po-6c0v8.8` | PDB packets exist only when a PDB object exists. Nothing reports a Deployment that no PDB selects, and nothing reads affinity or topology spread. |
| 20 | N1: N+1 query in a loop | GENUINELY-NEW | `crates/rvl-core/src/lib.rs:292` | `po-6c0v8.4` | No retriever emits a loop-enclosure fact. Only the form with the loop and the query in one function is reachable, and the detector must be named for that. |

## What changed against the list the epic started with

The epic recorded three things as known on 2026-08-07, to be verified and not
assumed. Two held. One no longer holds.

- **Rank 1 and rank 3 are shipped.** Confirmed.
- **Ranks 7, 10, 12, 17, 18, and 19 are "wired and abstaining".** This is no
  longer true. The Kubernetes, Prometheus, GitHub Actions, and Dockerfile
  specs landed between August and October. The main class of each of these six
  ranks now ships. What is left is three small corpus gaps (7b, 10b, 19b) and
  four retriever gaps that the config lane cannot answer with any corpus
  (10c, 12c, 18b, 19c).
- **The three wave beads carry the genuinely new set.** Confirmed, with one
  exception. H1 in wave 2 is not new: a swallowed error already ships through
  the emission lane as RC-027, and wave 2 said no lane was wired.

Count by rank: 3 ranks ship in full (1, 3, 17), 5 ship in their main class
with a remainder (7, 10, 12, 18, 19), 1 ships in part through a different lane
(8), and 11 are new in full (2, 4, 5, 6, 9, 11, 13, 14, 15, 16, 20).

**Update, 2026-10-04 (`po-6c0v8.3`).** Wave 2 landed its retrieval and its
lane. Rows 8b, 15, and 16 moved from GENUINELY-NEW to
LANE-WIRED-NEEDS-CORPUS: the Go and Python helpers emit the fact, and no spec
judges it. The corpus entries, and the helpers that do not emit the packet,
are `po-6c0v8.10`. The count above and the table below this point are the
2026-10-04 snapshot and were not recomputed.

## What to build, and what not to build

**Do not build.** A timeout detector, a secret detector, a swallowed-error
detector, or any Kubernetes, Prometheus, or GitHub Actions check for the
classes in a SHIPPED row.

**Corpus only.** Rows 7b, 10b, and 19b. Each is a `ConfigKeySpec` entry in
`po-av01j.44`. No code changes in this repository.

**Retrieval first.** The 12 code classes stay in the three wave beads, with
the corrections recorded as notes on each bead:

| Bead | Classes | Correction |
| --- | --- | --- |
| `po-6c0v8.2` | M6, D2, F2, F3 | None to scope. Reuse the construction snippet (M6, F2), the capacity argument (D2), and the retrieval census (F3). |
| `po-6c0v8.3` | H2, H3, G5/G6, E5/E6 | H1 is removed: it ships. Landed for Go (H3) and Python on 2026-10-04. What is left is in `po-6c0v8.10`. |
| `po-6c0v8.4` | B1/B2, N1, Q4, I1, J7 | None to scope. I1 must not contradict the emission lane on stdlib log calls. |

Four classes had no bead. Each is now a child of the epic:

| Bead | Class | Row |
| --- | --- | --- |
| `po-6c0v8.5` | K3: liveness handler touches a dependency | 10c |
| `po-6c0v8.6` | Q26: Dockerfile `USER`, `runAsNonRoot` value, fat base | 12c |
| `po-6c0v8.7` | Q21/Q22: no dependency scanning or SAST job | 18b |
| `po-6c0v8.8` | O8: workload with no PDB or anti-affinity | 19c |

The control-code block that every wave bead names (`po-av01j.105`) is closed.
It is no longer a reason to wait.

## How the evidence was collected

A status has two halves, and they come from different places.

**What a retriever emits** comes from this repository. Each row cites the line
that emits the fact, or, for a GENUINELY-NEW row, the nearest line that shows
the fact is missing. For the config lane, the complete list of emitted keys is
`EMITTED_KEYS` in `crates/rvl-config/src/key_ledger.rs`.

**What the corpus judges** does not come from this repository. Specs ship in
the signed artifact. The spec state on this page is the output of
`rvl cache keys` and `rvl cache status` on 2026-10-04, with rvl 1.2.2, the
commercial artifact `2026-09-17.2cb3446d`, and the OSS artifact
`2026-10-04.88644acd`: 95 keys emitted, 33 with a spec, 59 that await a spec,
3 vocabulary only.

To check a config row again, run:

```bash
rvl sync
rvl cache keys
```

A key under "specced" is SHIPPED. A key under "awaiting a spec" is
LANE-WIRED-NEEDS-CORPUS. A class with no key is GENUINELY-NEW.

A test holds the table to its contract
(`crates/rvl/tests/lens_reconciliation_doc.rs`): all 20 ranks are present,
each row has one of the three statuses and a citation that resolves, each row
that is not SHIPPED names a bead, and each config key named here is in the
ledger. The test does not check the corpus half, because the corpus is not in
the repository.
