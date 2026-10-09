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
| 2 | M6: connection pool unbounded or unsized | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/bounds.go:87`, `helpers/pyindex/pyindex.py:1367`, `crates/rvl-bounds/src/lib.rs:153` | `po-6c0v8.9` | Updated 2026-10-04 by `po-6c0v8.2`. The Go and Python helpers emit one `unsized_construction` packet per pool, with the setters and options seen in scope. No `construction_bounds` spec is in the corpus, so the lane judges nothing yet. Since `po-6c0v8.14`, `javaindex` emits the packet for HikariCP (`HikariConfig`, `HikariDataSource`). The other helpers do not emit the packet. |
| 3 | Q1/Q2: hardcoded secret | SHIPPED | `crates/rvl-content/src/lib.rs:79`, `crates/rvl/src/main.rs:3472` | None needed | The G5 content lane. Nine rules, in-process, every finding maps to RC-043. |
| 4 | Q4: SQL injection through concatenation | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/misuse_shapes.go:78`, `helpers/pyindex/pyindex.py:1094`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.11` | Updated 2026-10-07 by `po-6c0v8.4`. The Go and Python helpers emit `sql_concat_in_call`: SQL text built in the argument of a query call. Only this same-expression form is emitted, and the class is named for it. The form that needs data flow is not claimed. No control is arbitrated for the class. |
| 5 | B1/B2: retry with no backoff, cap, or jitter | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/misuse_shapes.go:78`, `helpers/pyindex/pyindex.py:1094`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.11` | Updated 2026-10-07 by `po-6c0v8.4`. The Go and Python helpers emit `retry_shape` with the identity `constant_delay`, `no_jitter`, or `unbounded_attempts`. The shape is read from the delay expression of a wait on the failure path of an attempt loop. A loop over a collection, a poll interval, and a delay that a function computes are not emitted. Python also reads `tenacity` configurations. |
| 6 | D2: unbounded queue, channel, or mailbox | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:1367`, `crates/rvl-bounds/src/lib.rs:153` | `po-6c0v8.9` | Updated 2026-10-04 by `po-6c0v8.2`. Python queue constructors are emitted. Go `make(chan T)` is not, on purpose: an unbuffered channel is a rendezvous, not an unbounded queue. |
| 7a | M1: container without requests, or without a memory limit | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:352`, `crates/rvl-config/src/key_ledger.rs:136` | None needed | `kubernetes container.resources.requests.cpu` and `kubernetes container.resources.requests.memory` on RC-024, `kubernetes container.resources.limits.memory` on RC-067. All expect `present`. |
| 7b | M1: container without a CPU limit | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:354`, `crates/rvl-config/src/key_ledger.rs:135` | `po-av01j.44` | `kubernetes container.resources.limits.cpu` is emitted and has no spec. A CPU limit is contested practice, so this needs a decision before a spec. |
| 8a | H1: swallowed error | SHIPPED | `helpers/goindex/emission.go:360`, `crates/rvl-emission/src/lib.rs:109` | None needed | The G4 emission lane. The Go, Python, and TypeScript helpers emit swallow aggregates, and three `violates` specs map them to RC-027. The finding is one advisory row per control with at most five evidence sites. |
| 8b | H2/H3: overbroad catch, discarded error value | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:1167`, `helpers/goindex/misuse.go:134`, `helpers/javaindex/javaindex.java:1176`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.10` | Updated 2026-10-08 by `po-6c0v8.17`. The Python and Java helpers emit `overbroad_catch` and the Go helper emits `discarded_error`, as `misuse_shape` aggregates. The Java identities are `java.lang.Exception` and `java.lang.Throwable`. No `misuse_shapes` spec is in the corpus, so the lane judges nothing yet. A handler that 8a counts as a swallow is not reported again. The other helpers do not emit the packet. |
| 9 | F2: cache with no eviction, TTL, or size cap | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/bounds.go:87`, `helpers/pyindex/pyindex.py:1367`, `crates/rvl-bounds/src/lib.rs:153` | `po-6c0v8.9` | Updated 2026-10-04 by `po-6c0v8.2`. Same packet as M6. Emitted for go-cache, `functools.lru_cache`, `functools.cache`, and, since `po-6c0v8.14`, the Caffeine builder (`javaindex`). |
| 10a | K2: container without a liveness or readiness probe | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:368`, `crates/rvl-config/src/key_ledger.rs:133` | None needed | `kubernetes container.liveness-probe` and `kubernetes container.readiness-probe` on RC-020. |
| 10b | K2: container without a startup probe | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:370`, `crates/rvl-config/src/key_ledger.rs:140` | `po-av01j.44` | `kubernetes container.startup-probe` is emitted and has no spec. |
| 10c | K3: liveness probe whose handler touches a dependency | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:386`, `crates/rvl-propagate/src/probe_handler.rs:77` | `po-6c0v8.5` | Updated 2026-10-08 by `po-6c0v8.5`. The Kubernetes retriever emits the `httpGet` path of a liveness probe as `kubernetes container.liveness-probe.http-get.path`. The scan joins it to a route in the same repository and reports `server_entry.liveness-probe-handler-io` on RC-020 when the handler holds a G1 call site. No spec is necessary. The join abstains when the path or the handler is not resolved, and it does not follow a call from the handler into another function. See [The liveness probe join](retrievers.md#the-liveness-probe-join). |
| 11 | F3: unbounded read of a body, file, or result set | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/bounds.go:356`, `crates/rvl-bounds/src/lib.rs:153` | `po-6c0v8.9` | Updated 2026-10-04 by `po-6c0v8.2`. Go `io.ReadAll` is emitted with the calls its argument passes through. It is still not a G1 call site, so the retrieval census counts it as before. Python reads are not emitted. |
| 12a | Q25: mutable image tag | SHIPPED | `crates/rvl-config/src/dep_manifests.rs:768`, `crates/rvl-config/src/kubernetes/manifest.rs:390` | None needed | `dep-manifests dockerfile.base_image_pin` and `kubernetes container.image.pin` on RC-041. Both expect `digest` or `tag`. |
| 12b | Q26: container with no security context | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:377`, `crates/rvl-config/src/key_ledger.rs:139` | None needed | `kubernetes container.security-context` on RC-044, presence only. This is not a root-container check: see 12c. |
| 12c | Q26: container runs as root (Dockerfile `USER`) | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/dep_manifests.rs:908`, `crates/rvl-config/src/key_ledger.rs:101` | `po-6c0v8.19` | Updated 2026-10-08 by `po-6c0v8.6`. `dep-manifests dockerfile.final_stage_user` is emitted once for each Dockerfile and has no spec. The value is `root`, `non-root`, or `absent`, from the last `USER` of the final stage. A final stage that is built `FROM` an earlier stage has the user of that stage. `absent` is not a verdict of root: with no `USER`, the base image sets the user, and the provenance names that image. No value is emitted for a `USER` that reads a build argument with no default in the file, or an `ENV`. |
| 12d | Q26: `runAsNonRoot` value, fat base image | GENUINELY-NEW | `crates/rvl-config/src/kubernetes/manifest.rs:739`, `crates/rvl-config/src/dep_manifests.rs:701` | `po-6c0v8.20` | Split from 12c on 2026-10-08. `kubernetes container.security-context` is judged for presence only: nothing reads the value of `runAsNonRoot`. Nothing reads the size class of a base image. That check needs a decision first: is a list of image names an acceptable classifier? |
| 13 | I1: unstructured or print-style logging | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/misuse_shapes.go:78`, `helpers/pyindex/pyindex.py:1094`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.11` | Updated 2026-10-07 by `po-6c0v8.4`. The Go and Python helpers emit `print_logging` for print functions that write to a standard stream. Stdlib `log.Print*` and `logging` calls are not emitted: G4 counts them as log emissions that can satisfy RC-027, and that boundary is not arbitrated. The default severity is `low`, and the corpus sets it. |
| 14 | J7: average latency in place of a histogram | LANE-WIRED-NEEDS-CORPUS | `helpers/goindex/misuse_shapes.go:78`, `helpers/pyindex/pyindex.py:1094`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.11` | Updated 2026-10-07 by `po-6c0v8.4`. The Go and Python helpers emit `latency_scalar_metric` at the registration call of a Prometheus gauge or counter with a latency name. Other metric clients are not read. |
| 15 | G5/G6: sync-over-async, blocking in async | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:1167`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.10` | Updated 2026-10-04 by `po-6c0v8.3`. The Python helper emits `blocking_in_async` and `sync_over_async` for a table of module-level functions. A blocking method on a client object is not emitted. Go has no async functions. |
| 16 | E5/E6: fire-and-forget async, missing await | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:1167`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.10` | Updated 2026-10-04 by `po-6c0v8.3`. The Python helper emits `fire_and_forget` and `missing_await`. A coroutine function is known only when the same module defines it. Since `po-6c0v8.16` the TypeScript helper emits `missing_await` for a floating promise, with the identities `promise` and `thenable` (`helpers/tsindex/tsindex.js`, `floatingCall`). |
| 17 | L5: alert with no runbook link | SHIPPED | `crates/rvl-config/src/prometheus.rs:318`, `crates/rvl-config/src/key_ledger.rs:154` | None needed | `prometheus-rules rule.annotations.runbook` on RC-006. Ships in the OSS tier. |
| 18a | Q29: action not pinned to a commit SHA | SHIPPED | `crates/rvl-config/src/github_actions.rs:315`, `crates/rvl-config/src/key_ledger.rs:125` | None needed | `github-actions step.uses.ref` and `github-actions job.uses.ref` on RC-042, pattern `sha40`. |
| 18b | Q21/Q22: no dependency scanning, no SAST in CI | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-structure/src/inventory.rs:61`, `crates/rvl-structure/src/lib.rs:176` | `po-6c0v8.12` | Updated 2026-10-08 by `po-6c0v8.7`. The G7 inventory emits `ci_scans` in the `repo_structure` record: the known dependency-scan and SAST actions and commands seen across all GitHub Actions workflows. `RepoStructure::scanner_seen` reads an absence only when the walk is complete, at least one workflow parsed, and no workflow file, external reusable workflow, or local composite action was left unread. No control judges the fact, so no verdict is emitted. Other CI systems are not read. A scanner that is not in the table is not seen. |
| 19a | O8: single replica | SHIPPED | `crates/rvl-config/src/kubernetes/manifest.rs:263`, `crates/rvl-config/src/key_ledger.rs:148` | None needed | `kubernetes workload.replicas` on RC-017, at least 2. `kubernetes hpa.min-replicas` has the same spec. |
| 19b | O8: PodDisruptionBudget values | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:228`, `crates/rvl-config/src/key_ledger.rs:143` | `po-av01j.44` | `kubernetes pdb.min-available` and `kubernetes pdb.max-unavailable` are emitted and have no spec. |
| 19c | O8: workload with no PDB, no anti-affinity | LANE-WIRED-NEEDS-CORPUS | `crates/rvl-config/src/kubernetes/manifest.rs:586`, `crates/rvl-config/src/key_ledger.rs:165` | `po-av01j.44` | Updated 2026-10-08 by `po-6c0v8.8`. `kubernetes workload.pdb-coverage`, `kubernetes pod.anti-affinity`, and `kubernetes pod.topology-spread-constraints` are emitted for a Deployment and a StatefulSet and have no spec. Coverage is a selector match in the rendered set: one kustomization, one chart render, or one directory of bare manifests. No coverage packet is emitted when the set has a part that was not read, or when a selector or a namespace is not decided in the repository. |
| 20 | N1: N+1 query in a loop | LANE-WIRED-NEEDS-CORPUS | `helpers/pyindex/pyindex.py:1094`, `crates/rvl-misuse/src/lib.rs:169` | `po-6c0v8.11` | Updated 2026-10-07 by `po-6c0v8.4`. The Python helper emits `loop_variable_query`: a query method on a relation of the loop variable, with the loop and the call in one function. The class has the name of that shape, not of the N+1 defect, and the cross-function defect is not reported. Go has no such form. The control is RC-073 (`po-av01j.105`). |

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

**Update, 2026-10-04 (`po-6c0v8.2`).** Wave 1 landed its retrieval and its
lane. Ranks 2, 6, 9, and 11 moved from GENUINELY-NEW to
LANE-WIRED-NEEDS-CORPUS: the Go and Python helpers emit the fact, and no spec
judges it. That leaves 7 ranks new in full (4, 5, 13, 14, 15, 16, 20). The
corpus entries, and the helpers that do not emit the packet, are
`po-6c0v8.9`. The count and the table below this point are the 2026-10-04
snapshot and were not recomputed.

**Update, 2026-10-04 (`po-6c0v8.3`).** Wave 2 landed its retrieval and its
lane. Rows 8b, 15, and 16 moved from GENUINELY-NEW to
LANE-WIRED-NEEDS-CORPUS: the Go and Python helpers emit the fact, and no spec
judges it. The corpus entries, and the helpers that do not emit the packet,
are `po-6c0v8.10`. With both waves, 5 ranks stay new in full (4, 5, 13, 14,
20). The count above and the table below this point are the 2026-10-04
snapshot and were not recomputed.

**Update, 2026-10-07 (`po-6c0v8.4`).** Wave 3 landed its retrieval in the
misuse lane. Ranks 4, 5, 13, 14, and 20 moved from GENUINELY-NEW to
LANE-WIRED-NEEDS-CORPUS: the Go and Python helpers emit the fact (rank 20 is
Python only), and no spec judges it. No rank stays new in full. The corpus
entries, the controls that are not arbitrated (ranks 4 and 13), and the
helpers that do not emit the packet are `po-6c0v8.11`. The count above and
the table below this point are the 2026-10-04 snapshot and were not
recomputed.

**Update, 2026-10-08 (`po-6c0v8.5`).** Row 10c moved from GENUINELY-NEW to
SHIPPED. The manifest carries the path of the liveness probe, and the scan
joins it to the handler in the same repository. Three retriever gaps stay
(12c, 18b, 19c).

**Update, 2026-10-08 (`po-6c0v8.17`).** The Java helper emits
`overbroad_catch` (row 8b). The status of the row does not change: no spec
judges the class.

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
| `po-6c0v8.2` | M6, D2, F2, F3 | Landed for Go and Python on 2026-10-04. What is left is in `po-6c0v8.9`. |
| `po-6c0v8.3` | H2, H3, G5/G6, E5/E6 | H1 is removed: it ships. Landed for Go (H3) and Python on 2026-10-04. What is left is in `po-6c0v8.10`. |
| `po-6c0v8.4` | B1/B2, N1, Q4, I1, J7 | None to scope. I1 does not report stdlib log calls, so it does not contradict the emission lane. Landed for Go and Python on 2026-10-07 (N1 for Python only). What is left is in `po-6c0v8.11`. |

Four classes had no bead. Each is now a child of the epic:

| Bead | Class | Row |
| --- | --- | --- |
| `po-6c0v8.5` | K3: liveness handler touches a dependency. Landed on 2026-10-08. | 10c |
| `po-6c0v8.6` | Q26: Dockerfile `USER`. Landed on 2026-10-08. The `runAsNonRoot` value and the fat base are in `po-6c0v8.20`. | 12c, 12d |
| `po-6c0v8.7` | Q21/Q22: no dependency scanning or SAST job | 18b |
| `po-6c0v8.8` | O8: workload with no PDB or anti-affinity | 19c |

**Update, 2026-10-08 (`po-6c0v8.8`).** Row 19c moved from GENUINELY-NEW to
LANE-WIRED-NEEDS-CORPUS. The Kubernetes retriever emits the three facts. The
specs are corpus work in `po-av01j.44`, as for rows 7b, 10b, and 19b. The
retriever gaps that are left are 10c, 12c, and 18b.

**Update, 2026-10-08 (`po-6c0v8.6`).** Row 12c is split. The Dockerfile
retriever emits the user of the final stage, so 12c moved from GENUINELY-NEW
to LANE-WIRED-NEEDS-CORPUS: the key is in the mint queue (`rvl cache keys`),
and the spec is corpus work in `po-6c0v8.19`. The new row 12d holds the part
that was not built: the value of `runAsNonRoot` in a manifest, and the fat
base image, which waits for a decision (`po-6c0v8.20`). The retriever gaps
that are left are 12d and 18b.

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
