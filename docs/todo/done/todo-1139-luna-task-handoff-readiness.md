---
id: TODO-1139
title: Verify every actionable TODO has an executable plan
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-23
depends_on: []
---

# TODO-1139: Verify the actionable task corpus

## Why and evidence

The user will let a Luna session implement the remaining QuicFuscate tasks in
this same repository and will ask Codex to review that work afterward. Before
handoff, every actionable finding needs a source-grounded implementation plan,
an exact target state, explicit dependencies and blockers, and a testable
acceptance gate. The board currently has 100 detail files directly under
`docs/todo/`: 51 OPEN, 18 BLOCKED, 2 PARTIAL, 1 ACTIVE, 1 IN_PROGRESS,
1 STOPPED, and 26 SCRAP. The user excluded SCRAP from this handoff. The
STOPPED Devin path audit remains stopped by the user's earlier instruction.
Thus 73 current details are actionable or gate-blocked, subject to recount
when this task completes.

The repository ignores `/docs/todo/`; 19 actionable details were local and
untracked at the start of this review. They are part of the requested durable
task structure, so the planning commit must explicitly track them along with
this archived readiness record. Luna will use this same checkout. This task
does not reopen the stopped Devin session audit and cannot certify findings
from work that was never inspected.

## Target contract

- For every non-SCRAP, non-STOPPED detail directly under `docs/todo/`, verify
  the board link, frontmatter ID/status, current source paths and signatures,
  factual motivation, exact implementation owner, dependency order, preserved
  behavior, target state, measurable acceptance, relevant test/native proof,
  and a bounded next executable step. Repair stale or contradictory claims in
  the owning detail and board. An investigation task may use a decision gate
  with predeclared measurements when an implementation choice cannot honestly
  be fixed before evidence exists.
- Keep BLOCKED tasks blocked until their stated external/native/prerequisite
  gate is evidenced. Reconcile partial/in-progress tasks to their actual
  remaining work; do not reassign finished work. Preserve SCRAP decisions and
  the user's STOPPED audit disposition.
- A planning review is a readiness claim at one source revision, not a
  guarantee that a future implementation or unknown finding is perfect. Luna
  revalidates code and tests when starting each task; Codex reviews its commits
  and evidence before accepting the work.

## Implementation and proof

- [x] Recount the actionable corpus and check every board link, status,
      dependency, duplicate ID, ignored-local file, and archive location.
      Preserve the explicit SCRAP and STOPPED exclusions.
- [x] Review the active/partial/blocked legacy tasks against their current
      owners and evidence. For each, specify the exact remaining gate or
      justified no-change verdict; update its detail surgically.
- [x] Review each OPEN detail against current source and related tasks in
      dependency order. Add only missing concrete decisions, measurable
      outcomes, test gates, and source-backed boundaries. Resolve conflicting
      architecture statements at the owning task, not by duplicating plans.
- [x] Re-run structural/link consistency checks and read the full diff of
      changed task files. Confirm every actionable detail is reachable from
      `docs/todo.md`, no DONE detail remains in open `docs/todo/`, and every
      deferred/native gate is explicit. Record the exact reviewed revision.

## Acceptance

- All actionable details have source-verified, executable plans and exact
  acceptance or investigation gates at the recorded revision. Every exception
  is named; no generic readiness claim covers unreviewed source or the stopped
  Devin audit.
- Structural/link/status checks pass and task documents are synchronized in
  this same checkout. Handoff text is outside this task's completion gate.

## Current inventory (not yet acceptance)

- Reviewed base revision: `7dfba0fe`; task-document edits remain uncommitted
  and are not part of that source revision.
- 1,043 `### TODO-` board headings and 1,042 detail-link occurrences were
  observed after opening this task. TODO-1078 and TODO-1070 intentionally have
  no detail file; historical TODO-977 also lacks one. TODO-668 repeats a link,
  and TODO-270 points to two archived details. Do not infer missing files from
  raw heading and link counts.
- The 73 actionable/gate-blocked details have no missing dependency ID among
  the current detail corpus. This proves only graph references, not plan
  correctness or dependency readiness.
- The current structural validator checked 100 direct detail files and found
  zero status/link/frontmatter violations. That pass does not inspect source
  truth or adequacy of implementation plans.
- TODO-1137's missing H3 and nested-close prerequisites were identified and
  added to its detail. Its exit inventory remains a plan until focused wire
  proof closes the task.
- TODO-901's stale 1M pps/3x claim and send-only benchmark were removed from
  its remaining gate. The source already has GRO-aware Linux `recvmmsg` receive
  batching and `SO_REUSEPORT` shards; multicore RX performance is unproven.
- TODO-902's completed copy fix is archived, leaving TODO-927 as the only
  x86_64 io_uring performance decision. The tracked detail was renamed into
  `done/` and explicitly added despite the directory ignore rule.
- TODO-1072 wrongly planned to ingest TODO-913..TODO-964 as open work. Board
  status inspection shows the series is already done except TODO-927, so the
  cluster now starts from TODO-1071's fresh measurements and creates linked
  tasks only for remaining costs.
- TODO-1073/1074/1076 had broad acceptance without a fixed measurement
  matrix; they now specify repeated cost/effect or scenario evidence and
  separate task ownership for any newly discovered defect. TODO-1036's
  one-median provider switch criterion was tightened to paired native trials
  and a cross-platform default verdict.
- TODO-1081 required TODO-1107's protected pre-dial discovery while
  TODO-1107 waited for TODO-1096, which itself waited for TODO-1081. The
  execution contract is now entry architecture (TODO-1075), protected
  bootstrap (TODO-1107), ECH service selection (TODO-1081), and integrated
  runtime proof (TODO-1096).
- TODO-562's 1,392-line historical detail now has a current top-level gate:
  the workspace manifest lists the root plus 36 leaf crates, and no further
  six-crate extraction is authorized by the original plan. Its BLOCKED
  remainder is a fresh seam/workspace/feature/native/CI acceptance proof;
  TODO-1089 owns the stale AGENTS.md crate inventory.
- TODO-678's old pool file path was historical after extraction to
  `qf-memory-pool`. A current execution gate now names the real owner and
  limits its BLOCKED remainder to Miri/native evidence rather than replaying
  completed TODO-826..TODO-833 fixes.
- TODO-516 likewise carried an old zero-mlock/absent-munlock narrative at
  the top despite `qf-memory-lock` and `qf-memory-pool` owning those paths
  now. Its current BLOCKED gate is native post-extraction lock/unlock and
  server lifecycle proof, not fresh implementation of the original feature.
- TODO-681's seven custom crypto implementation files were retired. Its
  current OPEN gate now proves the active `qf_crypto`/`ring`/`aegis` owner and
  local contracts; TODO-884/885 retain provider-native security/performance
  proof. The old unsafe/ISA inventory is historical and must not block
  private AEAD work as if those files were still compiled.
- TODO-885 now states the shipped `standard` packet-protection default and
  opt-in `auto+aegis` path at its objective, configuration, and acceptance
  boundaries. Automatic default promotion still requires the separate
  TODO-883/884/681 gates and a recorded decision.
- TODO-680's remaining BLOCKED gate is exact native ISA/Linux/sanitizer/Miri
  proof of retained Optimize/SIMD paths; completed TODO-834/836/837/839/689
  fixes must not be replayed. TODO-548 now itemizes its missing connected-TUN,
  selected-DNS, crash/restart/uninstall, and hosted release proofs. TODO-624
  depends on TODO-548 and reuses its one privileged PF evidence run.
- TODO-883's former no-0-RTT/no-private assertions were stale: standard
  protection is the shipped default, Rustls 0-RTT is opt-in/default-off, and
  TODO-885 already has opt-in AEGIS activation. TODO-883 now depends on
  TODO-1095's long-header framing repair before any standards-wire closure.
  TODO-884's old equal AEGIS/MORUS contest is historical after MORUS removal;
  its current decision compares opt-in libaegis with rustls/ring using
  security and same-path end-to-end gates. It also depends on TODO-681.
- TODO-804's detail still described two dirty Omega checkouts as current,
  while the board records an authorized 2026-08-20 cleanup and one TESTING
  checkout. Its current gate now requires a fresh read-only proof-root
  preflight and exact-revision artifact/runtime attribution, not repetition
  of historical cleanup.
- TODO-730's implicit TODO-804 prerequisite loop was removed. TODO-730 now
  owns only fail-closed local audit-runner reporting; TODO-804 alone owns the
  remote proof checkout. TODO-749/755/756/759/754 separate historical evidence
  from current dependency, browser, Graphify, and coverage-register gates.
- TODO-886's 2026-08-23 two-hop MTU failure is historical. Current TLS payload
  advertisement, authenticated peer limit, send clamp, and focused regressions
  are present; the exact-revision privileged two-hop rerun remains blocked.
- TODO-607 and TODO-623 now state exact native lifecycle matrices and stop
  treating the old self-owner rejection and unavailable Omega SSH route as
  present-tense defects. TODO-607 explicitly retains unsupported macOS and
  Windows server-routing boundaries.
- Final pre-archive direct-detail inventory: 52 OPEN, 17 BLOCKED, 2 PARTIAL,
  1 ACTIVE, 1 IN_PROGRESS, 1 DONE, 1 STOPPED, 26 SCRAP. Archiving this detail
  leaves 72 non-SCRAP, non-STOPPED actionable or gate-blocked details.
- `bash docs/todo/audit-todo-consistency.sh --output-dir
  /tmp/quicfuscate-todo-audit-1139` scanned 100 direct details and reported
  zero violations. Independent board-block/link/dependency checks found zero
  mismatches, missing referenced IDs, or cycles. `git diff --check` and
  `git diff --cached --check` were clean. These are planning-structure gates,
  not product implementation or native runtime proof.
- Planning is ready in this checkout at product revision `7dfba0fe`. All
  non-excluded tasks name a target or evidence-based decision gate, their
  owning implementation path, and measurable acceptance; the implementing
  agent must re-read signatures and rerun proof against its changed revision.
  The stopped Devin audit and any unknown findings remain outside this claim.
