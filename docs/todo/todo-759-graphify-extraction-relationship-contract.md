---
id: TODO-759
title: Make Graphify extraction and relationship evidence complete or fail closed
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-08-01
depends_on: []
---

# TODO-759: Make Graphify Extraction and Relationship Evidence Complete or Fail Closed

## Current execution gate (2026-09-23)

The run-scoped August counts below are historical, not current graph coverage.
First rerun `scripts/audits/verify-graphify-evidence.sh` against the current
repository and inspect its manifest plus `verify-audit-completeness.sh` result.
If semantic extraction is unavailable, retain the typed `BLOCKED` result and
explicit uncovered file/edge counts; no credential, stale cache, or raw AST
placeholder is a substitute for resolved relationships. For a positive gate,
use an authorized supported semantic provider or complete valid cache,
correct parser/identity gaps without deleting unresolved evidence, and prove
current revision/scope hash, every in-scope file class, endpoint resolution,
and nonzero expected relationships. This task is OPEN for the local evidence
refresh; an unavailable semantic provider remains a typed non-pass result.
TODO-754 consumes the output but does not precede this producer. The task
concerns audit evidence only;
it does not authorize a product refactor or broader external data transfer.

## Why

The exhaustive audit used deterministic Graphify detection and extraction to cover tracked, ignored, generated, dependency, sensitive, document, code, and image surfaces. The resulting graph is not currently a whole-project relationship proof: semantic credentials are unavailable, AST coverage is frontend-only and structurally dangling, and existing generated reports describe an older client-only corpus without current provenance.

## Findings

### 0. Current run-scoped evidence (2026-08-04)

- **Manifest:** `scripts/out/audits/graphify-20260804T223115Z/graphify-evidence.json`; schema `quicfuscate.graphify-evidence.v1`; Graphify `0.8.47`; source revision `940e25227454a38a709f2c20d5dace778e2a517e`; source-scope SHA-256 `65ca892878360e1fc32cea2ad9243dd537f0fbbacd6d7826b03c47fba2924547`; extraction mode `deterministic-ast-sequential`.
- **Detection:** 725 files and 1,255,784 words: 672 code, 29 documents, 24 images, 0 paper, 0 video; 3 sensitive files accounted for as redacted. Git scope: 966 tracked, 49,536 ignored, 0 non-ignored untracked paths. The scope has 80 Graphify ignore patterns.
- **AST coverage:** 14,591 raw nodes and 39,348 raw edges; 12,981 normalized nodes and 39,348 normalized edges. All 332 Rust files and all 139 shell/PowerShell script files have nodes. Six detected files have no AST nodes: three JSON/config files and three fixture files. No unsupported extension was reported, so the six files are an explicit file-coverage gap rather than silently accepted parser support.
- **AST health:** Raw evidence contains 1,478 dangling edges, 2,104 duplicate node IDs, and 12,307 absolute source-file references. Normalization produces stable content-addressed IDs, repository-relative source paths, and 0 dangling edges, while retaining 37,533 resolved, 350 ambiguous, and 1,465 unresolved edge statuses as explicit endpoint evidence. No edge was deleted to obtain the normalized zero-dangling result.
- **Semantic availability:** 53 content files, 0 cached files, 53 uncached files, 0 cached nodes/edges/hyperedges, no partial subagent results, and no `GEMINI_API_KEY` or `GOOGLE_API_KEY`. Semantic status is `UNAVAILABLE` and is not treated as a pass.
- **Legacy output:** `graphify-out/graph.json` remains stale: built at `57965230c92f1b741a0e52312191f93001897978`, 537 nodes, 1,616 links, and missing `source_scope_sha256`, `extraction_mode`, `tool_version`, and `generated_at_utc`.
- **Overall result:** `BLOCKED` for unavailable semantics, raw identity defects, explicit ambiguous/unresolved endpoints, incomplete file coverage, and stale legacy provenance. The generated report is `scripts/out/audits/graphify-20260804T223115Z/GRAPH_REPORT.md`; the validator accepts the fail-closed `BLOCKED` result and rejects stale/missing evidence.

### Current post-push refresh (2026-08-05)

- **Manifest:** `scripts/out/audits/graphify-20260805T080752Z/graphify-evidence.json`; the validator executed against pushed revision `d619a2d8b45089ee4233dcd4302b0e1c6a9e0a96` and returned `GRAPHIFY_EVIDENCE_STATUS=BLOCKED`.
- **Detection:** 728 files and 1,263,324 words: 675 code, 29 documents, 24 images, and 3 sensitive files accounted for as redacted; 80 Graphify ignore patterns.
- **Blocking result:** semantic extraction is unavailable because neither `GEMINI_API_KEY` nor `GOOGLE_API_KEY` is present; the manifest therefore records no fresh AST/legacy provenance and does not promote the evidence to green. The completeness validator accepts this explicit fail-closed state.

### Current live refresh (2026-08-07, final pushed revision)

- **Manifest:** `scripts/out/audits/graphify-20260807T001858Z/graphify-evidence.json`; source revision `26eb6b27b616e4b834033f2a421335ab28ebd1d9`; Graphify `0.8.47`; extraction mode `deterministic-ast-sequential`; source-scope SHA-256 `0e9d5c4183c0b12358f60951554e20b3f8bf06059711cd94e041a39b0ca844cc`.
- **Detection and scope:** 750 detected files / 1,320,070 words, 697 code files, 29 documents, 24 images, and 3 sensitive files accounted for as redacted. Git scope is 991 tracked, 25,664 ignored, and 0 non-ignored untracked paths.
- **AST coverage:** 15,370 raw nodes / 42,508 raw edges and 13,699 normalized nodes / 42,508 normalized edges. All 334 Rust files and 146 script files have nodes. Raw evidence retains 1,486 dangling edges; normalized evidence retains 385 ambiguous and 1,462 unresolved endpoint edges. Six detected code/configuration files have no AST nodes and are listed in the manifest.
- **Semantic and legacy status:** semantic extraction is `UNAVAILABLE` for all 53 uncached content files because neither `GEMINI_API_KEY` nor `GOOGLE_API_KEY` is available. The legacy `graphify-out/graph.json` remains stale and lacks current provenance fields. Overall status is intentionally `BLOCKED`; `verify-graphify-evidence.sh` exits `2` by design and the completeness validator rejects stale or missing evidence rather than promoting it.

The numbered findings below are the historical baseline that motivated this task; the run-scoped evidence above is the current source of truth for counts and status.

### Historical 0. Current local artifacts remain stale and client-scoped (2026-08-04)

- `graphify-out/GRAPH_REPORT.md` is dated 2026-07-30 and identifies the corpus as `src/implementations/client`; `graphify-out/graph.json` carries `built_at_commit=57965230c92f1b741a0e52312191f93001897978`, 537 nodes, 1,616 links, and no corpus/provenance metadata beyond that commit field.
- A live `graphify query` succeeds against that graph, but its BFS returns only client/platform nodes. It did not establish whole-project relationship coverage for the then-current 956 tracked and 34,778 ignored paths; the current local scope is recorded below.
- The previously audited source revision was `a1b2498f594900844bb638b6dfc117a076c929a2`; the current local HEAD is `8dfdabd0dbc931aa03ecef97ce0405a1460e6584`. The graph therefore remains explicit stale evidence and is not promoted to a green audit result.
- Current local scope reconciliation on `2026-08-04` reports `956` tracked paths, `41,962` ignored paths, and `0` non-ignored untracked paths. The passing scope validator does not refresh Graphify relationships or provenance.

### Historical 1. Deterministic detection reaches the complete enumerated corpus

- **Evidence:** Full detection enumerated 660 files and 1,111,514 words: 618 code files, 18 documents, 24 images, and 3 sensitive files skipped by policy. The Git-scope validator separately accounts for 894 tracked files, 64,050 ignored paths before the new audit TODO files, and one allowed untracked audit helper.
- **Impact:** The input scope is broad, but detection alone does not prove semantic extraction or usable relationships.

### Historical 2. Semantic extraction is incomplete and unavailable is not a pass

- **Evidence:** The Graphify environment reports `gemini_unavailable` and no Anthropic key. The semantic cache contains 42 files with zero cached results at the start of this run. A limited set of documentation and image subagents completed, but no whole-corpus semantic result exists.
- **Impact:** Unsupported or unavailable semantic extraction must remain an explicit audit limitation rather than being represented as a complete graph.

### Historical 3. AST extraction loses relationship identity

- **Evidence:** The deterministic AST extraction produced 168 nodes and 240 edges from only 22 frontend source files. All 240 edges have missing source endpoint IDs, with zero valid candidate edges, 220 target-known edges, 45 edge source files, and zero edges in the post-build graph.
- **Impact:** The output cannot support repository-wide dependency, call, or ownership conclusions; a graph with no material edges is not relationship coverage.

### Historical 4. Existing Graphify output has stale and ambiguous provenance

- **Evidence:** Existing `graphify-out/GRAPH_REPORT.md` and `graphify-out/graph.json` describe an older client-only graph of approximately 537 nodes and 1,616 edges, while the current full detect and extraction run uses a different corpus. The generated output has no current corpus hash and is ignored local state.
- **Impact:** A later audit could mistake stale client-only output for current whole-project evidence unless provenance and scope are machine-visible.

## Acceptance

- The audit workflow either produces a whole-project graph with supported Rust, scripts, frontend, docs, images, ignored/generated, and sensitive-scope accounting, or fails closed with a machine-readable unsupported-surface manifest.
- Semantic extraction availability, cache state, skipped sensitive files, and partial subagent results are explicit non-pass states with counts and provenance.
- AST output contains stable source and target identifiers, non-dangling edges, parser coverage counts, and a report of unsupported languages or file classes; zero-edge output fails the relationship gate when relationships are expected.
- Every generated graph/report records corpus identity, extraction mode, tool version, timestamp, ignored/generated policy, and source-scope hash so stale output cannot be presented as current proof.
- The existing audit completeness validator classifies graph artifacts and verifies the provenance/unsupported-surface contract. No product or UI implementation is part of this task.

## Sub-Tasks

- [x] Record the full detection scope and extraction availability in a machine-readable audit manifest.
- [x] Repair or replace the AST source-identity and language-coverage contract, including explicit Rust and script handling.
- [x] Add graph provenance and stale-output detection for ignored Graphify artifacts.
- [x] Define fail-closed behavior for unavailable semantic credentials and unsupported file classes.
- [x] Re-run the whole-project graph audit and attach exact counts and limitations to TODO-754.
- [ ] Re-run at the current revision and resolve or explicitly retain the
      semantic availability, parser coverage, and ambiguous/unresolved edge
      gates with status-bearing artifacts; synchronize TODO-754's scope claim.

## Notes

- This task records an audit-tool/evidence gap only. It does not authorize changes to the product source, frontend, or UI.
- The semantic subagent outputs obtained during this audit are partial evidence and must not be promoted to a whole-repository semantic pass.

## Deviations

The Graphify library returns duplicate raw IDs, dangling raw endpoints, and partial parser coverage. The audit therefore adds a deterministic normalized representation and explicit endpoint placeholders, but preserves the raw evidence and returns `BLOCKED`; it does not fabricate a relationship pass. Semantic extraction is not invoked without the supported credentials and remains `UNAVAILABLE`.

## Resolution

- Added `scripts/audits/verify-graphify-evidence.py` and `scripts/audits/verify-graphify-evidence.sh` as the source-owned, run-scoped fail-closed evidence contract.
- Extended `scripts/tests/audits/verify-audit-completeness.sh` to validate Graphify schema, provenance, current revision, source-scope hash, normalized identity, semantic classification, artifacts, and stale legacy attribution.
- Updated `docs/DOCUMENTATION.md` and `docs/MAP.md` with the Graphify evidence wiring and exact current boundary.

## Reality Check

- Python compile, Bash syntax, staged diff checks, the full sequential Graphify evidence run, normalized AST recheck, and the audit completeness validator passed their respective contracts.
- `bash scripts/audits/verify-graphify-evidence.sh` exits `2` by design because the evidence status is `BLOCKED`; this is the expected fail-closed result, not a tooling failure.
- `bash scripts/tests/audits/verify-audit-completeness.sh` exits `0` and reports `graphify=BLOCKED`; it verifies the blocked result without promoting it to green.
- No Rust build or frontend/UI source change was required for this audit-only task. Disk check recorded 17 GiB available and no Rust `target/` directory.

## Open Gates

- Hosted semantic extraction with authorized Gemini/Google credentials, or a complete valid semantic cache, is still unavailable.
- Graphify parser/source identity must be improved before ambiguous/unresolved endpoint counts can reach zero and before all detected files have AST nodes.
- Native/Linux/Windows runtime relationship proof, Omega checkout attribution, and remote publication remain external boundaries and are not inferred from this local run.
