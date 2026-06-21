# TODO 51: Documentation Transparency and Feature Contract

## Scope
- Public-facing project docs and feature claims:
  - `README.md`
  - `docs/DOCUMENTATION.md`
  - Supporting docs where feature support is described

## Problem Statement (Audit Evidence, 2026-03-05)
- External trust feedback flagged missing transparency about development process.
- No explicit AI-assisted development disclosure was found in core docs.
  - Evidence: no meaningful hits for AI/LLM disclosure in README/docs scan.
- Feature-state wording has drift risk (notably fastpath/XDP semantics) between docs and runtime behavior.
  - Evidence: `README.md:30`, `:126`; `docs/DOCUMENTATION.md:747`; runtime contradictions in `src/main.rs:1000`, `src/optimize.rs:3563`

## Objectives
- Add explicit transparency statement on development/review process.
- Introduce a strict feature-state contract in docs.
- Prevent future docs/runtime drift for support claims.

## Work Breakdown
### A. Transparency Baseline
- [x] Add concise "Development and Review Transparency" section in README. [x] 2026-03-08
- [x] Describe code-review, test, and validation expectations for security-sensitive code. [x] 2026-03-08

### B. Feature Contract Matrix
- [x] Add feature-state matrix with statuses: [x] 2026-03-08
  - `active`
  - `experimental`
  - `compat-only`
  - `deprecated`
- [x] Include fastpath/XDP/zerocopy status with platform/feature conditions. [x] 2026-03-08

### C. Consistency Cleanup
- [x] Reconcile contradictory wording across README and `docs/DOCUMENTATION.md`. [x] 2026-03-08
- [x] Ensure env-variable docs match actual runtime behavior. [x] 2026-03-08

### D. Drift Prevention
- [x] Add review checklist item for feature-claim changes. [x] 2026-03-08
- [x] Add script/check that flags obvious docs/runtime mismatches for key features. [x] 2026-03-08

## Acceptance Criteria
- [x] README/docs include clear transparency and support-state wording. [x] 2026-03-08
- [x] Feature claims are aligned with current runtime behavior. [x] 2026-03-08
- [x] Drift checks prevent contradictory support statements from reappearing. [x] 2026-03-08

## Deliverables
- [x] Updated README and `docs/DOCUMENTATION.md` transparency/feature matrix sections. [x] 2026-03-08
- [x] Docs consistency checklist/check script. [x] 2026-03-08

## Progress Notes
- 2026-03-05: Created from forensic runtime audit.
- 2026-03-08: Added explicit development/review transparency wording in README, added a feature-state matrix plus drift-prevention section in `docs/DOCUMENTATION.md`, and tied the contract explicitly to `scripts/tests/audits/audit-runtime-guardrails.sh`.
