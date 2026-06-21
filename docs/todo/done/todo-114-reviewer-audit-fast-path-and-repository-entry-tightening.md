# TODO 114: Reviewer Audit Fast-Path and Repository Entry Tightening

## Scope
- audit entry path
- reviewer fast path
- security review entry path
- repository truth ordering

## Problem Statement
- The repo now contains the right truth.
- The remaining reviewer cost is path length:
  - a skeptical reader still has to discover the right order to read things in.

## Desired End State
- A reviewer can start in one place and immediately find:
  - runtime truth
  - retained custom crypto truth
  - security review boundaries
  - strongest proof surfaces
  - transport overlap/divergence truth

## Current Truth Snapshot
- README and canonical docs already contain most of the necessary material.

## Architecture Gap
- What is missing is an explicit shortest-path review flow.

## Execution Plan

### Phase 1: Review Entry Flow
- Define the shortest ordered reviewer path through the repo.

### Phase 2: README and Canonical Doc Sync
- Ensure both surfaces provide the same minimal audit entry path.

### Phase 3: Evidence Cross-Linking
- Point directly to the strongest proof suites and audit scripts.

## Acceptance Criteria
- [x] A skeptical reviewer has a short, explicit entry path.
- [x] Review map and evidence map are easy to follow.

## Validation Matrix
- docs review
- guardrail updates if needed
