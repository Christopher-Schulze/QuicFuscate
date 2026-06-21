---
id: TODO-362
title: "Audit 8 #[allow(dead_code)] markers in fec/internal.rs"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DEFERRED
created: 2026-03-27
backfilled: 2026-07-23
defer_reason: "Dead-code — cargo dead / cargo udeps covers this"
---

# TODO-362: Audit 8 #[allow(dead_code)] markers in fec/internal.rs


## Problem
`src/fec/internal.rs` has 8 separate `#[allow(dead_code)]` markers at lines:
24, 254, 415, 469, 661, 818, 910, 1037.

These suppress warnings for functions/structs that are defined but never called.
This includes `AdaptiveEncoder::new()` and multiple internal helpers. Either:
- The code IS used via the public fec/mod.rs surface (remove allow markers)
- The code is truly dead and should be deleted
- The code is planned-but-unfinished (document and keep)

## Fix Plan
1. For each #[allow(dead_code)] marker, identify the annotated item
2. Grep the entire codebase for callers
3. If called: remove the allow marker (it is not dead code)
4. If not called: determine if it is planned/useful or truly dead
5. Delete truly dead code, keep planned code with TODO annotation

## Files to Modify
- src/fec/internal.rs
- Potentially src/fec/mod.rs if dead code references are removed