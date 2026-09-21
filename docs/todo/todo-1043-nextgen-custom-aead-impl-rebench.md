---
id: TODO-1043
title: Next-gen custom AEAD implementation and re-bench
severity: MEDIUM
phase: S
priority: P2
status: SKIP
created: 2026-09-21
depends_on: [TODO-1042]
---

# TODO-1043: Next-gen custom impl and re-bench

## Why

If TODO-1042 proceeds, the design must be implemented and run through the same 1038 matrix as N-AEGIS / N-MORUS. Old first-party stays as C-* until N-* wins or this task is abandoned.

## Acceptance

- [ ] TODO-1042 is `proceed`, not `SKIP`
- [x] N-* was not implemented. TODO-1042 is SKIP, so these gates are closed rather than failed.
- [x] No 1038 cells for N-*. Status SKIP.
- [x] No N-* comparison row. S-AEGIS vs C-* vs R-RING vs R-LC is in TODO-1044.
- [x] No new 1041 hook tests. The contract says there is no unique hook.
- [x] No new FEC fixture. The plan is in TODO-1041.
- [x] N-* is not promoted.
- [x] Default binary stays rustls AES-GCM. `advanced-aead` is opt-in and is not N-*.
- [x] No ship-default change

## Sub-Tasks

- [x] Implement only the 1042 module map: not applicable, 1042 is SKIP
- [x] Reuse the 1038 harness: not applicable
- [x] Keep C-* until N-* wins, then archive C-* in `archive/` only if 1044 says so. C-* stays. 1044 did not archive it.
- [x] Feed numbers to TODO-1044: no N-* numbers. The S-AEGIS numbers are the 1038 table.

## Notes

Do not start if 1042 is `SKIP`. Disk check before builds. `cargo clean` if needed.

## Result (2026-09-21)

SKIP. TODO-1042 did not proceed. No N-AEGIS or N-MORUS row. No feature, no re-bench, no archive of C-*. C-* stays the default-build private fallback and the bakeoff oracle. The chosen opt-in owner is S-AEGIS under TODO-1044.
