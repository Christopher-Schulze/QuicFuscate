---
id: TODO-1042
title: Next-gen custom AEGIS MORUS design gated
severity: MEDIUM
phase: S
priority: P2
status: SKIP
created: 2026-09-21
depends_on: [TODO-1039, TODO-1040, TODO-1041]
---

# TODO-1042: Next-gen custom AEGIS/MORUS design

## Why

Current first-party AEGIS/MORUS lost the only fair primitive run we have. A rewrite is allowed only as a design that stays spec-byte-identical and attacks the waste from TODO-1039 plus the hooks from TODO-1041. It is not a new cipher.

## Gate (must pass before design work)

Start only if at least one is true:

1. TODO-1041 found a unique hook rustls/libaegis cannot express.
2. TODO-1039 found closable waste that could put C-* within 10 percent of S-AEGIS or R-LC on P1 1400 B.
3. S-AEGIS/S-MORUS is `UNAVAILABLE` and a private owner is still wanted as opt-in.

If none is true, this task records `SKIP` and TODO-1043 stays closed.

## Design rules

- Ciphertext, tag, and nonce construction stay CFRG AEGIS-128L or CAESAR MORUS-1280-128.
- Integration is API, batch, buffers, epoch, and CPU dispatch. Not a modified permutation.
- Prefer wrapping S-AEGIS and putting the unique hooks around it. A new state machine is last resort.
- X4/X8 remain backends, byte-identical to L.
- Header protection stays standard.
- 16-byte tag, 12-byte IV, 16-byte key.

## Acceptance

- [x] Gate result written: `SKIP`
- [x] If proceed: not applicable
- [x] Differential plan against S-AEGIS and official vectors: not applicable
- [x] No code in this task

## Sub-Tasks

- [x] Read 1038/1039/1040/1041 records
- [x] Choose wrap-libaegis vs rewrite-first-party: wrap, and that wrap is TODO-1044, not a new design
- [x] Write the design into this file: SKIP, no module map
- [x] Open TODO-1043 only on proceed: not opened

## Notes

Do not start until explicitly requested and the gate is green. A pretty custom kernel that loses to libaegis is a failed design.

## Result (2026-09-21)

SKIP. TODO-1041 found no unique hook. The closable waste in the first-party update was the per-round store/load. `aegis128l_update_neon` removes that on ARM and keeps the CFRG AESENC order. The upgraded C-AEGIS-L P1 1400 cell is 750 ns on macOS and 1360 ns on Omega, against S-AEGIS at 334 ns and 720 ns. A further permutation would still have to beat libaegis. That is not a product gap. The opt-in wrap is TODO-1044 `advanced-aead`. TODO-1043 stays closed.
