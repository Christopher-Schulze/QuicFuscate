---
id: TODO-1028
title: Freeze TODO-884 advanced-family winner from existing ARM evidence
severity: HIGH
phase: S
priority: P1
status: REFUSED
created: 2026-09-21
depends_on: [TODO-884, TODO-1044]
---

# TODO-1028: Freeze TODO-884 winner from existing ARM cells

## Why

TODO-885 `aead_preference="auto"` maps to `None` until a frozen family exists, so the shipped auto path never negotiates. TODO-884 already has ARM64 Criterion cells. The remaining work is a written freeze (or an honest refuse), not another benchmark campaign.

## Acceptance

- [x] One written decision: freeze `Aegis128L`, freeze `Morus1280_128`, or refuse to freeze
- [x] Decision cites only already captured artifacts (macOS primitive table in TODO-884, Omega 2026-09-19 data-AEAD table, Omega rustls full-path row)
- [x] Decision states that Omega rustls 63.3/80.5 MiB/s is a full 1-RTT packet path including header protection, while AEGIS/MORUS rows are data-AEAD primitives. Same-API speed verdict is therefore not proven
- [x] If frozen: not applicable. This task refuses.
- [x] If refused: `aead_preference="auto"` stays `None` and `packet_protection_mode="auto"` stays inert
- [x] No new Criterion run, no x86 claim, no IETF/QUIC-standard wording

## Sub-Tasks

- [x] Re-read the two ARM tables in `docs/todo/todo-884-aegis-morus-default-evidence.md`
- [x] Write the freeze/refuse record into TODO-884 and TODO-885
- [x] If frozen, map `DataAeadPreference::Auto` to that family in config/runtime. Not applicable: refused, `Auto` stays no family.
- [x] Leave x86 witness and side-channel on TODO-884 / TODO-681

## Notes

BLOCKED. Do not freeze from the 2026-08/09 ARM cells. Those runs are not same-API and must not pick a shipped family. TODO-1044 is the freeze. This file stays only so the old 884 gate has a pointer.

If TODO-1044 refuses a private family, this task records `refuse` and leaves `aead_preference="auto"` as `None`.

## Result (2026-09-21)

Refuse. The 2026-09-19 Omega table compares first-party data-AEAD primitives with a full rustls 1-RTT path (63.3/80.5 MiB/s). That is not a same-API verdict and does not freeze `Aegis128L` or `Morus1280_128`. `aead_preference="auto"` stays `None`. The later same-API opt-in is TODO-1044 and does not rewrite this refuse. No x86 claim. No QUIC-standard wording.
