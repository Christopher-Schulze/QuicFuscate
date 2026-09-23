---
id: TODO-1067
title: Rewrite present-tense claims about deleted crypto
severity: MEDIUM
phase: S
priority: P2
status: DONE
created: 2026-09-22
depends_on: [TODO-1049]
---

# TODO-1067: Rewrite present-tense claims about deleted crypto

## Why

`bbc93fe2` removed first-party AES-GCM, ChaCha, Poly1305, GHASH controls, and the `subtle` dependency. Several status lines still describe that world as current. A later audit or agent will "fix" code to match the lie, or treat a closed bug as open.

Historical close-counts stay. "qf-crypto 104/104 at close" on TODO-1045 is the count when 1045 closed, before 1049 deleted oracle tests. Do not rewrite that to 59. Present tense is the bug.

## Hits that are in scope

Each line is a required edit or a required "historical" label. Do not stop after the first one.

1. `docs/todo.md` TODO-1035 bullet. It says the QKey test fixture still uses first-party ChaCha. After 1049 the fixture seals with `RingChaCha20Poly1305`. Rewrite the bullet. Leave the DONE fact (TLS-Cover and registry use ring).
2. `docs/todo.md` TODO-626 bullet, about line 3681. Present tense: the helper delegates to `subtle::ConstantTimeEq`, 13 production call sites, 141-test qf-crypto matrix. `subtle` is gone and the crate test count is 59. Mark the sentence as the historical close of TODO-626, or move the live claim to "tag comparison is inside ring and libaegis; the `subtle` crate dependency is gone (TODO-1049)".
3. `docs/DOCUMENTATION.md` section "Implementation Reconciliation (2026-08-03, GHASH dispatch configuration)". The superseded paragraph is right. The following "Regression proof" paragraph still says GCM passed 11/11 with `QUICFUSCATE_GHASH_PMULL=0` and `=1` as if that run is current proof. Label that paragraph as the 2026-08-03 run, and point current proof at the TODO-1049 result (qf-crypto 59/59, no GHASH override).
4. `docs/MAP.md` "Deep Audit Update (2026-08-01)", the crypto data-plane bullet that says TODO-626 routes all 13 tag checks through `subtle::ConstantTimeEq` and that GHASH/PMULL controls are release surfaces. The section banner says historical snapshots must not be read as status. The bullet itself has no date on the sentence. Add an explicit "as of 2026-08-01; superseded by TODO-1049" on that sentence so a grep for `subtle::ConstantTimeEq` cannot be mistaken for the owner.
5. `docs/todo/done/todo-1049-delete-dead-first-party-aead.md` section "Current code". It still lists `aes.rs`, `gcm.rs`, `chacha.rs`, `poly1305.rs`, and the first-party QKey sealer as present. The Result section says they are gone. Rewrite "Current code" into past tense, or move it under a "Plan at open" heading and leave Result as the status. A reader must not see both as true.
6. `docs/DOCUMENTATION.md` "Implementation Reconciliation (2026-08-03, crypto key and IV constructor boundaries)" names `ChaCha20Poly1305` and `AesHp::new` as the live constructors. Same rule: stamp the date on the claims or add one superseded line. Do not delete the historical evidence.

Search after the edits and classify every remaining hit. Required patterns:

- `subtle::ConstantTimeEq`
- `QUICFUSCATE_GHASH`
- `first-party ChaCha`
- `struct AesGcm128`
- `AesHp::new`
- `141-test` and `141 qf-crypto`

A hit in `docs/todo/done/`, in a sentence that names its own date, or inside TODO-1049's absence check (the audit script must still mention the deleted names) is allowed. A hit in `docs/todo.md` queue/status lines, or in DOCUMENTATION/MAP without a date or "superseded", is not allowed.

## Non-goals

- Do not rewrite `scripts/tests/audits/audit-runtime-guardrails.sh` negative patterns. Those names must stay so the absence check keeps failing if the code returns. That is TODO-1068's neighbor, not a doc deletion.
- Do not change cipher behavior.
- No frontend change. `packages/ui/AboutContent.svelte` already says `AES-128-GCM | AEGIS-128L`. Leave it.

## Design

One pass, one checklist in this file's Notes: path, line, action (rewrite or stamped historical). Then the edits. Then the grep again, pasted into Notes.

## Sub-Tasks

- [x] Fix the six numbered hits.
- [x] Re-run the pattern list. Record leftovers and why each is allowed.
- [x] TODO-1035, TODO-626, TODO-1049 detail, DOCUMENTATION, and MAP agree that ring and libaegis are the AEAD owners and that `subtle` and GHASH overrides are gone.

## Notes

Leftovers after the edit, all allowed:

- `docs/MAP.md` and `docs/DOCUMENTATION.md` still contain `subtle::ConstantTimeEq` and `QUICFUSCATE_GHASH` inside sentences dated 2026-08-01 or 2026-08-03, or marked superseded by TODO-1049.
- `AesHp::new` remains only under the 2026-08-03 historical snapshot banner.
- `docs/todo.md` TODO-1035 title still says "first-party ChaCha20-Poly1305" as the historical task name. The status bullet no longer claims the fixture uses it.
- `docs/todo.md` TODO-1066 records that the golden was sealed by first-party ChaCha at `a87b9584`. That is a past fact.
- Audit-script negative patterns were not edited.

## Result

The six required hits are stamped or rewritten. Historical close counts, including TODO-1045's 104/104, were left alone.

## Acceptance

- The TODO-1035 status line does not say the fixture uses first-party ChaCha.
- TODO-626's bullet is explicitly historical or describes ring/libaegis.
- The GHASH "Regression proof" paragraph cannot be read as a current `QUICFUSCATE_GHASH_PMULL` run.
- TODO-1049 "Current code" does not say the deleted files exist now.
- The pattern grep has no unmarked present-tense hit in the living status sections.

## Risks

- Stamping every historical paragraph in DOCUMENTATION would be a rewrite of the audit log. Only the sentences a grep hits, plus the six numbered items. Do not reflow unrelated 2026-08 evidence.
