---
id: TODO-1089
title: Reconcile lake-rooster task and product documentation with code evidence
severity: MED
phase: M
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1080, TODO-1081, TODO-1082, TODO-1083, TODO-1085, TODO-1086, TODO-1087, TODO-1092, TODO-1093]
---

# TODO-1089: Session documentation truth reconciliation

## Why and evidence

Several current-state claims outpace code or proof. `docs/DOCUMENTATION.md`
still presents deleted first-party AES/AEGIS types as current near its crypto
overview and describes the Reality response as scanner-valid near its
fallback section. TODO-1048 is DONE with all five `## Sub-Tasks` boxes open
and with a test described as a live TLS listener though it is a fixed UDP
byte response. TODO-1047 is DONE while Safari is unverified and Firefox uses
source constants. TODO-1055 lacks the captured inner-flow acceptance proof.
TODO-1056's target promises CID rotation but its result says stable DCID.
TODO-1057's title and broad shape claim exceed `getsockopt` proof.
TODO-1064 says no DNS refresh is needed for ECH and labels attached bytes as
"enabled" even when a persona blocks the offer. TODO-1071's provisional
allocation/copy counts are printed constants, not measurements. Several
result sections are dated 2026-09-27 or 2026-10-14 although this review is
on 2026-09-23; their chronology must be traced to the actual commit/session
timestamps before they can serve as evidence. The server QKey cover-SNI
allowlist claims certificate capability it does not establish, while desktop
and standalone clients use different effective names (TODO-1092).
The tracker also keeps many `DONE` entries under `## Active`; verify whether
this is inherited chronology or a stale active-state claim before changing
the board, and make the active work owner unambiguous without discarding its
history. TODO-1095/1096/1097 are further follow-ups that current product
wording must not predeclare as complete.
`README.md` still advertises "Server Push Cover Traffic" in Highlights and
its architecture/feature text after TODO-1055 removed the synthetic push
sender, while the remaining receive path rejects push frames. The same
README describes interval-based profile cycling without clarifying the
TODO-1056 next-connection-only boundary. `config/quicfuscate.toml` still
states that direct UDP always runs first and that ECH is exclusive to the
shared fallback hop; this conflicts with TODO-1075/1096's selected-entry
binding when shared IP or ECH is a required privacy property. Reconcile these
statements only after the owning runtime tasks establish the actual path.
`AGENTS.md:427` still reports thirty-five backend leaf crates and omits the
new `qf-hpke` crate, while the current `crates/qf-*/Cargo.toml` inventory has
thirty-six. Its backend-crate path table at line 537 also omits `qf-hpke` and
the already existing `qf-stealth`; align both inventories with the actual
workspace membership, without changing unrelated agent policy.
The shared `packages/ui/AboutContent.svelte` still states `Custom QUIC v1
[RFC 9000]` in both desktop and web About views. Current Engine/CLI defaults
prefer v2 and support v1, so the product UI gives a false single-version
claim. Name the supported versions and selected-default policy only after
TODO-1075/1082 reconcile persona and reachability evidence.
`SECURITY.md` says AES-128-GCM protects "every stealth mode" and then says
`performance` uses libaegis for authenticated 1-RTT payload. It omits the
same `off` payload policy stated in the README. State the handshake/header
owner separately from the per-mode post-auth payload owner so this security
contract has no contradictory blanket phrase.
Both shipped TOML samples place `reality_cover_targets` under a heading that
says the following keys apply only to `manual`, but the runtime consumes the
cover list in other presets. Move that key's explanation to the common entry
or cover section when TODO-1075/1096 fixes its exact role; do not tell an
operator that a live cover policy is inert.
The same `AGENTS.md` architecture summary still describes outbound FEC as
original-plus-repair packets outside QUIC, an inbound FEC wrapper, XOR/domain
fronting and Server Push cover, and Brain-controlled padding/timing/CC shape.
The session moved stealth-mode repairs into QUIC, removed the standalone
fronting and synthetic push paths, and froze Brain's wire-shape controls.
Reconcile that agent-facing data-flow and module map against current code;
do not use the stale diagram as evidence of a live product path.
`docs/CONTRIBUTING.md` still twice calls the runtime TLS fingerprint a
"deterministic in-memory ClientHello synthesis" although TODO-1062 removed
the synthetic ClientHello and the same document says rustls owns it. Its
refresh procedure also says ECH-GREASE is unconditional, while the current
ECH path explicitly does not invent GREASE when no ECH configuration exists
and persona gates can suppress an ECH offer. Reconcile the developer guide
with the actual `qftls` behavior and TODO-1081/1082 proof levels. TODO-1058
also falsely states that the DoH TLS 1.2 suites retain rustls defaults;
TODO-1101 owns the runtime/version correction and this task owns the final
documentation wording.

## Target contract

- A present-tense product claim names only currently implemented, reachable
  behavior and its proof level: source, unit test, local integration, wire
  capture, or live end-to-end run. Historical decisions remain visible as
  dated history, not rewritten into a false current state.
- Every DONE task's acceptance and checked sub-tasks match recorded evidence.
  If a claim lacks proof, link the exact follow-up TODO and state the boundary
  without silently turning the old task's history into an imagined test.
- Dates are supported by Git/session timestamps. A future-dated result is
  corrected or explicitly identified as prewritten/planned text.
- One owner for each topic: `docs/DOCUMENTATION.md` for product behavior,
  `docs/MAP.md` for code/wiring, `docs/todo.md` and detail files for task
  history and open work. No parallel `tasks.md` source is introduced.

## Implementation and proof

- [ ] Audit present-tense crypto, Reality, ECH, persona, fallback, migration,
      H3, server push removal, profile cycling, QKey SNI, outer header and
      benchmark statements in the owning docs against
      current source and raw evidence, including README, SECURITY,
      CONTRIBUTING, the shared About UI, and the crate inventories in AGENTS.md as entrypoints to
      the canonical product documentation. Check AGENTS.md's outbound/inbound
      data-flow and module integration claims against the session removals.
- [ ] Reconcile TODO-1047/1048/1055/1056/1057/1063/1064/1071 checklists,
      status prose, dates and links to the exact follow-up IDs. Reconcile the
      `## Active` heading with actual open/active work while preserving the
      repository's existing task-history convention.
- [ ] Verify every resulting path, test name, code symbol, date and number;
      remove stale wording surgically rather than mass-rewriting history.
- [ ] Remove README's synthetic server-push claims, distinguish session-level
      persona choice from port migration, and make default/selected-entry/ECH
      wording agree with the implemented and measured TODO-1075/1096 policy.
- [ ] Run existing documentation/task consistency checks and inspect the
      final diff for unsupported claims or duplicated sources of truth.

## Acceptance

- Zero known false present-tense claims, future-dated result assertions,
  dangling task links, or DONE acceptance statements without an explicit
  proof boundary or linked open follow-up.
- Each corrected statement links to source or recorded test/capture evidence;
  `docs/DOCUMENTATION.md`, `docs/MAP.md`, tracker and details agree on what
  is implemented versus what is still unproven. Both AGENTS.md crate lists
  match the current Cargo workspace members, including `qf-hpke` and
  `qf-stealth`, with no stale numeric count or removed runtime in its
  architecture/data-flow summary.
- The shared About view names the actually supported QUIC versions and a
  verified default policy; it never presents v1 as the only product protocol.
- SECURITY names AES-GCM and AEGIS by packet level and by every supported
  stealth mode, including `off`, without contradictory blanket claims.
- Both shipped TOML samples locate and describe cover-origin policy according
  to its actual cross-preset runtime use, separate from manual-only flags.
