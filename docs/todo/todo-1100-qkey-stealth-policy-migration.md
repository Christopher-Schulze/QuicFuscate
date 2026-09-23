---
id: TODO-1100
title: Migrate legacy QKey stealth values without silent policy changes
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1075, TODO-1092]
---

# TODO-1100: QKey stealth-policy migration and strict validation

## Why and evidence

Devin changed newly issued QKey values from `auto`/`max` to `dynamic`/
`Stealth MAX` in `apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte`
and `src/implementations/server/qkey_issue.rs`. Existing QKeys remain
parseable: `qf_engine_types::QKeyConfig` stores `stealth` as an optional
string, and `src/engine/qkey.rs` still tests arbitrary `full`. Both
`src/implementations/client/backend.rs::connect_with_qkey` and desktop
`apps/tauri/src-tauri/src/main.rs::build_client_engine_config_with_circuit`
map every unknown value to `StealthMode::Dynamic`. Server
`src/implementations/server/live_auth.rs::apply_qkey_policy_overrides`
instead ignores unknown values, leaving its current mode unchanged. A
historically issued `max` or `anti-dpi` QKey can therefore silently lose
its intended stealth level on the client, while client/server policy may
disagree. Case or spelling errors are likewise hidden.

## Target contract

- Define one small, typed parser for QKey stealth values at the shared
  engine-types boundary. Canonical serialization uses only `off`,
  `performance`, `stealth`, `Stealth MAX`, `manual`, `dynamic`. Explicitly
  recognize only legacy values demonstrated by prior issuance/tests (at
  least `auto` to `dynamic`, `max`/`anti-dpi` to `Stealth MAX`; inspect
  historical issuance for other actually used forms). The deprecated `full`
  test string is evidence of arbitrary codec acceptance, not permission to
  invent a product mapping.
- The parser returns a typed mode or a named error. Desktop, standalone
  client, server registry load/policy application, and issuance all use the
  same result. No `unknown => dynamic` or `unknown => keep current` branch
  remains at these boundaries. No unvalidated QKey mode reaches a dial or
  silently overrides a server policy.
- For a recognized historical alias, both peers choose the same canonical
  effective mode, and a later export emits only the canonical spelling.
  Unknown or malformed values fail with actionable migration guidance;
  keep the original QKey bytes intact. Existing checksum/token semantics
  are unchanged.
- Admin and desktop displays show the effective canonical mode and expose
  invalid legacy values as errors, not as a plausible default. Do not add
  a second mode enum or a parallel policy implementation.

## Implementation and proof

- [ ] Inventory historical QKey issuance strings from the changed commit
      range and persisted-registry fixtures; check `QKeyConfig` encode/decode,
      desktop import, standalone connect, server registry restore, live
      override, and UI formatting call chains.
- [ ] Add the canonical parser in the existing shared type owner and route
      all policy consumers through it. Keep alias support minimal and
      versioned or explicitly documented for compatibility.
- [ ] Add real QKey generate/parse/consume fixtures for every confirmed
      legacy spelling, each canonical spelling, case errors, arbitrary
      unknown values, and registry-restored records. Test same effective
      mode on both clients and server; prove malformed values fail before
      connecting and no prior token/checksum behavior changes.
- [ ] Update the owning QKey usage and migration documentation and remove
      obsolete UI fallbacks and tests that assert a silent `dynamic` choice.

## Acceptance

- 100% of accepted QKey stealth values resolve identically across desktop,
  standalone and server; historical issued values retain their intended
  behavior. Every other value fails visibly before connection/policy use.
- One parser owns the compatibility table and canonical output; no consumer
  silently defaults an invalid explicit value.
