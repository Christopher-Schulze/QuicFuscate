---
id: TODO-1093
title: Validate and round-trip cover-target TOML in the admin UI
severity: LOW
phase: M
priority: P3
status: OPEN
created: 2026-09-23
depends_on: [TODO-1048]
---

# TODO-1093: Cover-target UI TOML roundtrip

## Why and evidence

`apps/svelte-admin/src/lib/config-helpers.ts::coverTargetsToTomlValue`
escapes backslash and quote but accepts control characters/newlines and
serializes them inside a single-line TOML string. The UI can therefore write
invalid TOML before backend validation. `readStealthCoverTargets` extracts
quoted substrings by regex rather than using the already imported TOML parser,
so escaped strings and malformed arrays can display a different list from
the saved config. Current tests cover simple host lists only.
`StealthPanel.svelte` renders the new Cover Targets control only inside
`stealthPreset === "manual"`, although `reality_cover_targets` is a cover-origin
value consumed outside that preset. Operators choosing `dynamic`,
`stealth` or `Stealth MAX` cannot inspect or edit the selected cover target
through this control. The UI should not imply that selecting a cover origin
requires changing the stealth policy to `manual`.

## Target contract

- Parse the existing `stealth.reality_cover_targets` array using the repo's
  TOML reader and require strings only. Display the exact parsed list;
  malformed arrays are a visible error, not a silently empty list.
- Validate each edited host/port under the server's accepted target grammar
  before writing. Serialize via the existing TOML-safe formatting path or a
  complete TOML basic-string escape routine, preserving parse/serialize
  roundtrip. Reject commas/newlines/control characters in host input rather
  than guessing whether they are separators or target bytes.
- Preserve the legacy `fronting_domains` read alias for valid configs and
  remove its authority only after the new list has been written and parsed
  successfully. Other TOML keys and comments remain unchanged.
- Surface the validated cover-origin target wherever it can affect the
  selected connection, independent of the manual shaping switches. Keep one
  value and save path for every preset; keep it distinct from the relay's
  authenticated entry endpoint defined by TODO-1075/1096.

## Implementation and proof

- [ ] Inspect `readSectionValue`, `setSectionValue`, the local TOML parser and
      server target validation before choosing the smallest shared path.
- [ ] Add validation and a parse-after-write check to the existing UI edit
      flow without a new component or dependency.
- [ ] Test escaped quote/backslash, newline/control characters, malformed
      arrays, duplicate/empty targets, legacy alias, IPv6 bracket/port
      syntax, and unchanged surrounding comments.
- [ ] Verify that each selectable stealth preset shows the same effective
      cover-origin target and edits it through the same validated TOML path;
      changing a preset must not silently hide or replace a configured target.

## Acceptance

- Every accepted UI edit reparses to exactly the displayed target list and
  passes server-side target validation; every rejected edit leaves the
  original config byte-identical and displays a concrete error.
- No invalid single-line TOML string is emitted by cover-target editing.
- Cover-origin target visibility and persistence do not depend on selecting
  `manual`; a preset switch preserves the parsed target list byte-for-byte
  unless the user explicitly changes it.
