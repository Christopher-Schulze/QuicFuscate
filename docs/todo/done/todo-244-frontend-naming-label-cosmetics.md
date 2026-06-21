# TODO-244: Frontend Naming and Label Cosmetics

## Severity: LOW

## Problem

Three naming/label issues found during audit:

### 1. QKey/qkey Naming Inconsistency
- **File names**: `EditQKeyDialog.svelte`, `ImportQKeyDialog.svelte` (PascalCase "QKey")
- **Variable/field names**: `qkey` in `TunnelConfig`, `normalizeQKey()` in tauri-bridge
- Convention unclear: is it "QKey" (proper noun) or "qkey" (lowercase identifier)?

### 2. parseU16 Name Misleading
`apps/svelte-admin/src/lib/config-helpers.ts:139-147`:
```typescript
function parseU16(raw: string): number | null {
  // ... validates range 1200-9000
}
```
Name suggests u16 (0-65535) but actually validates MTU-like range 1200-9000. Should be `parseMtu()` or `parsePortRange()`.

### 3. "Control" Label Ambiguous
`apps/svelte-admin/src/lib/components/panels/StealthPanel.svelte:94`:
```html
<div ...>Control</div>
```
This labels a congestion control algorithm selector. "Control" alone is too vague - should be "Congestion Control" or "CC Algorithm".

## Fix

1. Establish naming convention: "QKey" in UI-facing text, "qkey" in code identifiers (this is already the de facto pattern, document it)
2. Rename `parseU16` to `parseMtu` in config-helpers.ts and update callers
3. Change label from "Control" to "Congestion Control" in StealthPanel.svelte

## Affected Files

- `apps/svelte-admin/src/lib/config-helpers.ts` - rename parseU16
- `apps/svelte-admin/src/lib/components/panels/StealthPanel.svelte` - fix label

## Verification

- `bun run check` passes
- `bun run test:unit` passes
- Visual: label reads "Congestion Control"
