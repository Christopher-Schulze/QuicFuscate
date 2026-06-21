# TODO-239: Desktop Duplication Sweep - Magic Numbers, Styles, Utilities

## Severity: MEDIUM

## Problem

Multiple duplication and code quality issues in `apps/svelte-desktop/`:

### 1. Magic Number 88 in ~15 Places
`setTimeout(..., 88)` appears 15 times across dialog and button components as a ripple animation delay:
- `ImportQKeyDialog.svelte:128, 130`
- `TunnelConfigDialog.svelte:102, 152, 154`
- `EditQKeyDialog.svelte:126, 128`
- `AddTunnelDialog.svelte:146, 148`
- `TunnelList.svelte:181, 225, 263, 269, 275`
- `TunnelStats.svelte:158`

### 2. Inline Styles Instead of Tailwind
Despite Tailwind being installed, several components use `style=""` attributes:
- Dialog overlays (4x): `style="backdrop-filter: blur(6px)"`
- `Switch.svelte:41`: inline box-shadow
- `Select.svelte:47`: inline background + backdrop-filter
- `LogsView.svelte:105`: inline will-change/transform
- `ThroughputChart.svelte:361`: inline image-rendering

### 3. WHITE_PILL + PILL_BACKDROP Duplicated (2x)
Identical style constants in:
- `TunnelListItem.svelte:24-25`
- `TunnelStats.svelte:50-51`

### 4. normalizeMode() Duplicated (2x)
Identical function in:
- `TunnelList.svelte:85-88`
- `TunnelStats.svelte:53-56`

### 5. toErrorMessage() Duplicated (2x, slightly different)
Nearly identical function (only fallback string differs):
- `src/routes/+layout.svelte:36-44` - fallback: "Unknown desktop UI error"
- `src/lib/updater.ts:55-63` - fallback: "unknown updater error"

## Fix

1. Extract `RIPPLE_DELAY_MS = 88` (or `BUTTON_ANIMATION_DELAY`) to `$lib/constants.ts`
2. Convert inline styles to Tailwind utilities or CSS custom properties in `app.css`
3. Extract `WHITE_PILL` + `PILL_BACKDROP` to `$lib/styles.ts`
4. Extract `normalizeMode()` to `$lib/tunnel-validators.ts` (already exists)
5. Extract `toErrorMessage()` to `$lib/format.ts` with optional context parameter

## Affected Files

- All dialog components (4x)
- `TunnelList.svelte`, `TunnelListItem.svelte`, `TunnelStats.svelte`
- `Switch.svelte`, `Select.svelte`, `LogsView.svelte`
- `src/routes/+layout.svelte`, `src/lib/updater.ts`
- New: `$lib/constants.ts` or extend existing utils

## Verification

- `bun run check` passes
- `bun run test:unit` passes
- Visual: all animations, styles, error messages unchanged
