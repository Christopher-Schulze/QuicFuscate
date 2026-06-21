# TODO-240: UI Component Divergence Desktop vs Admin

## Severity: HIGH

## Problem

`apps/svelte-desktop/` and `apps/svelte-admin/` have independent implementations of the same UI primitives with significant feature gaps:

### Switch.svelte
- **Desktop**: Minimal, inline box-shadow, `cn()` from local `$lib/format`
- **Admin**: Polished, state-dependent shadows, `cn()` from `@quicfuscate/ui`, different duration (200ms vs 260ms)

### Select.svelte
- **Desktop**: Minimal, no icons, basic dropdown
- **Admin**: ChevronDown icon, Check icon for selected item, maxHeight support, wrapper div

### TextInput.svelte
- **Desktop**: Barebones `<input>` wrapper, no label, no error state, no type variants, no autoFocus
- **Admin**: Full-featured: label wrapping, error state, aria-invalid, autoFocus with RAF, type support (password/email/etc.), ID slugification, disabled state

## Impact

- Users get inconsistent UX across desktop and admin apps
- Admin has better accessibility (labels, aria attributes, error states)
- Desktop is missing WCAG features
- Maintenance doubles: bug fixes must be applied in both places
- `packages/ui/` shared package exists but these primitives haven't been migrated to it

## Fix

1. Audit which implementation is more complete for each component (Admin wins for all 3)
2. Move the best implementation to `packages/ui/` as shared components
3. Make both apps import from `@quicfuscate/ui` instead of local implementations
4. Remove local copies from both `apps/svelte-desktop/src/lib/components/ui/` and `apps/svelte-admin/src/lib/components/ui/`
5. Ensure shared components accept all props needed by both apps

## Affected Files

- `packages/ui/` - add Switch, Select, TextInput
- `apps/svelte-desktop/src/lib/components/ui/Switch.svelte` (DELETE after migration)
- `apps/svelte-desktop/src/lib/components/ui/Select.svelte` (DELETE after migration)
- `apps/svelte-desktop/src/lib/components/ui/TextInput.svelte` (DELETE after migration)
- `apps/svelte-admin/src/lib/components/ui/Switch.svelte` (DELETE after migration)
- `apps/svelte-admin/src/lib/components/ui/Select.svelte` (DELETE after migration)
- `apps/svelte-admin/src/lib/components/ui/TextInput.svelte` (DELETE after migration)
- All views/panels that import these components - update import paths

## Verification

- `bun run check` passes in both apps
- `bun run test:unit` passes in both apps
- Visual: both apps render identically to current admin quality
- Accessibility: keyboard navigation, labels, error states work in both apps
