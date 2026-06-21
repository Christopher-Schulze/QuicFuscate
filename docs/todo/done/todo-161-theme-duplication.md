# TODO-161: Theme/Tailwind Definition Duplication Across Apps

## Status
**DOCUMENTED - part of UI Revamp (todo-190)**

## Severity
**MEDIUM**

## Context
Theme and Tailwind CSS definitions are fully duplicated across both frontend applications. The `@theme` blocks in each app's `index.css` are identical, meaning any design token change must be applied in two places - a classic DRY violation and source of drift.

- `archive/apps/web-admin-ui/src/index.css`: Contains full `@theme` block with color tokens, spacing, radii, shadows, fonts
- `archive/apps/desktop/src/index.css`: Contains identical `@theme` block

## Root Cause
No shared design token package exists in the monorepo. Each app was developed independently with copy-pasted theme definitions.

## Fix Plan
1. Create `packages/design-tokens/` directory
2. Extract shared Tailwind theme configuration into `packages/design-tokens/tailwind.config.ts`
3. Export CSS custom properties / `@theme` block from `packages/design-tokens/theme.css`
4. Update `archive/apps/web-admin-ui/src/index.css` to import from shared package
5. Update `archive/apps/desktop/src/index.css` to import from shared package
6. Remove duplicated `@theme` blocks from both apps
7. Verify both apps render identically after change

## Acceptance Criteria
- Single source of truth for all theme tokens in `packages/design-tokens/`
- Changes to theme propagate to both apps automatically
- No duplicated `@theme` blocks in app-level CSS
- Both apps visually identical before and after migration

## Dependencies
- None

## Affected Files
- `archive/apps/web-admin-ui/src/index.css`
- `archive/apps/desktop/src/index.css`
- `packages/design-tokens/` (new)
