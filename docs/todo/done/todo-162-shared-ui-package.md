# TODO-162: Shared UI Component Package

## Status
**DOCUMENTED - part of UI Revamp (todo-190)**

## Severity
**MEDIUM**

## Context
UI components such as `Btn`, `TextInput`, `Toggle`, `Segmented`, and `PillToggle` exist in both frontend applications with duplicated implementations. No shared component package exists in the monorepo, forcing parallel maintenance of identical components.

- `archive/apps/web-admin-ui/src/components/ui/controls.tsx`: Contains Btn, TextInput, Toggle, Segmented, PillToggle
- `archive/apps/desktop/src/components/`: Contains equivalent component set

## Root Cause
No `packages/ui/` shared package was established when the second app was created. Components were copy-pasted rather than extracted into a shared library.

## Fix Plan
1. Create `packages/ui/` with proper package.json and TypeScript config
2. Audit both apps for overlapping components - identify exact duplicates vs app-specific variants
3. Extract common components into `packages/ui/src/`
4. Export all shared components from package entry point
5. Update `archive/apps/web-admin-ui/` imports to reference `@quicfuscate/ui` (or chosen package name)
6. Update `apps/tauri/` imports to reference shared package
7. Remove duplicated component files from both apps
8. Keep app-specific components (if any) in their respective apps
9. Verify both apps build and render correctly

## Acceptance Criteria
- Shared components imported from single `packages/ui/` package
- No duplicated component implementations across apps
- Both apps build successfully with shared imports
- Visual parity maintained for all shared components

## Dependencies
- TODO-161 (theme duplication) - shared components should use shared design tokens

## Affected Files
- `archive/apps/web-admin-ui/src/components/ui/controls.tsx`
- `archive/apps/desktop/src/components/` (various component files)
- `packages/ui/` (new)
