# TODO-160: Eliminate Frontend Code Duplication via Shared Package

## Status
**DOCUMENTED - part of UI Revamp (todo-190)**. Shared items identified: cn() utility, format utils (formatBytes, formatDuration, formatTimestamp), theme tokens, component primitives (Btn, TextInput, Toggle, Segmented, PillToggle), API types.

## Severity
**HIGH**

## Context
Approximately 25% of code is duplicated between the web-admin (`archive/apps/web-admin-ui/`) and desktop (`apps/tauri/`) applications. This duplication creates maintenance burden, increases risk of divergent behavior, and makes feature development slower because changes must be applied in two places.

Specific duplications identified:
- `cn()` utility function: identical implementation in both apps for class name merging
- Theme definitions: identical ~1343-line CSS theme blocks in both `index.css` files
- UI components: `Btn`, `TextInput`, `Toggle`, `Segmented`, `PillToggle` components duplicated with minor variations
- Format utilities: `formatBytes()`, `formatDuration()`, `formatTimestamp()` and similar functions implemented independently in both apps
- Type definitions: shared types for tunnel configuration, server status, etc. defined in both apps

## Root Cause
The web-admin and desktop apps were developed as independent projects without a shared package layer. As features were added, common utilities and components were copy-pasted rather than extracted into a shared dependency. The monorepo structure supports sharing but was never leveraged for frontend code.

## Fix Plan
1. Create a shared package: `packages/shared/` (or `packages/ui-shared/`)
   ```
   packages/shared/
     src/
       utils/
         cn.ts          # class name merging
         format.ts      # formatBytes, formatDuration, etc.
       types/
         tunnel.ts      # shared tunnel types
         server.ts      # shared server status types
       components/      # shared UI components (after todo-157 alignment)
     package.json
     tsconfig.json
   ```
2. Extract shared utilities first (lowest risk):
   - `cn()` utility
   - `formatBytes()`, `formatDuration()`, `formatTimestamp()`
   - Any other pure utility functions duplicated in both apps
3. Extract shared types:
   - Tunnel configuration types
   - Server status/metrics types
   - API response types
4. Configure monorepo workspace references:
   - Add `packages/shared` to workspace in root `package.json`
   - Add dependency in both apps: `"@quicfuscate/shared": "workspace:*"`
5. Update imports in both apps to use the shared package
6. Remove duplicated code from both apps
7. After todo-157 (HeroUI to Shadcn migration), extract shared UI components:
   - `Btn`, `TextInput`, `Toggle`, `Segmented`, `PillToggle`
   - Only after both apps use the same component library
8. Unify theme/CSS definitions into shared Tailwind config

## Acceptance Criteria
- No duplicate utility functions across apps (cn, formatBytes, formatDuration, etc.)
- No duplicate type definitions across apps
- Shared package exists at `packages/shared/` with proper TypeScript config
- Both apps import from `@quicfuscate/shared` instead of local copies
- All unit tests pass in both apps
- All E2E tests pass in both apps
- Build pipeline handles the shared package correctly

## Dependencies
- todo-157 (HeroUI to Shadcn migration) - must be completed before shared UI components can be extracted
- Monorepo tooling (Turborepo) must support the new package

## Affected Files
- `packages/shared/` (new package directory)
- `packages/shared/package.json` (new)
- `packages/shared/tsconfig.json` (new)
- `packages/shared/src/utils/cn.ts` (extracted from both apps)
- `packages/shared/src/utils/format.ts` (extracted from both apps)
- `packages/shared/src/types/` (extracted from both apps)
- `archive/apps/web-admin-ui/package.json` (add shared dependency)
- `apps/tauri/package.json` (add shared dependency)
- `archive/apps/web-admin-ui/src/` (update imports throughout)
- `archive/apps/desktop/src/` (update imports throughout)
- Root `package.json` or `pnpm-workspace.yaml` (add packages/shared to workspace)
