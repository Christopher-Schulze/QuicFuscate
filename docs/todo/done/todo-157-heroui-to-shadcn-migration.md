# TODO-157: Migrate Web Admin from HeroUI to Shadcn/ui

## Status
**DOCUMENTED - part of UI Revamp (todo-190)**

## Severity
**HIGH**

## Context
The web-admin app (`archive/apps/web-admin-ui/`) uses HeroUI (formerly NextUI) as its component library, requiring 1343 lines of CSS `!important` overrides in `archive/apps/web-admin-ui/src/index.css` to achieve the desired styling. This is a massive maintenance burden and a sign that the component library fights the project's design system rather than supporting it.

Meanwhile, the desktop app (`apps/tauri/`) already uses Shadcn/ui successfully with clean, override-free styling. Having two different component libraries across the monorepo also prevents component sharing.

- `archive/apps/web-admin-ui/src/index.css`: ~1343 lines of CSS with extensive `!important` overrides
- `archive/apps/web-admin-ui/src/components/ui/controls.tsx`: Custom wrapper components (Btn, TextInput, Toggle, etc.) built on top of HeroUI
- `apps/tauri/`: Already uses Shadcn/ui with Tailwind - clean, no overrides needed
- `archive/apps/web-admin-ui/src/App.tsx`: Uses HeroUI Provider pattern

## Root Cause
HeroUI was likely chosen early in development for its visual appeal and rapid prototyping. As the design system evolved, HeroUI's opinionated styling clashed with project requirements, leading to an ever-growing layer of CSS overrides. The desktop app was built later (or refactored) using Shadcn/ui, creating a split.

## Fix Plan
1. Inventory all HeroUI components currently used in web-admin:
   - Buttons, Inputs, Modals, Dropdowns, Tables, Cards, Tabs, etc.
   - Map each to its Shadcn/ui equivalent
2. Set up Shadcn/ui in the web-admin app:
   - Install dependencies (radix-ui primitives, class-variance-authority, clsx, tailwind-merge)
   - Configure `components.json` for Shadcn/ui
   - Copy/generate Shadcn/ui components via CLI
3. Migrate component by component:
   - Start with leaf components (Button, Input, Badge)
   - Progress to compound components (Dialog, Dropdown, Table)
   - Update imports across all views
4. Remove HeroUI dependencies from `package.json`
5. Delete all CSS `!important` overrides from `index.css` that were compensating for HeroUI
6. Align component API with desktop app where possible to enable future sharing (todo-160)
7. Run all E2E tests after migration
8. Visual regression testing: compare before/after screenshots

## Acceptance Criteria
- Zero CSS `!important` overrides needed for the component library
- HeroUI fully removed from `package.json` and `node_modules`
- All views render correctly with Shadcn/ui components
- Web-admin and desktop use the same component library (Shadcn/ui)
- All existing E2E tests pass
- `index.css` reduced from ~1343 lines to < 200 lines

## Dependencies
- todo-160 (frontend code duplication) - this migration enables shared components
- May be part of a larger UI Revamp initiative (todo-190 if it exists)
- All E2E and unit tests must be updated to match new component structure

## Affected Files
- `archive/apps/web-admin-ui/package.json` (swap HeroUI for Shadcn/ui deps)
- `archive/apps/web-admin-ui/src/index.css` (massive reduction)
- `archive/apps/web-admin-ui/src/components/ui/controls.tsx` (rewrite to Shadcn/ui)
- `archive/apps/web-admin-ui/src/App.tsx` (remove HeroUI Provider)
- `archive/apps/web-admin-ui/src/views/configuration.tsx` (update component imports)
- `archive/apps/web-admin-ui/src/views/dashboard.tsx` (update component imports)
- `archive/apps/web-admin-ui/src/components/login-modal.tsx` (update component imports)
- All E2E test files under `scripts/tests/frontend/web-admin/`
