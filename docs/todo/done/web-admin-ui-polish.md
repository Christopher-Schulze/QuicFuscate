---
description: Web Admin UI Polish and Responsiveness Plan
---

# Web Admin UI Polish and Responsiveness Plan

## Scope
Improve visual consistency, layout clarity, and responsiveness without changing core information architecture. Ensure a clean, professional UX suitable for Linux server administration.

## UI Principles
- Clear information hierarchy and scanability.
- Consistent spacing and typography scale.
- Predictable button and control placement.
- Strong visual distinction for status and severity.

## Global UI Tasks
1. **Typography & Spacing**
   - Standardize heading sizes (`h2`, `h3`), body text, and monospace usage.
   - Normalize spacing tokens for panels, lists, and headers.
2. **Buttons & Controls**
   - Consistent primary/secondary/danger styling.
   - Disabled/loading states with clear affordance.
   - Align button sizes across views.
3. **Toast Placement**
   - Ensure toasts do not overlap critical UI.
   - Stacking behavior and max visible count.
4. **Status Indicators**
   - Unified colors and labels for online/offline, warn/error, demo mode.
5. **Empty/Loading States**
   - Consistent empty-state layout and messaging across views.
   - Skeletons for dashboard and key lists.

## View-Specific Polish
- **Dashboard**: group metrics with consistent cards, reduce visual noise.
- **Clients**: align columns, improve traffic readability, add loading empty state.
- **Keys/QKey**: highlight generated key, reduce clutter, add copy confirmation.
- **Config**: show unsaved state clearly, add warning on reload.
- **Logs**: consistent row spacing, sticky header, clear severity badges.

## Audit Findings (2026-01-31)
- React styling sources live in `archive/apps/web-admin-ui/src/index.css` plus per-view components under `archive/apps/web-admin-ui/src/views/`. Ensure configuration and QKey surfaces keep the same hierarchy as the dashboard.
- `assets/web-admin/` must be regenerated after UI changes; stale bundles can serve outdated assets if build is skipped.
- Remove or refactor any dead styling selectors that no longer correspond to rendered components.

## Responsiveness
- Breakpoints: 1280, 1024, 768, 480.
- Sidebar collapses to top bar on narrow widths.
- Tables switch to stacked rows on small screens.
- Maintain button usability on touch devices.

## Accessibility
- Color contrast >= WCAG AA for primary text.
- Focus ring visible on all interactive controls.
- Keyboard navigation for sidebar and actions.

## Acceptance Criteria
- UI looks consistent across views.
- Layout is usable on common admin resolutions.
- No text truncation or overlap on narrow screens.
