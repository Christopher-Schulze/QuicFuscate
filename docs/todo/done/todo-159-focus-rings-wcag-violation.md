# TODO-159: Fix Focus Ring WCAG Violation

## Status
**FIXED** - Global `*:focus-visible` and button/input focus suppression replaced with `outline: 2px solid var(--color-accent)` in both apps. HeroUI input wrapper sections retain `outline: none` because they use border-color change as custom focus indicator (WCAG-compliant). Remaining HeroUI-specific `outline: none` in data-slot rules are intentional custom indicators that will be removed entirely during Shadcn migration (todo-157/todo-190).

## Severity
**HIGH**

## Context
Both the web-admin and desktop apps globally disable focus rings using `:focus-visible { outline: none !important }` in their CSS. This is a WCAG AAA violation that makes the applications completely unusable for keyboard-only users. Focus indicators are a fundamental accessibility requirement - without them, keyboard users cannot see which element is currently focused.

- `archive/apps/web-admin-ui/src/index.css`: lines 547-574 contain `:focus-visible { outline: none !important }` and related focus-suppressing rules
- `archive/apps/desktop/src/index.css`: similar focus ring suppression rules
- Affects every interactive element: buttons, links, inputs, selects, checkboxes, tabs

## Root Cause
Focus rings were likely disabled to achieve a "cleaner" visual design, a common but harmful anti-pattern. The default browser focus rings (blue outline in Chrome, dotted border in Firefox) were considered visually unappealing, and rather than replacing them with custom focus indicators, they were removed entirely.

## Fix Plan
1. Remove all `:focus-visible { outline: none !important }` rules from both apps' CSS
2. Remove any `outline: 0`, `outline: none`, or `box-shadow: none` rules that suppress focus indicators on `:focus` or `:focus-visible`
3. Add custom focus ring styles that match the design system:
   ```css
   :focus-visible {
     outline: 2px solid var(--accent-500, #6366f1);
     outline-offset: 2px;
   }
   ```
   Or using Tailwind:
   ```css
   .focus-ring {
     @apply focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-500;
   }
   ```
4. For components with rounded corners, use `ring` utilities instead of `outline`:
   ```css
   :focus-visible {
     @apply ring-2 ring-accent-500 ring-offset-2 ring-offset-background;
   }
   ```
5. Test keyboard navigation through all interactive elements:
   - Tab through the entire page
   - Verify focus is visible on every button, link, input, select
   - Verify focus indicator has sufficient contrast ratio (3:1 minimum per WCAG 2.1)
6. Run accessibility audit tools (axe, Lighthouse) to confirm no remaining violations

## Acceptance Criteria
- All interactive elements have visible focus indicators when navigated via keyboard
- `:focus-visible` focus rings have at least 3:1 contrast ratio against surrounding colors
- No `outline: none !important` or focus-suppressing CSS anywhere in codebase
- Keyboard-only navigation through all pages is fully functional
- Lighthouse accessibility score >= 95
- WCAG 2.1 AA compliance for focus indicators (AAA preferred)

## Dependencies
- Design system color tokens for focus ring color
- Should coordinate with todo-157 (HeroUI to Shadcn migration) - Shadcn/ui has built-in focus ring support

## Affected Files
- `archive/apps/web-admin-ui/src/index.css`: lines 547-574 (remove focus suppression, add custom focus rings)
- `archive/apps/desktop/src/index.css` (remove focus suppression, add custom focus rings)
- `archive/apps/web-admin-ui/src/components/ui/controls.tsx` (verify components don't suppress focus)
- `archive/apps/desktop/src/components/` (verify components don't suppress focus)
