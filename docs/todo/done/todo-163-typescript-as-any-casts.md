# TODO-163: TypeScript `as any` Casts Removal

## Status
**PARTIAL** - Fixed `as any` casts in scoped files (web-admin-ui/src/, desktop/src/): event listeners use `EventListener`, error handling uses `instanceof Error`, CSS custom properties use `React.CSSProperties`, Tauri window detection uses `unknown as Record`, dialog child props properly typed, HeroUI classNames use `Record<string, string>`. Some remaining casts in HeroUI component props are structural to the library's type system and will be fully resolved by TODO-157 (HeroUI to Shadcn migration).

## Severity
**LOW**

## Context
Multiple `as any` type casts exist in the frontend codebase, bypassing TypeScript's type safety. Each instance represents a potential runtime type error that the compiler cannot catch.

- `archive/apps/desktop/src/App.tsx:156`: `(l.level as any) ?? "info"` - log level type not properly defined
- `archive/apps/web-admin-ui/src/App.tsx:81`: `onLock as any` - event handler type mismatch

## Root Cause
Missing or incomplete type definitions for external data (log entries, event handlers). Quick `as any` casts were used instead of proper type narrowing or interface definitions.

## Fix Plan
1. For `archive/apps/desktop/src/App.tsx:156`:
   - Define a proper `LogLevel` union type (`"info" | "warn" | "error" | "debug" | "trace"`)
   - Add type guard function `isLogLevel(value: unknown): value is LogLevel`
   - Replace `(l.level as any) ?? "info"` with type-safe narrowing
2. For `archive/apps/web-admin-ui/src/App.tsx:81`:
   - Identify the expected type signature for the `onLock` handler
   - Define proper event handler interface
   - Replace `onLock as any` with correctly typed callback
3. Search entire codebase for remaining `as any` patterns
4. Fix each instance with proper types, type guards, or generics

## Acceptance Criteria
- Zero `as any` casts in the entire frontend codebase
- All replacements use proper type annotations or type guards
- TypeScript strict mode passes without errors
- No new `@ts-ignore` or `@ts-expect-error` introduced as workarounds

## Dependencies
- None

## Affected Files
- `archive/apps/desktop/src/App.tsx`
- `archive/apps/web-admin-ui/src/App.tsx`
- Any other files found during codebase-wide search
