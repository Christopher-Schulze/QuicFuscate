# Release Task: API Type Safety Cleanup

## Scope
- Remove unsafe `any` parsing path in web admin API client and enforce typed error extraction.

## Current Finding
- Completed on 2026-02-12:
  - `archive/apps/web-admin-ui/src/api.ts` now parses JSON error payload as `unknown` with shape checks.
  - No `any` remains in the error parsing path.
  - Added unit coverage in `scripts/tests/frontend/web-admin/unit/api-error-parsing.test.ts`.

## Plan
1. Introduce a narrow interface for parsed error payload:
   - `message?: string`
   - `error?: string`
2. Parse as `unknown` and validate shape before access.
3. Keep fallback behavior for non-JSON payloads.
4. Add unit tests for:
   - JSON with `message`,
   - JSON with `error`,
   - invalid JSON,
   - plain text response.

## Acceptance Criteria
- No `any` remains in the parsing path.
- Behavior is unchanged for valid payloads and safer for malformed payloads.
- TypeScript check and tests pass.

## Deliverables
- Updated `archive/apps/web-admin-ui/src/api.ts`.
- API client tests for error parsing path.

## Verification
- `cd archive/apps/web-admin-ui && bun run test:unit`
- `cd archive/apps/web-admin-ui && bun run check`
