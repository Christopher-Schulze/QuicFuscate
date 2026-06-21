# TODO-167: Admin Interface Unix/HTTP Handler Redundancy

## Status
**DONE** (documentation phase; handler extraction deferred)

## Severity
**LOW**

## Context
Two parallel admin interface implementations exist with no shared handler logic despite providing similar functionality:

- `src/implementations/server/admin.rs` (570 LOC): Unix domain socket admin interface
- `src/implementations/server/admin_http.rs` (3012 LOC): HTTP-based admin interface

Both implement similar admin operations (status queries, configuration management, client management) but with completely independent handler implementations. This means bug fixes or feature additions must be applied in two places.

## Root Cause
The HTTP admin interface was likely added after the Unix socket interface as an alternative transport, but handlers were reimplemented rather than extracted into a shared layer.

## Fix Plan
1. Audit both files to identify overlapping operations and shared logic
2. Extract shared handler logic into `src/implementations/server/admin_handlers.rs` (or similar)
3. Define handler trait/functions that operate on abstract request/response types
4. Refactor `admin.rs` to become a thin Unix socket transport adapter calling shared handlers
5. Refactor `admin_http.rs` to become a thin HTTP transport adapter calling shared handlers
6. Verify all admin operations work identically on both transports
7. Run existing admin-related tests

## Acceptance Criteria
- Common admin operations share a single implementation
- `admin.rs` and `admin_http.rs` are thin transport adapters only
- No duplicated business logic between the two files
- All admin operations functional on both transports
- Tests pass for both admin interfaces

## Dependencies
- None

## Affected Files
- `src/implementations/server/admin.rs`
- `src/implementations/server/admin_http.rs`
- `src/implementations/server/admin_handlers.rs` (new - shared handler layer)
- `src/implementations/server/mod.rs` (module registration)
