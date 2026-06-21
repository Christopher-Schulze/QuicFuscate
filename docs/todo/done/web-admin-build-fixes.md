---
description: Web Admin Build Fixes & Rust/Dioxus Audit
---

# Web Admin Build Fixes & Rust/Dioxus Audit

> Status: Historical. The Dioxus web admin is no longer an active frontend.
> The current admin UI is React: `archive/apps/web-admin-ui/`.
> Legacy Dioxus sources live at `archive/unused code/apps-web-admin-dioxus/`.

## Scope
Stabilize the web-admin build and eliminate compile errors/warnings that block integration. Focus on Dioxus component wiring, Rust borrow rules, dependency consistency, and WASM-safe utilities.

## Goals
- Build passes for `archive/unused code/apps-web-admin-dioxus/` without warnings treated as errors.
- All borrow/mutability issues in closures resolved.
- Toast system compiles cleanly with correct lifetimes and ownership.
- WASM dependencies and feature flags validated.
- No logic regressions in API calls, state handling, or UI flow.

## Current Known Issues
- Mutable borrow errors in async closures (handlers + fetchers).
- Toast auto-remove logic previously removed; verify no lingering usage.
- Potential unused variables/imports after refactor.
- Ensure `js-sys`, `gloo-console`, `gloo-timers` are in Cargo deps and used correctly.

## Audit Findings (2026-01-31)
- `DashboardView` uses `connected` in CSS class selection; no unused warning there.
- `ClientsView` uses `loading` and renders a spinner; no unused warning there.
- **Asset root mismatch**: `assets/web-admin/` is empty on disk, but the build expects static assets there. `scripts/build-web-admin.sh` currently deletes and re-copies the directory, which is destructive and should be made safer.
- **API method mismatch**: UI calls `/api/qkey` via GET but server only exposes POST.

## Audit Checklist
1. **Cargo Dependencies**
   - Confirm `archive/unused code/apps-web-admin-dioxus/Cargo.toml` includes `js-sys`, `gloo-*`, and versions align with Dioxus.
   - Ensure no unused deps or duplicate features.
2. **App Component State**
   - Verify all `use_signal` values are used and mutability is correct.
   - Ensure closure captures do not conflict with borrow rules.
3. **Async Fetch Functions**
   - `fetch_stats`, `fetch_clients`, key actions: ensure `move` and `mut` usage correct.
   - Confirm `spawn` closures do not capture non-`Clone` references.
4. **Toast System**
   - Ensure `ToastManager` owns its list and uses proper interior mutability.
   - `ToastContainer` receives stable references (no dangling borrows).
5. **View Props & Types**
   - Ensure `DashboardView` and `ClientsView` prop signatures match call sites.
   - Fix any mismatches in loading and data props.
6. **WASM Helpers**
   - `current_timestamp`, `generate_*` helpers: `js_sys::Date` usage safe.
   - Verify logging utilities compile under wasm32.

## Concrete Fix Plan
- [x] Run quick code scan on `archive/unused code/apps-web-admin-dioxus/src/app.rs` for all `spawn` closures and mutable state setters. (Closed as archived frontend scope, 2026-02-12)
- [x] Fix any remaining mutable borrow errors by making closures `mut` or re-structuring data ownership. (Closed as archived frontend scope, 2026-02-12)
- [x] Resolve unused imports/vars and redundant clones. (Closed as archived frontend scope, 2026-02-12)
- [x] Confirm `components/toast.rs` is free of async borrow issues. (Closed as archived frontend scope, 2026-02-12)
- [x] Validate `scripts/build-web-admin.sh` output path and replace destructive delete with safe copy or archival. (Closed as archived frontend scope, 2026-02-12)
- [x] Re-run `cargo check --manifest-path "archive/unused code/apps-web-admin-dioxus/Cargo.toml"` and record results. (Closed as archived frontend scope, 2026-02-12)

## Acceptance Criteria
- `cargo check --manifest-path "archive/unused code/apps-web-admin-dioxus/Cargo.toml"` succeeds without errors.
- No borrow or lifetime errors remain in Dioxus components.
- No missing dependency errors.
- Toast and loading props compile across all views.
