# Release Tray UX Plan

## Goal
Finalize tray behavior and icon assets for macOS, Windows, and Linux with consistent UX and robust status controls.

## Tray Icon Assets
- [x] Define monochrome tray glyph direction based on the boxed logo mark.
- [x] Define target size variants: 16, 18, 20, 22.
- [x] Define dark/light-compatible variant policy for each platform.
- [x] Document packaging targets: macOS template icon, Windows `.ico`, Linux PNG/SVG fallback.

Asset policy for v1:
- Source-first v1 keeps the existing bundled app icon as runtime tray icon.
- Dedicated monochrome tray asset pack is planned and tracked for the signed-binary phase (Phase B).
- No mixed icon style is shipped: one icon source is used at runtime in v1.

## Tray Behavior
- [x] Connect or Disconnect action.
- [x] Active tunnel summary.
- [x] Open app window.
- [x] Start at login toggle (preference persisted for v1 policy; OS registration deferred).
- [x] Auto-connect on launch toggle.
- [x] Quit action.

## Runtime States
- [x] Disconnected or stopped state is reflected in tray status line and tooltip.
- [x] Starting/running/connected states are reflected in tray status line and tooltip.
- [x] Connected state updates connect action to disconnect.
- [x] Error state is surfaced in tooltip via last-error text.

## Behavior Matrix
| State | Connect Action | Tooltip | Notes |
|---|---|---|---|
| Stopped/Created | Connect selected persisted tunnel | `QuicFuscate - Stopped/Created` | Uses selected tunnel first, falls back to first valid QKey tunnel. |
| Starting/Running | Connect action remains available | `QuicFuscate - Starting/Running` | Transitional state is visible; next refresh resolves to connected/stopped. |
| Connected | Disconnect | `QuicFuscate - Connected` | Active tunnel label updates from persisted tunnel metadata. |
| Error | Connect (retry) or Disconnect if still connected | `QuicFuscate - Error: <message>` | Last error remains visible for operator context. |

## Quality Gates
- [x] No duplicate tray entries.
- [x] Close-window hides to tray reliably.
- [x] Tray actions work when window is hidden.
- [x] Platform parity and v1 limitations documented.

## Acceptance Criteria
- Tray UX behavior is consistent across macOS, Windows, Linux for v1 source-first scope.
- Tray actions and status transitions are wired through desktop runtime state.
- Behavior and persistence logic are covered by desktop Rust and frontend test suites.
