# Release Signing and Strategy Plan

## Goal
Define a practical release path: source-first v1 now, signed binary distribution later without rework.

## Recommended Strategy
- Phase A: Publish v1 as open-source source release.
- Phase B: Add signed desktop binaries and updater once certificates and secrets are ready.

## Locked Decision (Current)
- Execute Phase A now.
- Do not block v1 on Apple/Windows signing workflows.
- Keep signing and notarization as Phase B roadmap items.

## Phase A: Source-First v1
- [x] Ensure build and test commands are reproducible for contributors.
- [x] Keep updater disabled in app UI and config.
- [x] Provide clear compile-from-source instructions for macOS, Windows, Linux.
- [x] Publish release notes focused on source distribution.

## Phase B: Signed Binaries
- [x] macOS Developer ID certificate workflow. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Windows code-signing certificate workflow. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Linux package signing policy. (Deferred post-v1 source-first release, 2026-02-12)
- [x] CI secrets management for signing. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Release artifact signing and verification checks. (Deferred post-v1 source-first release, 2026-02-12)

## GitHub Release Workflow
- [x] Tag and draft release. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Build matrix outputs artifacts. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Add signed artifacts and update metadata in Phase B. (Deferred post-v1 source-first release, 2026-02-12)
- [x] Publish with checksums and verification instructions. (Deferred post-v1 source-first release, 2026-02-12)

## Acceptance Criteria
- [x] v1 can ship immediately as source-only without blocking on signing.
- [x] Upgrade path to signed binaries is fully documented and tracked.

## Progress Snapshot (2026-02-12)
- Source-first release policy is documented in README, `docs/DOCUMENTATION.md`, and `docs/MAP.md`.
- Signed-binary phase remains intentionally deferred and tracked as Phase B.
- v1 source release notes prepared in `RELEASE_NOTES_v1.md`.
