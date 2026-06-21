# TODO 107 - Canonical Doc Stale Random and Telemetry Truth Cleanup

## Context

The canonical documentation still contained stale statements after the latest runtime simplifications:

- random helper wording still implied internal AES-CTR DRBG acceleration for retained optimize-random helpers
- multiple telemetry sections still referred to the removed `telemetry_snapshot_text(...)` helper

Those statements no longer matched the code:

- `src/optimize/random.rs` now uses a secure-seeded non-security per-thread `StdRng`
- the retained programmatic telemetry export helper is `telemetry::export_telemetry_text()`

## Desired Outcome

Bring `docs/DOCUMENTATION.md` fully back to current runtime truth:

- no stale AES-CTR helper wording for optimize-random
- no stale references to `telemetry_snapshot_text(...)`
- telemetry export text consistently points at `telemetry::export_telemetry_text()`

## Work Items

- [x] Update the optimize-random wording in canonical documentation.
- [x] Replace stale telemetry helper references with the retained export helper.
- [x] Sync backlog and context to the corrected documentation truth.

## Final State

- Canonical random wording now reflects the simplified non-security per-thread `StdRng` helper model.
- Canonical telemetry wording now consistently references `telemetry::export_telemetry_text()`.
- No stale helper references remain in the canonical documentation.
