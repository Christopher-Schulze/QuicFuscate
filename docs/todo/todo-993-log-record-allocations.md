---
id: TODO-993
title: TODO-993 — Per-record allocations in the production logger
status: OPEN
created: 2026-09-19
---

# TODO-993 — Per-record allocations in the production logger

## Context

`ProductionLogger::log` allocated three `String`s for every enabled record —
`record.target().to_string()`, `record.args().to_string()` and
`record.file().map(str::to_string)` — before handing the record to the async
writer channel. Under `-v` (debug) operation this is hundreds of allocations
per second on the dataplane thread; flamegraph analysis showed ~7% in
`log::Level::fmt`/record formatting while profiling with debug logging.

## Implementation

`crates/qf-logging/src/lib.rs`: `OwnedRecord.target`/`file` are now
`Cow<'static, str>` populated via `record.module_path_static()` and
`record.file_static()`. Standard `log!` call sites carry `'static` module
paths and file names, so the common case borrows instead of allocating; a
custom `target:` differing from `module_path()` still falls back to an owned
copy, preserving exact semantics. The formatted message keeps its one
unavoidable allocation (`fmt::Arguments` cannot cross the channel). Three
allocations per record become one.

- `format_owned_json` uses `record.target.to_string()` /
  `file.to_string()` for the `Cow` fields.
- Test `OwnedRecord` literals updated to `Cow::Borrowed`.

## Verification

- `cargo check -p qf-logging`, `cargo clippy -p qf-logging`, `cargo fmt`: clean.
- `cargo test -p qf-logging`: 22/22 green.
- Workspace `cargo check --lib`: clean.

## Notes

- The remaining `message` allocation could be avoided only by pooling
  formatted buffers with a return channel — disproportionate complexity vs.
  the single-alloc steady state.
- Disabled records stay macro-gated by `log::set_max_level`; this change
  only affects enabled records.
