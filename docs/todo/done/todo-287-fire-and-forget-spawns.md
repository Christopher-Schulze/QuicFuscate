# TODO-287: Fire-and-Forget tokio::spawn Calls

## Problem
7 of 10 `tokio::spawn` calls discard the JoinHandle, meaning:
- Panics in spawned tasks are silently swallowed
- No way to gracefully shut down these tasks
- Resource leaks on long-running server instances

## Source
AI Model Review (Gemini 3.1 Pro, GLM-5) - verified correct.

## Locations
- `src/implementations/server/admin.rs:388`
- `src/implementations/server/admin_http.rs:455`
- `src/implementations/server/mod.rs:1412, 1428, 1446`
- `src/implementations/server/metrics.rs:47, 54`

## Fix
Store JoinHandles and abort on shutdown, or use `tokio::spawn` with error logging wrapper.

## Acceptance Criteria
- All spawned tasks have their JoinHandles stored or explicitly documented as intentionally fire-and-forget
- Panic in spawned task is logged, not silently swallowed
