# TODO-179: Memory Pool Size Auto-Scaling

## Status
COMPLETED

## Severity
LOW

## Context
The memory pool size is hardcoded to 67108864 bytes (64MB). This value is a fixed constant that does not adapt to the system it runs on. On small embedded systems or containers with limited RAM, 64MB may be excessive. On large servers with hundreds of GB, 64MB is a bottleneck that forces unnecessary pool exhaustion and fallback allocations.

- Hardcoded `memory_pool_size = 67108864` in configuration
- No runtime detection of available system memory
- No configuration knob to override pool size
- Pool exhaustion on large servers leads to heap fallback (performance degradation)

## Root Cause
The pool size was set as a reasonable default during initial development and never made dynamic or configurable. No system memory detection was implemented.

## Fix Plan
1. Add `memory_pool_size` as a configurable field in `config/quicfuscate.toml` with `"auto"` as default
2. Implement auto-scaling logic:
   - Detect available system RAM via `sysinfo` crate or platform-specific APIs
   - Default: 5% of total RAM
   - Minimum: 16MB (small systems floor)
   - Maximum: 256MB (cap to prevent over-allocation)
3. Allow explicit override in config: `memory_pool_size = 134217728` (explicit bytes)
4. Log the selected pool size at startup for observability
5. Update documentation with pool sizing guidance

## Acceptance Criteria
- Memory pool size adapts to system RAM when set to "auto"
- Explicit override works via config file
- Pool size bounded between 16MB and 256MB in auto mode
- Selected pool size logged at startup
- Configuration documented

## Dependencies
- `sysinfo` crate or platform-specific memory detection

## Affected Files
- `config/quicfuscate.toml`
- `src/optimize/memory.rs`
- `src/engine/config.rs`
- `docs/documentation.md`
