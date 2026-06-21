# TODO-173: Server Configuration Template Expansion

## Status
**DONE**

## Severity
**LOW**

## Context
The default server configuration template is minimal to the point of being unusable as a reference:

- `config/server-linux.default.toml`: Only 3 lines total
  ```toml
  [stealth]
  mode = "performance"
  ```
- Missing sections: listen address, QKey registry path, admin port, TLS configuration, logging levels, FEC settings, transport tuning, and more
- Users must read source code to discover available configuration options

## Root Cause
Template was created as a minimal starting point and never expanded as new configuration options were added to the codebase.

## Fix Plan
1. Audit `src/engine/config.rs` to enumerate all configuration sections and fields
2. Cross-reference with `config/quicfuscate.toml` (client config) for shared options
3. Expand `config/server-linux.default.toml` with all available sections:
   - `[server]`: listen address, port, max clients, session timeout
   - `[tls]`: cert path, key path, ALPN protocols
   - `[stealth]`: mode, persona, timing parameters
   - `[fec]`: mode, redundancy, interval
   - `[transport]`: MTU, buffer sizes, batch settings
   - `[admin]`: socket path, HTTP port, authentication
   - `[qkey]`: registry path, rotation interval
   - `[logging]`: level, format, output
   - `[limits]`: rate limiting, connection limits
4. All values should be commented with descriptions and defaults
5. Sensible production defaults pre-filled

## Acceptance Criteria
- Template covers all configurable server options
- Every field has a comment explaining its purpose and default value
- Template is valid TOML when uncommented
- Users can configure the server fully from the template without reading source

## Dependencies
- None

## Affected Files
- `config/server-linux.default.toml`
- `src/engine/config.rs` (reference only - read for available options)
