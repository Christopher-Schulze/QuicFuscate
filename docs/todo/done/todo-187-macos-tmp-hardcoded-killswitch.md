# TODO-187: macOS Kill-Switch Hardcoded /tmp Path

## Status
COMPLETED

## Severity
LOW

## Context
The kill-switch writes its pf configuration to a hardcoded path `/tmp/quicfuscate_killswitch.conf`. Since `/tmp` is a shared directory, multiple QuicFuscate instances running simultaneously will overwrite each other's configuration files, causing one or both instances to have incorrect kill-switch rules.

- `src/implementations/client/killswitch.rs:248`: hardcoded `/tmp/quicfuscate_killswitch.conf`
- Multiple instances write to same file - last writer wins
- Race condition: instance A writes config, instance B overwrites, instance A loads B's config
- Cleanup by one instance may remove another instance's active config

## Root Cause
The temporary file path was hardcoded as a simple implementation. No consideration for multi-instance scenarios.

## Fix Plan
1. Replace hardcoded path with unique-per-process path:
   - Option A: `/tmp/quicfuscate_killswitch_{PID}.conf` using `std::process::id()`
   - Option B: Use `tempfile` crate for secure, unique temporary file creation
2. Option B is preferred as it also handles:
   - Secure file creation (no TOCTOU race)
   - Automatic cleanup via `TempDir`/`NamedTempFile`
   - No predictable path (security benefit)
3. Ensure cleanup removes the process-specific file on shutdown
4. Add cleanup of orphaned config files on startup (find stale `/tmp/quicfuscate_killswitch_*.conf`)

## Acceptance Criteria
- Each QuicFuscate instance uses a unique temporary config file
- No conflict when multiple instances run simultaneously
- Config file cleaned up on normal shutdown
- Orphaned files from crashed instances handled on next startup

## Dependencies
- `tempfile` crate (if Option B chosen)
- todo-186 (pfctl enable race) - related kill-switch hardening

## Affected Files
- `src/implementations/client/killswitch.rs`
- `Cargo.toml` (if adding tempfile dependency)
