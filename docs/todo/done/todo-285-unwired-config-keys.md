# TODO-285: Document or Remove Unwired Config Keys

## Problem
Three config keys are parsed from TOML but never wired to runtime behavior:
- `enable_pq` (line 123 in config/quicfuscate.toml)
- `key_update_interval` (line 137)
- `enable_retry` (line 81)

Users may set these expecting behavior changes that never happen - misleading.

## Source
AI Model Review (Mimo v2 Pro, Gemini 3.1 Pro) - verified correct.

## Location
- `config/quicfuscate.toml` - parsed keys
- `src/main.rs` - config parsing
- Missing: actual wiring to runtime

## Fix
Add clear comments in config/quicfuscate.toml marking these as "reserved/not yet implemented" and update DOCUMENTATION.md to reflect their status.

## Acceptance Criteria
- Config file clearly marks unwired keys
- DOCUMENTATION.md reflects actual status
- No user confusion possible
