---
id: TODO-364
title: "Document relationship between dual 0-RTT config fields"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-364: Document relationship between dual 0-RTT config fields


## Problem
Two config fields control 0-RTT behavior:
- `[connection].enable_0rtt = true` (in quicfuscate.toml)
- `[transport].enable_early_data = false` (in quicfuscate.toml)

Their interaction is not documented:
- Which takes precedence?
- Are they the same concept at different layers?
- Can they be set independently?

Operators may set one expecting it to control the other.

## Fix Plan
1. Read the code to understand how both fields are used
2. If they are redundant: remove one and add a deprecation alias
3. If they serve different purposes: document the difference in DOCUMENTATION.md
4. Add a comment in quicfuscate.toml explaining the relationship
5. Optionally: add a startup warning if conflicting values are set

## Files to Modify
- config/quicfuscate.toml (add comments)
- docs/DOCUMENTATION.md (document relationship)
- Potentially src/engine/config.rs (add validation)