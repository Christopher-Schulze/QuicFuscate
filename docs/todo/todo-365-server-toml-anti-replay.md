---
id: TODO-365
title: "server-linux.default.toml missing [anti_replay] section"
severity: "MODERATE"
phase: legacy
priority: legacy
status: DONE
created: 2026-03-27
backfilled: 2026-07-23
---

# TODO-365: server-linux.default.toml missing [anti_replay] section


## Problem
`config/server-linux.default.toml` is the server deployment template but it completely
omits the `[anti_replay]` section. The canonical `quicfuscate.toml` has:

```toml
[anti_replay]
enabled = true
max_ticket_age_secs = 10
max_entries = 100000
max_early_data_size = 16384
```

Anti-replay is a SERVER-SPECIFIC feature (protects against 0-RTT replay attacks).
It should absolutely be documented in the server template. Operators using the
template will get code defaults with no visibility into available knobs.

Also missing from server template: `[interface].xdp_mode` and `xdp_flags` (relevant
for Linux server deployments).

## Fix Plan
1. Add `[anti_replay]` section to server-linux.default.toml with appropriate defaults
2. Add commented `[interface]` XDP entries for Linux operators
3. Verify alignment with quicfuscate.toml for all shared sections

## Files to Modify
- config/server-linux.default.toml