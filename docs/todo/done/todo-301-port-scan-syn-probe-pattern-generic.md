---
id: TODO-301
title: Port_Scan_SYN probe pattern too generic - potential false positives
severity: MEDIUM
status: done
created: 2026-03-24
---

# TODO-301: Port_Scan_SYN Probe Detection Pattern Too Generic

## Mandatory Gate

**Before marking this TODO complete, ALL of the following must be checked and updated:**
- `src/stealth/mod.rs` - `load_probe_patterns()` and `matches_pattern()`
- `scripts/tests/suites/test-stealth.sh` - stealth suite
- `scripts/tests/rust/rt-probe-detection.rs` - probe detection test
- `docs/DOCUMENTATION.md` - any mention of probe detection patterns
- `docs/DOCUMENTATION.md` - durable behavior truth

---

## Current State

In `src/stealth/mod.rs`, `load_probe_patterns()`:

```rust
ProbePattern {
    name: "Port_Scan_SYN".to_string(),
    pattern: vec![0x00, 0x00, 0x00, 0x02],
    mask: None,          // <-- no mask: exact prefix match
    _severity: 4,
},
```

This matches ANY incoming UDP payload starting with bytes `[0x00, 0x00, 0x00, 0x02]`.

## Risk Assessment

**Context that limits impact:**
- `probe_detector` is only instantiated when `config.dynamic_enabled = true` (Intelligent mode only)
- `process_incoming_packet()` is called on recovered QUIC packet payloads, not raw UDP datagrams
- Valid QUIC packets NEVER start with `0x00`: Long-header packets have bit 7 set (0x80+), short-header packets have bit 6 set (0x40+). The Fixed Bit is mandatory per RFC 9000.
- So this pattern can only match non-QUIC traffic sent to the QUIC port (which IS suspicious)
- Escalation threshold is 5 hits within 60 seconds before triggering mode change

**Residual risk:**
- The 4-byte pattern with no mask and no minimum-length requirement is architecturally fragile
- No test validates that this pattern does NOT fire on legitimate traffic
- The pattern was likely copied from a TCP SYN inspection tool and has no valid semantics at the QUIC UDP payload level
- If the server ever processes traffic at a different layer (e.g., raw UDP payloads pre-QUIC), false positives are possible

## Fix

Replace the generic pattern with a more specific one, or add a mask. The original intent was to detect bare TCP SYN probes sent to a UDP port, which are:

- TCP SYN: starts with source port (2 bytes) + dest port (2 bytes) + seq number (4 bytes) + ack (4 bytes) + flags byte
- The TCP flags byte for SYN-only is `0x02`
- So a minimal TCP SYN would be: `[src_port_hi, src_port_lo, 0x14, 0x33, ...]` (for port 5171 dest)

A more specific pattern with mask:
```rust
ProbePattern {
    name: "Port_Scan_SYN".to_string(),
    // TCP flags byte at offset 13 = 0x02 (SYN only), reserved bits 0
    // Minimum TCP header is 20 bytes; match on flags byte position
    pattern: vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
    mask: Some(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0xff]),
    _severity: 4,
},
```

Or, simpler: **remove this pattern entirely**. The GFW_TLS_Probe and DPI_QUIC_Scan patterns cover the most relevant real-world probers (GFW active probing, QUIC fingerprinting). Port scanning a UDP port with TCP SYNs is unusual and if it happens, it would produce a packet that is immediately invalid as a QUIC packet (wrong Fixed Bit), so it would be rejected before even reaching the probe detector.

**Recommended fix: remove Port_Scan_SYN pattern** and add a comment explaining that raw TCP SYN probes cannot appear as valid QUIC payloads due to the Fixed Bit invariant.

## Completion Criteria

- `load_probe_patterns()` has no generic unmasked 4-byte patterns
- `rt-probe-detection.rs` has a test asserting normal QUIC short-header packets (0x40+) do NOT trigger the detector
- All mandatory gate items checked and updated
