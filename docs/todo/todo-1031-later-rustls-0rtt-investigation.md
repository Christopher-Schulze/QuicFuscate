---
id: TODO-1031
title: Later rustls-standard 0-RTT investigation (never private AEAD)
severity: MEDIUM
phase: L
priority: P2
status: OPEN
created: 2026-09-21
depends_on: [TODO-720]
---

# TODO-1031: Later rustls-standard 0-RTT investigation

## Why

TODO-720 correctly disabled a half-wired 0-RTT claim. The strike register still exists and does nothing. Chrome resumes with 0-RTT, so a later stealth pass must decide whether missing early data is a resume fingerprint. This is reconnect latency and fingerprint work, not bulk throughput, and it must not reopen first-party or private AEADs.

Do not implement now. Investigate only after the standard-crypto posture is settled.

## Acceptance

- [ ] Decision: stay disabled, or enable rustls PacketKey 0-RTT with the existing strike register
- [ ] Private-AEAD 0-RTT is explicitly rejected in the decision record
- [ ] Replay, no-ticket, expired-ticket, and key-install failure paths are specified before any enable
- [ ] Resume-with-0-RTT vs resume-without-0-RTT fingerprint cost is written down
- [ ] Reconnect latency gain is measured against current 1-RTT resume
- [ ] Config remains fail-closed until the wiring and strike register are one proven path
- [ ] No production enable in this task unless a follow-up implementation task is opened

## Sub-Tasks

- [ ] Map rustls early-data secrets to the current PacketKey installer
- [ ] Confirm `StrikeRegister` ownership on every 0-RTT datagram
- [ ] Bound early data to handshake/control, never TUN payload, unless a later task proves replay-safe VPN semantics
- [ ] Compare Chrome resume 0-RTT shape against our current no-0-RTT resume
- [ ] Keep `enable_0rtt` rejected until the proof exists

## Notes

Current truth: `get_0rtt_keys()` is `None`, `enable_0rtt()` errors, `install_0rtt_keys()` has no production caller, and engine validation rejects the flags. That stay-disabled posture is correct until this investigation runs.
