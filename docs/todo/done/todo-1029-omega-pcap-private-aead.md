---
id: TODO-1029
title: Omega pcap/wire proof for private AEAD upgrade (TODO-885)
severity: HIGH
phase: S
priority: P1
status: DONE
created: 2026-09-21
depends_on: [TODO-885]
---

# TODO-1029: Omega packet-capture proof for the private AEAD upgrade

## Why

TODO-885 has live TUN+QKey+MASQUE proof and `quicfuscate_private_upgrade_activated_total=1`. That is owner-install telemetry, not wire evidence. Reviewers and the 885 acceptance list still require a capture that shows the payload owner change without changing QUIC packet shape.

## Acceptance

- [x] One Omega capture (client and server) covering handshake, pre-auth 1-RTT, activation, and post-activation data
- [x] Initial and Handshake decrypt/classify as rustls-standard AES-GCM
- [x] Header protection remains rustls-standard before and after activation
- [x] Post-activation 1-RTT payload fails to open with the rustls 1-RTT key and opens with the negotiated private owner
- [x] Packet form, CID, PN length, and 16-byte tag overhead stay QUIC-shaped
- [x] `standard` peer capture stays rustls-only (no private owner)
- [x] Artifact path, commit, and command recorded in TODO-885
- [x] No keys, QKeys, or exporter bytes in the committed artifact

## Sub-Tasks

- [x] Reuse the existing Omega TUN e2e path (`scripts/tests/tun-e2e-netns.sh` / omega wrappers)
- [x] Capture on the underlay UDP port, not TUN
- [x] Classify packets by QUIC header + known rustls keys vs private keys
- [x] Attach the artifact pointer to TODO-885

## Notes

Do not start until explicitly requested. Telemetry-only activation is already recorded in TODO-885 and must not be restated as wire proof.

## Result (2026-09-22)

DONE on Omega (`~/QuicFuscate`, aarch64, QUIC v2 `0x6b3343cf`). Wire proof tool: `src/bin/qf-aead-wire-proof.rs`; instrumentation: `SSLKEYLOGFILE` + `QUICFUSCATE_PRIVATE_KEY_DUMP` env-gated dumps in `scripts/tests/tun-e2e-netns.sh` and `Connection::activate_private_packet_protection`.

Run A — both peers `stealth.mode=off` (auto+AEGIS upgrade armed). Artifacts on Omega at `/tmp/qf1029/runA4/` (client.pcap, server.pcap, keylog.txt, private.dump — operator-local, not committed). Analyzer verdict on both pcaps:

- `initial=3`, `handshake=5` — all opened with rustls AES-128-GCM, zero failures
- `standard_1rtt=9` — all pre-boundary 1-RTT opened with rustls traffic secrets
- `private_1rtt=50`, `below_boundary=0` — every post-boundary packet fails rustls keys and opens with AEGIS-128L epoch material derived from the dumped schedule root + context hash
- `standard_above_boundary=0` — no packet above the boundary opens with standard keys
- `unopened=0`, `shape_violations=0`, `cross_peer_mismatch=false`
- Client dump `write_boundary=5 read_boundary=4`, server dump mirrored (`write=4 read=5`); client-write key bytes equal server-read key bytes exactly

Run B — client `mode=off`, server `mode=stealth` (standard-only policy). Artifacts `/tmp/qf1029/runB/`. Verdict `--expect standard`: `standard_1rtt=69`, `private_1rtt=0`, `unopened=0`; no `private.dump` was emitted at all — mixed-policy negotiation never installs the private owner, and the auto side falls back to rustls-only without leaking private packets.

Analyzer reproduction command on Omega:

```
sudo ./target/release/qf-aead-wire-proof \
  --pcap /tmp/qf1029/runA4/client.pcap \
  --keylog /tmp/qf1029/runA4/keylog.txt \
  --privdump /tmp/qf1029/runA4/private.dump \
  --port 4433
```

Notable wire finding: the dataplane emits coalesced UDP datagrams (userland GSO/GRO — `src/transport/xdp.rs::coalesce_packets`, receiver splits via `gso_size` cmsg in `src/optimize/uring_batch/recv.rs`). A single 700-byte datagram carried two private short-header packets (pn=6 566B + pn=7 134B); short headers have no length field, so the analyzer recovers the split by trial open at candidate positions. This is a capture artifact, not a crypto fault — both segments authenticate as private epoch-1 above the boundary.

Header protection stays rustls-standard for standard and private payloads (verified — the private install only swaps `packet_aead_owner`, never `header_protection_owner`). QUIC packet shape unchanged by the owner switch: same short-header form, CID, PN encoding, 16-byte tag overhead.

## Follow-up Maintenance (2026-09-23)

The analyzer's truncated packet-number reconstruction now uses checked additions at the `u64` boundary instead of an always-true maximum comparison. A regression exercises the non-wrapping boundary; this does not change the captured QUIC classification.
