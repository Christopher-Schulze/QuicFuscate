---
id: TODO-1029
title: Omega pcap/wire proof for private AEAD upgrade (TODO-885)
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-885]
---

# TODO-1029: Omega packet-capture proof for the private AEAD upgrade

## Why

TODO-885 has live TUN+QKey+MASQUE proof and `quicfuscate_private_upgrade_activated_total=1`. That is owner-install telemetry, not wire evidence. Reviewers and the 885 acceptance list still require a capture that shows the payload owner change without changing QUIC packet shape.

## Acceptance

- [ ] One Omega capture (client and server) covering handshake, pre-auth 1-RTT, activation, and post-activation data
- [ ] Initial and Handshake decrypt/classify as rustls-standard AES-GCM
- [ ] Header protection remains rustls-standard before and after activation
- [ ] Post-activation 1-RTT payload fails to open with the rustls 1-RTT key and opens with the negotiated private owner
- [ ] Packet form, CID, PN length, and 16-byte tag overhead stay QUIC-shaped
- [ ] `standard` peer capture stays rustls-only (no private owner)
- [ ] Artifact path, commit, and command recorded in TODO-885
- [ ] No keys, QKeys, or exporter bytes in the committed artifact

## Sub-Tasks

- [ ] Reuse the existing Omega TUN e2e path (`scripts/tests/tun-e2e-netns.sh` / omega wrappers)
- [ ] Capture on the underlay UDP port, not TUN
- [ ] Classify packets by QUIC header + known rustls keys vs private keys
- [ ] Attach the artifact pointer to TODO-885

## Notes

Do not start until explicitly requested. Telemetry-only activation is already recorded in TODO-885 and must not be restated as wire proof.
