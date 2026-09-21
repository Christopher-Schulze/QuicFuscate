---
id: TODO-1033
title: Ship default rustls AES-GCM packet protection
severity: HIGH
phase: S
priority: P0
status: OPEN
created: 2026-09-21
depends_on: []
---

# TODO-1033: Ship default rustls AES-GCM

## Why

Max stealth requires Chrome-shaped QUIC on the first packets and on pre-auth 1-RTT. RFC 9001 Initial is AES-GCM. rustls Handshake and 1-RTT are AES-GCM or ChaCha. `packet_protection_mode="auto"` is inert today and still advertises a private upgrade. The shipped default must be standard rustls AES-GCM. Private AEGIS/MORUS stays opt-in behind TODO-1044.

## Acceptance

- [ ] `config/quicfuscate.toml` and server default TOML set `packet_protection_mode = "standard"`
- [ ] `CryptoConfig::default()` uses `PacketProtectionMode::Standard`
- [ ] `aead_preference="auto"` plus empty `force_aead` installs no private family
- [ ] Engine validation still rejects `standard` plus an explicit private family
- [ ] `advanced-required` stays fail-closed and is not the default
- [ ] Docs say the product default is rustls AES-GCM, never AEGIS/MORUS
- [ ] Existing TODO-885 private machine remains in tree and stays inert on the default
- [ ] No frontend visual change
- [ ] Focused config/validation tests prove the default and the conflict reject

## Sub-Tasks

- [ ] Flip defaults in `crates/qf-crypto/src/lib.rs` `CryptoConfig` and TOML
- [ ] Add a rust-tests case: default config -> no private family, handshake/1-RTT rustls
- [ ] Update `docs/DOCUMENTATION.md` product-default sentence
- [ ] Leave TODO-885 protocol code in place

## Notes

Do not start until explicitly requested. This task does not wait for TODO-1032. Bakeoff winners cannot change this default; they can only become an explicit opt-in.
