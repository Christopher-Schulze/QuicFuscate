---
id: TODO-1035
title: Move TLS-Cover and first-party ChaCha20-Poly1305 onto rustls/ring
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1034]
---

# TODO-1035: Move TLS-Cover AEAD and first-party ChaCha off the live path

## Why

TLS-Cover needs an AEAD for cover records. It does not need a first-party ChaCha20-Poly1305 or first-party AES-GCM. rustls/ring already owns those ciphers. Keeping a second stack is review cost with no stealth or FEC gain.

## Live owners today

- `crates/qf-crypto/src/chacha.rs`, `poly1305.rs`, `lib.rs` `ChaCha20Poly1305`
- `crates/qf-crypto/src/tls_cover.rs`
- `src/qftls/tls_cover_provider.rs` installs `TlsCoverKeyMaterial::ChaCha20Poly1305` or AES material
- `src/implementations/server/qkey_registry_storage.rs` seals QKey registry entries at rest with first-party `ChaCha20Poly1305` (server, live)
- Cover is not the VPN 1-RTT owner

## Acceptance

- [ ] Cover record seal/open uses rustls/ring (or the same aws-lc owner as TODO-1034), not `chacha.rs`/`gcm.rs`
- [ ] `qkey_registry_storage.rs` at-rest seal/open uses the same standard owner; the versioned TODO-539 envelope format stays byte-readable for existing stores (decrypt old, re-seal on write, or documented migration)
- [ ] First-party ChaCha20-Poly1305 has no production caller
- [ ] RFC 8439 vectors remain as oracle tests if the first-party module is kept
- [ ] Cover record shape, TLS content type, and sequence handling stay byte-compatible with current tests
- [ ] rustls Handshake/1-RTT path unchanged
- [ ] No visible UI change
- [ ] Focused TLS-Cover tests plus qf-crypto cover tests pass

## Sub-Tasks

- [ ] Read `TlsCoverCipher` install and record APIs
- [ ] Wrap rustls/ring AES-GCM and ChaCha20-Poly1305 for cover records
- [ ] Delete production calls into first-party ChaCha/Poly1305
- [ ] Keep first-party modules only if TODO-1038 still needs them as oracles

## Notes

Cover is stealth-adjacent. Changing the record AEAD owner must not change the cover record layout. If a rustls API cannot do cover records without pulling handshake state, wrap `ring::aead` directly rather than inventing ChaCha again.
