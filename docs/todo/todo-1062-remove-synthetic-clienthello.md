---
id: TODO-1062
title: Stop emitting the synthetic ClientHello
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1047]
---

# TODO-1062: Stop emitting the synthetic ClientHello

## Why

`key_share_ext` fills key shares with xorshift, including ML-KEM-sized blobs. Those bytes are not a valid X25519MLKEM768 public key. A parser that checks the ML-KEM structure flags them immediately. A bad mimic is easier to detect than a real handshake (Houmansadr, "The Parrot is Dead", 2013). The rustls hello is the real one. The synthetic blob must not become the wire hello.

## Current code

- `crates/qf-stealth/src/tls_cover.rs` `key_share_ext` and `key_share_ext_multi` expand an xorshift seed. They are not a KEM.
- `TlsCover::generate_client_hello` is stored on `FingerprintProfile.client_hello`.
- `src/main/runtime.rs` generates those hellos at startup only to check `len > 100`.
- `src/qftls/tls_cover_provider.rs` does not own the protocol ClientHello. `next_crypto_frame` emits ring-sealed cover records before the handshake completes.
- No socket write of `profile.client_hello` was found. The builder is still a landmine if a later path sends it.

## Target

- No production or test path sends `generate_client_hello` bytes on a socket.
- Persona configuration goes through rustls only (TODO-1047).
- Delete `key_share_ext` and the synthetic hello builder once tests stop treating them as a wire format.
- Cover records may stay as ring AEAD of opaque padding until TODO-1052 replaces them. They must not start with a fake ClientHello. If `generate_fake_crypto_frame` embeds a synthetic hello, stop embedding it.

## Non-goals

- Do not remove rustls.
- No frontend visual change.

## Design

1. Classify every `generate_client_hello`, `key_share_ext`, and `client_hello` write as startup log, byte-layout test, or send path. Record that list in Notes before editing.
2. Send-path hits are removed in this task.
3. Byte-layout tests are deleted with the builder. Do not keep the xorshift.
4. Startup validation checks that rustls can build a hello for each persona, not that the synthetic builder returns 100 bytes.

## Sub-Tasks

- [ ] Call-site classification in Notes.
- [ ] Remove emission of synthetic hellos on any socket or crypto frame.
- [ ] Point startup validation at rustls.
- [ ] Delete `key_share_ext` and unused builder functions.
- [ ] `rg` finds no `key_share_ext`.

## Acceptance

- The existing test that rustls key-share groups overlap the persona still passes.
- No function fills a key share from an xorshift seed.

## Risks

- TLS-cover tests assert on synthetic handshake bytes. Replace those assertions with "cover ciphertext does not parse as a ClientHello", or delete the test if the frame no longer claims to be a hello.
