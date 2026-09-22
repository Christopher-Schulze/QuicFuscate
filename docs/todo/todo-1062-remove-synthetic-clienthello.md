---
id: TODO-1062
title: Stop emitting the synthetic ClientHello
severity: HIGH
phase: S
priority: P1
status: DONE
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

- [x] Call-site classification in Notes.
- [x] Remove emission of synthetic hellos on any socket or crypto frame.
- [x] Point startup validation at rustls.
- [x] Delete `key_share_ext` and unused builder functions.
- [x] `rg` finds no `key_share_ext`.

## Notes

Call sites before the deletion:

- `src/main/runtime.rs` startup check called `generate_client_hello` and accepted `len > 100`. Not a socket write. Now `RustlsProvider::client_hello_len_for_persona`.
- `FingerprintProfile::new_with_snapshot` stored the builder output in `client_hello`. Nothing read those bytes onto a socket. The field is gone.
- `plan_tls_cover_record` stamped plaintext with handshake type `0x01` and version `0x0303` before encryption. That stamp is gone. The record header stays a TLS record; the plaintext is random.
- `src/qftls/tests.rs` parses rustls Initial frames. Those tests stay.
- `crates/qf-reality` `client_hello` is captured cover-site bytes, not this builder.
- Layout tests in `src/stealth/tests.rs` and `crates/qf-stealth/src/tls_cover.rs` asserted the xorshift hello. Deleted with the builder. ServerHello cipher-id tests stay.

## Result

No production or test function fills a key share from an xorshift seed. `rg key_share_ext` and `rg generate_client_hello` are empty in Rust. Cover records do not embed a ClientHello. Persona hellos come from rustls. TODO-1047 still owns making those hellos match a capture.

## Acceptance

- The existing test that rustls key-share groups overlap the persona still passes.
- No function fills a key share from an xorshift seed.

## Risks

- TLS-cover tests assert on synthetic handshake bytes. Replace those assertions with "cover ciphertext does not parse as a ClientHello", or delete the test if the frame no longer claims to be a hello.
