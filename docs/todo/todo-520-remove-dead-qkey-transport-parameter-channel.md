---
id: TODO-520
title: Remove dead QKey transport-parameter channel and false confidentiality claims
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-07-21
depends_on: [TODO-415]
supersedes: []
---

# TODO-520: Remove Dead QKey Transport-Parameter Channel and False Confidentiality Claims

## Why

The client stores the reusable QKey bearer in a provider-local field that claims to inject it into QUIC transport parameters. That claim is false in two independent ways. Client transport parameters belong to ClientHello rather than server `EncryptedExtensions`, and the actual rustls client/server constructors receive empty transport-parameter vectors. No runtime caller reads `get_quic_transport_params()` or calls `set_peer_transport_params()`, so the later provider-local mutation never reaches rustls or the wire.

The current code is therefore not a proven live credential disclosure. It is dead security machinery with false confidentiality documentation and a server branch that can never authenticate. The existing `x-qf-auth` HTTP/3 header is the real 1-RTT-encrypted authentication path. The server's authentication gate blocks MASQUE, TUN, and application forwarding until that header validates.

## Acceptance

- Client Initial and ClientHello bytes contain no QKey bearer or credential-derived equivalent.
- QKey authentication succeeds only through a handshake-confidential channel.
- Missing or invalid authentication cannot forward MASQUE, TUN, or application payloads.
- The QKey transport-parameter API, storage, parser, tests, and false confidentiality claims are removed atomically.
- A repository guard proves no runtime producer, parser, accessor, or server branch can route the bearer through QUIC transport parameters, while an end-to-end test proves encrypted authentication still succeeds.
- Application readiness is impossible before rustls completes, and certificate failures terminate the client with the exact TLS error instead of entering an unauthenticated polling loop.
- Standalone server startup cannot poison future allocations when `RLIMIT_MEMLOCK` is finite.
- Full native test, Clippy, cross-target, documentation, and live Omega authentication gates pass.
- Protected Svelte/Tauri UI surfaces remain byte-unchanged.

## Sub-Tasks

- [x] Map every QKey transport-parameter producer, consumer, fallback, and authorization gate.
- [x] Add a pre-handshake credential-confidentiality regression that captures the current runtime truth.
- [x] Remove the dead client transport-parameter bearer path and retain encrypted HTTP/3 authentication.
- [x] Prove invalid and missing credentials fail closed before protected data forwarding.
- [x] Reconcile TODO-415 and current architecture/security documentation with protocol truth.
- [x] Fail closed on TLS verification errors and bind application readiness to rustls completion.
- [x] Harden finite-limit memory locking and rate-limit client statistics logging found during live proof.
- [~] Run local, cross-target, CI, and Omega authentication proof.

## Notes

- RFC 9001 Section 8.2 places client `quic_transport_parameters` in `ClientHello` and server parameters in `EncryptedExtensions`.
- RFC 9001 Section 5.2 derives Initial secrets from the client's initial Destination Connection ID; RFC 9000 states that an attacker can observe client transport parameters. Any future client credential transport-parameter implementation would therefore be unsafe.
- Runtime evidence: every rustls QUIC constructor in `src/qftls.rs` receives `Vec::<u8>::new()` transport parameters. The later QKey mutation is read only by unused provider accessors, and the peer setter has no runtime caller. `src/implementations/server/mod.rs` already supports encrypted HTTP/3-header authentication and blocks protected forwarding until authentication.
- The dead trait methods, provider fields, parser/encoder, connection wrappers, unreachable server authentication branch, and four obsolete transport-parameter tests are removed. The real H3 injection tests now call the production helper instead of a duplicated stub.
- Two table-driven regressions cover the complete H3 authentication outcome matrix and the shared fail-closed payload gate used by MASQUE and stream delivery. The runtime guardrail now fails on any reintroduced QKey transport-parameter producer, parser, accessor, server branch, or confidentiality overclaim.
- Post-fix local validation passes 1,673/1,673 library tests plus every binary, integration, runtime, parity, security, and example target. `qkey_auth_integration` proves untrusted TLS fails before H3, public establishment follows rustls completion, valid encrypted H3 authentication succeeds, and invalid authentication closes fail-closed. Workspace Clippy passes with `rust-tests` and warnings denied. The local AArch64 Linux cross-check reaches the `ring` build script but cannot run because this Mac lacks `aarch64-linux-gnu-gcc`; native GitHub ARM64 CI and repeated Omega proof remain open.
- Native Windows CI and the Clippy matrix passed on commit `eb283d2`. The first Omega deployment probe exposed a real release gap: the existing Linux server bundle is x86_64 while Omega is AArch64. The release workflow now builds a separate native `linux-arm64` server bundle on GitHub's ARM64 runner and blocks tagged publication on that artifact. Omega proof must use that exact native artifact rather than installing a Rust toolchain on the server.
- The first native ARM64 Omega probe exposed three real runtime defects rather than a QKey cryptographic failure: pre-header packets were committed as `auth_failed`, transport liveness was exposed as application readiness before rustls completed, and TLS verification errors were swallowed as possible probe traffic. QKey datagram authentication now has explicit Pending/Authenticated/Rejected progress, `Connection::is_established()` requires rustls completion, and terminal TLS errors propagate through Core to the CLI.
- Local UDP CLI proof uses a CA-signed `CA:FALSE` P-256 leaf for `cloudflare-dns.com`. The trusted run completes TLS in 17.6 ms, sends HTTP/3 immediately, and records `client_authenticated`; the same server without the CA exits status 1 with `UnknownIssuer` before HTTP/3. The integration harness now also proves that an untrusted certificate fails before QKey authentication and that public establishment never precedes TLS completion.
- Live proof also exposed 5 ms info-log spam and a finite-`RLIMIT_MEMLOCK` hazard. Client statistics are now emitted at most once per second. `MCL_FUTURE` is enabled only with an unlimited memlock budget; finite or unreadable limits use `MCL_CURRENT`, while per-block locking remains best-effort. This preserves full systemd protection with `LimitMEMLOCK=infinity` without allowing a standalone server's future allocations to fail with `ENOMEM`.
- No UI change is required or allowed.

## Deviations

None.
