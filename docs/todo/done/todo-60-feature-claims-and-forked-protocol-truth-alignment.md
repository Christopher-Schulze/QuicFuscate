# TODO 60: Feature Claims and Forked Protocol Truth Alignment

## Scope
- Public and internal truth surfaces across:
  - `src/lib.rs`
  - module headers/comments in runtime-critical files
  - `docs/DOCUMENTATION.md`
  - `docs/MAP.md`
  - any support-state or protocol-positioning text

## Problem Statement (Audit Evidence, 2026-03-05)
- Top-level feature claims still overstate what is currently canonical runtime truth.
  - Evidence: `src/lib.rs:5`-`:9`
- The project is now explicitly a full fork, but some wording still reads like standard QUIC-adjacent optimization layering rather than hard protocol divergence.
- Custom 1-RTT AEAD posture is valid only under the fork assumption and should be presented as such.
  - Evidence: `src/transport/packet.rs:1178`-`:1181`; `src/crypto.rs:9320`, `:9359`, `:9455`

## Objectives
- Make feature claims honest about runtime ownership and support state.
- Make protocol posture honest about the fork and ecosystem divergence.
- Remove marketing/documentation overclaim that exceeds actual runtime integration.

## Work Breakdown
### A. Feature-State Honesty
- [x] Audit top-level/module-level claims against canonical runtime wiring.
- [x] Downgrade or reword claims that overstate active integration.

### B. Forked Protocol Posture
- [x] Document fork-only protocol decisions explicitly, including custom 1-RTT AEAD posture and implications for interoperability/upstream parity.
- [x] Align module comments with the fact that this is no longer aiming at upstream-compat semantics by default.

### C. Internal Comment Hygiene
- [x] Review module headers and major comments for hype/overclaim versus actual runtime truth.
- [x] Replace mismatched wording with precise ownership/support-state language.

### D. Guardrails
- [x] Add checks or review checklist items for future overclaim drift in module headers and docs.

## Acceptance Criteria
- [x] Public/internal text matches actual runtime truth.
- [x] Fork posture is explicit and technically accurate.
- [x] Canonical runtime path and feature state are not overstated anywhere obvious.

## Deliverables
- [x] Updated truth-aligned feature/protocol wording.
- [x] Fork-posture documentation notes.
- [x] Anti-overclaim review/guardrail additions.

## Progress Notes
- 2026-03-05: Created from deep review after feature/runtime contract work exposed remaining overclaim and protocol-posture ambiguity.
- 2026-03-08: Closed the first top-level truth-alignment burst across `src/lib.rs`, `src/implementations/server/mod.rs`, `README.md`, and `docs/DOCUMENTATION.md`. Top-level wording now states explicitly that QuicFuscate is a forked runtime, not a drop-in upstream QUIC implementation; the server module header no longer claims a generic production-ready server surface; README feature claims now distinguish canonical runtime features from compatibility-only MASQUE/XOR surfaces and present custom data-plane AEAD as a fork-specific posture rather than a TLS/standards claim. Added runtime-audit guardrails to keep the fork posture and non-overclaim server header wording in place.
- 2026-03-08: Continued the same burst in runtime-critical module comments. `src/core.rs` now describes the canonical forked connection runtime instead of a generic "full QUIC connection lifecycle", and `src/reality.rs` no longer claims to prove that the fork is a standard QUIC server. Added audit guardrails to prevent those module-level overclaims from reappearing.
- 2026-03-08: Continued the top-level truth sweep in `README.md` and `docs/DOCUMENTATION.md`. Surface-maturity wording no longer claims release-ready or feature-complete product status, and the TLS boundary section now states explicitly that custom 1-RTT data-plane AEAD is a fork-specific transport decision rather than a TLS cipher-suite or upstream interoperability claim. Added audit guardrails for both surface-maturity overclaim and AEAD-vs-TLS boundary wording.
- 2026-03-08: Continued the forked AEAD truth sweep into runtime-adjacent comments. `src/transport/packet.rs` now describes 0-RTT/1-RTT as following the forked data-plane AEAD contract, and `src/crypto.rs::install_data_aead_config(...)` now states explicitly that the data-plane AEAD choice is not a TLS cipher-suite decision. Added audit guardrails so those runtime-near comments keep the forked posture explicit.
- 2026-03-08: TODO 60 is complete. Top-level crate/docs wording, runtime-critical module comments, surface-maturity text, and forked data-plane AEAD language now consistently describe the forked runtime instead of implying upstream QUIC or broader product maturity. The runtime audit suite now guards the main reentry points for this truth surface.
