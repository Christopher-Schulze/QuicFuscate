# TODO-1045: Drop homemade AEGIS/MORUS, keep rustls AES-GCM-128 and libaegis

- Status: DONE
- Result (2026-09-21): first-party `aegis`/`morus` modules and `src/optimize/crypto/morus.rs` deleted, `PrivateAeadFamily` has only `Aegis128L` (protocol id 1; removed MORUS id 2 unassigned), `force_aead` accepts only `auto`/`aegis` and rejects `morus` spellings, `standard`+private conflicts and `advanced-required` without family both fail closed in `CryptoConfig::validate`, `payload_protection_pin` wires `performance`/`off` to libaegis and every stealth mode to rustls AES-128-GCM. `cargo test -p qf-crypto --lib` 104/104 green including `libaegis_matches_pinned_cfrg_aegis128l_vector_1`. `cargo check --lib --bins` clean. Grep finds no `MorusAead`/`Morus1280_128`/`mod morus`/`mod aegis` under `crates/qf-crypto`. Bench owners `S-AEGIS-X2`/`S-AEGIS-X4` added for measurement only; pin stays 128L.
- Payload pin (2026-09-21): `[stealth] mode = "performance"` (alias `base`) is the only mode that offers libaegis AEGIS-128L for post-auth 1-RTT payload (`payload_protection_pin(true)` = `Auto` + `PrivateAeadFamily::Aegis128L`). `off`, `stealth`, `anti-dpi`/`max`, `intelligent`/`auto`, and `manual` pin rustls AES-128-GCM for the whole connection. Both peers must be in performance mode or the upgrade does not complete. Handshake, Initial, header protection, and pre-auth 1-RTT stay AES-128-GCM in every mode. No L/X2/X4 runtime switch and no trial decrypt. Shipped config stays `mode = "auto"`, so the default remains AES-GCM.
- macOS ARM profile 2026-09-21, P1 median ns, iters 400, owners R-RING / S-AEGIS / S-AEGIS-X2 / S-AEGIS-X4: 64 B 125 / 125 / 208 / 458; 1200 B 500 / 292 / 375 / 625; 1400 B 584 / 334 / 375 / 625; 8192 B 2667 / 1333 / 1292 / 1500. L wins 64, 1200, and 1400. At 8192 X2 is one timer bucket ahead of L (1292 vs 1333).
- Omega Neoverse-N1, same owners and sizes, iters 400, P1 median ns, R-RING / S-AEGIS / S-AEGIS-X2 / S-AEGIS-X4: 64 B 280 / 240 / 400 / 920; 1200 B 1120 / 680 / 840 / 1400; 1400 B 1280 / 720 / 920 / 1440; 8192 B 6160 / 3040 / 3200 / 4000. L wins every size, including 8192. X4 is slower than rustls AES-GCM at 64, 1200, and 1400.
- Pin: AEGIS-128L. Both hosts agree on the QUIC sizes. X2 and X4 stay measurement owners only.
- Date: 2026-09-21

## Why

Same-API P1 1400 evidence (macOS ARM and Omega Neoverse-N1) already picked the owners. Further homemade kernels do not beat libaegis, and MORUS does not beat rustls AES-GCM-128 on hosts that have hardware AES. Shipping a first-party cipher next to an audited library keeps the "we rolled our own" surface for no speed win.

## Keepers

- Ship default stays `packet_protection_mode=standard`: rustls AES-GCM-128 for Handshake and pre-auth 1-RTT, ring AES-128-GCM plus AES header protection for QUIC Initial, ring ChaCha20-Poly1305 for the production ChaCha owner. `CryptoConfig::default()` stays `Standard`. Config files stay `standard`.
- Opt-in speed owner is libaegis only (`aegis` crate `=0.9.18`, Frank Denis / jedisct1, MIT). It is a normal `qf-crypto` dependency, not a compile feature and not a QUIC or TLS cipher suite. The shipped config (`[stealth] mode = "auto"`) never calls it. Performance mode is the only caller, via `payload_protection_pin`. `aead_preference` and `force_aead` do not select it.
- `aead_preference="auto"` and empty/`auto` `force_aead` install no private family. They do not select libaegis.
- `standard` plus any private selection still fails validation. `advanced-required` still requires an explicit family and still fails closed at engine construction until TODO-1029.
- Header protection stays standard AES. Pipeline stays pad inside QUIC, then AEAD plus header protection, then timing, then FEC of the sealed datagram.
- `rustls-aws-lc` stays a non-default feature. Ring stays the rustls crypto provider.
- First-party AES-GCM and ChaCha remain only as test oracles and the QKey legacy-envelope fixture. They are not the live packet owner.

## Why libaegis is not the default

Speed is not stealth. Chrome and QUIC payload protection are AES-GCM or ChaCha20-Poly1305. A peer or middlebox that has the handshake keys can open AES-GCM and cannot open AEGIS. Without keys, a 10k x 1400 B nearest-mean distinguisher on ciphertext byte 0 stayed at about 0.50 accuracy (`cheap_keyless_distinguisher=false`), so AEGIS is not a visible banner. The stealth cost is "not Chrome-identical". libaegis is audited third-party code, and it is still not a QUIC cipher suite. That is why it stays opt-in.

## Evidence that homemade is out (do not re-bench to reopen this)

P1 median ns, lower is faster. Decision size is 1400 B.

- macOS profile, iters 800, after NEON AESENC: R-RING 584, S-AEGIS 334, C-AEGIS-L 750, C-AEGIS-X4 792, C-MORUS 1167.
- Omega iters 400, after NEON AESENC: R-RING 1320, S-AEGIS 720, C-AEGIS-L 1360, C-MORUS 2360.
- After register-resident MORUS: macOS P1 1400 R-RING 625, S-AEGIS 334, C-AEGIS-L 791, S-MORUS 1375, C-MORUS 833. Omega P1 1400 R-RING 1280, S-AEGIS 720, C-AEGIS-L 1360, S-MORUS 2680, C-MORUS 2080.
- Custom MORUS beat the `morus` 0.1.3 crate and still lost to rustls and libaegis on both ARM hosts. That is an algorithm gap (8 AESENC per 32 bytes versus 5 rotate/AND/XOR rounds), not a missed kernel.
- No SIMD wrapper around libaegis. libaegis already is the hardware-AES kernel. P2 batch was about the same ns/packet as P1.

## Remove

- First-party AEGIS: `crates/qf-crypto/src/aegis.rs`, `aegis/aegis_aes_block.rs`, `aegis/batch.rs`, `aegis/tests.rs`. Widths L, X4, and X8. No stub module.
- First-party MORUS: `crates/qf-crypto/src/morus.rs`, `morus/state_ops.rs`, `morus/morus_tests.rs`.
- Unused duplicate `src/optimize/crypto/morus.rs` (not a compiled module).
- `morus` crate `=0.1.3` dependency and every bakeoff owner that needs it (`S-MORUS`, `C-MORUS`, `C-AEGIS-L`, `C-AEGIS-X4`, `C-AEGIS-X8`). `--match-x` goes with the widths.
- `PrivateAeadFamily::Morus1280_128` and `DataAeadPreference::Morus`. Wire family id `2` fails closed (`InvalidField`). Supported-family mask accepts only bit 0 (protocol id 1, AEGIS-128L). A mask that sets the old MORUS bit is invalid.
- `force_aead` spellings `morus`, `morus-1280-128`, `morus1280-128` fail `CryptoConfig::validate`. They are not a private family.
- Product construction no longer calls `CryptoAeadPlan::select_for_len`. `select_data_aead`, `select_packet_data_aead`, `select_private_packet_data_aead`, and `build_data_aead_for_benches` build `LibAegis128L` only. `BenchDataAeadBackend` keeps `Aegis128L` only.
- Feature `advanced-aead` on `qf-crypto` goes away because libaegis is always linked. The root feature name stays as an empty alias so old `--features advanced-aead` commands still parse. It does not change the binary.
- `qf-cpu::CryptoAeadPlan` and `Aegis128Profile` stay. They are no longer on the product cipher path. Deleting them is a separate optimizer cleanup, not this cut.

## What stays true

- TODO-1029 stays UNAVAILABLE. Production private enable stays blocked. Do not fake a pcap.
- TODO-1031 stays OPEN. Do not implement 0-RTT.
- TODO-1028 stays REFUSED. `auto` does not freeze a family.
- TODO-1033 stays DONE. Do not flip the ship default to libaegis.
- No frontend. No Docker. No commit unless asked.

## Acceptance

- `cargo test -p qf-crypto --lib --offline` passes, including a CFRG AEGIS-128L vector against the `aegis` crate and a private-owner roundtrip, forgery, wrong-AD, and QUIC-size test through `select_private_packet_data_aead`.
- Packet private-owner test still seals and opens, using `PrivateAeadFamily::Aegis128L`.
- Private negotiation: family id 2 is rejected; a selection whose family is not the local AEGIS choice fails closed; a server with no family still falls back or terminates.
- `CryptoConfig` with `force_aead="morus"` fails validation. Default config validates and requests no private family.
- Grep of `*.rs` has no `MorusAead`, `Morus1280`, `Aegis128X4`, or `mod morus` / `mod aegis` under `crates/qf-crypto`.
