---
id: TODO-1048
title: Replace domain fronting with a real Reality fallback
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-21
depends_on: [TODO-1047, TODO-1062]
---

# TODO-1048: Replace domain fronting with a real Reality fallback

## Why

Domain fronting sends an SNI that does not match the certificate. Google and Cloudflare reject that. An active probe then sees a certificate error, which is a tell. Reality is the replacement: without the tunnel secret the peer completes a real handshake to a cover site; with the secret the tunnel runs. The project already has a Reality proxy. It is a second mechanism next to fronting, and the fallback is not required to be a byte-real relay of that site.

## Current code

- `StealthConfig.enable_domain_fronting` and `fronting_domains` in `crates/qf-stealth/src/stealth_config.rs`.
- `src/stealth/manager.rs` returns `(fronted_domain, real_host)` from the fronting manager when the flag is on.
- `StealthConfig::stealth_max()` turns fronting and rotation on. `dynamic` starts from the performance preset and can escalate.
- Reality proxy is constructed when `dynamic_enabled` is set (`manager.rs` around the `reality_proxy` init). Cover targets include Cloudflare, Google, and Quad9 style relays.
- `DomainFrontingManager::broad_provider_rotation` is the rotation helper. It is not a second stealth mode name.

## Target

One mechanism.

- Delete the operator-facing "SNI != certificate host" behavior. `enable_domain_fronting` goes away. Existing configs that set it true fail validation with a pointer to Reality cover targets, or map onto the cover-target list only when the target is also the certificate name.
- The cover-target list is the old fronting domain list, filtered to hosts whose certificate the proxy will actually present or relay.
- Probe with no valid tunnel authenticator: TCP or UDP bytes are relayed to the live cover origin. The proxy does not synthesize a ServerHello. It does not use `key_share_ext`.
- Probe with a valid secret: the tunnel proceeds. Its ClientHello is the rustls persona hello from TODO-1047, and the SNI equals the name on the certificate the client is supposed to see for that hop.
- `stealth_max()` stops enabling fronting. It enables the Reality cover-target relay instead.

## Non-goals

- No XTLS Vision port (TODO-1063). Vision splices inner TLS onto TCP. This task does not add a second TLS record layer.
- No new cipher.
- No frontend visual change. Config key removal is a schema change; UI labels stay until a separate visual task.

## Design

1. Inventory every read of `enable_domain_fronting`, `get_fronted_domain`, and `fronting_domains`.
2. Add `reality_cover_targets: Vec<CoverTarget>` with host, port, and expected certificate name. Default list is the current built-in providers that can complete a handshake.
3. Active-probe path: if authentication fails, `relay_bidirectional` to the selected cover target using the already accepted socket bytes, including the ClientHello already received. Do not parse and rebuild it.
4. Validation: a cover target whose SNI hint differs from `certificate_name` is a config error.
5. Tests that expected split SNI/Host are rewritten to expect a relay or a rejection.

## Sub-Tasks

- [ ] Config and serde: reject or map `enable_domain_fronting`.
- [ ] `stealth_max()` and escalation stop setting the old flag.
- [ ] Probe failure relays to a live target; a unit test uses a local TLS listener as the cover origin.
- [ ] Authenticated path does not open the relay.
- [ ] Docs and `config/quicfuscate.toml` comments name Reality targets, not fronting.

## Acceptance

- No production path sets a QUIC/TLS SNI different from the certificate name of that hop.
- An unauthenticated probe against a test listener receives the listener's real handshake bytes, unmodified by the proxy.
- `stealth`, `Stealth MAX`, and `dynamic` still come up with AES-GCM payload (mode pin unchanged).

## Tests

- Local cover listener with a known certificate. Probe transcript equals a direct connection to that listener, aside from TCP/UDP metadata.
- Config with mismatched SNI and certificate name fails `validate`.

## Risks

- Relaying to a public site from tests must not hit the network. The acceptance test is local only.
- A dedicated VPN IP is still the identity. This task removes the certificate mismatch. It does not hide the IP. Shared-IP hiding is TODO-1063 and TODO-1064.
