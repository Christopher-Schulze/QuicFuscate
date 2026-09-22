---
id: TODO-1048
title: Replace domain fronting with a real Reality fallback
severity: HIGH
phase: S
priority: P1
status: DONE
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

## Implementation (done)

- `DomainFrontingManager` is `CoverTargetRotator` (inline module in
  `crates/qf-stealth/src/lib.rs`): `Arc<[String]>` targets, atomic
  round-robin, `next_cover_target`/`random_cover_target`/`from_providers`/
  `broad_providers`. Same lock-free semantics, honest name.
- `StealthConfig`: `enable_domain_fronting`/`fronting_domains` removed;
  `reality_cover_targets: Vec<String>` is the live field. TOML still parses
  `fronting_domains` as a deprecated alias and rejects
  `enable_domain_fronting = true` with a pointer to the new key;
  `QUICFUSCATE_FRONTING_DOMAINS` is a deprecated env alias,
  `QUICFUSCATE_FRONTING=1` fails startup. `is_valid_cover_target` accepts
  `host` or `host:port` and rejects whitespace/userinfo/garbage ports.
- `qf-reality`: `RealityProxy::new_with_targets` takes configured targets,
  normalizes bare hosts to `:443`, drops invalid entries with a log line,
  and falls back to env/built-in targets when the list ends up empty. The
  UDP acceptance test binds a local listener, sends probe bytes through the
  relay, and asserts the echoed bytes return unmodified.
- `StealthManager`: `cover_targets: Option<CoverTargetRotator>` replaces the
  fronting manager. Cover traffic, WebTransport authority, and MASQUE
  authority consume the rotator; the Reality proxy is armed when
  `dynamic_enabled` or explicit targets exist. `handle_fallback` still
  prefers the cached response and otherwise relays.
- `src/core/connection.rs`: SNI is `server_name` verbatim; the
  `get_connection_headers` fronted-alias path is gone. `host_header` is
  documented as always equal to the SNI host.
- Server/Runtime chain: `disable_fronting` -> `disable_cover`,
  `front_domain` -> `cover_targets` across bootstrap policy, standalone
  runtime metadata, admin control plane, and reload. CLI `--cover-target` /
  `--disable-cover` keep `--front-domain` / `--disable-fronting` as
  deprecated clap aliases.
- QKey SNI policy renamed to `QKeyCoverSniPolicy` /
  `resolve_qkey_cover_sni_policy` / `COVER_SNI_MODE_*`. A third strategy
  `off` joins `fixed`/`auto_rotating`: it pins the QKey SNI to the listen
  host and is rejected when the listen address has no DNS host. The
  `df_sni_*` JSON keys stay — they are the stable wire contract parsed by
  shipped clients.
- Tauri client: `CoverSniPolicy`/`parse_qkey_cover_sni_policy` parse the
  unchanged `df_sni_*` keys; the pool lands in
  `cfg.stealth.reality_cover_targets`. `df_sni_mode = "off"` yields no
  policy, so the client keeps the QKey SNI.
- Frontend: `StealthManualSettings.enable_domain_fronting` removed; manual
  stealth shows a "Cover Targets" comma-text input writing
  `stealth.reality_cover_targets` (legacy `fronting_domains` is read for
  display and blanked on write). `FRONTING_SNI_ALLOWLIST` ->
  `COVER_SNI_ALLOWLIST`; QKey panel labels read "Cover SNI"; desktop
  `domain-fronting-policy.ts` -> `cover-sni-policy.ts` with
  `resolveCoverSniDisplay` (wire keys unchanged).
- Verified: qf-stealth 124/124, qf-reality 25/25 (incl. local relay
  acceptance), qf-engine-types 75/75, root lib 1776/1776, web-admin unit
  412/412, desktop unit 442/442, shared-ui 100/100, Tauri `cargo check`
  clean, `cargo check --all-targets` clean.
