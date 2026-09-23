---
id: TODO-1092
title: Bind issued QKey SNI to the actual authenticated endpoint
severity: HIGH
phase: S
priority: P1
status: OPEN
created: 2026-09-23
depends_on: [TODO-1048, TODO-1080, TODO-1081]
---

# TODO-1092: QKey SNI and certificate binding

## Why and evidence

`src/implementations/server/qkey_issue.rs` issues a QKey whose default SNI
is the first global CDN allowlist entry, and fixed/rotating modes also select
from that global list. Allowlist membership does not establish that the
configured server endpoint presents or legitimately relays a certificate for
the name. `apps/tauri/src-tauri/src/main.rs::build_engine_config_from_qkey`
then discards the QKey SNI for recognized cover policies and uses the remote
endpoint host, while `src/implementations/client/backend.rs` retains the
QKey SNI for the standalone client. Consequently the two clients can dial
the same QKey with different TLS names; either may fail certificate validation
or make the claimed cover identity false, depending on deployment. Existing
policy comments assert certificate ownership without validating it.
The `off` policy says it requires a DNS listen host, but
`is_valid_sni_host` accepts an IPv4 literal such as `127.0.0.1`, and
`extract_host_from_endpoint` passes it through. The corresponding test only
rejects IPv6 literals. Issuance therefore conflates a DNS SNI identity with
an IP SAN identity for this mode.
The desktop `parse_qkey_cover_sni_policy` also invents a six-name built-in
pool when an `auto_rotating` QKey omits or empties `df_sni_pool`, while the
server's current pool has a larger fixed list and a valid QKey already
carries its chosen pool. That desktop fallback can select a cover name the
QKey did not authorize. Treat a missing/empty legacy pool as a typed
compatibility case bound to the deployment, not as permission to rotate
through client-local CDN names.

## Target contract

- Issue and consume TODO-1075's one validated entry binding; reject a QKey
  that would require desktop and standalone clients to infer different TLS,
  ECH, HTTP authority, cover, or carrier identities. Preserve separation
  between authenticated entry identity and unauthenticated probe cover origin.
- A QKey identifies an endpoint, a TLS server name, and an authenticated
  certificate/CA relationship that every client interprets identically.
  Issuance validates that relationship against configured deployment
  certificate names or a real relay binding, not a static list of famous
  CDN names. A cover name is eligible only when the deployed hop can actually
  complete a valid TLS handshake for it.
- Direct dedicated-IP tunnel QKeys use a certificate-valid name belonging to
  the deployment. Shared outer-hop QKeys use the selected outer service's
  certificate name and ECH service binding from TODO-1081. Probe cover targets
  are separately labeled and must not silently become the tunnel's SNI.
- Validate DNS names and IP literals as distinct identity types. A numeric
  endpoint may use a matching IP SAN under a direct profile, but must never
  be labeled or serialized as a DNS cover SNI; reject malformed host labels,
  wildcard syntax outside the certificate contract and unspecified listen
  addresses before issuing a dialable QKey.
- Desktop and standalone clients derive the same effective SNI from the same
  QKey. Legacy `df_sni_*` fields remain parseable, but ambiguous or unsafe
  legacy names or an absent/empty auto-rotation pool produce an explicit
  compatibility error or a documented, certificate-valid migration; no
  client-local fallback list or silent substitution.
- Operator override is validated and clearly marked as changing the
  authenticated identity. Debug-only certificate bypass never masks a
  production mismatch.

## Implementation and proof

- [ ] Trace QKey issue/parse/desktop/standalone/outer-hop TLS constructor
      signatures and current certificate validation, including IP SAN and
      hostname SAN behavior.
- [ ] Replace the global CDN eligibility assumption with deployment-bound
      certificate/relay capability. Keep old wire keys only for compatibility.
- [ ] Unify effective-SNI derivation across clients and validate it before
      dialing. Separate probe cover-target rotation from tunnel TLS identity.
- [ ] Use local certificates and listeners to test matching and mismatching
      SANs, direct-IP and DNS endpoints, desktop and standalone parity,
      legacy QKeys, fixed/rotating/off policy, and shared ECH outer hop.
- [ ] Add a desktop/standalone parity case for an `auto_rotating` legacy QKey
      with absent and empty `df_sni_pool`; neither client may invent an
      unbound cover name, and a valid server-issued pool stays intact.
- [ ] Exercise `off` issuance for DNS host, IPv4/IPv6 literal, wildcard and
      malformed labels, and unspecified listen address; assert the emitted
      TLS name type and certificate SAN result, not only string acceptance.
- [ ] Correct QKey UI labels, defaults, server policy comments, TODO-1048
      and product documentation to state what the endpoint can prove.

## Acceptance

- Same QKey yields the same authenticated SNI and certificate result in both
  clients. Zero issued default QKeys depend on an unproven third-party CDN
  certificate at a dedicated tunnel endpoint.
- A mismatched certificate or unsupported cover name fails issuance or dial
  with a named cause; a matching local endpoint completes a verified TLS
  handshake in the integration test. No test relies on `verify_peer=false`.
