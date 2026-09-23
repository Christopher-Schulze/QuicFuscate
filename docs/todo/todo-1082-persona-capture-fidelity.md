---
id: TODO-1082
title: Prove every enabled browser persona from real wire captures
severity: MED
phase: S
priority: P2
status: OPEN
created: 2026-09-23
depends_on: [TODO-1047]
---

# TODO-1082: Persona capture fidelity

## Why and evidence

TODO-1047 asks for a captured ClientHello and transport parameters per browser
persona but is DONE with one Chrome wire capture, Firefox neqo source
constants, and a Safari `unverified-catalog` entry in
`crates/qf-stealth/fixtures/transport_params.toml`. The freshness audit warns
on unverified entries rather than failing. Reusing a fixture table does not
prove that actual rustls QUIC Initial bytes match any browser's wire image.
Derived Edge/Opera/Brave profiles need the same provenance decision.
The Engine and standalone defaults prefer QUIC v2 (`["v2", "v1"]`), but the
Chrome fixture records transport parameters and ClientHello fields without
an explicit captured QUIC wire version. A v1-derived persona cannot be
called first-flight equivalent to a v2 default without a v2 browser capture:
v2 changes the visible version, long-header type bits and Initial
protection. Record the captured version per sample and compare only against
the same emitted version; keep v1 and v2 as negotiated versions of the same
tunnel, not separate persona implementations.
The new `transport_params.rs` also converts signed TOML integers with `as
u64`, so a negative fixture value would become a huge advertised value.
Embedded fixture parsing, required-key lookup and transport-parameter
encoding use `expect`/`panic` on first production use; `framed_param_value`
checks framing but not that the supplied parameter ID is actually
`version_information` (0x11). The checked-in fixture currently parses, so
this is a fixture-integrity and future-edit failure path, not evidence of a
presently crashing normal run.
The publicly exported `decode_transport_params` helper is used only by
tests in this repository, yet panics on a truncated or overlong untrusted
block through `expect` and `assert!`. Keep it as a bounded diagnostic/test
parser with a typed failure result instead of an externally callable panic.
`scripts/capture/quic_initial_listener.py` wraps each received UDP payload
in invented Ethernet/IPv4/UDP headers with fixed loopback addresses, TTL 64,
IP ID 0x1234 and no UDP checksum. That pcap is useful for decrypting the
browser's QUIC Initial, but it is not evidence of the browser's real outer
IP/UDP persona. The helper opens `--out` with `wb`, silently truncating an
existing capture. `wrap_frame` has no explicit maximum-payload check before
writing the 16-bit IPv4 total length; a direct oversized input raises at
`struct.pack`, although the helper's IPv4 UDP socket cannot normally receive
such an oversized datagram. `--count` and `--port` also lack explicit range
validation. These are capture-integrity and diagnostics defects in a new
session tool, not a claim that the current fixture is bad.

## Target contract

- Each enabled browser/OS persona has a dated, versioned, reproducible
  first-party packet capture from the named browser and platform, or is
  explicitly labeled experimental and excluded from automatic selection.
  Source constants alone cannot be described as a wire capture.
- Compare actual emitted ClientHello, QUIC transport parameters, ALPN,
  extension order, key-share offer, SNI/ECH behavior, packet number/Initial
  framing, selected QUIC version and relevant HTTP/3 settings against the
  captured session.
  Document unavoidable rustls/kernel differences as measurable deltas, not
  silently synthetic values.
- Label the synthetic listener pcap as QUIC-payload evidence only. Outer
  IP/UDP persona proof uses an actual network-interface capture from
  TODO-1085. Capture helpers refuse an existing output path, validate port,
  count and IPv4/UDP length bounds before writing, and close/flush artifacts
  on errors without presenting a partial pcap as a complete sample.
- The freshness gate fails for any enabled verified persona older than the
  repository's six-month limit and for any enabled persona with no qualifying
  capture. Keep existing provisional fixtures readable for investigation.

## Implementation and proof

- [ ] Inventory every selectable persona and its current fixture provenance,
      including default/random selection and derived browser variants.
- [ ] Capture Firefox, Safari/WebKit, Edge, Opera and Brave where enabled;
      preserve browser build, OS, capture command, raw pcap hash, timestamp,
      and decoded field manifest. If a capture is unavailable, disable that
      persona from automatic selection and state the limitation.
- [ ] Extend the audit to compare actual generated Initial/ClientHello output
      with each captured manifest, including supported ECH behavior. Require
      a recorded v1 or v2 version for each capture; compare the version,
      long-header type, Initial protection and Retry path against the actual
      configured first dial. A v1-only capture cannot certify a v2 image.
- [ ] Validate the embedded fixture's numeric range, required keys, known
      `sends` names, type-specific values, bounded GREASE length, and
      `version_information` ID before it can enter the runtime. Reject
      negative TOML integers before conversion; make malformed caller input
      return a typed error rather than panic. Keep a single validated
      fixture representation for both flow control and wire encoding.
- [ ] Add failable malformed-fixture and malformed-framed-parameter tests:
      negative and overlarge numbers, missing required key, unknown `sends`
      name, wrong parameter ID, truncated length and oversized GREASE.
      Make `decode_transport_params` return an error for truncated varints,
      out-of-bounds value lengths and duplicate IDs; update root/crate test
      callers to assert the same decoded values through that result.
- [ ] Reconcile TODO-1047 and documentation with the measured support matrix.
- [ ] Make `quic_initial_listener.py` create the output exclusively, validate
      CLI ranges and wrapper input length, report a clear capture failure
      on oversize/truncation, and include an explicit synthetic-link-layer
      provenance marker in its artifact manifest. Test existing-file refusal,
      invalid port/count and maximum legal IPv4 UDP payload. Keep its output
      out of TODO-1085's real outer-header proof set.

## Acceptance

- 100% of automatically selectable personas have a passing, fresh capture
  manifest; zero unverified-catalog personas are selected automatically.
- The test fails when any compared wire field drifts, when a capture expires,
  or when the declared browser/OS does not match its artifact metadata.
- The support matrix names every deliberate difference and its measured wire
  effect; no persona is marketed as capture-equivalent without that proof.
- A malformed embedded fixture is caught by the repository gate before
  release; malformed runtime parameter input returns an error without a
  process panic or wrapped/overflowed advertised value.
- The capture helper never truncates an earlier pcap, rejects an impossible
  IPv4 packet length with a clear error, and cannot be mistaken for physical
  IP/UDP-header evidence.
