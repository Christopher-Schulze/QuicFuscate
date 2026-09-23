---
id: TODO-1091
title: Finish complete lake-rooster changed-path evidence audit
severity: MED
phase: M
priority: P1
status: STOPPED
created: 2026-09-23
depends_on: []
---

# TODO-1091: Complete lake-rooster changed-path audit

## Disposition (2026-09-23)

The user ended this audit and explicitly instructed that no more Devin CLI
inspection be done. Preserve the inventory and the verified findings below
as historical evidence. The unchecked steps remain unverified, not complete;
resume only if the user gives a new explicit instruction.

## Why and evidence

The current review identified concrete defects in Reality, ECH, fallback,
benchmarking, capture integrity, persona proof, migration, 0-RTT and docs.
The session spans commits `c8ed2976` through `9d8cee50` and 326 changed
paths. Earlier review read the conversation/history and high-risk paths but
did not verify every raw tool output or every changed path. Calling the
entire implementation 100% audited would overstate the evidence.

Audit continuation (2026-09-23): `devin list --format json` confirms
`lake-rooster`. Its `cli/transcripts/lake-rooster.json` ends at
2026-09-22T22:09:20Z and is not the final session state; Devin CLI's
`sessions.db` has later message nodes and confirms the last work on
TODO-1071 after commit `9d8cee50`. Git independently confirms 52 commits
and 326 net changed paths. A newly verified cross-cutting defect is the
missing RFC long-header Length field (TODO-1095); the analyzer's private
format accommodation does not prove a standards-compliant wire image.
A read-only inventory of the Devin CLI database found 19,598 stored message
nodes on multiple branches, 11,465 unique message IDs and 6,331 distinct
tool-result messages. Their inline result content totals about 13.96 MB;
304 truncated results link to 304 still-present overflow files totaling
about 3.97 MB. A fresh message-ID-deduplicated scan found 192 distinct tool
results whose content ends in a nonzero `Exit code:` line; this replaces the
earlier 188 estimate. It includes intermediate failures, not 192 current
product defects. This is an inventory, not a semantic review of every result
or a 52/52 commit and 326/326 path disposition. The abbreviated 108-step ATIF
export ends before the last session work and cannot stand in for the CLI
database plus overflow files.
The main chain ends at node 19597; nodes 19316, 19409,
19502 and 19595 are transcript-export-only user requests, each answered
`OK`. The last substantive work immediately before those requests was
post-commit TODO-1071 investigation: Devin observed that the `fec_pipeline`
Criterion filter selected zero registered groups and that a broad bench
build on the primary host was killed by `systemd-oomd`. The current TODO-1071
detail owns both failures. The later export-only turns do not constitute a
completed benchmark run or a final implementation change.
This checkpoint also compared the changed crypto safety-audit gate with the
current `qf-crypto` source: its former nonempty-unsafe requirement was
removed when no `unsafe fn` remains in that crate. That change alone is not
a safety-contract bypass finding. The GeoIP feature-gate and legacy QKey
registry diffs were inspected without a new verified defect; neither
inspection counts as a complete call-chain disposition for its path.
The CLI's failed `is_in_early_data_requires_active_directional_keys` run at
node 15068 was checked against current HEAD `9d8cee50` with the exact focused
Rust test on 2026-09-23: 1 passed, 0 failed. Later CLI results also show the
QKey HTTP/3 auth and outer-hop MASQUE integration tests passing after their
earlier failures. These historical red runs are not current findings by
themselves; their larger suites and current deployment remain unverified.
The shared About component still presents QUIC v1 as the sole product
protocol even though Engine/CLI defaults prefer v2; TODO-1089 owns the
user-facing version truth. The new admin Cover Targets input is only
rendered under the `manual` preset, while `reality_cover_targets` is
consumed in other modes. TODO-1093 now owns cross-preset visibility and
persistence, distinct from the relay endpoint in TODO-1075/1096.
The desktop QKey parser additionally supplies its own six-name CDN pool
when `auto_rotating` has no usable `df_sni_pool`; a valid current server QKey
already carries a pool, but a malformed/legacy QKey can acquire names it
never authorized. TODO-1092 now requires a typed compatibility outcome and
desktop/standalone parity proof rather than a client-local fallback list.
The current pass also traced `RealityProxy`, `StealthManager::masque_proxy`,
the core H3 CONNECT-IP builder and validator, ECH/fallback ownership tasks,
the browser transport-parameter encoder, and the Maybenot adapter against
the pinned Maybenot 2.2.2 source. TODO-1096 owns the cover-origin versus
proxy-authority role confusion and integrated one-entry rollout; TODO-1082
now owns fixture validation/panic-proofing; TODO-1097 owns the unbounded
same-time Maybenot event feedback. These are source-backed findings, not
evidence that the complete 326-path review has finished.
Further source tracing found that ordinary `stealth` never constructs its
Reality proxy and a separately enabled cover cache can consume a probe
without a sender (TODO-1080); in-QUIC FEC repairs debit only their symbol
body against the claimed wire-byte cap (TODO-1098); and TODO-1029's
production-compiled private-key dump lacks an owned, owner-only artifact
boundary (TODO-1099). The pinned Maybenot event docs also expose event
class/timing drift, now recorded in TODO-1097.
Frontend/QKey review found that pre-existing `auto`/`max`/`anti-dpi` values
now silently map to client `dynamic` while the server leaves an unrecognized
value unchanged; TODO-1100 owns the canonical migration and rejection rule.
The DoH path passes only TLS 1.3 cipher IDs to an independent TCP client,
and its suite replacement removes TLS 1.2 despite the task's contrary claim;
TODO-1101 owns wire-persona proof and the version policy correction.
The TODO-1029 pcap analyzer accepts incomplete captures through silent
parser skips and weak packet-class thresholds; it also reuses the wrong body
offset after updated HP changes PN length. TODO-1102 owns proof completeness.
The crypto benchmark suite's comparison uses filtered `cargo test` wall
durations rather than timed same-API AEAD samples; TODO-1071 now owns this
measurement-label and empty-speedup correction.
The optional deep orchestrator now only receives atomic writes and still
causes process sampling, with no runtime read after server push removal;
TODO-1103 owns removal and the associated documentation truth.
The TODO-1054 cover scheduler begins at captured Initial packets only after
the live handshake, double-debits cover PING padding, and treats plaintext
length as a captured UDP length class. TODO-1104 owns phase alignment,
transactional wire accounting and trace-fixture validation.
The performance regression suite selects a deleted AES-GCM Criterion cell,
and the baseline path it consults has no file. Its empty-filter check is
red, while valid cells cannot enforce the stated percentage thresholds.
It also reverses the throughput comparison, discards Criterion units,
allows a throughput-to-time fallback, and the transport suite stores whole
command duration as its cell result. TODO-1071 owns exact cells, measured
baselines, unit-safe direction-aware gates and result parsing.
The H3 cover request and WebTransport paths pre-charge heuristic header
sizes before QPACK/QUIC output and do not reconcile errors or dropped work;
the one-shot WebTransport plan is claimed before admission. TODO-1105 owns
exact shared-ledger charge and slot disposition for these H3 cover origins.
The in-QUIC FEC receiver raises its epoch floor before decoder admission;
receiver errors can still reject the symbol after that mutation, and the
sender's `u32` wrap conflicts with a plain `<` receive comparison. TODO-1106
owns atomic transition, error-state rollback and bounded epoch semantics.
The current H3/MASQUE header builders inject `x-qf-auth` even into outer-hop
requests. A future shared TLS terminator would see that credential unless
its trust role and inner/outer credential split are explicit. TODO-1096 now
owns an edge-visible transcript proof; no current third-party leak is claimed.
The DoH endpoint constructor synchronously resolves hostname endpoints
through the system resolver before the tunnel is authenticated. With the
Engine kill switch already blocking, startup can fail; without a kill
switch, stealth-mode bootstrap can use ordinary underlay DNS despite the
no-cleartext fallback claim. TODO-1107 owns protected bootstrap selection
and both-runtime proof. This is a source-observed path, not a captured leak.
ECH discovery has only one production caller, the CLI circuit path, and is
absent from public Engine startup. That caller runs before its kill switch
exists and calls the blocking DoH constructor inside an async function;
TODO-1081 now owns common dial ownership and executor-safe preparation.
The new QUIC Initial capture helper truncates an existing output file and
constructs invented IP/UDP headers that cannot prove an OS wire persona.
Its wrapper also lacks an explicit length guard, although a normal IPv4 UDP
receive cannot reach the oversized input. TODO-1082 owns capture integrity
and provenance separation from TODO-1085's actual-interface proof.
Architecture reconciliation of TODO-1075/1083/1096 found their original
direct-first retry rule would bypass the shared address even when the user
configured that benefit as the primary profile. Those tasks now specify
one entry profile with shared-primary selection where bound, direct-only
selection where appropriate, and no fallback below the binding's privacy
or ECH floor. This is a design correction, not a claim that the shared
carrier has been implemented or proved.
The stealth manager additionally invents `cdn.cloudflare.com` as the H3
cover/WebTransport authority when the cover list is empty. TODO-1096 now
requires a validated service or no request, instead of assuming that name
is served by the actual connected peer.
Desktop `TunnelStats` converts `dynamic` to `performance` even though the
Tauri stats field comes from `Engine::active_stealth_mode`, which returns
`StealthManager::mode()` and therefore only the configured `Dynamic` mode.
It cannot report the current Brain escalation. TODO-1108 owns display
truth without inventing another mode.
In QuicFrame mode the FEC absorber strips every received DATAGRAM whose
first byte is `0xFE` before validating the remaining bytes. That shares an
unnegotiated namespace with generic application and H3 DATAGRAMs and
rebuilds the full queue each poll. TODO-1109 owns collision-free routing,
exactly-once delivery and bounded receive cost; no present normal-sized
MASQUE collision is claimed without a reproducer.
The Engine resolves a hostname entry with `to_socket_addrs` only after its
kill switch is blocking. A cold-cache first dial can fail; moving that
lookup before the firewall without authentication would expose underlay
DNS. TODO-1096 now owns the protected pre-dial address/identity binding,
coordinated with TODO-1107's ECH DoH bootstrap.
The TODO-1055 push removal retained a receive-path error-code mismatch:
without any advertised `MAX_PUSH_ID`, `classify_peer_unidirectional_stream`
returns `H3_STREAM_CREATION_ERROR` for a server push type `0x01`, while RFC 9114
Section 4.6 specifies `H3_ID_ERROR`. For a client-initiated push stream at
the server it returns `H3_FRAME_UNEXPECTED`, while Section 6.2.2 specifies
`H3_STREAM_CREATION_ERROR`. TODO-1110 owns both narrow protocol
correction; this does not justify restoring synthetic push cover.
TODO-1057 also introduced an unconditional Unix file-descriptor import in
the exported outer-header module, blocking native Windows compilation.
TODO-1111 owns the cross-platform socket backend and native build proof;
TODO-1085 remains the separate emitted-packet fidelity owner.
The TODO-1051 admitted batch pops control frames, commits Application ACKs
and consumes PTO probes before sealing. Its abort path only restores stream
transmissions; TODO-1112 owns transactional send-state commitment and
fault-injected failure proof, coordinated with TODO-1104's cover ledger.
The qf-hpke adapter enables the pinned `hpke-rs/hazmat` feature solely for
private-key extraction; upstream `Debug` then exposes private-key and
context bytes even though the adapter's wrappers redact their own output.
TODO-1113 owns removal through the existing backend KEM-generation API.
The agent-facing workspace overview still counts thirty-five leaf crates
and omits the session's `qf-hpke` addition; its path table also omits the
existing `qf-stealth` child. TODO-1089 now owns this exact documentation
inventory repair. Its architecture/data-flow summary also still names
removed XOR/fronting/Server Push paths, external FEC wrapping, and Brain
wire-shape mutation; TODO-1089 now owns those stale agent-facing claims.
`RealityProxy::new_with_targets` keeps its implicit external target set when
every explicitly configured origin is invalid; TODO-1096 now requires a
typed, fail-closed distinction between absent and invalid origin policy.
The WebTransport H3 settings gate ignores QUIC DATAGRAM/reliable-reset
capabilities. Chrome/Safari fixture entries omit `reset_stream_at`; Firefox
advertises it without a transport `RESET_STREAM_AT` handler. TODO-1114 owns
draft-pinned negotiation and real-peer/persona proof before cover is enabled.
The WebTransport server also returns `200` for any syntactically valid
nonempty CONNECT authority/path; TODO-1114 now requires authorized-resource
matching and a negative unknown-host transcript.
The runtime defaults prefer QUIC v2, while the browser fixture does not
record the captured QUIC version. RFC 9369 provides no new application or
privacy capability over v1; TODO-1082/1075 now require version-matched
capture and measured entry-version policy rather than a presumed v2 benefit.
Devin CLI node 11478 contains raw ephemeral packet key/IV material in a
terminal result. TODO-1099 now records local transcript retention and
requires future proof diagnostics to avoid stdout secrets; no key bytes
were copied into task documents, and external disclosure is unproven.
The later Devin CLI node 18908 shows the new Criterion TLS handshake cell
panicking on `UnknownIssuer`; TODO-1071 now owns an exact trust-chain
reproducer and verified-handshake gate before that cell supplies a baseline.
The HTTPS-record parser silently caps declared DNS counts and returns an
ECH key before validating the rest of its RDATA; TODO-1081 now names the
exact malformed-count and trailing-parameter rejection tests.
The QKey `off` issuance path labels an accepted IPv4 literal as a DNS SNI
host, although its own comment claims DNS-only and only its IPv6 case is
tested. TODO-1092 now owns typed DNS/IP identity validation and SAN proof.
The changed `StealthMetrics::record_mode` has no repository caller. Its mode
counters retain `auto`/`max` names, omit several valid modes and are not
exported. TODO-1079 now owns a consumer check and removal or truthful
instrumentation; this is a low-severity code-quality finding.
`README.md` still advertises synthetic server-push cover after its sender
was removed, and its profile-cycling text does not state the next-connection
boundary. The shipped sample config's unconditional direct-first and
fallback-only ECH wording also conflicts with the selected-entry target
where shared-IP/ECH identity is mandatory. TODO-1089 now owns the exact
documentation reconciliation after TODO-1075/1096 defines runtime truth.
The v2 server's `validate_peer_version_information` explicitly accepts a
missing authenticated parameter and marks it validated; a current test
requires that behavior. RFC 9369 Section 4 requires v2 endpoints to validate
the version-information parameter. TODO-1115 now owns the symmetric v2 gate,
the narrow v1 compatibility rule and both-role negative handshake proof.
The WebTransport client emits `Origin`, but the server accepts a pending
session without checking that header. The current draft requires the server
to verify any supplied Origin. TODO-1114 now includes exact Origin
admission/rejection and transcript tests.
The standalone client swaps to a candidate UDP socket before migration
validation but only polls that new socket; its `recv_mut` reports the old
core-local address, and its connected send helper discards `SendInfo` path
metadata. TODO-1116 now owns two-socket receive/send routing, success and
rollback proof. TODO-1086's CID privacy repair depends on that functional
path foundation.

## Target contract

- Inventory every session turn and tool result from the Devin CLI
  `lake-rooster` history, every commit in the session range, and every
  changed path. Record a reviewed/unreviewed evidence matrix in this task
  detail or the owning existing task docs, with no new generic worklog.
- For each changed source, test, script, config, UI and doc path, inspect the
  diff and current file in context, its callers/consumers, relevant existing
  tests, and task acceptance. Flag defects, weak proof, inconsistencies,
  simplifications and vision-level alternatives. Do not invent findings for
  paths with no issue; explicitly record a checked-no-finding disposition.
- Verify functional claims at the smallest meaningful boundary. Distinguish
  source inspection, unit/integration result, capture, primary-host run and
  production deployment. Do not rerun a full build merely to increase a
  percentage; run targeted proof when a concrete risk remains.
- Attach every new finding to its owning open TODO or create a focused new
  detail, with exact observed behavior, target state, tests and owner. Dedup
  against TODO-1071 and TODO-1080 through TODO-1099.

## Implementation and proof

- [ ] Read the complete CLI session, including the last turn and all output
      blocks; reconcile session claims with the actual HEAD and Git history.
- [ ] Record all 326 changed paths and 52 commits with a disposition and
      scope-relevant proof pointer. Recount against `git diff --name-only`
      before closing so no path disappears from the matrix.
- [ ] Review security/protocol, crypto, transport/FEC, frontend/IPC,
      benchmark/test scripts and docs against their actual call chains and
      user-visible contracts.
- [ ] Transfer additional findings into the existing tracker with technical
      acceptance; reconcile duplicate or already fixed findings explicitly.
- [ ] Perform a final current-HEAD/status/document-link audit before
      declaring the lake-rooster review complete.

## Acceptance

- 326/326 changed paths and 52/52 commits have a reviewed disposition, with
  any scope drift from new commits recounted. Zero uninspected session tool
  outputs. Every actionable finding has one owning open task and measurable
  acceptance; no finding is silently lost between chat and tracker.
- The final report distinguishes verified defects from conceptual choices
  and proof gaps, and does not claim 100% coverage before this checklist is
  actually complete.
