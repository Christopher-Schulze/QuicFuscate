---
id: TODO-454
title: NAT traversal (STUN/TURN/ICE) for restrictive firewalls
severity: HIGH
phase: "J"
priority: P2
status: DONE
created: 2026-06-30
depends_on: []
---

# TODO-454: NAT Traversal (STUN/TURN/ICE) for Restrictive Firewalls

## Current Status

Implemented as an optional path-discovery layer, not as a default stealth layer.
`src/transport/nat.rs` contains STUN Binding, ICE host/server-reflexive
candidate gathering, TURN Allocate/CreatePermission/SendIndication, and the
`NatPathDiscovery` controller. Discovery is default-off, reason-gated by
`NatTraversalMode`, cooldown-limited, and candidate-capped. Engine TOML
`[nat_traversal]` maps into transport config.

## Problem

NAT traversal must not become permanent background STUN/ICE traffic. For this
VPN architecture the normal path is client to public server over QUIC/H3/MASQUE,
so NAT traversal is useful mainly when direct UDP fails, when roaming changes
the local path, or when mesh/peer discovery is explicitly enabled.

Standard QUIC path validation (PATH_CHALLENGE / PATH_RESPONSE) can handle
address changes when the public mapping is predictable, but:

- **Symmetric NAT**: each destination gets a different public IP:port mapping.
  The client doesn't know its public address for a given server, and
  peer-reflexive candidates can't be predicted.
- **Restrictive firewalls**: block incoming UDP entirely. No amount of path
  validation can punch through a firewall that drops all inbound UDP.
- **No relay fallback**: without TURN, if direct connectivity is impossible,
  the connection cannot be established.

Current implementation evidence:

- `src/transport/nat.rs` - STUN/TURN/ICE building blocks and `NatPathDiscovery`.
- `src/transport/config.rs` - `NatTraversalConfig`, `NatTraversalMode`, and
  `NatDiscoveryReason`.
- `src/engine/config.rs` - `[nat_traversal]` TOML section.
- `config/quicfuscate.toml` and `config/server-linux.default.toml` - documented
  default-off runtime configuration.

## Goal

Implement STUN/TURN/ICE primitives and expose them as an optional, bounded path
discovery feature:

1. **STUN binding** (RFC 8489) - discover public IP:port (server-reflexive
   candidate).
2. **ICE candidate gathering** - host, server-reflexive (srflx), relay
   candidates.
3. **ICE connectivity checks** - test candidate pairs, select best working
   pair.
4. **TURN relay fallback** (RFC 8656) - relay traffic through TURN server when
   direct connectivity fails (symmetric NAT / restrictive firewall).
5. **Config**: `[nat_traversal]` with default-off policy, STUN/TURN server
   lists, ICE toggle, probe cooldown, and candidate cap.

## Implemented Architecture

### Step 1: STUN/TURN/ICE primitives

`src/transport/nat.rs` contains the NAT traversal primitives in one cohesive
module instead of splitting them into parallel files:

- `StunClient`: STUN Binding Request/Response and XOR-MAPPED-ADDRESS parsing.
- `IceAgent`: host and server-reflexive candidate gathering, candidate
  priority calculation, and best-pair selection.
- `TurnClient`: TURN Allocate, CreatePermission, and SendIndication building
  blocks.

The current implementation exposes these primitives without making NAT
traversal a permanent background protocol surface.

### Step 2: Optional path discovery policy

`NatPathDiscovery` wraps the low-level primitives with runtime policy:

1. NAT traversal is disabled by default.
2. Discovery only runs when `NatTraversalConfig::allows_discovery(reason)`
   permits it.
3. Probe bursts are cooldown-limited by `probe_interval_ms`.
4. Returned candidates are capped by `max_candidates`.
5. With `ice_enabled = false`, discovery returns bounded host candidates only.
6. With `ice_enabled = true`, discovery may gather STUN server-reflexive
   candidates.

This matches the project decision: NAT traversal is an optional connectivity
and path-discovery layer, not a stealth mechanism by itself.

### Step 3: Runtime configuration

`src/transport/config.rs` defines:

- `NatTraversalMode`: `off`, `connectivity-fallback`, `roaming`, `mesh`,
  `always`.
- `NatDiscoveryReason`: direct-path failure, roaming, mesh, or manual request.
- `NatTraversalConfig`: enabled flag, mode, STUN/TURN server lists, ICE toggle,
  probe cooldown, and candidate cap.

`src/engine/config.rs` exposes `[nat_traversal]` in TOML and maps it into
transport config. `config/quicfuscate.toml` and
`config/server-linux.default.toml` document the default-off production stance.

### Step 4: Engine/client wiring

The Engine runtime and client connection setup now carry NAT traversal config
into the transport layer. This makes the feature available to path-management
code without changing the default direct QUIC/H3/MASQUE flow.

### Scope Boundary

The current production scope is optional path discovery. Full TURN relay as a
transparent data-plane socket, active NAT keepalives on nominated pairs, and a
real two-peer symmetric-NAT relay E2E test are not default runtime behavior.
Those become necessary only if NAT traversal is elevated from optional
connectivity aid to a hard production requirement for peer-to-peer or mesh
mode.

## Files Modified

- `src/transport/nat.rs` - STUN/TURN/ICE primitives and `NatPathDiscovery`.
- `src/transport/config.rs` - NAT traversal modes, reasons, config, setters,
  defaults, and serialization tests.
- `src/transport.rs` - public re-exports for NAT traversal types.
- `src/engine/config.rs` - `[nat_traversal]` TOML config and validation.
- `src/engine/engine.rs` - runtime transport config propagation.
- `src/implementations/client/connection.rs` - client transport config
  propagation.
- `config/quicfuscate.toml` and `config/server-linux.default.toml` - documented
  default-off configuration.

## Acceptance Criteria

- [x] NAT traversal is disabled by default.
- [x] Discovery is reason-gated by policy (`connectivity-fallback`, `roaming`,
      `mesh`, `always`).
- [x] Discovery is cooldown-limited and candidate-capped.
- [x] Engine TOML config maps into transport config.
- [x] Client runtime config maps into transport config.
- [x] `ice_enabled = false` preserves current direct-connect behavior.
- [x] Unit tests cover STUN/TURN message parsing/building, ICE priorities, host
      gathering, and `NatPathDiscovery` policy.
- [x] No permanent STUN probe loop is enabled.
- [x] NAT traversal is documented as connectivity/path discovery, not default
      stealth.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| STUN binding (real server) | < 1s | 1 RTT to STUN server |
| ICE candidate gathering (3 servers) | < 3s | Parallel STUN + TURN |
| ICE connectivity checks (10 pairs) | < 5s | Parallel checks |
| TURN relay connection | < 10s | Allocate + permission + ICE |
| Symmetric NAT integration test | < 30s | Full handshake via relay |
| Keepalive interval | 15s | Binding indication, no response |
| TURN refresh | 50% of allocation lifetime | Proactive refresh |
| STUN encode/parse unit tests | < 2s | Round-trip all message types |
| Memory per ICE agent | < 16 KiB | Candidates + pairs + check list |
