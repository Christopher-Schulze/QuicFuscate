---
id: TODO-435
title: "Wire DoH resolution and implement DNS-over-tunnel proxy"
severity: HIGH
phase: "H"
priority: P1
status: OPEN
created: 2026-06-30
depends_on: [TODO-422]
---

# TODO-435: Wire DoH resolution and implement DNS-over-tunnel proxy

## Problem

The codebase contains a fully implemented DNS-over-HTTPS (DoH) resolution
subsystem that is never invoked. The functions `resolve_doh`,
`resolve_doh_multi`, and `resolve_doh_single` are defined in
`src/stealth/mod.rs:938-1056` with a complete multi-provider fallback
architecture (`DOH_PROVIDERS` at line 960, round-robin rotation via
`DOH_PROVIDER_INDEX` at line 966, a dedicated Tokio runtime `DOH_RUNTIME`
at line 938). A grep for `resolve_doh` across the entire `src/` tree
returns **zero call sites outside the defining module** — the code is
dead weight.

Meanwhile the client's DNS configuration path is fundamentally broken:

1. **`ServerConfig.dns_servers` is a dead field.** The field is declared
   at `src/implementations/server/mod.rs:104-105` and populated with a
   default of `[1.1.1.1, 8.8.8.8]` at line 120, but no code ever
   transmits these values to connecting clients. The server's accept
   path (`build_live_server_client_init` at line 2042, `accept_session`
   at line 2230) never references `dns_servers`. Clients therefore fall
   back to hardcoded defaults at `src/implementations/client/backend.rs:295-301`.

2. **`search_domains` is always empty.** At
   `src/implementations/client/backend.rs:303`:
   ```rust
   self.platform.set_dns(&DnsConfig { servers: dns_servers, search_domains: vec![] })?;
   ```
   The `vec![]` literal is unconditional. The `DnsConfig` struct
   (`src/implementations/client/platform/traits.rs:44-49`) supports
   `search_domains: Vec<String>`, and the Linux platform backend
   (`src/implementations/client/platform/linux.rs:321-335`) has working
   code to apply them via `resolvconf` — but the field is never
   populated from config.

3. **No DNS proxy exists.** The client sets system DNS to `1.1.1.1` /
   `8.8.8.8` via `set_dns`, which means DNS queries go directly to the
   upstream resolver over the physical network interface — **outside**
   the QUIC tunnel. This is a DNS leak: an observer on the local
   network can see which domains the user is resolving, defeating the
   entire purpose of the VPN. There is no code that intercepts UDP port
   53 traffic on the TUN interface and forwards it through the tunnel.

4. **No DNS forwarding on the server.** The server has no mechanism to
   receive DNS queries from clients and forward them to upstream
   resolvers. The MASQUE CONNECT-UDP infrastructure exists
   (`src/transport/h3.rs:836-900`: `connect_udp`,
   `enable_masque_datagram`, `send_masque_datagram`,
   `try_recv_masque_datagram`) but is used only for the TUN data plane,
   not for DNS.

5. **DoH config is plumbed but unused.** `StealthConfig.enable_doh`
   (`src/stealth/mod.rs:3203`) and `doh_provider` are threaded from
   `EngineConfig` (`src/engine/config.rs:746-748`) through
   `RuntimeStealthPolicy` (`src/implementations/server/mod.rs:302-306`)
   into `apply_runtime_stealth_overrides` (line 3086), which sets
   `sc.enable_doh` and `sc.doh_provider` on the per-connection
   `StealthConfig`. But nothing ever calls `resolve_doh` with this
   configuration. The DoH subsystem is wired to the config bus but the
   output wire is disconnected.

## Goal

- DNS queries from the client **always** traverse the QUIC tunnel,
  never the local network.
- The server receives DNS queries from clients and forwards them to
  upstream resolvers (system resolver or DoH via `resolve_doh` when
  `enable_doh=true`).
- `ServerConfig.dns_servers` is pushed to clients on connect and
  applied as the system DNS.
- `search_domains` is populated from configuration and applied.
- The existing `resolve_doh` / `resolve_doh_multi` / `DOH_PROVIDERS`
  code is actively used by the server's DNS forwarding path.
- A test verifies that a client domain resolution goes through the
  QUIC tunnel, not the local resolver.

## Implementation Plan

### Step 1: Push `dns_servers` and `search_domains` to clients on connect

**File:** `src/implementations/server/mod.rs`

- Extend the connection handshake to include DNS configuration. The
  server already sends HTTP/3 headers during the MASQUE CONNECT
  exchange (`build_live_server_client_init` at line 2042,
  `create_live_server_connection`). Add custom headers
  `x-quicfuscate-dns-servers` (comma-separated IPs) and
  `x-quicfuscate-search-domains` (comma-separated domains) to the
  response headers sent by the server after accepting a client.
- Add `search_domains: Vec<String>` to `ServerConfig`
  (`src/implementations/server/mod.rs:104`), with a default of
  `vec![]` in the `Default` impl (line 110).
- In `build_live_server_client_init` (line 2042), capture
  `server_config.dns_servers` and `server_config.search_domains` and
  pass them through `LiveClientBuildRequest` so they are available
  when the server sends its HTTP/3 response headers.

### Step 2: Parse DNS config on the client during handshake

**File:** `src/transport/h3.rs`, `src/implementations/client/connection.rs`

- In the H3 response header processing path
  (`src/transport/h3.rs:487` — "Process incoming readable streams"),
  detect `x-quicfuscate-dns-servers` and
  `x-quicfuscate-search-domains` response headers and store them in a
  new `DnsPushConfig` struct accessible from the client connection.
- Expose a method `ClientConnection::dns_push_config(&self) ->
  Option<&DnsPushConfig>` on `src/implementations/client/connection.rs`.

### Step 3: Apply pushed DNS config in the client backend

**File:** `src/implementations/client/backend.rs`

- In `connect()` (line 253), after the QUIC connection is established
  (line 273) and before `set_dns` (line 303), read the pushed DNS
  config from the connection. If the server pushed `dns_servers`,
  use those instead of the hardcoded fallback. If the server pushed
  `search_domains`, populate the `DnsConfig.search_domains` field
  instead of `vec![]`.
- Replace line 303:
  ```rust
  self.platform.set_dns(&DnsConfig { servers: dns_servers, search_domains: vec![] })?;
  ```
  with logic that sources both fields from the pushed config (or
  falls back to `config.interface.dns_servers` / config-derived
  `search_domains`).

### Step 4: Add `search_domains` to `InterfaceConfig`

**File:** `src/engine/config.rs`

- Add `pub search_domains: Vec<String>` to `InterfaceConfig` (near
  line 446, after `dns_servers`).
- Default to `vec![]` in the `Default` impl (line 462).
- Add parsing in the config loader (the `from_toml` / `from_env`
  path) for a `[interface] search_domains = [...]` key.

### Step 5: Implement DNS proxy on the client

**File:** `src/implementations/client/dns_proxy.rs` (new)

- Create a `DnsProxy` struct that:
  - Binds a UDP socket on the TUN interface IP (e.g. `10.8.0.2:53`).
  - Receives DNS queries (UDP port 53 packets).
  - Encapsulates each query as a MASQUE CONNECT-UDP datagram targeted
    at the server's DNS forwarder address (the first entry in the
    pushed `dns_servers`, or the server TUN IP `10.8.0.1:53`).
  - Sends the datagram via `Connection::masque_send_datagram`
    (`src/transport/connection.rs:891`).
  - Receives responses via
    `Connection::masque_try_recv_datagram` (line 909) and sends them
    back to the original client UDP source.
- The DNS proxy runs as a Tokio task spawned in the client's IO
  driver loop (`src/implementations/client/io_driver.rs`).
- The system DNS is set to the TUN interface IP (e.g. `10.8.0.2`) so
  that all DNS queries are routed to the local proxy, which forwards
  them through the tunnel.

### Step 6: Implement DNS forwarding on the server

**File:** `src/implementations/server/dns_forwarder.rs` (new)

- Create a `DnsForwarder` struct that:
  - Listens for MASQUE CONNECT-UDP datagrams with the DNS target
    address (the server TUN IP, port 53).
  - Parses the encapsulated DNS query.
  - Forwards the query to the upstream resolver:
    - If `StealthConfig.enable_doh` is true, use `resolve_doh` /
      `resolve_doh_multi` from `src/stealth/mod.rs:1050` to resolve
      the domain, then construct a DNS response packet.
    - Otherwise, forward the raw UDP query to the system resolver or
      to `ServerConfig.dns_servers` entries (`1.1.1.1`, `8.8.8.8`).
  - Encapsulates the response as a MASQUE datagram and sends it back
    to the client.
- The forwarder is integrated into the server's run loop
  (`src/implementations/server/mod.rs:3962` — the TUN reader /
  datagram forwarding path). When a datagram arrives with the DNS
  target, route it to `DnsForwarder` instead of writing it to the TUN
  interface.

### Step 7: Wire DoH into the server DNS forwarder

**File:** `src/implementations/server/dns_forwarder.rs`

- When `enable_doh` is true, the forwarder calls:
  ```rust
  let client = reqwest::Client::builder()
      .timeout(Duration::from_secs(5))
      .build()?;
  let ip = crate::stealth::resolve_doh(&client, &domain, &doh_provider).await?;
  ```
  using `DOH_RUNTIME` (`src/stealth/mod.rs:938`) to drive the async
  resolution. This is the first actual call site for `resolve_doh`
  in the entire codebase.
- The `doh_provider` is sourced from `StealthConfig.doh_provider`
  which is already set per-connection via
  `apply_runtime_stealth_overrides` (line 3086).

### Step 8: Tests

**File:** `tests/dns_tunnel_test.rs` (new), or inline `#[cfg(test)]`

- Unit test: `DnsProxy` receives a DNS query for `example.com` and
  forwards it as a MASQUE datagram. Verify the datagram content
  contains the original DNS query.
- Unit test: `DnsForwarder` receives a DNS query datagram, forwards
  to upstream, and returns a response datagram. Mock the upstream
  resolver.
- Integration test: Start a server + client pair with TUN enabled.
  Client resolves `example.com` through the tunnel. Verify (via
  packet capture or mock) that no DNS query leaves the client's
  physical interface — all DNS goes through QUIC datagrams.
- Test: `ServerConfig.dns_servers` is pushed to client and applied
  as system DNS. Verify `DnsConfig.servers` on the client matches the
  server's configured values.
- Test: `search_domains` from config is applied. Verify
  `DnsConfig.search_domains` is non-empty when configured.

## Files to Modify/Create

- `src/implementations/server/mod.rs` — push `dns_servers` /
  `search_domains` in handshake, add `search_domains` to
  `ServerConfig`
- `src/implementations/server/dns_forwarder.rs` — **new**: server-side
  DNS forwarding with DoH integration
- `src/implementations/client/backend.rs` — apply pushed DNS config,
  replace `vec![]` for `search_domains`
- `src/implementations/client/dns_proxy.rs` — **new**: client-side
  DNS proxy intercepting port 53 on TUN
- `src/implementations/client/connection.rs` — expose
  `dns_push_config()` accessor
- `src/implementations/client/io_driver.rs` — spawn DNS proxy task
- `src/transport/h3.rs` — parse `x-quicfuscate-dns-*` response headers
- `src/engine/config.rs` — add `search_domains` to `InterfaceConfig`
- `src/stealth/mod.rs` — first real call site for `resolve_doh` (via
  server DNS forwarder)
- `tests/dns_tunnel_test.rs` — **new**: integration tests

## Acceptance Criteria

- [ ] `grep -rn "resolve_doh(" src/ | grep -v "stealth/mod.rs"` returns
      at least one call site in the server DNS forwarder.
- [ ] `ServerConfig.dns_servers` is transmitted to clients during the
      connection handshake and appears in the client's
      `DnsConfig.servers`.
- [ ] `DnsConfig.search_domains` is populated from config, not
      hardcoded to `vec![]`.
- [ ] Client DNS queries for UDP port 53 on the TUN interface are
      intercepted by `DnsProxy` and forwarded through QUIC datagrams.
- [ ] Server `DnsForwarder` receives DNS query datagrams and forwards
      them to upstream resolvers.
- [ ] When `enable_doh=true`, the server uses `resolve_doh` /
      `resolve_doh_multi` for DNS resolution.
- [ ] Integration test verifies no DNS query leaves the client's
      physical interface during domain resolution.
- [ ] `cargo test` passes with all new tests green.
- [ ] `cargo clippy` reports no new warnings.

## Resource Budget

| Scenario | Budget | Notes |
|----------|--------|-------|
| DNS proxy per-query latency | < 2 ms | Local UDP intercept + QUIC datagram encapsulation |
| DNS forwarder upstream (DoH) | < 50 ms | `resolve_doh` with multi-provider fallback; 5 s timeout per provider |
| DNS forwarder upstream (plain) | < 10 ms | Direct UDP to 1.1.1.1 / 8.8.8.8 |
| Memory per active DNS query | < 4 KB | Query buffer + response buffer + datagram framing |
| Concurrent DNS queries per client | 256 | Bounded by QUIC datagram queue depth (`enable_datagrams(256, 256)`) |
