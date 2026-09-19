# TODO-984 - `--cleanup-firewall` unusable after config drift and unimplemented for the server

## Symptom

`quicfuscate server --cleanup-firewall` did not exist as a maintenance path:
the flag lived in `SharedArgs` but `Commands::Server` never forwarded it, so
the server started normally instead of cleaning and exiting. Once wired, the
first Omega run still failed:

```text
stale routing cleanup failed: Command failed: durable routing state identity
does not match the requested server routing
```

leaving stale nftables tables, routing records and sysctl mutations on the
host permanently — there was no supported way to remove them.

## Root cause

`cleanup_stale_routing_records` rebuilt each `RoutingManager` from the
*current* `ServerConfig` (`configured_routing_manager`) and
`validate_persisted_ownership` requires exact identity equality across
`tun_name`, `server_ipv4`, `netmask`, `wan_interface`, `server_ipv6`,
`ipv6_prefix_len`, `firewall_backend` and `client_to_client_enabled`. Any
configuration drift between the crashed session and the cleanup invocation —
a renamed WAN interface, a different backend, a profiling-namespace interface
that no longer exists — made cleanup refuse forever. The persisted record
itself already contains the full installed identity, so requiring the caller
to reproduce it via flags was both unnecessary and impossible in the cases
cleanup exists for.

Additionally, `--cert`/`--key` were unconditionally `required` by clap, the
privilege-drop identity was resolved before the cleanup branch, and the
firewall-owner orphan path (owner record without routing record) refused
removal whenever the resource was still present.

## Fix

`--cleanup-firewall` is now a true maintenance mode for the server:

- `run_server` takes `cleanup_firewall`; `Commands::Server` forwards
  `shared.cleanup_firewall`. The branch runs before certificate loading,
  audit init and the privilege drop, skips privilege-target resolution and
  startup capability validation, and returns without opening a listener.
- `--cert`/`--key` use `required_unless_present = "cleanup_firewall"`;
  the runtime resolves them to empty paths that are never read in that mode.
- `cleanup_persisted_routing_records()` is record-driven: it enumerates
  `persisted_tun_names()`, reads each durable record directly
  (`read_persisted_state_for`) and rebuilds the manager from the *persisted*
  identity (`RoutingManager::from_persisted_state`). A surviving
  `firewall-owner.json` whose routing record is already gone is handled by
  `from_persisted_firewall_owner` — the owner record is itself the ownership
  proof.
- `cleanup_stale_explicit()` permits teardown of a firewall-only orphan
  whose resource is still present: the durable `owner_generation` marker is
  verified via `verify_owned_firewall_resource` before teardown, so nothing
  is guessed. The implicit startup path (`cleanup_stale`) keeps refusing
  that case.
- All safety checks are unchanged: active-owner PID/boot-id rejection,
  cross-TUN rejection, generation mismatch, and foreign-resource refusal.

Startup cleanup semantics (`cleanup_stale_routing_records` with the current
config) are intentionally untouched — a mismatched record still blocks
startup rather than silently removing differently-shaped state.

## Verification

- Unit tests: `persisted_state_rebuilds_manager_identity_after_config_drift`
  (dual-stack, nftables, c2c, non-default WAN), 
  `persisted_firewall_owner_rebuilds_manager_identity`,
  `persisted_state_rebuild_rejects_invalid_addresses`. Routing suite 27/27.
- `cargo check --lib --bins`, `cargo fmt --check`, `cargo clippy --lib` clean.
- Omega (aarch64, kernel 6.17) release binary:
  - No state: exits 0 immediately.
  - Drift: server in a netns with `--wan-interface eth1`, `kill -9`,
    namespace deleted (eth1 gone). `--cleanup-firewall` *without* WAN flags
    removed both records and exited 0 — the case the old code refused.
  - Live resource: host server on `--wan-interface enp0s6`, `kill -9`;
    cleanup removed `table inet quicfuscate_rt` and both records, exit 0.
  - Active owner: cleanup against a running server refused with
    `durable routing state is still owned by active PID`, exit 1.
  - Graceful `SIGTERM` shutdown still removes records and table itself.
  - Omega left clean: no netns, no nft tables, no records, no processes.

## Remaining

- Firewall-only orphan teardown when the resource is present is covered by
  code (`cleanup_stale_explicit`) but the Omega orphan run had its table
  already gone with the namespace; a present-resource orphan run is a useful
  follow-up fixture.
- macOS/Windows print an informational message only — they keep no durable
  firewall state by design.
