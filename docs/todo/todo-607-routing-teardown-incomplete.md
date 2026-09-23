---
id: TODO-607
title: routing teardown leaves IP forwarding, TUN address and macOS pf enabled
severity: HIGH
phase: S
priority: P3
status: BLOCKED
created: 2026-07-31
depends_on: []
---

# TODO-607: Complete Routing Teardown (Forwarding, Interface State, pf)

## Current execution gate (2026-09-23)

The active source has `RoutingManager::teardown()` and
`recover_current_persisted_ownership()` under
`src/implementations/server/routing.rs`; the old CI self-owner rejection
described below predates that split and is not evidence of a current failure.
Run `scripts/tests/tun-e2e-netns.sh` and the Linux lifecycle wrapper on one
fresh exact revision with privileged network namespaces. Exercise setup
failure/retry, graceful stop, SIGKILL/restart, active-owner refusal, and
foreign-state conflict. Before namespace deletion, compare the managed TUN,
addresses/link state, IPv4/IPv6 forwarding, selected firewall resources, and
durable ownership record to their recorded pre-run states. Any failure must
retain diagnostic artifacts and a named source owner; close only on the full
native matrix with zero owned residue. Do not replay the historical source fix.

## Why

The original Linux finding is partly stale after TODO-571: the current Linux manager records owned address, link, and forwarding mutations and restores them during graceful teardown and setup rollback. TODO-607 now adds durable Linux host-state ownership and fail-closed active-owner detection, and removes mutating server routing behavior from the unsupported macOS and Windows surfaces. The remaining closure requirement is execution of the privileged native Linux lifecycle gate; the shipped server runtime remains Linux-only and rejects non-Linux server TUN mode before host mutation.

## Findings

### 1. Linux graceful ownership is implemented, but crash recovery cannot restore forwarding state
- **Files:** `src/implementations/server/routing.rs:38-45,293-364,622-718,764-789`
- **Current:** `RoutingOwnership` records IPv4/IPv6 address additions, link-up ownership, and previous forwarding values. Linux now runs stale recovery before opening a replacement TUN, including persisted records discovered for an unnamed standalone TUN, then writes a schema-2 atomic mode-0600 record before host mutation containing the requested configuration, original TUN ifindex, boot ID, PID, and `/proc` start time. `teardown()` and `cleanup_stale()` recover only exact before/after transitions, preserve external changes, aggregate independent failures, and remove the durable record only after complete cleanup.
- **Remaining problem:** The implementation and local static/unit/full-library gates are complete. The privileged native Linux lifecycle gate now reaches runtime on commit `cec9c9c`, but graceful server shutdown fails closed because durable routing state remains behind at `/run/quicfuscate/routing/7174756e30.json`; the server reports that the record is still owned by active PID `3272`. The gate still must prove setup failure/retry, graceful stop, SIGKILL/restart recovery, active-owner refusal, and zero residue on a Linux runner.
- **Required direction:** Retain the crash-safe ownership contract and execute the native Linux proof. Never blindly reset global forwarding or delete an address that may belong to another owner.

### 2. Internal macOS teardown does not reverse its host mutations
- **Files:** `src/implementations/server/routing.rs:367-391,802-814,1352-1358,1418-1444,1607-1635,1730-1737`; `src/firewall/mod.rs:442-477`
- **Current:** `RoutingManager` no longer mutates macOS addresses, forwarding, pf, or anchors. On macOS, server `setup()`, `cleanup_stale()`, and `teardown()` return `UnsupportedPlatform`; the retained PF rule generator is test-only.
- **Boundary:** `open_server_tun()` rejects macOS server TUN mode before creating host state, and the public routing surface now matches that boundary. Native macOS server ownership remains intentionally unsupported until a separate task provides reversible ownership and privileged proof.

### 3. Internal Windows teardown leaves forwarding enabled
- **Files:** `src/implementations/server/routing.rs:394-410,816-835,1460-1470`
- **Current:** `RoutingManager` no longer mutates Windows forwarding or NetNat state. On Windows, server `setup()`, `cleanup_stale()`, and `teardown()` return `UnsupportedPlatform`; the retained NetNat script generator is test-only.
- **Boundary:** Windows server TUN mode is rejected by `open_server_tun()` before host mutation, and the public routing surface now matches that boundary. Native Windows server ownership remains intentionally unsupported until a separate task provides reversible ownership and privileged proof.

### 4. Runtime lifecycle wiring is Linux-only and must stay explicit
- **Files:** `src/implementations/server/parts/dns_signals.rs:356-374`; `src/implementations/server/parts/runtime_admin.rs:295-345`; `src/implementations/server/parts/runtime_impl.rs:114-245`
- **Current:** Both embedded and standalone server startup run persisted Linux stale recovery before opening the TUN and call the shared routing owner only under `target_os = "linux"`; unnamed standalone startup enumerates persisted records before OS allocation, and non-Linux `open_server_tun()` fails before TUN creation. Current canonical docs state this platform boundary.
- **Risk:** Any future platform enablement must not reuse the current macOS/Windows helpers as if their teardown were complete. The runtime support claim, ownership state, stale cleanup, and privileged proof must be extended atomically.

### 5. Graceful teardown reuses the stale-owner refusal path
- **Files:** `src/implementations/server/routing.rs:436-455,1120-1188`; `src/implementations/server/parts/runtime_admin.rs:275-292`
- **Historical:** Before the 2026-08-08 routing slice, `RoutingManager::teardown()` called `recover_persisted_ownership()` after firewall teardown. That recovery function always called `reject_active_owner()`, so the graceful owner rejected itself before restoring host state or removing its record. The source now authenticates the durable owner first and uses `recover_current_persisted_ownership()` for graceful release; the native Linux gate remains open.
- **Evidence:** CI run `30791153467`, job `91614771645`, reported `durable routing state is still owned by active PID 3272` for `/run/quicfuscate/routing/7174756e30.json` during graceful server shutdown. The source call graph deterministically matches that message; this is not an unclassified runner residue.
- **Required direction:** Separate current-owner release from startup stale recovery. Graceful teardown must authenticate its own durable record, restore only its exact before/after transitions, remove the record after complete cleanup, and retain `reject_active_owner()` for recovery of records belonging to another live process. Add direct regression coverage for both current-owner teardown and active-owner startup refusal.

### 6. Firewall teardown runs before ownership validation and can leave partial cleanup
- **Files:** `src/implementations/server/routing.rs:933-1008,1212-1339,1701-1715,1889-1895`
- **Historical:** Before the 2026-08-08 routing slice, `RoutingManager::teardown()` removed fixed firewall resources before inspecting the persisted record. The source now authenticates the global firewall owner and validates the exact selected resource before any firewall or host-state mutation; setup rollback retains the durable records when verification fails.
- **Evidence:** The native failure message is emitted only after the firewall teardown call returns, while the durable record remains at `/run/quicfuscate/routing/7174756e30.json`. The source ordering proves a partial-cleanup state even without an additional runner probe: firewall policy can be gone while the recorded address, link, forwarding, and ownership record remain.
- **Required direction:** Authenticate the current durable owner and validate the cleanup contract before mutating firewall state. Make firewall, host-state, and ownership-file cleanup transactional from the caller's perspective: preserve the record on any failure, retry only owned resources, and add a regression that proves an active-owner refusal performs no firewall mutation.

### 7. Native graceful cleanup does not directly prove zero host residue
- **Files:** `scripts/tests/tun-e2e-netns.sh:402-417`; `scripts/tests/tun-e2e-traffic-analysis-netns.sh:248-255`
- **Current:** After sending SIGTERM to the restarted server, the harness asserts only that the fixed durable routing JSON file is absent. It does not inspect the server namespace for the TUN link/address, selected nftables table or iptables chains, or the before/after forwarding values before deleting the namespaces. The outer traffic-analysis wrapper checks only product PIDs and namespace names after the base harness returns.
- **Evidence:** `cleanup()` deletes `ns-srv` and `ns-cli` immediately after the JSON assertion, so any remaining namespace-local firewall or interface state disappears with the test fixture. The current native job therefore proves the ownership-file boundary and traffic lifecycle, but not every zero-residue postcondition claimed by the acceptance.
- **Required direction:** Capture and assert the exact managed TUN, address/link, forwarding, and selected firewall postconditions before namespace deletion. Preserve the failure artifacts and run the same residue checks after both graceful and process-loss/restart paths.
## Acceptance

- Linux graceful teardown and setup rollback restore every mutation recorded by `RoutingOwnership`, verify postconditions, preserve externally changed forwarding state, and aggregate independent cleanup failures.
- Ownership validation completes before any firewall or host-state mutation, and active-owner refusal leaves all managed resources unchanged.
- The native lifecycle harness directly observes managed TUN, address/link, forwarding, firewall, and durable-record postconditions before deleting its namespaces.
- Crash recovery has an explicit durable ownership or service-manager contract for forwarding and any surviving TUN interface state; startup never guesses and never deletes unrelated state.
- The internal macOS server routing path remains explicitly unsupported and cannot mutate addresses, forwarding, pf, or anchors; tests and documentation match that boundary. Native enablement requires its own reversible-ownership task.
- The internal Windows server routing path remains explicitly unsupported and cannot mutate forwarding or NetNat state; tests and documentation match that boundary. Native enablement requires its own reversible-ownership task.
- Embedded and standalone Linux lifecycle tests prove setup failure, retry, graceful stop, and process-loss recovery boundaries; no non-Linux server capability is advertised without native proof.
- No existing routing tests regress (`cargo test --features rust-tests routing`).

## Sub-Tasks

- [x] Audit the current Linux graceful teardown and setup-rollback ownership path.
- [x] Define the crash-recovery ownership boundary for Linux forwarding and interface state.
- [x] Reconcile internal macOS address, forwarding, pf, and anchor teardown.
- [x] Reconcile internal Windows forwarding teardown.
- [x] Add lifecycle-test assertions for every retained platform path and failure boundary.
- [x] Separate current-owner graceful teardown from stale active-owner refusal and add direct regression coverage.
- [x] Validate ownership before firewall teardown and prove setup rollback cannot leave firewall and host state split.
- [x] Extend the native harness with direct host-state and firewall residue assertions before namespace cleanup.
- [ ] Execute the privileged native Linux lifecycle gate and retain pass evidence.

## Notes

- TODO-571 introduced the current Linux ownership ledger and fail-closed address/link verification; this task must not re-document that resolved pre-571 behavior as current.
- `cleanup_stale()` now owns stale firewall identities plus the durable Linux host-state recovery contract; recovery is refused for an active owner, a boot mismatch, an ifindex conflict, or any before/after conflict.
- Linux now persists an atomic mode-0600 ownership record under `/run/quicfuscate/routing/` before host mutation. It binds the requested routing configuration to the original TUN ifindex plus boot ID, PID, and `/proc` start time; active owners and boot changes are refused, PID reuse is detected, and conflicts or failed cleanup retain the record for retry.
- The server routing manager now rejects mutating setup, stale cleanup, and teardown on macOS and Windows before host mutation. Their retained PF and NetNat helpers are pure test generators until native ownership and proof exist.
- `scripts/tests/tun-e2e-netns.sh` now asserts pre-open durable-state recovery, durable-state publication, SIGKILL/restart stale recovery, authenticated post-restart traffic, and graceful durable-state removal. The Linux CI workflow invokes this path through `tun-e2e-traffic-analysis-netns.sh`.
- The historical native failure had a deterministic source cause: graceful `RoutingManager::teardown()` reused `recover_persisted_ownership()`, whose `reject_active_owner()` guard was correct for startup stale recovery but rejected the same process during normal release. The 2026-08-08 source separates current-owner release and retains the stale-owner guard for startup recovery.
- The historical teardown order ran firewall cleanup before owner validation. The 2026-08-08 source validates the durable global owner and exact firewall resource before mutation, and setup rollback refuses guessed cleanup when a resource is absent or externally changed.
- Before the residue-assertion slice, the native harness checked only the durable JSON path, then deleted both network namespaces; that historical gap is retained here to explain the acceptance change.
- The native harness now captures the server-namespace IPv4/IPv6 forwarding baseline, records the selected firewall backend from the durable routing state, and checks durable firewall-owner removal, absent `qtun0` links, exact forwarding restoration, and absent selected iptables/nftables resources before namespace deletion. The assertions are static/local evidence only until the privileged Linux lifecycle gate executes them.
- The 2026-08-08 routing slice separates `recover_current_persisted_ownership()` from active-owner startup recovery, authenticates the durable global firewall owner before teardown, validates the selected firewall resource before mutation, and retains state on any verification or cleanup failure. The global fixed-identity contract is implemented under TODO-802; the privileged Linux lifecycle and residue assertions remain the external closure gate.
- Local native execution is unavailable on this macOS host because the privileged Linux network-namespace prerequisites, Linux release binary, `flock`, and Linux sysroot are absent. The historical CI build blocker from run `30788423402`, job `91606697972`, is resolved by commit `cec9c9c`; the current CI run `30791153467`, job `91614771645`, completed the Linux release build, TUN provisioning/rollback, veth connectivity, authenticated traffic, packet capture, and crash/restart ownership checks. It then failed during graceful server shutdown because `/run/quicfuscate/routing/7174756e30.json` remained owned by active PID `3272`, so the native acceptance subtask remains open with a concrete routing-cleanup failure. The implementation and static/local gates are complete, but TODO-607 cannot close until that cleanup path and the remaining lifecycle assertions pass.
- TODO-608 is the adjacent setup-error finding and is stale against the current checked command/postcondition path; it is being reconciled separately.
- TODO-769 owns the separate embedded `EngineConfig.interface.tun_ip` versus `ServerConfig`/routing-owner divergence.
- TODO-687 is the active prerequisite task. Resume this task only after the Linux build succeeds and the native lifecycle harness has an execution result for the pushed source.

## Deviations

None.

## Continuation Verification (2026-08-10)

- The guarded release routing filter passes `24/24` deterministic tests under
  `implementations::server::routing`; owner identity, active-owner refusal,
  current-owner recovery decisions, firewall/resource collision checks,
  dual-stack ruleset contracts, and explicit unsupported-platform boundaries
  are green on ARM64 macOS.
- The privileged Linux lifecycle gate remains open. No Linux namespace,
  forwarding, TUN-link, firewall-residue, or Omega result is inferred from the
  local routing filter.
