---
id: TODO-624
title: macOS pf anchors are loaded but never referenced by the main ruleset
severity: HIGH
phase: S
priority: P1
status: BLOCKED
created: 2026-08-01
depends_on: [TODO-548]
---

# TODO-624: macOS pf Anchor Activation and Kill-Switch Rollback Contract

## Current execution gate (2026-09-23)

The managed reference installer and local rollback/state fixes are implemented.
TODO-548 owns the remaining privileged end-to-end PF proof. Reuse its **same**
native run and retained artifacts to close this narrower finding: prove the
main ruleset references `com.quicfuscate.killswitch`, the active anchor is
actually evaluated for IPv4/IPv6 non-VPN traffic, failed activation leaves no
new owned rule, and unrelated anchors plus prior PF enablement survive
cleanup. Preserve `scripts/tests/macos-pf-anchor-proof.sh` as the focused
read-only inspector. Do not add a second PF installer, state machine, or
separate mutating proof harness. A loaded anchor by itself is insufficient.

## Why

The macOS helpers load rules into anchor namespaces via `pfctl -a <anchor> -f`
but do not own installation of the corresponding main-ruleset reference. The
client kill-switch path checks for an existing reference and fails when it is
absent. A separate rollback problem remains when a client policy load succeeds
but the later activation check fails. The current source no longer exposes a
server-side macOS PF mutation helper: `RoutingManager` rejects macOS before
host mutation, so the server acceptance is already satisfied by an explicit
unsupported boundary.

## Findings

### 1. Kill-switch activation has a fail-fast prerequisite and incomplete rollback
- **File:** `src/implementations/client/killswitch.rs:826-845` (`block_traffic`),
  `:859-898` (`apply_policy`), `:806-824` (`ensure_pf_enabled`)
- **Current:** Rules are loaded with `pfctl -a com.quicfuscate.killswitch -f <conf>`.
  `ensure_pf_enabled` checks `pfctl -sr` for the exact anchor or
  `com.quicfuscate/*` (`:806-824`) before allowing the operation to succeed.
- **Problem:** The client path has a real fail-fast prerequisite, but it neither
  installs nor clearly surfaces the required main-ruleset ownership contract. If
  the load succeeds and this later check fails, the newly loaded anchor is not
  rolled back by `block_traffic`/`apply_policy`; subsequent stale cleanup must
  remove it. This is not a silent client success.
- **Fix:** Keep the client fail-fast behavior, return an actionable diagnostic,
  and make failed activation clean up the just-loaded anchor before returning.

### 2. Server routing has an explicit unsupported boundary
- **File:** `src/implementations/server/routing.rs:1014-1018`, `:1200-1204`, `:1427-1430`
- **Current:** macOS `setup`, `cleanup_stale`, and `teardown` return
  `RoutingError::UnsupportedPlatform` before any PF command or host mutation.
  The remaining `pf_rules` function is a test-only pure ruleset generator and
  cannot report runtime readiness.
- **Resolution:** No server PF activation patch is required. Introducing a
  dormant `setup_pf` path would expand the supported surface without native
  ownership or privileged proof. The server subtask is satisfied by the
  fail-closed boundary; `TODO-607` remains the owner of Linux routing teardown.

### 3. enable() marks enabled before backend activation
- **File:** `src/implementations/client/killswitch.rs:131-141`
- **Current:** `enabled.store(true)` runs before `backend.block_traffic()`; on
  failure `enabled` stays `true` by design.
- **Problem:** The flag represents the intended fail-closed ownership policy, but
  a failed backend activation can leave it inconsistent with `rules_active` and
  causes `Drop` to retain/log rules that may not have been installed. The policy
  needs a typed transitional/failed state or an explicit cleanup contract.
- **Fix:** Make the state transition and backend rollback atomic from the caller's
  perspective, preserving fail-closed behavior without claiming successful
  activation when the backend returned an error.

## Acceptance

- On a host with no `anchor` reference in `pf.conf`, the client kill switch fails
  with an actionable error and removes any just-loaded anchor; server routing does
  not claim readiness without the same reference proof.
- With the reference present, kill switch rules demonstrably block non-VPN
  traffic (verified with `pfctl -sr` + a live connect test).
- `enabled` and backend-rule state have a defined, testable relationship after a
  failed `enable()`.

## Sub-Tasks

- [x] Keep client activation fail-fast and make the main-ruleset reference
  check exact, actionable, and rollback-safe.
- [x] Confirm the server routing boundary rejects macOS before host mutation;
  no obsolete `setup_pf`/teardown path is added.
- [x] Fix `enable()` ordering/rollback in `killswitch.rs`.
- [x] Add a macOS integration check script under `scripts/tests/` verifying
  anchor presence after setup.

## Notes

- Overlaps with `TODO-607` (routing teardown incomplete: pfctl -E never disabled,
  IP forwarding and TUN IP left behind) - coordinate fixes.
- macOS `pfctl -s Anchors` lists loaded anchors, but a listed anchor without a
  main-ruleset reference is still never evaluated; presence checks must inspect
  the main ruleset. The shipped server runtime is Linux-only; this detail does
  not promote the internal macOS helper into a supported server capability.
- Focused client tests pass 74/74 and routing tests pass 20/20. Locked
  all-target checking and strict all-feature Clippy pass; format, diff, shell
  syntax, and script help checks pass. The full local library run covered 2,195
  tests but remained red on the external-DNS DoH cache test and one intermittent
  Stealth Cover freshness assertion; the latter passed in an isolated rerun.
- `scripts/tests/macos-pf-anchor-proof.sh` is read-only and requires root. It
  was not executed against the live host because the current process is UID 501
  and shared PF state must not be mutated without explicit authorization.

## Deviations

The local implementation and deterministic tests are complete. The privileged
live PF proof remains blocked because this session is not root and must not
mutate shared PF state. The added script is read-only and is the required
operator/CI gate for that proof.
