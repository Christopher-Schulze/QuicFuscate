---
id: TODO-961
title: `apply_policy` observer call: `Option::take` instead of `Arc::clone`
status: DONE
created: 2026-09-18
---

# TODO-961 - `apply_policy` observer call: `Option::take` instead of `Arc::clone`

## Status
DONE

## Problem
After writing an ACK frame, `recv.rs` invoked the transport observer's
policy hook via

```rust
if let Some(obs) = self.observer.as_ref().cloned() {
    obs.apply_policy(self);
}
```

`apply_policy` needs `&mut self`, so holding a `&self.observer` borrow
across the call is impossible - the code paid an `Arc` clone (atomic
increment + drop decrement) on **every emitted ACK** purely to satisfy the
borrow checker, not for ownership.

## Solution
Move the `Arc` out of the slot for the duration of the call:

```rust
if let Some(obs) = self.observer.take() {
    obs.apply_policy(self);
    self.observer = Some(obs);
}
```

Zero atomic traffic per ACK; the clone was never semantically required.

Safety: `apply_policy(&self, target: &mut dyn TransportPolicyTarget)` only
sees the restricted policy-target interface (stealth/FEC/ACK/CC/padding
setters) - it cannot emit observer events or re-enter the receive path, so
the slot being `None` for the call's duration is unobservable. The only
other `apply_policy` impls (brain/killswitch) sit behind different types.
A panic inside `apply_policy` propagates through `recv` and tears the
connection down regardless, so the no-restore window is irrelevant.

## Verification
- `cargo check -p quicfuscate --all-targets`, `cargo clippy
  -p quicfuscate --all-targets`, `cargo fmt --check`: clean.
- `cargo test -p quicfuscate --lib transport::`: 363/363 local.
- Omega (aarch64): check + `transport::connection` 142/142 + clippy -
  native Linux green.
