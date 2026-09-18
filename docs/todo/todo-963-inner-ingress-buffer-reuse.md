# TODO-963 - Multi-hop inner ingress: buffer reuse instead of alloc+drop per datagram

## Status
DONE

## Problem
In circuit (multi-hop) mode every inner-hop payload passed through
`InnerIngress`: `push` allocated `payload.to_vec()` and `pop` handed the
`Vec` to `deliver_inner_ingress`, which fed `hop.recv(&payload)` and then
dropped it - one alloc/free cycle per tunnelled datagram, on the hot path
whenever a bounded N-hop circuit carries traffic.

## Solution
Applied the TODO-947 freelist pattern:

- `InnerIngressState` gains a bounded `spare: Vec<Vec<u8>>` (capped at
  `MAX_QUEUED_INNER_DATAGRAMS`).
- `push` pulls a retired buffer from `spare` (`unwrap_or_default`),
  clears it, and `extend_from_slice`s the payload - zero alloc once the
  queue reaches steady state.
- New `pop_into(&mut Vec<u8>)` swaps the front datagram into the caller's
  persistent scratch and parks the scratch's previous allocation in
  `spare` - no copy, no alloc, the byte-capacity accounting is unchanged.
- `ClientDataPlane` gains `inner_ingress_scratch`, and
  `deliver_inner_ingress` drains via `pop_into` + `hop.recv(&scratch)`.
- `pop()` is retained `#[cfg(test)]` for the existing queue tests.

Semantics preserved: same bounds (`MAX_QUEUED_INNER_DATAGRAMS`,
`MAX_QUEUED_INNER_BYTES`), same byte accounting, same delivery order.

## Verification
- `cargo check -p quicfuscate --all-targets`, clippy, `cargo fmt --check`:
  clean.
- `cargo test -p quicfuscate --lib circuit` 9/9 local;
  `circuit_runtime::tests` 2/2 incl. the bounds/order queue test.
- Omega (aarch64): native check + circuit tests 9/9 + clippy - green.
