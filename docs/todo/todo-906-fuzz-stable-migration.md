# TODO-906: Migrate fuzz lane to stable Rust and fix netem-impaired circuit transport errors

Renumbered from the collided "TODO-894" used in commit `2a3beb2`; number 894
already belonged to the archived Brain EnvSnapshot task.

## Why

The fuzz lane depended on nightly-only `cargo-fuzz` + AddressSanitizer, which
contradicted the floating-stable toolchain policy and drifted the CI lockfiles.
Separately, netem-impaired circuit runs dropped circuits on transient
`ConnectionError::BufferTooShort`/`Done` conditions and crashed server startup
on stale nftables ownership records.

## What landed (commit `2a3beb2`)

- Fuzz targets moved from `fuzz_targets/` libFuzzer binaries to stable
  deterministic `pub fn exercise(&[u8])` corpus + generated-input regression
  runners under `scripts/tests/fuzz/src/targets/`.
- `rust-toolchain.toml` pinned to floating `stable`; `config/tool-versions.env`
  drops `RUST_NIGHTLY_TOOLCHAIN` and `CARGO_FUZZ_VERSION`; all CI workflows use
  `dtolnay/rust-toolchain@stable`.
- `scripts/audits/verify-fuzz-contract.sh` enforces the stable contract (no
  libFuzzer, no nightly, no ASan references).
- `scripts/audits/verify-reproducible-dependencies.sh` accepts floating-stable
  and rejects version-suffixed nightly channels.
- Client assignment negotiation (`negotiate_assignment` receive path) and
  `flush_outbound` (send path) treat `BufferTooShort`/`Done` as transient under
  netem impairment instead of dropping the circuit.
- Routing `cleanup_stale` checks `nft_table_exists` before removing stale
  ownership records: absent resource removes the record and continues; present
  resource still verifies owner fatally (no fail-open for foreign owners).

## Verified Evidence

- Fuzz contract audit: PASS. Stable fuzz suite: 7/7.
- Unimpaired 3-hop on Omega: PASS.
- The remaining impaired 3-hop latency/throughput gap diagnosed under this task
  was closed by TODO-905 (PTO backoff bound for nested circuit hops).

## Deviations

None.
