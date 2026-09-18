# TODO-938 — Server-Ingress: Per-Datagram Arc-Clones + Settings-Clone

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`process_live_server_client_datagram` (live_auth.rs) wurde pro **eingehendem
Datagramm** aufgerufen und nahm dabei sieben `Arc<T>`-Parameter **by value** sowie
`ServerAssignmentSettings` **by value** entgegen. Der Runtime-Loop klonte dafür
pro Paket 6 `Arc`s (Atomics + Speicherbarrieren) und das komplette
`ServerAssignmentSettings` inkl. `dns_servers: Vec<IpAddr>` (Heap-Alloc +
Element-Copy) — obwohl alle Werte über den Paket-Call hinaus unverändert leben.

## Fix
- `live_auth.rs`: alle sieben Arc-Parameter auf `&Arc<T>` umgestellt; die seltenen
  MASQUE/DNS-Pfade klonen weiterhin intern bei Bedarf (`Arc::clone(x)` direkt auf
  der Referenz — `needless_borrow`-Fixes inklusive).
- `assignment_settings: &ServerAssignmentSettings` — kein Vec-Clone mehr.
- `runtime_impl/runtime_loop.rs`: Callsite reicht Referenzen durch statt zu
  klonen.

## Effekt
- 6× `Arc::clone` (je 2 atomare Ops) pro Datagramm eliminiert.
- 1× `Vec<IpAddr>`-Heap-Clone pro Datagramm eliminiert.
- Zero-Cost auf dem Hot-Path; Semantik identisch (Lebensdauer durch Caller
  garantiert).

## Verifikation
- Lokal: `cargo check -p quicfuscate` sauber.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` + `cargo clippy`
  sauber (0 Warnings), `cargo test --lib live_auth` 4/4 grün.

## Grenzen
- Reine Borrow-Disziplin; kein Funktions-Feature. Weitere Per-Datagram-Clones
  in anderen Ingress-Pfaden bleiben Teil des Dauer-Sweeps.
