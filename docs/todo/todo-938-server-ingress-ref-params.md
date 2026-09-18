# TODO-938 - Server-Ingress: Per-Datagram Arc-Clones + Settings-Clone

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`process_live_server_client_datagram` (live_auth.rs) wurde pro **eingehendem
Datagramm** aufgerufen und nahm dabei sieben `Arc<T>`-Parameter **by value** sowie
`ServerAssignmentSettings` **by value** entgegen. Der Runtime-Loop klonte dafuer
pro Paket 6 `Arc`s (Atomics + Speicherbarrieren) und das komplette
`ServerAssignmentSettings` inkl. `dns_servers: Vec<IpAddr>` (Heap-Alloc +
Element-Copy) - obwohl alle Werte ueber den Paket-Call hinaus unveraendert leben.

## Fix
- `live_auth.rs`: alle sieben Arc-Parameter auf `&Arc<T>` umgestellt; die seltenen
  MASQUE/DNS-Pfade klonen weiterhin intern bei Bedarf (`Arc::clone(x)` direkt auf
  der Referenz - `needless_borrow`-Fixes inklusive).
- `assignment_settings: &ServerAssignmentSettings` - kein Vec-Clone mehr.
- `runtime_impl/runtime_loop.rs`: Callsite reicht Referenzen durch statt zu
  klonen.

## Effekt
- 6x `Arc::clone` (je 2 atomare Ops) pro Datagramm am Callsite eliminiert.
- 1x `Vec<IpAddr>`-Heap-Clone pro Datagramm eliminiert.
- 3x `Arc::clone` pro Datagramm im `poll_http3_with_headers`-Setup eliminiert:
  `tun_fault_for_stream`/`tun_notify_for_stream`/`shutdown_for_stream` wurden
  unbedingt pro Datagramm geklont, obwohl die `FnMut`-Callbacks nur fuer die
  Dauer des Calls leben (`h3_runtime.rs:1459`, keine `'static`-Bound) - die
  Closures capturen jetzt die `&Arc`-Parameter direkt.
- Zero-Cost auf dem Hot-Path; Semantik identisch (Lebensdauer durch Caller
  garantiert).
- Auditiert, belassen: `conn.masque_downlink_queue()` und
  `flush_masque_relay_responses` klonen `Option<Arc>` - `None` ist frei fuer
  Non-MASQUE-Clients, und der Borrow muss ueber den `&mut conn`-Call stabil
  sein.

## Verifikation
- Lokal: `cargo check -p quicfuscate` sauber.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` + `cargo clippy`
  sauber (0 Warnings), `cargo test --lib live_auth` 4/4 gruen.

## Grenzen
- Reine Borrow-Disziplin; kein Funktions-Feature. Weitere Per-Datagram-Clones
  in anderen Ingress-Pfaden bleiben Teil des Dauer-Sweeps.
