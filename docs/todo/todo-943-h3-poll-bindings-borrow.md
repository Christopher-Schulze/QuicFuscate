# TODO-943 - H3-Poll-Loop: 6 Arc-Clones pro Poll -> Borrowed-Bindings-View

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`http3_poll_bindings()` baute pro `poll_http3_event_loop`-Aufruf ein
`Http3PollBindings` mit fuenf `Option<Arc>`-Callback-Clones plus einem
`memory_pool: Arc`-Clone - 6 Refcount-Atomics pro Datagramm-Poll, obwohl die
Callbacks nur waehrend des Polls gelesen werden (`FnMut`-Handler werden ueber
`&Option<...>`-Referenzen an die Dispatcher weitergereicht).

## Fix
- `Http3PollBindings<'a>` traegt jetzt `&'a Option<...>`/`&'a Arc<...>`-Felder -
  eine reine Borrow-View auf die Connection-Felder (types.rs).
- `MasqueDispatchContext<'a>` bindet `&'a Http3PollBindings<'a>` unveraendert.
- `OptimizationManager::memory_pool_ref()` neu: `&Arc<MemoryPool>` ohne Clone.
- Die View wird **inline** in `poll_http3_event_loop` konstruiert -
  absichtlich kein `&self`-Helper: ein Methoden-Receiver borgt ganz `self`
  und kollidiert mit den `&mut self.conn`/`self.h3_conn`-Borrows im Loop.
  Feld-Level-Borrows sind disjunkt und erlaubt.
- Alle 17 `&context.bindings.X`-Callsites zu `context.bindings.X`
  (Felder sind bereits Referenzen).

## Effekt
- 6x `Arc::clone` (12 atomare Ops) pro H3-Poll-Aufruf eliminiert - betrifft
  Server-Ingress (`poll_http3_with_headers` pro Datagramm) und Client
  (`poll_http3_to_ingress`).
- Callback-Semantik identisch: Handler werden weiter ueber `Arc<Mutex<...>>`
  gelockt/aufgerufen, nur ohne Klon beim View-Aufbau.

## Verifikation
- Lokal: `cargo check` + `clippy --lib` sauber; `cargo test --lib h3` 115/115,
  `--lib masque` 47/47.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` sauber;
  `cargo test --lib h3` 115/115 gruen.
