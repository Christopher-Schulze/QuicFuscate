# TODO-944 — H3-Poll-Loop: `conn.stats().clone()` pro Iteration → lazy fetch

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`prepare_http3_poll_iteration` klonte `self.conn.stats()` (~24 `usize`-Felder,
≈200 B) **pro Iteration** des H3-Poll-Loops — obwohl `stats` nur in
`emit_server_push_cover_burst` gelesen wurde, das bei fehlendem
`server_push_cover_plan()` sofort early-returned. Der Stats-Clone war also
unbedingter Aufwand für einen Low-Rate-Cover-Traffic-Pfad.

## Fix
- `prepare_http3_poll_iteration` gibt nur noch `intelligent_level` zurück.
- `emit_server_push_cover_burst` holt `conn.stats()` selbst — nach dem
  Early-Return, nur wenn ein Cover-Burst tatsächlich fällig ist; `sent`/`lost`
  werden in Locals kopiert, der Borrow endet vor `h3.generate_stealth_cover_burst`.

## Effekt
- Ein ~200-B-Struct-Clone pro Poll-Iteration eliminiert (N Iterationen pro
  Datagramm-Poll).
- Semantik identisch: Stats werden erst bei tatsächlichem Cover-Burst gelesen.

## Verifikation
- Lokal: `cargo check` + `clippy --lib` sauber; `cargo test --lib h3` 115/115.
- Omega (aarch64, io_uring): `cargo check` sauber; `cargo test --lib h3` 115/115.
