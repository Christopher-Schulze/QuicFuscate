# TODO-941 — Server-TUN-Uplink: 2 Arc-Clones + read+write Sessions-Lock pro Paket

## Status
DONE (lokal + Omega/aarch64 verifiziert)

## Befund
`process_server_tun_packet` nahm pro TUN-Uplink-Paket:
1. `live.server_tun.clone()` — Arc-Clone, obwohl nur `&TunInterface` gebraucht wird.
2. `Arc::clone(&live.live_state.domain.shared.forwarding_policy)` — Arc-Clone für
   einen reinen `&self`-Methodenaufruf (`classify_downlink`).
3. `sessions.read()` für die Route→Target-Auflösung, dann `sessions.write()` pro
   Target für `bandwidth_stats` + `check_bandwidth` — zwei Acquisitions auf
   demselben RwLock pro Unicast-Paket.

## Fix
- `server_tun`/`forwarding_policy` werden jetzt geborgt (`as_ref()`/Feld-Referenz) —
  deref-Koersion deckt die `&TunInterface`-Parameter ab.
- Ein `sessions.write()`-Guard wird von der Routen-Klassifikation über die
  gesamte Target-Schleife gehalten (Route-Lookup + `bandwidth_stats` +
  `check_bandwidth` in einem). `live.live_state.clients` /
  `pending_tun_downlinks` sind disjunkte Feld-Borrows und bleiben nutzbar.
- `drop(sessions)` vor `flush_tun_downlink_queue(live, …)` — der Call braucht
  `&mut live` vollständig.
- Auditiert: `send_masque_downlink` berührt nur conn-internen State
  (`masque_peer_flows`, Dgram-Queue) — keine `sessions`-Re-Acquisition, kein
  Deadlock-Risiko durch den längeren Guard.

## Effekt
- 2× `Arc::clone` (4 atomare Ops) pro Uplink-Paket eliminiert.
- Lock-Acquisitions auf `sessions` pro Unicast-Paket: 2 → 1.
- Downlink-Fanout identisch (iteriert über demselben Guard).

## Verifikation
- Lokal: `cargo check`, `cargo clippy --lib` sauber; `cargo test --lib tun` 53/53.
- Omega (aarch64, Kernel 6.17, io_uring-Feature): `cargo check` + `clippy`
  sauber; `cargo test --lib tun` 58/58 grün.

## Grenzen
- `packet.to_vec()` im Backpressure-Enqueue (Zeile ~800/843) bleibt: die
  Pending-Queue muss das Payload besitzen. Ein `TunPacket`-Retention-Pfad
  (PooledBlock statt Kopie) ist als separates Finding denkbar.
