# TODO-982 - systemd-resolved DNS leak: tunnel link DNS lacked the `~.` routing domain

## Symptom

On Linux hosts running systemd-resolved, the client's `set_dns` configured the
tunnel link's DNS servers via `resolvectl dns <tun> <servers>` but never set a
routing domain. systemd-resolved selects the query link by route-only domains
(`~domain`) and default-route flags — a link with DNS servers but no routing
domain does not capture unmatched names. The physical link's DHCP-provided DNS
therefore stayed eligible, leaking lookups to the LAN/ISP resolver while the
tunnel was connected.

Impact depends on caller:

- Standalone client DoH proxy (`ClientDnsRuntime`): system DNS pointed at
  `127.0.0.1` on the TUN link only — without `~.` most queries never reached
  the proxy at all, bypassing DoH protection entirely.
- Embedded backend (`ClientBackend::connect`): configured tunnel DNS servers
  (1.1.1.1/8.8.8.8 or assigned) stayed unused for unmatched names.
- With `--kill-switch` the same queries hit the port-53 DROP rules instead of
  leaking — fail-closed, but DNS resolution broke.

The legacy `/etc/resolv.conf` path was never affected: a `nameserver` rewrite
is a global resolver redirect, so all lookups already went to the tunnel DNS.
macOS (`networksetup -setdnsservers`, global per service) and Windows
(per-interface `netsh`) route through the TUN default routes and are not
affected by the resolved routing-domain issue.

## Fix

`src/implementations/client/platform/linux.rs`:

- `set_dns` now always emits `resolvectl domain <tun> <search...> "~."` after
  assigning servers on systemd-resolved systems. `~.` is the catch-all
  route-only domain (the wg-quick/Tailscale convention): it outranks every
  other link's default-route flag, so all lookups route to the tunnel link's
  DNS — the local DoH proxy or the configured resolvers.
- `resolvectl revert <tun>` on `restore_dns` removes the domain together with
  the link's DNS servers, so cleanup semantics are unchanged.
- A domain-command failure fails `set_dns` closed, which triggers the existing
  DNS rollback in `ClientDnsRuntime::start_with_config`.

## Tests

- `platform::linux::tests::systemd_domain_args_always_route_all_lookups_through_the_tunnel`
  — asserts `~.` is always appended, with and without search domains. Linux-only
  (module is `target_os = "linux"`); runs on Omega/CI.

## Notes

- Residual platform limitation (not a leak under resolved): Windows uses
  parallel multi-homed DNS across interfaces; the kill switch's port-53 drop
  covers it when enabled, but without `--kill-switch` Windows may still race
  LAN DNS. Full NRPT enforcement is a separate work item.
- The same `~.` treatment automatically covers the embedded backend path
  (`ClientBackend::connect`), which shares this `set_dns` implementation.
