/**
 * Parse a remote endpoint into host + port.
 * Accepts host[:port] and bracketed IPv6 ([::1]:4433).
 */
export function parseRemote(remote: string): { server: string; port: number } | null {
  const trimmed = remote.trim();
  if (!trimmed) return null;
  if (/\s/.test(trimmed)) return null;
  if (/[/?#@]/.test(trimmed)) return null;

  const parsePort = (portStr: string): number | null => {
    if (!portStr) return 4433;
    if (!/^\d+$/.test(portStr)) return null;
    const port = Number.parseInt(portStr, 10);
    if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
    return port;
  };

  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end < 0) return null;
    const host = trimmed.slice(1, end);
    if (!host || /\s/.test(host)) return null;
    // Anything after "]" must be either nothing or ":port". The old form treated any
    // other suffix as an absent port and defaulted to 4433, so "[2001:db8::1]junk"
    // was silently normalized into a different, valid-looking endpoint.
    const suffix = trimmed.slice(end + 1);
    if (suffix === "") return { server: host, port: 4433 };
    if (!suffix.startsWith(":")) return null;
    // A colon with nothing after it is malformed, not "no port given"; only an absent
    // suffix means the default applies.
    const portStr = suffix.slice(1);
    if (portStr === "") return null;
    const port = parsePort(portStr);
    if (!port) return null;
    return { server: host, port };
  }

  const colonCount = (trimmed.match(/:/g) || []).length;
  if (colonCount > 1) return null;

  const [host, portStr] = trimmed.split(":");
  if (!host) return null;
  if (!/^[A-Za-z0-9._-]+$/.test(host)) return null;
  const port = parsePort(portStr ?? "");
  if (!port) return null;
  return { server: host, port };
}

export function normalizeRemoteForStorage(remote: string): string | null {
  const parsed = parseRemote(remote);
  if (!parsed) return null;
  const host = parsed.server.includes(":") ? `[${parsed.server}]` : parsed.server;
  return `${host}:${parsed.port}`;
}

export function isValidSniHost(value: string): boolean {
  const sni = value.trim();
  if (!sni) return false;
  if (/\s/.test(sni)) return false;
  if (/[/?#@]/.test(sni)) return false;
  if (sni.includes(":")) return false;
  return true;
}
