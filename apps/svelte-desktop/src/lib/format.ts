import { unknownErrorMessage } from "@quicfuscate/error-reporting";
import { formatClockTime } from "@quicfuscate/time";
import type { TauriLogTimestamp } from "$lib/types";

export function countryCodeToFlag(code: string | undefined): string {
  if (!code || code.length !== 2) return "";
  const cp = [...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65);
  return String.fromCodePoint(...cp);
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function formatDuration(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  const hh = String(h).padStart(2, "0");
  const mm = String(m).padStart(2, "0");
  const ss = String(s).padStart(2, "0");
  if (d > 0) return `${d}d ${hh}:${mm}:${ss}`;
  return `${hh}:${mm}:${ss}`;
}

export function formatRate(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps} bps`;
}

export function formatTimestamp(ts: TauriLogTimestamp | null): string {
  return formatClockTime(ts);
}

export function normalizeMode(raw: string | null | undefined, fallback = "auto"): string {
  const v = (raw ?? "").trim().toLowerCase();
  return v || fallback;
}

export function toErrorMessage(value: unknown, fallback = "Unknown error"): string {
  return unknownErrorMessage(value, fallback);
}
