import { unixMillisecondsToDate, unixSecondsToMilliseconds } from "@quicfuscate/time";
import type { AdminLogTimestamp, AdminQKeyTimestamp } from "$lib/types";

export function formatBitsPerSecond(bitsRaw: number): string {
  const bits = Math.max(0, Number.isFinite(bitsRaw) ? bitsRaw : 0);
  const units = [
    { factor: 1, unit: "bit/s" },
    { factor: 1_000, unit: "Kbit/s" },
    { factor: 1_000_000, unit: "Mbit/s" },
    { factor: 1_000_000_000, unit: "Gbit/s" },
    { factor: 1_000_000_000_000, unit: "Tbit/s" },
  ] as const;
  let selected: (typeof units)[number] = units[0];
  for (const u of units) {
    if (bits >= u.factor) selected = u;
  }
  const scaled = bits / selected.factor;
  const decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(decimals)} ${selected.unit}`;
}

export function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

export function formatMetricBytes(valueRaw: number): string {
  const value = Math.max(0, valueRaw);
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let unitIndex = 0;
  let scaled = value;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  const decimals = scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2;
  return `${scaled.toFixed(decimals)} ${units[unitIndex]}`;
}

export function formatMetricCount(value: number): string {
  return Math.max(0, Math.round(value)).toLocaleString("en-US");
}

export function formatMetricValue(name: string, value: number): string {
  if (name === "quicfuscate_up") return value >= 1 ? "Online" : "Offline";
  if (name === "quicfuscate_uptime_seconds") return formatUptime(Math.max(0, Math.floor(value)));
  if (name === "quicfuscate_bytes_in_total" || name === "quicfuscate_bytes_out_total") return formatMetricBytes(value);
  if (name.endsWith("_active")) return value >= 1 ? "Enabled" : "Disabled";
  if (Number.isInteger(value)) return formatMetricCount(value);
  return value.toFixed(2);
}

export function formatTimestamp(ts: AdminLogTimestamp | null): string {
  const date = unixMillisecondsToDate(ts);
  if (!date) return "Time unavailable";
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatTimestampIso(ts: AdminLogTimestamp | null): string {
  const date = unixMillisecondsToDate(ts);
  return date ? date.toISOString() : "Time unavailable";
}

export function formatUnixSeconds(ts: AdminQKeyTimestamp | null): string | null {
  if (ts === null) return null;
  const milliseconds = unixSecondsToMilliseconds(ts, "admin-qkey");
  return milliseconds ? unixMillisecondsToDate(milliseconds)?.toLocaleString() ?? null : null;
}
