import type { MetricsMap } from "$lib/types";

export function parsePrometheusText(raw: string): MetricsMap {
  const map: MetricsMap = {};
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const match = parts[0].match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{.*\})?$/);
    if (!match) continue;
    const value = Number(parts[1]);
    if (!Number.isFinite(value)) continue;
    map[match[1]] = (map[match[1]] ?? 0) + value;
  }
  return map;
}
