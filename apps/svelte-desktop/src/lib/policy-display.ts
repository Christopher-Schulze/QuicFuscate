import { congestionControlDisplayLabel } from "@quicfuscate/ui/congestion-control";

function normalize(raw: string | null | undefined): string {
  return (raw ?? "").trim().toLowerCase();
}

export function displayStealthMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (!v) return "Auto";
  if (v === "off") return "Off";
  if (v === "manual") return "Manual";
  if (v === "performance" || v === "base") return "Performance";
  if (v === "stealth") return "Stealth";
  if (v === "anti-dpi" || v === "antidpi" || v === "max" || v === "stealthmax" || v === "stealth-max") return "AntiDPI";
  if (v === "auto" || v === "intelligent") return "Auto";
  return "Auto";
}

export function displayFecMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (v === "off" || v === "zero") return "Off";
  return "Auto";
}

export function displayCcMode(raw: string | null | undefined): string {
  const v = normalize(raw);
  if (!v || v === "server") return "BBR3";
  return congestionControlDisplayLabel(v);
}

export function displayMtu(raw: string | null | undefined): string {
  const v = (raw ?? "").trim();
  if (!v || v.toLowerCase() === "server") return "1200";
  if (/^\d+$/.test(v)) return v;
  return "1200";
}
