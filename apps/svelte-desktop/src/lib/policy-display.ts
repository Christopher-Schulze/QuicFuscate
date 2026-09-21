import { congestionControlDisplayLabel } from "@quicfuscate/ui/congestion-control";

function normalize(raw: string | null | undefined): string {
  return (raw ?? "").trim().toLowerCase();
}

export function displayStealthMode(raw: string | null | undefined): string {
  const v = (raw ?? "").trim();
  if (
    v === "off" ||
    v === "manual" ||
    v === "performance" ||
    v === "stealth" ||
    v === "Stealth MAX" ||
    v === "dynamic"
  ) {
    return v;
  }
  return v || "dynamic";
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
