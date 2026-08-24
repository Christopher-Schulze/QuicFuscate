import type { StealthManualSettings, StealthPresetUi, CcSelection } from "$lib/types";
import { parseCongestionControlAlgorithm } from "@quicfuscate/ui/congestion-control";
import { parse as parseTomlDocument } from "smol-toml";

export const DEFAULT_STEALTH_MANUAL: StealthManualSettings = {
  enable_domain_fronting: true,
  enable_http3_masquerading: true,
  use_tls_cover: true,
  use_qpack_headers: true,
  enable_traffic_padding: false,
  enable_timing_obfuscation: false,
  enable_protocol_mimicry: true,
  enable_doh: true,
};

export const FRONTING_SNI_ALLOWLIST = [
  "cdn.cloudflare.com", "cloudflare-dns.com", "one.one.one.one", "warp.plus", "workers.dev",
  "cdn.fastly.net", "fastly.com", "fastlylb.net", "fsly.net",
  "akamaized.net", "akamai.net", "akamaihd.net", "akamaitechnologies.com", "edgesuite.net",
  "cloudfront.net", "amazonaws.com", "aws.amazon.com", "awsstatic.com",
  "googleapis.com", "googleusercontent.com", "googlevideo.com", "gstatic.com", "google.com",
  "azureedge.net", "azure.microsoft.com", "windows.net", "msecnd.net",
  "stackpathdns.com", "stackpathcdn.com", "bootstrapcdn.com",
  "kxcdn.com", "keycdn.com", "b-cdn.net", "bunnycdn.com",
  "incapdns.net", "imperva.com",
] as const;

export function normalizeTomlTextForUi(raw: string): string {
  if (raw.includes("\\n")) {
    const realNewlines = raw.split("\n").length - 1;
    const looksLikeLegacy =
      raw.includes("\\n[") || raw.includes("]\\n") || raw.includes("\\n#") || raw.includes("\\n\\n");
    const containsQuotedEscaped =
      raw.includes('"\\\\n"') || raw.includes("'\\\\n'");
    if (realNewlines <= 1 && looksLikeLegacy && !containsQuotedEscaped) {
      return raw.split("\\n").join("\n");
    }
  }
  return raw;
}

function parseSectionName(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed.startsWith("[")) return null;
  const end = trimmed.indexOf("]");
  if (end < 0) return null;
  const name = trimmed.slice(1, end).trim();
  return name ? name : null;
}

function parseKvLine(line: string): { key: string; value: string } | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) return null;
  const idx = trimmed.indexOf("=");
  if (idx < 0) return null;
  const key = trimmed.slice(0, idx).trim();
  const value = trimmed.slice(idx + 1).trim();
  if (!key) return null;
  return { key, value };
}

function isTomlTable(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) && !(value instanceof Date);
}

function lookupTomlTable(root: Record<string, unknown>, section: string): Record<string, unknown> | null {
  let current: unknown = root;
  for (const part of section.split(".")) {
    if (!isTomlTable(current) || !(part in current)) return null;
    current = current[part];
  }
  return isTomlTable(current) ? current : null;
}

function formatTomlScalar(value: unknown): string | null {
  if (typeof value === "string") return value.length > 0 ? value : null;
  if (typeof value === "boolean" || typeof value === "number" || typeof value === "bigint") {
    return String(value);
  }
  return null;
}

function parseTomlRoot(contents: string): Record<string, unknown> | null {
  try {
    const parsed = parseTomlDocument(normalizeTomlTextForUi(contents));
    return isTomlTable(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function expectedWrittenScalar(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith("\"") && trimmed.endsWith("\""))
    || (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function applySurgicalSectionValue(
  contents: string,
  section: string,
  key: string,
  value: string,
): string {
  const lines = contents.split("\n");
  let inSection = false;
  let sectionFound = false;
  let updated = false;
  let insertAt: number | null = null;
  let lastKeyLine: number | null = null;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    const sec = parseSectionName(trimmed);
    if (sec) {
      if (inSection && !updated && insertAt == null) insertAt = i;
      inSection = sec === section;
      if (inSection) sectionFound = true;
      continue;
    }
    if (!inSection) continue;
    const kv = parseKvLine(trimmed);
    if (!kv) continue;
    if (kv.key !== key) continue;
    lastKeyLine = i;
  }

  if (lastKeyLine != null) {
    const original = lines[lastKeyLine];
    const commentIdx = original.indexOf("#");
    const comment = commentIdx >= 0 ? original.slice(commentIdx).trimEnd() : "";
    const suffix = comment ? ` ${comment}` : "";
    lines[lastKeyLine] = `${key} = ${value}${suffix}`;
    updated = true;
  }

  if (!updated) {
    if (sectionFound) {
      const idx = insertAt ?? lines.length;
      lines.splice(idx, 0, `${key} = ${value}`);
    } else {
      if (lines.length && lines[lines.length - 1].trim() !== "") lines.push("");
      lines.push(`[${section}]`);
      lines.push(`${key} = ${value}`);
    }
  }

  return lines.join("\n");
}

export function setSectionValue(contents: string, section: string, key: string, value: string): string {
  const next = applySurgicalSectionValue(contents, section, key, value);
  const readBack = readSectionValue(next, section, key);
  const expected = expectedWrittenScalar(value);
  if ((expected.length === 0 && readBack != null) || (expected.length > 0 && readBack !== expected)) {
    throw new Error(`TOML write did not round-trip [${section}] ${key}`);
  }
  const parsed = parseTomlRoot(next);
  if (parseTomlRoot(contents) != null && parsed == null) {
    throw new Error(`TOML write produced invalid document for [${section}] ${key}`);
  }
  return next;
}

function readSectionValueFromLines(contents: string, section: string, key: string): string | null {
  const lines = contents.split("\n");
  let inSection = false;
  let found: string | null = null;
  for (const line of lines) {
    const trimmed = line.trim();
    const sec = parseSectionName(trimmed);
    if (sec) {
      inSection = sec === section;
      continue;
    }
    if (!inSection) continue;
    const kv = parseKvLine(trimmed);
    if (!kv) continue;
    if (kv.key !== key) continue;
    const raw = (kv.value.split("#")[0] ?? "").trim();
    const unquoted = raw.replace(/^"|"$/g, "").trim();
    found = unquoted ? unquoted : null;
  }
  return found;
}

export function readSectionValue(contents: string, section: string, key: string): string | null {
  const normalized = normalizeTomlTextForUi(contents);
  const fromLines = readSectionValueFromLines(normalized, section, key);
  if (fromLines != null) return fromLines;
  const root = parseTomlRoot(contents);
  if (root == null) return null;
  const table = lookupTomlTable(root, section);
  if (table == null || !(key in table)) return null;
  return formatTomlScalar(table[key]);
}

function parseBool(raw: string | null): boolean | null {
  const v = (raw ?? "").trim().toLowerCase();
  if (v === "true") return true;
  if (v === "false") return false;
  return null;
}

export function parseMtu(raw: string | null): number | null {
  const v = (raw ?? "").trim();
  if (!v) return null;
  if (!/^\d+$/.test(v)) return null;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return null;
  if (n < 1200 || n > 9000) return null;
  return n;
}

export function parsePort(raw: string | null): number | null {
  const v = (raw ?? "").trim();
  if (!v) return null;
  if (!/^\d+$/.test(v)) return null;
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return null;
  if (n < 1 || n > 65535) return null;
  return n;
}

export function normalizeCcSelection(raw: string | null): CcSelection {
  const v = (raw ?? "").trim().toLowerCase();
  if (!v) return "bbr3";
  return parseCongestionControlAlgorithm(v) ?? "__custom__";
}

export function stealthPresetFromMode(mode: string | null): StealthPresetUi {
  const m = (mode ?? "").toLowerCase();
  if (m === "off") return "off";
  if (m === "manual") return "manual";
  if (m === "performance" || m === "base") return "performance";
  if (m === "stealth") return "stealth";
  if (m === "anti-dpi" || m === "antidpi" || m === "max" || m === "stealthmax" || m === "stealth-max") return "antidpi";
  return "auto";
}

export function fecPresetFromConfig(contents: string): "auto" | "off" {
  const mode = (readSectionValue(contents, "fec", "mode") ?? "").trim().toLowerCase();
  if (mode === "off" || mode === "zero") return "off";
  return "auto";
}

export function readStealthFlag(contents: string, key: keyof StealthManualSettings): boolean {
  const v = parseBool(readSectionValue(contents, "stealth", key));
  if (v != null) return v;
  return DEFAULT_STEALTH_MANUAL[key];
}

export function normalizeQKey(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (trimmed.startsWith("QKey-")) return trimmed;
  if (trimmed.toLowerCase().startsWith("qkey-")) return `QKey-${trimmed.slice(5)}`;
  return trimmed;
}

export function compactDisplayValue(value: string, maxLength: number): string {
  const normalized = value.trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength)}...`;
}

export function canonicalizeConfigForCompare(raw: string): string {
  return normalizeTomlTextForUi(raw).replace(/\r\n/g, "\n").trimEnd();
}
