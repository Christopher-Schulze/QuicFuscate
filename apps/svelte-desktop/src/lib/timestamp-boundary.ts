import {
  describeTimestampError,
  parseUnixMilliseconds,
  type TimestampValidationError,
} from "@quicfuscate/time";
import type { DesktopCreatedAt, LogEntry, TauriLogTimestamp } from "$lib/types";

export interface RawTauriLogLine {
  tsMs?: unknown;
  timestampValid?: unknown;
  timestampError?: unknown;
  level?: unknown;
  message?: unknown;
  target?: unknown;
}

export function createDesktopCreatedAt(): DesktopCreatedAt {
  const result = parseUnixMilliseconds(Date.now(), "desktop-created");
  if (!result.ok) {
    throw new Error(`desktop-created timestamp rejected: ${describeTimestampError(result.error)}`);
  }
  return result.value;
}

function validationMessage(error: TimestampValidationError): string {
  return `Tauri log timestamp rejected: ${describeTimestampError(error)}`;
}

function isLogLevel(value: unknown): value is LogEntry["level"] {
  return value === "trace" || value === "debug" || value === "info" || value === "warn" || value === "error";
}

export function parseTauriLogLine(raw: unknown): LogEntry | null {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) return null;
  const line = raw as RawTauriLogLine;
  if (!isLogLevel(line.level) || typeof line.message !== "string") return null;

  const backendMarkedValid = line.timestampValid === true;
  const parsed = backendMarkedValid
    ? parseUnixMilliseconds(line.tsMs, "tauri-log")
    : { ok: false as const, error: "not-a-number" as const };
  const timestamp: TauriLogTimestamp | null = parsed.ok ? parsed.value : null;
  const timestampError = parsed.ok
    ? null
    : typeof line.timestampError === "string" && line.timestampError.trim().length > 0
      ? line.timestampError.trim()
      : backendMarkedValid
        ? validationMessage(parsed.error)
        : "Tauri marked the log timestamp invalid";

  return {
    timestamp,
    timestampValid: parsed.ok,
    timestampError,
    level: line.level,
    message: line.message,
    target: typeof line.target === "string" ? line.target : undefined,
  };
}
