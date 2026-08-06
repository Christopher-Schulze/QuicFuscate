import {
  describeTimestampError,
  parseUnixMilliseconds,
  parseUnixSeconds,
} from "@quicfuscate/time";
import type { AdminLogTimestamp, AdminQKeyTimestamp, LogEntry, QKeyEntry } from "$lib/types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseAdminQKeyEntry(value: unknown): QKeyEntry | null {
  if (!isRecord(value) || typeof value.id !== "string" || value.id.trim().length === 0) return null;
  const created = parseUnixSeconds(value.created_at, "admin-qkey");
  const expiresResult = value.expires_at === null || value.expires_at === undefined
    ? null
    : parseUnixSeconds(value.expires_at, "admin-qkey");
  const expires = expiresResult?.ok ? expiresResult.value : null;

  return {
    id: value.id.trim(),
    name: typeof value.name === "string" ? value.name : null,
    qkey: typeof value.qkey === "string" ? value.qkey : null,
    created_at: created.ok ? created.value : null,
    expires_at: expires,
    created_at_error: created.ok ? null : describeTimestampError(created.error),
    expires_at_error: expiresResult === null || expiresResult.ok ? null : describeTimestampError(expiresResult.error),
    stealth: typeof value.stealth === "string" ? value.stealth : null,
    fec: typeof value.fec === "string" ? value.fec : null,
  };
}

export function parseAdminQKeyEntries(value: unknown): QKeyEntry[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(parseAdminQKeyEntry)
    .filter((entry): entry is QKeyEntry => entry !== null);
}

export interface ParsedQKeyCreateResponse {
  qkey: string;
  created_at: AdminQKeyTimestamp | null;
  expires_at: AdminQKeyTimestamp | null;
  created_at_error: string | null;
  expires_at_error: string | null;
}

export function parseAdminQKeyCreateResponse(value: unknown): ParsedQKeyCreateResponse | null {
  if (!isRecord(value) || typeof value.qkey !== "string" || value.qkey.trim().length === 0) return null;
  const createdResult = value.created_at === null || value.created_at === undefined
    ? null
    : parseUnixSeconds(value.created_at, "admin-qkey");
  const expiresResult = value.expires_at === null || value.expires_at === undefined
    ? null
    : parseUnixSeconds(value.expires_at, "admin-qkey");
  return {
    qkey: value.qkey,
    created_at: createdResult?.ok ? createdResult.value : null,
    expires_at: expiresResult?.ok ? expiresResult.value : null,
    created_at_error: createdResult === null || createdResult.ok ? null : describeTimestampError(createdResult.error),
    expires_at_error: expiresResult === null || expiresResult.ok ? null : describeTimestampError(expiresResult.error),
  };
}

function logTimestampError(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : fallback;
}

export function parseAdminLogEntry(value: unknown): LogEntry | null {
  if (!isRecord(value) || typeof value.level !== "string" || typeof value.msg !== "string") return null;

  const backendMarkedValid = value.timestamp_valid === true;
  const parsed = backendMarkedValid
    ? parseUnixMilliseconds(value.ts, "admin-log")
    : { ok: false as const, error: "not-a-number" as const };
  const timestamp: AdminLogTimestamp | null = parsed.ok ? parsed.value : null;
  const timestampError = parsed.ok
    ? null
    : logTimestampError(
        value.timestamp_error,
        backendMarkedValid
          ? `Admin log timestamp rejected: ${describeTimestampError(parsed.error)}`
          : "Admin API marked the log timestamp invalid",
      );

  return {
    ts: timestamp,
    timestampValid: parsed.ok,
    timestampError,
    level: value.level,
    msg: value.msg,
  };
}

export function parseAdminLogEntries(value: unknown): LogEntry[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(parseAdminLogEntry)
    .filter((entry): entry is LogEntry => entry !== null);
}
