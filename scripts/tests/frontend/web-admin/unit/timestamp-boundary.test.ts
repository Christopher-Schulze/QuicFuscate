import { describe, expect, test } from "vitest";
import {
  parseAdminLogEntries,
  parseAdminLogEntry,
  parseAdminQKeyCreateResponse,
  parseAdminQKeyEntries,
} from "../../../../../apps/svelte-admin/src/lib/timestamp-boundary";

describe("admin timestamp boundaries", () => {
  test("accepts Unix-second QKey metadata and rejects millisecond-shaped values", () => {
    const entries = parseAdminQKeyEntries([
      { id: "valid", created_at: 1_710_000_000, expires_at: 1_710_003_600 },
      { id: "mismatched", created_at: 1_710_000_000_000, expires_at: null },
      { id: "zero", created_at: 0, expires_at: null },
    ]);

    expect(entries.map((entry) => entry.id)).toEqual(["valid", "mismatched", "zero"]);
    expect(entries[0]?.created_at).toBe(1_710_000_000);
    expect(entries[0]?.expires_at).toBe(1_710_003_600);
    expect(entries[1]).toMatchObject({ created_at: null, created_at_error: expect.stringContaining("other Unix time unit") });
    expect(entries[2]).toMatchObject({ created_at: null, created_at_error: expect.stringContaining("zero") });
  });

  test("does not fabricate metadata when QKey creation timestamps are invalid", () => {
    expect(parseAdminQKeyCreateResponse({ qkey: "QKey-REAL", created_at: 0, expires_at: null })).toMatchObject({
      qkey: "QKey-REAL",
      created_at: null,
      created_at_error: expect.stringContaining("zero"),
    });
    expect(parseAdminQKeyCreateResponse({ qkey: "QKey-REAL", created_at: 1_710_000_000, expires_at: null })).toEqual({
      qkey: "QKey-REAL",
      created_at: 1_710_000_000,
      expires_at: null,
      created_at_error: null,
      expires_at_error: null,
    });
  });

  test("propagates invalid admin log timestamp state without rendering epoch zero", () => {
    const lines = parseAdminLogEntries([
      { ts: 1_710_000_000_000, timestamp_valid: true, timestamp_error: null, level: "info", msg: "valid" },
      { ts: 0, timestamp_valid: false, timestamp_error: "wall clock unavailable", level: "error", msg: "invalid" },
    ]);

    expect(lines).toHaveLength(2);
    expect(lines[0]).toMatchObject({ ts: 1_710_000_000_000, timestampValid: true, timestampError: null });
    expect(lines[1]).toMatchObject({ ts: null, timestampValid: false, timestampError: "wall clock unavailable" });
  });

  test("rejects a seconds-shaped admin log value even when the backend flag is true", () => {
    const line = parseAdminLogEntry({
      ts: 1_710_000_000,
      timestamp_valid: true,
      level: "warn",
      msg: "mismatched unit",
    });
    expect(line).toMatchObject({ ts: null, timestampValid: false });
    expect(line?.timestampError).toContain("other Unix time unit");
  });
});
