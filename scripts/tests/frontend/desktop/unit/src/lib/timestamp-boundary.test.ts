import { describe, expect, test } from "vitest";
import {
  MAX_UNIX_DATE_MILLISECONDS,
  parseUnixMilliseconds,
  parseUnixSeconds,
  unixMillisecondsToDate,
  unixSecondsToMilliseconds,
} from "../../../../../../../packages/time/index";
import {
  normalizePersistedTunnels,
} from "../../../../../../../apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte";
import { parseTauriLogLine } from "../../../../../../../apps/svelte-desktop/src/lib/timestamp-boundary";

describe("shared timestamp boundary", () => {
  test.each([
    [0, "zero"],
    [-1, "pre-epoch"],
    [1.5, "fractional"],
    [Number.NaN, "non-finite"],
    [Number.POSITIVE_INFINITY, "non-finite"],
    [MAX_UNIX_DATE_MILLISECONDS + 1, "date-range"],
    [1_710_000_000, "unit-mismatch"],
  ] as const)("rejects invalid Unix milliseconds %s as %s", (value, error) => {
    expect(parseUnixMilliseconds(value, "tauri-log")).toEqual({ ok: false, error });
  });

  test.each([
    [0, "zero"],
    [-1, "pre-epoch"],
    [1.5, "fractional"],
    [Number.NaN, "non-finite"],
    [Number.MAX_SAFE_INTEGER + 1, "unsafe-integer"],
    [MAX_UNIX_DATE_MILLISECONDS / 1000 + 1, "date-range"],
    [1_710_000_000_000, "unit-mismatch"],
  ] as const)("rejects invalid Unix seconds %s as %s", (value, error) => {
    expect(parseUnixSeconds(value, "admin-qkey")).toEqual({ ok: false, error });
  });

  test("accepts a future timestamp without mistaking it for a unit mismatch", () => {
    const futureMs = Date.UTC(2050, 0, 1);
    const milliseconds = parseUnixMilliseconds(futureMs, "tauri-persisted-tunnel");
    const seconds = parseUnixSeconds(Math.floor(futureMs / 1000), "admin-qkey");
    expect(milliseconds.ok).toBe(true);
    expect(seconds.ok).toBe(true);
  });

  test("centralizes seconds-to-milliseconds conversion", () => {
    const seconds = parseUnixSeconds(1_710_000_000, "admin-qkey");
    expect(seconds.ok).toBe(true);
    if (!seconds.ok) return;
    const milliseconds = unixSecondsToMilliseconds(seconds.value, "admin-qkey");
    expect(milliseconds).toBe(1_710_000_000_000);
    expect(unixMillisecondsToDate(milliseconds)?.getUTCFullYear()).toBe(2024);
  });

  test("does not invent a creation timestamp for invalid Tauri persistence", () => {
    const normalized = normalizePersistedTunnels([
      {
        id: "valid",
        name: "Valid",
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
        createdAt: 123,
      },
      {
        id: "zero",
        name: "Zero",
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
        createdAt: 0,
      },
    ]);

    expect(normalized.tunnels.map((tunnel) => tunnel.id)).toEqual(["valid"]);
    expect(normalized.tunnels[0]?.createdAt).toBe(123);
    expect(normalized.invalidTimestampCount).toBe(1);
  });

  test("keeps an invalid Tauri log visible without a valid timestamp", () => {
    const invalid = parseTauriLogLine({
      tsMs: 0,
      timestampValid: false,
      timestampError: "wall clock unavailable",
      level: "error",
      message: "engine failure",
    });
    expect(invalid).toMatchObject({
      timestamp: null,
      timestampValid: false,
      timestampError: "wall clock unavailable",
      message: "engine failure",
    });
  });
});
