import { describe, expect, test } from "vitest";
import {
  boundedString,
  counter,
  finiteNumber,
  oneOf,
  parseEngineStats,
  parseEngineStatus,
  parseUpdaterResult,
  percentage,
} from "../../../../../../../apps/svelte-desktop/src/lib/ipc-contracts";

describe("ipc-contracts primitives", () => {
  test("finiteNumber rejects the values that survive ?? 0", () => {
    // These are the exact values that used to pass through `stats.x ?? 0`, which only
    // substitutes for null and undefined, and then reached the throughput math.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, "5", null, undefined, {}]) {
      expect(finiteNumber(bad, 0, 100)).toBeNull();
    }
    expect(finiteNumber(0, 0, 100)).toBe(0);
    expect(finiteNumber(100, 0, 100)).toBe(100);
    expect(finiteNumber(101, 0, 100)).toBeNull();
    expect(finiteNumber(-1, 0, 100)).toBeNull();
  });

  test("counter rejects negative totals", () => {
    expect(counter(0)).toBe(0);
    expect(counter(-1)).toBeNull();
    expect(counter(Number.NaN)).toBeNull();
  });

  test("percentage is bounded to 0..100", () => {
    expect(percentage(50)).toBe(50);
    expect(percentage(100)).toBe(100);
    expect(percentage(100.1)).toBeNull();
    expect(percentage(-0.1)).toBeNull();
  });

  test("boundedString trims, rejects empty, and bounds length", () => {
    expect(boundedString("  ok  ", 10)).toBe("ok");
    expect(boundedString("   ", 10)).toBeNull();
    expect(boundedString("x".repeat(11), 10)).toBeNull();
    expect(boundedString(42, 10)).toBeNull();
  });

  test("oneOf keeps unknown values out of a closed union", () => {
    const levels = ["info", "warn", "error"] as const;
    expect(oneOf("warn", levels)).toBe("warn");
    expect(oneOf("catastrophe", levels)).toBeNull();
    expect(oneOf(7, levels)).toBeNull();
  });
});

describe("parseEngineStatus", () => {
  test("requires a usable state", () => {
    expect(parseEngineStatus(null)).toBeNull();
    expect(parseEngineStatus({})).toBeNull();
    expect(parseEngineStatus({ state: "" })).toBeNull();
    expect(parseEngineStatus({ state: 5 })).toBeNull();
  });

  test("nulls malformed optional fields without discarding a valid state", () => {
    // A bad error string must not hide a real state transition.
    const parsed = parseEngineStatus({ state: "running", activeTunnelId: 7, lastError: "" });
    expect(parsed).toEqual({ state: "running", activeTunnelId: null, lastError: null });
  });
});

describe("parseEngineStats", () => {
  const valid = {
    latencyMs: 12,
    lossPercent: 1.5,
    bytesIn: 100,
    bytesOut: 200,
    packetsIn: 3,
    packetsOut: 4,
    uptimeSecs: 60,
    stealthMode: "auto",
    fecMode: "auto",
    fecActivityPercent: 10,
    fecRecoveredPackets: 2,
  };

  test("accepts a valid sample and maps it to the store shape", () => {
    const parsed = parseEngineStats(valid);
    expect(parsed).not.toBeNull();
    expect(parsed?.rxBytes).toBe(100);
    expect(parsed?.txBytes).toBe(200);
    expect(parsed?.currentSni).toBeUndefined();
  });

  test("absent numeric fields default, present invalid ones reject the sample", () => {
    expect(parseEngineStats({})?.rxBytes).toBe(0);

    // Mixing a trusted counter with a nonsense one yields a throughput figure that
    // looks measured and is not, so the whole sample is dropped.
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, "100"]) {
      expect(parseEngineStats({ ...valid, bytesIn: bad })).toBeNull();
    }
    expect(parseEngineStats({ ...valid, lossPercent: 101 })).toBeNull();
    expect(parseEngineStats({ ...valid, fecActivityPercent: -1 })).toBeNull();
  });

  test("a present but malformed SNI is not silently dropped", () => {
    expect(parseEngineStats({ ...valid, currentSni: "   " })).toBeNull();
    expect(parseEngineStats({ ...valid, currentSni: 5 })).toBeNull();
    expect(parseEngineStats({ ...valid, currentSni: " vpn.example.com " })?.currentSni)
      .toBe("vpn.example.com");
  });

  test("rejects a non-object response", () => {
    expect(parseEngineStats(null)).toBeNull();
    expect(parseEngineStats([])).toBeNull();
    expect(parseEngineStats("stats")).toBeNull();
  });
});

describe("parseUpdaterResult", () => {
  const install = () => Promise.resolve();

  test("requires both versions and a callable install", () => {
    expect(parseUpdaterResult({ version: "1.0.0", downloadAndInstall: install })).toBeNull();
    expect(parseUpdaterResult({ currentVersion: "0.9.0", downloadAndInstall: install })).toBeNull();
    // An update object that cannot install must never reach the UI as available.
    expect(parseUpdaterResult({ currentVersion: "0.9.0", version: "1.0.0" })).toBeNull();
    expect(
      parseUpdaterResult({ currentVersion: "0.9.0", version: "1.0.0", downloadAndInstall: "nope" }),
    ).toBeNull();
  });

  test("accepts a well-formed result and bounds its optional metadata", () => {
    const parsed = parseUpdaterResult({
      currentVersion: "0.9.0",
      version: "1.0.0",
      date: "2026-08-08",
      downloadAndInstall: install,
    });
    expect(parsed?.version).toBe("1.0.0");
    expect(parsed?.date).toBe("2026-08-08");
    expect(parsed?.body).toBeUndefined();

    expect(
      parseUpdaterResult({
        currentVersion: "0.9.0",
        version: "1.0.0",
        date: "",
        downloadAndInstall: install,
      }),
    ).toBeNull();
  });
});
