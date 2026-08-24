import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import {
  getActiveTunnelId,
  getLogs,
  getThroughput,
  getTunnelStates,
  getTunnelStats,
  setActiveTunnelId,
  setLogs,
  setThroughput,
  setTunnelStates,
  setTunnelStats,
  setTunnels,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import {
  engineConnect,
  engineLogsClear,
  engineRotate,
  startEnginePollers,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte";
import type { CircuitConfig } from "../../../../../../apps/svelte-desktop/src/lib/types";
import { getFrontendClockHarness } from "../../../test-clock";
import { desktopCreatedAt } from "./timestamp-fixtures";

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

function setTauriMode(): void {
  (window as typeof window & { __TAURI_INTERNALS__?: Record<string, unknown> }).__TAURI_INTERNALS__ = {
    invoke: invokeMock,
  };
}

function resetStores(): void {
  setTunnels([{ id: "t1", name: "Alpha", remote: "vpn.example.com:4433", sni: "cdn.example.com", qkey: "QKey", createdAt: desktopCreatedAt(1), hasToken: false }]);
  setActiveTunnelId(null);
  setTunnelStates({});
  setTunnelStats({});
  setThroughput({});
  setLogs([]);
}

function setVisibility(state: "hidden" | "visible"): void {
  getFrontendClockHarness().setVisibility(state);
}

function circuit(remote: string, role: "relay" | "exit" = "exit"): CircuitConfig {
  return {
    hops: [{
      id: `hop-${remote}`,
      label: "Exit",
      remote,
      sni: "exit.example.com",
      qkeyId: "0123456789ab",
      qkey: "QKey",
      role,
      verifyPeer: true,
      connectTimeoutMs: 10_000,
      idleTimeoutMs: 30_000,
      hasToken: true,
    }],
    maxHops: 3,
    maxParallelCircuits: 2,
    allowSingleHopFallback: false,
    diversity: {
      provider: false,
      region: false,
      jurisdiction: false,
      failureDomain: false,
    },
  };
}

describe("desktop engine poller ownership", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    resetStores();
    setTauriMode();
    getFrontendClockHarness().useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("discards delayed status, stats, and log responses after teardown", async () => {
    const status = deferred<{ state: string; activeTunnelId: string | null }>();
    const stats = deferred<{ bytesIn: number; bytesOut: number }>();
    const logs = deferred<{ cursor: number; lines: { tsMs: number; timestampValid: boolean; timestampError: string | null; level: string; message: string }[] }>();
    invokeMock.mockImplementation((command: string) => {
      if (command === "engine_status") return status.promise;
      if (command === "engine_stats") return stats.promise;
      if (command === "engine_logs_since") return logs.promise;
      return Promise.resolve(null);
    });

    const stop = startEnginePollers();
    await vi.advanceTimersByTimeAsync(1000);
    stop();
    status.resolve({ state: "Connected", activeTunnelId: "t1" });
    stats.resolve({ bytesIn: 100, bytesOut: 200 });
    logs.resolve({ cursor: 4, lines: [{ tsMs: 1, timestampValid: true, timestampError: null, level: "error", message: "late" }] });
    await vi.advanceTimersByTimeAsync(0);

    expect(getActiveTunnelId()).toBeNull();
    expect(getTunnelStates()).toEqual({});
    expect(getTunnelStats()).toEqual({});
    expect(getThroughput()).toEqual({});
    expect(getLogs()).toEqual([]);
  });

  test("binds connect and rotation arguments to the native command contracts", async () => {
    invokeMock.mockResolvedValue(undefined);
    const primary = circuit("203.0.113.10:4433");
    const alternate = circuit("203.0.113.20:4433");
    const settings = { general: { logLevel: "info" } };

    await engineConnect("t1", "PrimaryQKey", settings, "front.example.com", primary, alternate);
    expect(invokeMock).toHaveBeenNthCalledWith(
      1,
      "engine_connect",
      {
        request: {
          tunnelId: "t1",
          qkeyData: "PrimaryQKey",
          sniOverride: "front.example.com",
          circuit: primary,
          alternateCircuit: alternate,
          settings,
        },
      },
      undefined,
    );

    await engineRotate("t1", "AlternateQKey", settings, alternate);
    expect(invokeMock).toHaveBeenNthCalledWith(
      2,
      "engine_rotate",
      {
        tunnelId: "t1",
        qkeyData: "AlternateQKey",
        sniOverride: null,
        circuit: alternate,
        settings,
      },
      undefined,
    );
  });

  test("serializes log polls and rejects cursor regressions and cleared epochs", async () => {
    const first = deferred<{ cursor: number; lines: { tsMs: number; timestampValid: boolean; timestampError: string | null; level: string; message: string }[] }>();
    const second = deferred<{ cursor: number; lines: { tsMs: number; timestampValid: boolean; timestampError: string | null; level: string; message: string }[] }>();
    const clearCommand = deferred<null>();
    let logCall = 0;
    invokeMock.mockImplementation((command: string, payload?: { cursor?: number }) => {
      if (command === "engine_logs_since") {
        logCall += 1;
        if (logCall === 1) {
          expect(payload?.cursor).toBe(0);
          return first.promise;
        }
        expect(payload?.cursor).toBe(5);
        return second.promise;
      }
      if (command === "engine_logs_clear") return clearCommand.promise;
      return Promise.resolve(null);
    });

    expect("__TAURI_INTERNALS__" in window).toBe(true);
    const stop = startEnginePollers();
    expect(vi.getTimerCount()).toBe(3);
    await vi.advanceTimersByTimeAsync(351);
    await vi.dynamicImportSettled();
    await vi.advanceTimersByTimeAsync(700);
    expect(logCall).toBe(1);

    first.resolve({ cursor: 5, lines: [{ tsMs: 1_710_000_000_000, timestampValid: true, timestampError: null, level: "info", message: "first" }] });
    await vi.advanceTimersByTimeAsync(0);
    await vi.dynamicImportSettled();
    await vi.advanceTimersByTimeAsync(350);
    expect(logCall).toBe(2);
    expect(getLogs()[0]).toMatchObject({
      timestamp: 1_710_000_000_000,
      timestampValid: true,
      timestampError: null,
    });

    second.resolve({ cursor: 4, lines: [{ tsMs: 2, timestampValid: false, timestampError: "wall clock unavailable", level: "error", message: "regressed" }] });
    await vi.advanceTimersByTimeAsync(0);
    expect(getLogs().map((entry) => entry.message)).toEqual(["first"]);

    const cleared = deferred<{ cursor: number; lines: { tsMs: number; timestampValid: boolean; timestampError: string | null; level: string; message: string }[] }>();
    invokeMock.mockImplementation((command: string) => {
      if (command === "engine_logs_since") return cleared.promise;
      if (command === "engine_logs_clear") return clearCommand.promise;
      return Promise.resolve(null);
    });
    await vi.advanceTimersByTimeAsync(350);
    const clearPromise = engineLogsClear();
    cleared.resolve({ cursor: 9, lines: [{ tsMs: 0, timestampValid: false, timestampError: "wall clock unavailable", level: "warn", message: "after clear" }] });
    await vi.advanceTimersByTimeAsync(0);
    expect(getLogs().map((entry) => entry.message)).toEqual(["first"]);
    clearCommand.resolve(null);
    await clearPromise;
    stop();
  });

  test("does not start hidden pollers and polls all resources after becoming visible", async () => {
    invokeMock.mockImplementation((command: string) => {
      if (command === "engine_status") return Promise.resolve({ state: "Connected", activeTunnelId: "t1" });
      if (command === "engine_stats") return Promise.resolve({ bytesIn: 100, bytesOut: 200 });
      if (command === "engine_logs_since") return Promise.resolve({ cursor: 0, lines: [] });
      return Promise.resolve(null);
    });

    setVisibility("hidden");
    const stop = startEnginePollers();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(invokeMock).not.toHaveBeenCalled();

    setVisibility("visible");
    await vi.advanceTimersByTimeAsync(0);
    expect(invokeMock).toHaveBeenCalledWith("engine_status", {}, undefined);
    expect(invokeMock).toHaveBeenCalledWith("engine_stats", {}, undefined);
    expect(invokeMock).toHaveBeenCalledWith("engine_logs_since", { cursor: 0 }, undefined);
    stop();
  });

  test("uses monotonic throughput samples and rebases across visibility gaps", async () => {
    let bytesIn = 100;
    let bytesOut = 200;
    const clock = getFrontendClockHarness();
    clock.setMonotonicTime(1_000);
    invokeMock.mockImplementation((command: string) => {
      if (command === "engine_status") return Promise.resolve({ state: "Connected", activeTunnelId: "t1" });
      if (command === "engine_stats") return Promise.resolve({ bytesIn, bytesOut });
      if (command === "engine_logs_since") return Promise.resolve({ cursor: 0, lines: [] });
      return Promise.resolve(null);
    });

    const stop = startEnginePollers();
    try {
      await vi.advanceTimersByTimeAsync(900);
      expect(getThroughput()).toEqual({});

      bytesIn = 1_100;
      bytesOut = 2_200;
      clock.setMonotonicTime(2_000);
      await vi.advanceTimersByTimeAsync(900);
      expect(getThroughput()).toEqual({ t1: { downBps: 8_000, upBps: 16_000 } });

      setVisibility("hidden");
      expect(getThroughput()).toEqual({});
      bytesIn = 2_100;
      bytesOut = 3_200;
      clock.setMonotonicTime(3_000);
      await vi.advanceTimersByTimeAsync(900);
      expect(getThroughput()).toEqual({});

      setVisibility("visible");
      bytesIn = 2_200;
      bytesOut = 3_300;
      clock.setMonotonicTime(4_000);
      await vi.advanceTimersByTimeAsync(900);
      expect(getThroughput()).toEqual({});

      bytesIn = 2_300;
      bytesOut = 3_400;
      clock.setMonotonicTime(5_000);
      await vi.advanceTimersByTimeAsync(900);
      expect(getThroughput()).toEqual({ t1: { downBps: 800, upBps: 800 } });
    } finally {
      stop();
    }
  });
});
