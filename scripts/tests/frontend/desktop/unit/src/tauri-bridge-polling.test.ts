import { beforeEach, describe, expect, test, vi } from "vitest";

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
  engineLogsClear,
  startEnginePollers,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte";

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
  setTunnels([{ id: "t1", name: "Alpha", remote: "vpn.example.com:4433", sni: "cdn.example.com", qkey: "QKey", createdAt: 1, hasToken: false }]);
  setActiveTunnelId(null);
  setTunnelStates({});
  setTunnelStats({});
  setThroughput({});
  setLogs([]);
}

describe("desktop engine poller ownership", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    resetStores();
    setTauriMode();
    vi.useFakeTimers();
  });

  test("discards delayed status, stats, and log responses after teardown", async () => {
    const status = deferred<{ state: string; activeTunnelId: string | null }>();
    const stats = deferred<{ bytesIn: number; bytesOut: number }>();
    const logs = deferred<{ cursor: number; lines: { tsMs: number; level: string; message: string }[] }>();
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
    logs.resolve({ cursor: 4, lines: [{ tsMs: 1, level: "error", message: "late" }] });
    await vi.advanceTimersByTimeAsync(0);

    expect(getActiveTunnelId()).toBeNull();
    expect(getTunnelStates()).toEqual({});
    expect(getTunnelStats()).toEqual({});
    expect(getThroughput()).toEqual({});
    expect(getLogs()).toEqual([]);
  });

  test("serializes log polls and rejects cursor regressions and cleared epochs", async () => {
    const first = deferred<{ cursor: number; lines: { tsMs: number; level: string; message: string }[] }>();
    const second = deferred<{ cursor: number; lines: { tsMs: number; level: string; message: string }[] }>();
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

    first.resolve({ cursor: 5, lines: [{ tsMs: 1, level: "info", message: "first" }] });
    await vi.advanceTimersByTimeAsync(0);
    await vi.dynamicImportSettled();
    await vi.advanceTimersByTimeAsync(350);
    expect(logCall).toBe(2);

    second.resolve({ cursor: 4, lines: [{ tsMs: 2, level: "error", message: "regressed" }] });
    await vi.advanceTimersByTimeAsync(0);
    expect(getLogs().map((entry) => entry.message)).toEqual(["first"]);

    const cleared = deferred<{ cursor: number; lines: { tsMs: number; level: string; message: string }[] }>();
    invokeMock.mockImplementation((command: string) => {
      if (command === "engine_logs_since") return cleared.promise;
      if (command === "engine_logs_clear") return clearCommand.promise;
      return Promise.resolve(null);
    });
    await vi.advanceTimersByTimeAsync(350);
    const clearPromise = engineLogsClear();
    cleared.resolve({ cursor: 9, lines: [{ tsMs: 3, level: "warn", message: "after clear" }] });
    await vi.advanceTimersByTimeAsync(0);
    expect(getLogs().map((entry) => entry.message)).toEqual(["first"]);
    clearCommand.resolve(null);
    await clearPromise;
    stop();
  });
});
