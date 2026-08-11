import { beforeEach, describe, expect, test, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({
  invoke: invokeMock,
}));

import {
  getHydrationDone,
  getError,
  getSelectedId,
  getSettings,
  getTunnels,
  getPersistenceStatus,
  setHydrationDone,
  setError,
  setPersistenceStatus,
  setSelectedId,
  setSettings,
  setTunnels,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import {
  loadPersistedState,
  PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS,
  persistState,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte";
import { desktopCreatedAt } from "./timestamp-fixtures";

function resetDesktopStore(): void {
  setTunnels([]);
  setSelectedId(null);
  setHydrationDone(false);
  setError(null);
  setPersistenceStatus({ phase: "loading", dirty: false, error: null });
  setSettings({
    general: {
      logLevel: "info",
      autoConnectOnLaunch: false,
      startAtLogin: false,
      updaterEnabled: false,
      updaterChannel: "stable",
    },
    hardware: {
      detectedFeatures: [],
    },
  });
}

describe("desktop state persistence", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    resetDesktopStore();
    (window as typeof window & { __TAURI_INTERNALS__?: Record<string, unknown> }).__TAURI_INTERNALS__ = {
      invoke: invokeMock,
    };
  });

  test("persistState writes the current tunnels, selection, and settings", async () => {
    setTunnels([
      {
        id: "t1",
        name: "Alpha",
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
        qkey: "QKey-ABC",
        createdAt: desktopCreatedAt(123),
        hasToken: true,
      },
    ]);
    setSelectedId("t1");
    setSettings({
      general: {
        logLevel: "debug",
        autoConnectOnLaunch: true,
        startAtLogin: false,
        updaterEnabled: false,
        updaterChannel: "stable",
      },
      hardware: {
        detectedFeatures: ["avx2"],
      },
    });

    await persistState();

    expect(invokeMock).toHaveBeenCalled();
    const [command, payload] = invokeMock.mock.calls[0] ?? [];
    expect(command).toBe("save_state");
    expect(payload).toEqual({
      data: {
        schemaVersion: 1,
        tunnels: getTunnels(),
        selectedTunnelId: "t1",
        settings: getSettings(),
      },
    });
  });

  test("persistState propagates native keychain rejection to its queue owner", async () => {
    invokeMock.mockRejectedValueOnce(new Error("keychain storage is unavailable"));

    await expect(persistState()).rejects.toThrow("keychain storage is unavailable");

    const [command, payload] = invokeMock.mock.calls[0] ?? [];
    expect(command).toBe("save_state");
    expect(payload).toEqual(expect.objectContaining({ data: expect.any(Object) }));
  });

  test("loadPersistedState hydrates valid tunnels and keeps only supported settings", async () => {
    invokeMock.mockImplementation(async (command: string) => {
      if (command === "load_state") {
        return {
          schemaVersion: 1,
          tunnels: [
            null,
            {
              id: "",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
            },
            {
              id: "good-1",
              name: "",
              remote: "vpn.example.com:4433",
              sni: "cdn.example.com",
              qkey: "QKey-TEST",
              hasToken: true,
              createdAt: 123,
              countryCode: "de",
              location: "  Frankfurt  ",
            },
          ],
          selectedTunnelId: "missing-id",
          settings: {
            general: { logLevel: "trace", autoConnectOnLaunch: true },
            hardware: { detectedFeatures: ["aes"] },
            connection: { stale: true },
          },
        };
      }
      return null;
    });

    await loadPersistedState();

    expect(getTunnels()).toEqual([
      {
        id: "good-1",
        name: "vpn.example.com:4433",
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
        qkey: "QKey-TEST",
        createdAt: 123,
        hasToken: true,
        countryCode: "DE",
        location: "Frankfurt",
      },
    ]);
    expect(getSelectedId()).toBe("good-1");
    expect(getSettings().general.logLevel).toBe("trace");
    expect(getSettings().general.autoConnectOnLaunch).toBe(true);
    expect(getHydrationDone()).toBe(true);
    expect(getPersistenceStatus()).toEqual({ phase: "ready", dirty: false, error: null });
    expect((getSettings() as Record<string, unknown>).connection).toBeUndefined();
  });

  test("loadPersistedState preserves current state and exposes native rejection", async () => {
    setTunnels([{
      id: "current",
      name: "Current",
      remote: "current.example.com:4433",
      sni: "cdn.example.com",
      qkey: "",
      createdAt: desktopCreatedAt(44),
      hasToken: false,
    }]);
    invokeMock.mockRejectedValueOnce(new Error("state file is unavailable"));

    const result = await loadPersistedState();

    expect(result).toEqual({ status: "failed", message: "state file is unavailable" });
    expect(getTunnels()).toHaveLength(1);
    expect(getTunnels()[0]?.id).toBe("current");
    expect(getHydrationDone()).toBe(true);
    expect(getPersistenceStatus()).toEqual({
      phase: "load-error",
      dirty: false,
      error: "state file is unavailable",
    });
  });

  test("load retry replaces startup state only after native recovery succeeds", async () => {
    invokeMock
      .mockRejectedValueOnce(new Error("keychain unavailable"))
      .mockResolvedValueOnce({
        schemaVersion: 1,
        tunnels: [{
          id: "recovered",
          name: "Recovered",
          remote: "vpn.example.com:4433",
          sni: "cdn.example.com",
          qkey: "",
          createdAt: 123,
          hasToken: true,
        }],
        selectedTunnelId: "recovered",
        settings: {},
      });

    expect(await loadPersistedState()).toEqual({
      status: "failed",
      message: "keychain unavailable",
    });
    expect(getPersistenceStatus().phase).toBe("load-error");

    expect(await loadPersistedState()).toEqual({ status: "loaded" });
    expect(getSelectedId()).toBe("recovered");
    expect(getPersistenceStatus()).toEqual({ phase: "ready", dirty: false, error: null });
  });

  test("an interrupted native startup load fails at its explicit timeout", async () => {
    vi.useFakeTimers();
    invokeMock.mockReturnValueOnce(new Promise<null>(() => {}));

    const pendingLoad = loadPersistedState();
    expect(getHydrationDone()).toBe(false);
    expect(getPersistenceStatus()).toEqual({ phase: "loading", dirty: false, error: null });

    await vi.advanceTimersByTimeAsync(PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS);
    expect(await pendingLoad).toEqual({
      status: "failed",
      message: `Native desktop state loading did not complete within ${PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS} ms.`,
    });
    expect(getHydrationDone()).toBe(true);
    expect(getPersistenceStatus()).toEqual({
      phase: "load-error",
      dirty: false,
      error: `Native desktop state loading did not complete within ${PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS} ms.`,
    });
  });

  test("loadPersistedState skips invoke in browser mode and completes hydration", async () => {
    delete (window as typeof window & { __TAURI_INTERNALS__?: Record<string, unknown> }).__TAURI_INTERNALS__;

    await loadPersistedState();

    expect(invokeMock).not.toHaveBeenCalled();
    expect(getHydrationDone()).toBe(true);
    expect(getPersistenceStatus()).toEqual({ phase: "browser", dirty: false, error: null });
  });

  test("skips invalid backend timestamps and exposes the invalid-state error", async () => {
    invokeMock.mockResolvedValue({
      schemaVersion: 1,
      tunnels: [{
        id: "bad-time",
        name: "Bad time",
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
        createdAt: 0,
      }],
      selectedTunnelId: "bad-time",
      settings: {},
    });
    const dateNow = vi.spyOn(Date, "now").mockImplementation(() => {
      throw new Error("backend-owned timestamp must not use browser Date.now");
    });

    await loadPersistedState();

    expect(dateNow).not.toHaveBeenCalled();
    expect(getTunnels()).toEqual([]);
    expect(getError()).toContain("creation timestamp was invalid");
    expect(getHydrationDone()).toBe(true);
    dateNow.mockRestore();
  });
});
