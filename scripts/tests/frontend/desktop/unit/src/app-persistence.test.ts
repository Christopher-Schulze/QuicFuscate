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
  setHydrationDone,
  setError,
  setSelectedId,
  setSettings,
  setTunnels,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import {
  loadPersistedState,
  persistState,
} from "../../../../../../apps/svelte-desktop/src/lib/stores/tauri-bridge.svelte";
import { desktopCreatedAt } from "./timestamp-fixtures";

function resetDesktopStore(): void {
  setTunnels([]);
  setSelectedId(null);
  setHydrationDone(false);
  setError(null);
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
    expect((getSettings() as Record<string, unknown>).connection).toBeUndefined();
  });

  test("loadPersistedState skips invoke in browser mode and completes hydration", async () => {
    delete (window as typeof window & { __TAURI_INTERNALS__?: Record<string, unknown> }).__TAURI_INTERNALS__;

    await loadPersistedState();

    expect(invokeMock).not.toHaveBeenCalled();
    expect(getHydrationDone()).toBe(true);
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
