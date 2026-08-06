import { tick } from "svelte";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../../../testing-library";

const addToastMock = vi.hoisted(() => vi.fn());
const engineConnectMock = vi.hoisted(() => vi.fn());
const engineDisconnectMock = vi.hoisted(() => vi.fn());
const qkeyParseMock = vi.hoisted(() => vi.fn());
let runtimeAvailable = false;

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: (...args: unknown[]) => addToastMock(...args),
  };
});

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>("$lib/stores/tauri-bridge.svelte");
  return {
    ...actual,
    isTauri: () => runtimeAvailable,
    engineConnect: (...args: unknown[]) => engineConnectMock(...args),
    engineDisconnect: (...args: unknown[]) => engineDisconnectMock(...args),
    qkeyParse: (...args: unknown[]) => qkeyParseMock(...args),
  };
});

import TunnelList from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/TunnelList.svelte";
import {
  getError,
  getSelectedId,
  getTunnelStates,
  getTunnels,
  setError,
  setQkeyPolicies,
  setSelectedId,
  setSettings,
  setTunnelStates,
  setTunnels,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import { desktopCreatedAt } from "../../timestamp-fixtures";

function seedTunnels(): void {
  setTunnels([
    {
      id: "t1",
      name: "Alpha",
      remote: "alpha.example.com:4433",
      countryCode: "US",
      createdAt: desktopCreatedAt(),
      qkey: "",
      sni: "alpha.example.com",
      hasToken: false,
    },
    {
      id: "t2",
      name: "Beta",
      remote: "beta.example.com:4433",
      countryCode: "DE",
      createdAt: desktopCreatedAt(),
      qkey: "QKey-BETA",
      sni: "beta.example.com",
      hasToken: true,
    },
  ]);
  setSelectedId(null);
  setTunnelStates({});
  setQkeyPolicies({});
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

function getCardByName(name: string): HTMLElement {
  const labels = screen.getAllByText(name);
  const button = labels
    .map((label) => label.closest("button[data-selected]"))
    .find((candidate): candidate is HTMLElement => Boolean(candidate));
  if (!button) throw new Error(`tunnel card not found for ${name}`);
  return button;
}

describe("desktop tunnel list", () => {
  beforeEach(() => {
    runtimeAvailable = false;
    addToastMock.mockReset();
    engineConnectMock.mockReset();
    engineDisconnectMock.mockReset();
    qkeyParseMock.mockReset();
    qkeyParseMock.mockResolvedValue({
      stealth: "auto",
      fec: "auto",
      extra: null,
      sni: "cdn.example.com",
    });
    seedTunnels();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("deleting a selected tunnel clears selection", async () => {
    setSelectedId("t1");
    render(TunnelList);

    const alphaRow = getCardByName("Alpha");
    await fireEvent.click(within(alphaRow.parentElement as HTMLElement).getByRole("button", { name: "Open configuration" }));
    await vi.advanceTimersByTimeAsync(90);
    await tick();
    const configDialog = await screen.findByRole("dialog", {}, { timeout: 10000 });
    await fireEvent.click(within(configDialog).getByRole("button", { name: "Delete" }));
    await vi.advanceTimersByTimeAsync(90);
    await tick();
    const confirmDialog = await screen.findByRole("dialog", { name: "Delete Tunnel" }, { timeout: 10000 });
    await fireEvent.click(within(confirmDialog).getByRole("button", { name: "Delete" }));
    await vi.advanceTimersByTimeAsync(90);
    await tick();

    await waitFor(() => {
      expect(getSelectedId()).toBeNull();
    });
    expect(getTunnels().map((t) => t.id)).toEqual(["t2"]);
  }, 25000);

  test("connect in browser mode sets error and keeps tunnel inactive", async () => {
    setSelectedId("t2");
    render(TunnelList);

    await fireEvent.click(screen.getByRole("button", { name: "Connect" }));

    await waitFor(() => {
      expect(getError()).toBe("Connect requires the desktop app runtime");
    });
    expect(getTunnelStates().t2).toBe("inactive");
    expect(engineConnectMock).not.toHaveBeenCalled();
  });

  test("connect failure sets error and returns tunnel to inactive", async () => {
    runtimeAvailable = true;
    engineConnectMock.mockRejectedValue("boom");
    setSelectedId("t2");
    render(TunnelList);

    await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getError()).toBe("boom");
    });
    expect(getTunnelStates().t2).toBe("inactive");
    expect(engineConnectMock).toHaveBeenCalledTimes(1);
  });

  test("connect becomes disabled while activating and does not double invoke", async () => {
    runtimeAvailable = true;
    let resolveConnect: (() => void) | null = null;
    const connectPromise = new Promise<void>((resolve) => {
      resolveConnect = resolve;
    });
    engineConnectMock.mockImplementation(() => connectPromise);
    setSelectedId("t2");
    render(TunnelList);

    const connectButton = screen.getByRole("button", { name: "Connect" });
    await fireEvent.click(connectButton);

    await waitFor(() => {
      expect(getTunnelStates().t2).toBe("activating");
    });
    expect(screen.getByRole("button", { name: "Connect" })).toBeDisabled();

    await fireEvent.click(screen.getByRole("button", { name: "Connect" }));
    expect(engineConnectMock).toHaveBeenCalledTimes(1);

    resolveConnect?.();
    await waitFor(() => {
      expect(getTunnelStates().t2).toBe("active");
    });
  });

  test("disconnect failure sets error and returns tunnel to inactive", async () => {
    runtimeAvailable = true;
    engineDisconnectMock.mockRejectedValue("disconnect exploded");
    setSelectedId("t2");
    setTunnelStates({ t2: "active" });
    render(TunnelList);

    await fireEvent.click(screen.getByRole("button", { name: "Disconnect" }));
    const dialog = await screen.findByRole("dialog", { name: "Disconnect Tunnel" });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Disconnect" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getError()).toBe("disconnect exploded");
    });
    expect(getTunnelStates().t2).toBe("inactive");
    expect(engineDisconnectMock).toHaveBeenCalledTimes(1);
  });

});
