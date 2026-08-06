import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "../../testing-library";

const qkeyParseMock = vi.hoisted(() => vi.fn());
const engineConnectMock = vi.hoisted(() => vi.fn());
const engineDisconnectMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>(
    "$lib/stores/tauri-bridge.svelte",
  );
  return {
    ...actual,
    isTauri: () => false,
    engineConnect: (...args: unknown[]) => engineConnectMock(...args),
    engineDisconnect: (...args: unknown[]) => engineDisconnectMock(...args),
    qkeyParse: (...args: unknown[]) => qkeyParseMock(...args),
  };
});

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: vi.fn(),
    ripple: () => {},
  };
});

import TunnelsView from "../../../../../../../apps/svelte-desktop/src/lib/components/views/TunnelsView.svelte";
import {
  setTunnels,
  setSelectedId,
  setTunnelStates,
  setTunnelStats,
  setQkeyPolicies,
  setThroughput,
  getSelectedId,
} from "../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import type { TunnelConfig } from "../../../../../../../apps/svelte-desktop/src/lib/types";
import { desktopCreatedAt } from "../timestamp-fixtures";

function makeTunnel(overrides: Partial<TunnelConfig> = {}): TunnelConfig {
  return {
    id: "t-1",
    name: "Test Tunnel",
    remote: "10.0.0.1:443",
    sni: "example.com",
    qkey: "QKEY_VALID_DATA_HERE",
    createdAt: desktopCreatedAt(),
    hasToken: false,
    ...overrides,
  };
}

function resetStores(): void {
  setTunnels([]);
  setSelectedId(null);
  setTunnelStates({});
  setTunnelStats({});
  setQkeyPolicies({});
  setThroughput({});
}

describe("views/TunnelsView", () => {
  beforeEach(() => {
    qkeyParseMock.mockReset();
    engineConnectMock.mockReset();
    engineDisconnectMock.mockReset();
    resetStores();
  });

  test("renders the Tunnels heading", async () => {
    const { container } = render(TunnelsView);

    await waitFor(() => {
      const heading = container.querySelector(".text-lg.font-bold");
      expect(heading).not.toBeNull();
      expect(heading!.textContent).toBe("Tunnels");
    });
  });

  test("renders Create button", async () => {
    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Open tunnel composer" })).toBeInTheDocument();
    });
  });

  test("renders Import QKey button", async () => {
    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Open QKey vault" })).toBeInTheDocument();
    });
  });

  test("shows empty state when no tunnels exist", async () => {
    const { container } = render(TunnelsView);

    await waitFor(() => {
      // The large "0" numeral is the empty state indicator (text-[32px])
      const emptyNumeral = container.querySelector('span[class*="text-\\[32px\\]"]');
      expect(emptyNumeral).not.toBeNull();
      expect(emptyNumeral!.textContent).toBe("0");
    });
  });

  test("shows tunnel count badge matching number of tunnels", async () => {
    const tunnels = [
      makeTunnel({ id: "t-1", name: "Tunnel Alpha" }),
      makeTunnel({ id: "t-2", name: "Tunnel Beta" }),
      makeTunnel({ id: "t-3", name: "Tunnel Gamma" }),
    ];
    setTunnels(tunnels);

    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByText("3")).toBeInTheDocument();
    });
  });

  test("renders tunnel names when tunnels are populated", async () => {
    setTunnels([
      makeTunnel({ id: "t-1", name: "Frankfurt VPN" }),
      makeTunnel({ id: "t-2", name: "Tokyo Relay" }),
    ]);

    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByText("Frankfurt VPN")).toBeInTheDocument();
      expect(screen.getByText("Tokyo Relay")).toBeInTheDocument();
    });
  });

  test("selecting a tunnel updates selectedId in store", async () => {
    const tunnels = [
      makeTunnel({ id: "t-1", name: "Tunnel A" }),
      makeTunnel({ id: "t-2", name: "Tunnel B" }),
    ];
    setTunnels(tunnels);

    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByText("Tunnel B")).toBeInTheDocument();
    });

    await fireEvent.click(screen.getByText("Tunnel B"));

    await waitFor(() => {
      expect(getSelectedId()).toBe("t-2");
    });
  });

  test("tunnel count badge updates when a tunnel is added", async () => {
    setTunnels([makeTunnel({ id: "t-1", name: "One" })]);
    render(TunnelsView);

    await waitFor(() => {
      expect(screen.getByText("1")).toBeInTheDocument();
    });

    setTunnels([
      makeTunnel({ id: "t-1", name: "One" }),
      makeTunnel({ id: "t-2", name: "Two" }),
    ]);

    await waitFor(() => {
      expect(screen.getByText("2")).toBeInTheDocument();
    });
  });

  test("empty state disappears when tunnels are added after initial render", async () => {
    const { container } = render(TunnelsView);

    await waitFor(() => {
      const emptyNumeral = container.querySelector('span[class*="text-\\[32px\\]"]');
      expect(emptyNumeral).not.toBeNull();
    });

    setTunnels([makeTunnel({ id: "t-1", name: "New Tunnel" })]);

    await waitFor(() => {
      const emptyNumeral = container.querySelector('span[class*="text-\\[32px\\]"]');
      expect(emptyNumeral).toBeNull();
      expect(screen.getByText("New Tunnel")).toBeInTheDocument();
    });
  });

  test("outer container has expected layout classes", () => {
    const { container } = render(TunnelsView);

    const outer = container.firstElementChild as HTMLElement;
    expect(outer).not.toBeNull();
    expect(outer.classList.contains("flex")).toBe(true);
    expect(outer.classList.contains("h-full")).toBe(true);
  });
});
