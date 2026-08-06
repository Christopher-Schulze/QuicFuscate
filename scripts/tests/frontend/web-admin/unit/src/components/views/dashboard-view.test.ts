import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, render, screen, fireEvent, waitFor } from "../../../testing-library";

const getJsonMock = vi.hoisted(() => vi.fn());
const postJsonMock = vi.hoisted(() => vi.fn());
const getTextMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    getJson: (...args: unknown[]) => getJsonMock(...args),
    postJson: (...args: unknown[]) => postJsonMock(...args),
    getText: (...args: unknown[]) => getTextMock(...args),
  };
});

import DashboardView from "../../../../../../../../apps/svelte-admin/src/lib/components/views/DashboardView.svelte";
import {
  setAuthRequired,
  setAuthError,
  setStatus,
  setClients,
  setMetrics,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

const STATUS_RESPONSE = {
  success: true,
  data: {
    version: "0.2.0",
    uptime_secs: 3600,
    clients_active: 2,
    bytes_in: 1024000,
    bytes_out: 2048000,
    listen: "0.0.0.0:443",
  },
};

const CLIENTS_RESPONSE = {
  success: true,
  data: [
    { id: "c1", ip: "10.0.0.1", bytes_in: 100, bytes_out: 200 },
    { id: "c2", ip: "10.0.0.2", bytes_in: 300, bytes_out: 400 },
  ],
};

const METRICS_RESPONSE = {
  success: true,
  data: {
    metrics: {
      quicfuscate_connections_rejected: 5,
      quicfuscate_bytes_in_total: 50000000,
      quicfuscate_bytes_out_total: 80000000,
    },
  },
};

const BLOCKED_RESPONSE = {
  success: true,
  data: { ips: ["192.168.1.99"] },
};

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

function setVisibility(state: "hidden" | "visible"): void {
  Object.defineProperty(document, "visibilityState", { configurable: true, value: state });
  document.dispatchEvent(new Event("visibilitychange"));
}

function mockAllEndpoints() {
  getJsonMock.mockImplementation((path: string) => {
    if (path === "/api/status") return Promise.resolve(STATUS_RESPONSE);
    if (path === "/api/clients") return Promise.resolve(CLIENTS_RESPONSE);
    if (path.startsWith("/api/metrics")) return Promise.resolve(METRICS_RESPONSE);
    if (path === "/api/blocked") return Promise.resolve(BLOCKED_RESPONSE);
    return Promise.resolve({ success: true, data: null });
  });
}

describe("DashboardView", () => {
  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    getTextMock.mockReset();
    setAuthRequired(false);
    setAuthError(null);
    setStatus(null);
    setClients([]);
    setMetrics(null);
    mockAllEndpoints();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("renders dashboard heading", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByText("Dashboard")).toBeInTheDocument();
  });

  test("renders the Refresh button", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  test("renders Server section heading", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByText("Server")).toBeInTheDocument();
  });

  test("renders KPI card labels after data loads", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    expect(screen.getByText("Listen")).toBeInTheDocument();
    expect(screen.getByText("Uptime")).toBeInTheDocument();
    expect(screen.getByText("Upstream")).toBeInTheDocument();
    expect(screen.getByText("Downstream")).toBeInTheDocument();
    expect(screen.getByText("Clients")).toBeInTheDocument();
    expect(screen.getByText("Rejected")).toBeInTheDocument();
    expect(screen.getByText("Inbound Total")).toBeInTheDocument();
    expect(screen.getByText("Outbound Total")).toBeInTheDocument();
  });

  test("renders IP Access Control section heading", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByText("IP Access Control")).toBeInTheDocument();
  });

  test("fetches status, clients, metrics, and blocked on mount", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    expect(getJsonMock).toHaveBeenCalledWith("/api/status");
    expect(getJsonMock).toHaveBeenCalledWith("/api/clients");
    expect(getJsonMock).toHaveBeenCalledWith("/api/metrics/json");
    expect(getJsonMock).toHaveBeenCalledWith("/api/blocked");
  });

  test("pauses hidden polling and refreshes all resources when visible again", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);
    getJsonMock.mockClear();

    setVisibility("hidden");
    await vi.advanceTimersByTimeAsync(16_000);
    expect(getJsonMock).not.toHaveBeenCalled();

    setVisibility("visible");
    await vi.advanceTimersByTimeAsync(0);
    expect(getJsonMock).toHaveBeenCalledWith("/api/status");
    expect(getJsonMock).toHaveBeenCalledWith("/api/clients");
    expect(getJsonMock).toHaveBeenCalledWith("/api/metrics/json");
    expect(getJsonMock).toHaveBeenCalledWith("/api/blocked");
  });

  test("renders listen value from status", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("0.0.0.0:443")).toBeInTheDocument();
    });
  });

  test("renders connected IPs from client list", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("10.0.0.1")).toBeInTheDocument();
      expect(screen.getByText("10.0.0.2")).toBeInTheDocument();
    });
  });

  test("renders blocked IPs", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("192.168.1.99")).toBeInTheDocument();
    });
  });

  test("renders Block IP buttons for connected IPs", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      const blockButtons = screen.getAllByRole("button", { name: "Block IP" });
      expect(blockButtons.length).toBe(2);
    });
  });

  test("renders Unblock IP button for blocked IPs", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      const unblockButtons = screen.getAllByRole("button", { name: "Unblock IP" });
      expect(unblockButtons.length).toBe(1);
    });
  });

  test("renders Clear button in server section", async () => {
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByRole("button", { name: "Clear" })).toBeInTheDocument();
  });

  test("shows no IP activity message when no clients and no blocked IPs", async () => {
    getJsonMock.mockImplementation((path: string) => {
      if (path === "/api/status") return Promise.resolve(STATUS_RESPONSE);
      if (path === "/api/clients") return Promise.resolve({ success: true, data: [] });
      if (path.startsWith("/api/metrics")) return Promise.resolve(METRICS_RESPONSE);
      if (path === "/api/blocked") return Promise.resolve({ success: true, data: { ips: [] } });
      return Promise.resolve({ success: true, data: null });
    });

    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("No IP activity detected")).toBeInTheDocument();
    });
  });

  test("calls block API when Block IP button is clicked", async () => {
    postJsonMock.mockResolvedValue({ success: true });
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Block IP" }).length).toBeGreaterThan(0);
    });

    const blockButtons = screen.getAllByRole("button", { name: "Block IP" });
    await fireEvent.click(blockButtons[0]);
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(postJsonMock).toHaveBeenCalledWith("/api/block", { ip: "10.0.0.1" });
    });
  });

  test("calls unblock API when Unblock IP button is clicked", async () => {
    postJsonMock.mockResolvedValue({ success: true });
    render(DashboardView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Unblock IP" }).length).toBeGreaterThan(0);
    });

    const unblockButtons = screen.getAllByRole("button", { name: "Unblock IP" });
    await fireEvent.click(unblockButtons[0]);
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(postJsonMock).toHaveBeenCalledWith("/api/unblock", { ip: "192.168.1.99" });
    });
  });

  test("discards a blocked response that predates an optimistic block", async () => {
    const initialBlocked = deferred<typeof BLOCKED_RESPONSE>();
    const reconciledBlocked = deferred<typeof BLOCKED_RESPONSE>();
    let blockedCalls = 0;
    postJsonMock.mockResolvedValue({ success: true });
    getJsonMock.mockImplementation((path: string) => {
      if (path === "/api/status") return Promise.resolve(STATUS_RESPONSE);
      if (path === "/api/clients") return Promise.resolve(CLIENTS_RESPONSE);
      if (path.startsWith("/api/metrics")) return Promise.resolve(METRICS_RESPONSE);
      if (path === "/api/blocked") {
        blockedCalls += 1;
        if (blockedCalls === 1) return Promise.resolve({ success: true, data: { ips: [] } });
        return blockedCalls === 2 ? initialBlocked.promise : reconciledBlocked.promise;
      }
      return Promise.resolve({ success: true, data: null });
    });

    render(DashboardView);
    await waitFor(() => {
      expect(screen.getAllByRole("button", { name: "Block IP" }).length).toBe(2);
    });
    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(blockedCalls).toBe(2));
    await fireEvent.click(screen.getAllByRole("button", { name: "Block IP" })[0]);
    await waitFor(() => expect(postJsonMock).toHaveBeenCalledWith("/api/block", { ip: "10.0.0.1" }));

    initialBlocked.resolve({ success: true, data: { ips: ["10.0.0.2"] } });
    await vi.advanceTimersByTimeAsync(0);
    await waitFor(() => expect(blockedCalls).toBe(3));
    expect(screen.getAllByText("10.0.0.1").length).toBeGreaterThan(0);
    const blockedColumn = screen.getByText("Blocked").parentElement;
    expect(blockedColumn?.textContent).not.toContain("10.0.0.2");

    reconciledBlocked.resolve({ success: true, data: { ips: ["10.0.0.1"] } });
    await waitFor(() => expect(screen.getAllByText("10.0.0.1").length).toBeGreaterThan(0));
  });
});
