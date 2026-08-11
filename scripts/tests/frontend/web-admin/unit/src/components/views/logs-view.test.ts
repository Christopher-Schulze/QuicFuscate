import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../../../testing-library";
import { getFrontendClockHarness } from "../../../../../test-clock";

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

import LogsView from "../../../../../../../../apps/svelte-admin/src/lib/components/views/LogsView.svelte";
import { adminApiSchemas } from "../../../../../../../../apps/svelte-admin/src/lib/admin-api-contracts";
import {
  setAuthRequired,
  setAuthError,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

const MODE_RESPONSE = {
  success: true,
  data: { mode: "normal" },
};

const STATUS_ONLINE = {
  success: true,
  data: { version: "0.2.0", uptime_secs: 100 },
};

const LOGS_RESPONSE = {
  success: true,
  data: {
    lines: [
      { ts: 1710000000000, timestamp_valid: true, timestamp_error: null, level: "info", msg: "Server started" },
      { ts: 1710000001000, timestamp_valid: true, timestamp_error: null, level: "warn", msg: "High latency detected" },
      { ts: 1710000002000, timestamp_valid: true, timestamp_error: null, level: "error", msg: "Connection dropped" },
    ],
    cursor: 3,
  },
};

const EMPTY_LOGS_RESPONSE = {
  success: true,
  data: { lines: [], cursor: 0 },
};

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}

function setVisibility(state: "hidden" | "visible"): void {
  getFrontendClockHarness().setVisibility(state);
}

function mockAllEndpoints(opts?: { logs?: unknown; mode?: unknown; status?: unknown }) {
  getJsonMock.mockImplementation((path: string) => {
    if (path === "/api/config/logging") return Promise.resolve(opts?.mode ?? MODE_RESPONSE);
    if (path === "/api/status") return Promise.resolve(opts?.status ?? STATUS_ONLINE);
    if (path.startsWith("/api/logs")) return Promise.resolve(opts?.logs ?? LOGS_RESPONSE);
    return Promise.resolve({ success: true, data: null });
  });
}

describe("LogsView", () => {
  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    getTextMock.mockReset();
    setAuthRequired(false);
    setAuthError(null);
    mockAllEndpoints();
    getFrontendClockHarness().useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("renders Logs heading", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByText("Logs")).toBeInTheDocument();
  });

  test("renders Save and Refresh buttons", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByRole("button", { name: "Save" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
  });

  test("renders Logging Mode section heading", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(50);

    expect(screen.getByText("Logging Mode")).toBeInTheDocument();
  });

  test("renders all four log mode options", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(100);

    expect(screen.getByRole("radio", { name: "Verbose" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Normal" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Minimal" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "No-Log" })).toBeInTheDocument();
  });

  test("Normal mode is checked by default", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByRole("radio", { name: "Normal" })).toHaveAttribute("aria-checked", "true");
    });
  });

  test("renders Live Output section heading in non no-log mode", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("Live Output")).toBeInTheDocument();
    });
  });

  test("renders Copy and Clear buttons in Live Output", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      // Copy button has a nested structure but text "Copy" exists
      expect(screen.getAllByText("Copy").length).toBeGreaterThan(0);
      expect(screen.getByRole("button", { name: "Clear" })).toBeInTheDocument();
    });
  });

  test("renders log entries from API response", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("Server started")).toBeInTheDocument();
      expect(screen.getByText("High latency detected")).toBeInTheDocument();
      expect(screen.getByText("Connection dropped")).toBeInTheDocument();
    });
  });

  test("renders log level badges", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("info")).toBeInTheDocument();
      expect(screen.getByText("warn")).toBeInTheDocument();
      expect(screen.getByText("error")).toBeInTheDocument();
    });
  });

  test("shows entry count label", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("3 entries")).toBeInTheDocument();
    });
  });

  test("fetches logging mode, status, and logs on mount", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    expect(getJsonMock).toHaveBeenCalledWith("/api/config/logging", adminApiSchemas.loggingRead);
    expect(getJsonMock).toHaveBeenCalledWith("/api/status", adminApiSchemas.status);
    expect(getJsonMock).toHaveBeenCalledWith("/api/logs?cursor=0", adminApiSchemas.logs);
  });

  test("pauses hidden polling and refreshes mode, status, and logs when visible again", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);
    getJsonMock.mockClear();

    setVisibility("hidden");
    await vi.advanceTimersByTimeAsync(15_000);
    expect(getJsonMock).not.toHaveBeenCalled();

    setVisibility("visible");
    await vi.advanceTimersByTimeAsync(0);
    expect(getJsonMock).toHaveBeenCalledWith("/api/config/logging", adminApiSchemas.loggingRead);
    expect(getJsonMock).toHaveBeenCalledWith("/api/status", adminApiSchemas.status);
    expect(getJsonMock).toHaveBeenCalledWith("/api/logs?cursor=3", adminApiSchemas.logs);
  });

  test("shows waiting message when logs are empty", async () => {
    mockAllEndpoints({ logs: EMPTY_LOGS_RESPONSE });

    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("Waiting for log entries...")).toBeInTheDocument();
    });
  });

  test("shows mode descriptions for each option", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(100);

    expect(screen.getByText(/Full debug logging/)).toBeInTheDocument();
    expect(screen.getByText(/Info-level logging/)).toBeInTheDocument();
    expect(screen.getByText(/Warnings and errors only/)).toBeInTheDocument();
    expect(screen.getByText(/Strict zero-log privacy mode/)).toBeInTheDocument();
  });

  test("renders online/offline status chip", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("Online")).toBeInTheDocument();
    });
  });

  test("shows offline when status endpoint fails", async () => {
    mockAllEndpoints({
      status: Promise.reject(new Error("connection refused")),
    });

    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByText("Offline")).toBeInTheDocument();
    });
  });

  test("Save button is disabled when mode has not changed", async () => {
    render(LogsView);
    await vi.advanceTimersByTimeAsync(200);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
  });

  test("discards an older log response after refresh starts reconciliation", async () => {
    const initialLogs = deferred<typeof LOGS_RESPONSE>();
    const refreshedLogs = deferred<typeof LOGS_RESPONSE>();
    let logCalls = 0;
    getJsonMock.mockImplementation((path: string) => {
      if (path === "/api/config/logging") return Promise.resolve(MODE_RESPONSE);
      if (path === "/api/status") return Promise.resolve(STATUS_ONLINE);
      if (path.startsWith("/api/logs")) {
        logCalls += 1;
        return logCalls === 1 ? initialLogs.promise : refreshedLogs.promise;
      }
      return Promise.resolve({ success: true, data: null });
    });

    render(LogsView);
    await waitFor(() => expect(logCalls).toBe(1));
    await fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    initialLogs.resolve({
      success: true,
      data: { lines: [{ ts: 1710000000000, timestamp_valid: true, timestamp_error: null, level: "error", msg: "stale response" }], cursor: 7 },
    });
    await vi.advanceTimersByTimeAsync(0);
    await waitFor(() => expect(logCalls).toBe(2));
    expect(screen.queryByText("stale response")).not.toBeInTheDocument();

    refreshedLogs.resolve({
      success: true,
      data: { lines: [{ ts: 1710000001000, timestamp_valid: true, timestamp_error: null, level: "info", msg: "fresh response" }], cursor: 8 },
    });
    await waitFor(() => expect(screen.getByText("fresh response")).toBeInTheDocument());
  });
});
