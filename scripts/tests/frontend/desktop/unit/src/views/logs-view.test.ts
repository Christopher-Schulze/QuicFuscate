import { beforeEach, describe, expect, test, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "../../testing-library";

const engineLogsClearMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>("$lib/stores/tauri-bridge.svelte");
  return {
    ...actual,
    engineLogsClear: (...args: unknown[]) => engineLogsClearMock(...args),
  };
});

import LogsView from "../../../../../../../apps/svelte-desktop/src/lib/components/views/LogsView.svelte";
import {
  getLogs,
  setLogs,
} from "../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import { tauriLogTimestamp } from "../timestamp-fixtures";

describe("desktop logs view", () => {
  beforeEach(() => {
    engineLogsClearMock.mockReset();
    setLogs([]);
  });

  test("Copy copies all visible log entries", async () => {
    const writeTextMock = vi.fn(async () => undefined);
    Object.defineProperty(window.navigator, "clipboard", {
      configurable: true,
      value: { writeText: writeTextMock, readText: vi.fn(async () => "") },
    });

    setLogs([
      { timestamp: tauriLogTimestamp(1710000000000), timestampValid: true, timestampError: null, level: "info", message: "connected" },
      { timestamp: tauriLogTimestamp(1710000005000), timestampValid: true, timestampError: null, level: "warn", message: "latency spike" },
    ]);

    render(LogsView);
    await fireEvent.click(screen.getByTitle("Copy all logs"));

    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledTimes(1);
    });
    const copied = String(writeTextMock.mock.calls[0]?.[0] ?? "");
    expect(copied).toContain("[INFO] connected");
    expect(copied).toContain("[WARN] latency spike");
  });

  test("Clear clears log container and calls engine clear command", async () => {
    setLogs([
      { timestamp: tauriLogTimestamp(1710000000000), timestampValid: true, timestampError: null, level: "info", message: "connected" },
      { timestamp: tauriLogTimestamp(1710000005000), timestampValid: true, timestampError: null, level: "warn", message: "latency spike" },
    ]);
    engineLogsClearMock.mockResolvedValue(undefined);

    render(LogsView);
    await fireEvent.click(screen.getByRole("button", { name: "Clear" }));

    const dialogTitle = await screen.findByText("Clear Live Output");
    const dialog = dialogTitle.closest('[role="dialog"]') as HTMLElement;
    await fireEvent.click(within(dialog).getByRole("button", { name: "Clear" }));

    await waitFor(() => {
      expect(getLogs()).toEqual([]);
    });
    expect(engineLogsClearMock).toHaveBeenCalledTimes(1);
  });
});
