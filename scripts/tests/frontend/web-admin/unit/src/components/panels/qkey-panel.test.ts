import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../../../testing-library";

const getJsonMock = vi.hoisted(() => vi.fn());
const postJsonMock = vi.hoisted(() => vi.fn());

vi.mock("$lib/api", async () => {
  const actual = await vi.importActual<typeof import("$lib/api")>("$lib/api");
  return {
    ...actual,
    getJson: (...args: unknown[]) => getJsonMock(...args),
    postJson: (...args: unknown[]) => postJsonMock(...args),
  };
});

import QKeyPanel from "../../../../../../../../apps/svelte-admin/src/lib/components/panels/QKeyPanel.svelte";
import { adminApiSchemas } from "../../../../../../../../apps/svelte-admin/src/lib/admin-api-contracts";
import {
  setAuthError,
  setAuthRequired,
  setQkeyList,
  setQkeyListLoading,
} from "../../../../../../../../apps/svelte-admin/src/lib/stores/app.svelte";

describe("qkey panel", () => {
  beforeEach(() => {
    getJsonMock.mockReset();
    postJsonMock.mockReset();
    setAuthRequired(false);
    setAuthError(null);
    setQkeyList([]);
    setQkeyListLoading(false);
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("renders metadata-only registry entries and never reconstructs fake qkeys", async () => {
    getJsonMock.mockResolvedValue({
      success: true,
      data: {
        keys: [
          {
            id: "reg-12345",
            name: "Alpha",
            created_at: 1710000000,
            expires_at: 1710003600,
          },
        ],
      },
    });

    render(QKeyPanel);

    await screen.findByText("Registry ID");
    expect(screen.getByText("reg-12345")).toBeInTheDocument();
    expect(screen.queryByText(/QKey-/)).not.toBeInTheDocument();
  });

  test("generates a qkey and reveals it exactly once in the issued dialog", async () => {
    getJsonMock
      .mockResolvedValueOnce({
        success: true,
        data: { keys: [] },
      })
      .mockResolvedValueOnce({
        success: true,
        data: {
          keys: [
            {
              id: "reg-999",
              name: "Desktop",
              created_at: 1710000000,
            },
          ],
        },
      });
    postJsonMock.mockResolvedValue({
      success: true,
      data: {
        qkey: "QKey-REAL-SECRET",
        created_at: 1710000000,
        expires_at: 1710003600,
      },
    });

    render(QKeyPanel);

    await screen.findByText("No Keys created");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    await vi.advanceTimersByTimeAsync(90);

    const dialog = await screen.findByRole("dialog", { name: "Generate QKey" });
    await fireEvent.input(within(dialog).getByLabelText("Name of the Connection"), {
      target: { value: "Desktop" },
    });
    await fireEvent.input(within(dialog).getByLabelText("Port [1-65535]"), {
      target: { value: "4433" },
    });
    await fireEvent.click(within(dialog).getByRole("button", { name: "Generate" }));

    await waitFor(() => {
      expect(postJsonMock).toHaveBeenCalledWith("/api/qkey", {
        name: "Desktop",
        port: 4433,
        sni_strategy: "auto_rotating",
      }, adminApiSchemas.qkeyCreate);
    });

    const issuedDialog = await screen.findByRole("dialog", { name: "Issued QKey" });
    expect(within(issuedDialog).getByText("QKey-REAL-SECRET")).toBeInTheDocument();
    expect(within(issuedDialog).getByRole("button", { name: /Copy QKey/ })).toBeInTheDocument();
    expect(screen.getByText("reg-999")).toBeInTheDocument();
  });

  test("does not open the create dialog after the panel unmounts", async () => {
    getJsonMock.mockResolvedValue({ success: true, data: { keys: [] } });
    render(QKeyPanel);

    await screen.findByText("No Keys created");
    await fireEvent.click(screen.getByRole("button", { name: "Generate" }));
    cleanup();
    await vi.advanceTimersByTimeAsync(100);

    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });
});
