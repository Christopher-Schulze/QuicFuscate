import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "../../../testing-library";

const addToastMock = vi.hoisted(() => vi.fn());

vi.mock("@quicfuscate/ui", async () => {
  const actual = await vi.importActual<typeof import("@quicfuscate/ui")>("@quicfuscate/ui");
  return {
    ...actual,
    addToast: addToastMock,
  };
});

import TunnelConfigDialog from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/TunnelConfigDialog.svelte";
import {
  getTunnels,
  setTunnels,
  setSelectedId,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import type { TunnelConfig } from "../../../../../../../../apps/svelte-desktop/src/lib/types";
import { desktopCreatedAt } from "../../timestamp-fixtures";

function makeTunnel(overrides: Partial<TunnelConfig> = {}): TunnelConfig {
  return {
    id: "t1",
    name: "Test Tunnel",
    remote: "10.0.0.1:4433",
    sni: "cdn.example.com",
    qkey: "",
    createdAt: desktopCreatedAt(),
    hasToken: false,
    countryCode: "DE",
    ...overrides,
  };
}

describe("tunnel/TunnelConfigDialog", () => {
  let closeFn: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    closeFn = vi.fn();
    addToastMock.mockReset();
    const tunnel = makeTunnel();
    setTunnels([tunnel]);
    setSelectedId("t1");
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("renders dialog title 'Tunnel Configuration'", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByText("Tunnel Configuration")).toBeInTheDocument();
    });
  });

  test("renders tunnel name and remote in subtitle", async () => {
    const tunnel = makeTunnel({ name: "My VPN", remote: "1.2.3.4:4433" });
    setTunnels([tunnel]);
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByText(/My VPN/)).toBeInTheDocument();
      expect(screen.getByText(/1\.2\.3\.4:4433/)).toBeInTheDocument();
    });
  });

  test("renders name and remote input fields", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
      expect(screen.getByLabelText("Remote [IP-Address:Port]")).toBeInTheDocument();
    });
  });

  test("populates name field with tunnel name", async () => {
    const tunnel = makeTunnel({ name: "Alpha" });
    setTunnels([tunnel]);
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      const input = screen.getByLabelText("Name of the Connection") as HTMLInputElement;
      expect(input.value).toBe("Alpha");
    });
  });

  test("populates remote field with tunnel remote", async () => {
    const tunnel = makeTunnel({ remote: "192.168.1.1:5000" });
    setTunnels([tunnel]);
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      const input = screen.getByLabelText("Remote [IP-Address:Port]") as HTMLInputElement;
      expect(input.value).toBe("192.168.1.1:5000");
    });
  });

  test("Save button is disabled when form is clean (no edits)", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    });
  });

  test("Save button becomes enabled after editing name", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Changed Name" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });
  });

  test("renders Cancel button", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument();
    });
  });

  test("renders Delete button", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
    });
  });

  test("shows read-only server policy section", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByText("Server policy [read-only]")).toBeInTheDocument();
      expect(screen.getByText("Stealth")).toBeInTheDocument();
      expect(screen.getByText("FEC")).toBeInTheDocument();
      expect(screen.getByText("SNI [Server Name Indication]")).toBeInTheDocument();
    });
  });

  test("shows validation error for empty name on save", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
    });

    // Clear name and set remote (to make dirty=true)
    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "1.2.3.4:4433" },
    });

    // The save button requires dirty=true AND no parseError, but name empty won't set parseError
    // until save is clicked; dirty is true because we changed the remote
    const saveBtn = screen.getByRole("button", { name: "Save" });
    await fireEvent.click(saveBtn);
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(screen.getByText("Name is required.")).toBeInTheDocument();
    });
  });

  test("shows validation error for invalid remote on save", async () => {
    const tunnel = makeTunnel();
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Remote [IP-Address:Port]")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "not valid remote" },
    });

    const saveBtn = screen.getByRole("button", { name: "Save" });
    await fireEvent.click(saveBtn);
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(screen.getByText("Invalid remote. Use IP-Address:Port or [IPv6]:Port.")).toBeInTheDocument();
    });
  });

  test("save persists edited name and remote to store", async () => {
    const tunnel = makeTunnel({ name: "Original", remote: "10.0.0.1:4433" });
    setTunnels([tunnel]);
    setSelectedId("t1");
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
    });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Renamed VPN" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "192.168.1.1:5000" },
    });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Save" })).not.toBeDisabled();
    });

    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(closeFn).toHaveBeenCalled();
    });

    const updated = getTunnels().find((t) => t.id === "t1");
    expect(updated).toBeDefined();
    expect(updated!.name).toBe("Renamed VPN");
    expect(updated!.remote).toBe("192.168.1.1:5000");
  });

  test("does not save after the delayed action owner unmounts", async () => {
    const tunnel = makeTunnel({ name: "Original" });
    setTunnels([tunnel]);
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
    });
    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Unmounted" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    cleanup();
    await vi.advanceTimersByTimeAsync(100);

    expect(getTunnels()[0]?.name).toBe("Original");
    expect(closeFn).not.toHaveBeenCalled();
  });

  test("delete removes tunnel from store via confirm dialog", async () => {
    const tunnel = makeTunnel({ name: "ToDelete" });
    setTunnels([tunnel]);
    setSelectedId("t1");
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Delete" })).toBeInTheDocument();
    });

    // Click Delete -> sets confirmDeleteOpen=true after 88ms
    await fireEvent.click(screen.getByRole("button", { name: "Delete" }));
    await vi.advanceTimersByTimeAsync(100);

    // ConfirmDialog should appear with title "Delete Tunnel"
    const confirmDialog = await screen.findByRole("dialog", { name: "Delete Tunnel" });
    const confirmBtn = within(confirmDialog).getByRole("button", { name: "Delete" });
    await fireEvent.click(confirmBtn);
    // ConfirmDialog also uses setTimeout(onconfirm, 88)
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(getTunnels().find((t) => t.id === "t1")).toBeUndefined();
    });

    expect(closeFn).toHaveBeenCalled();
  });

  test("cancel closes dialog without modifying store", async () => {
    const tunnel = makeTunnel({ name: "Untouched", remote: "10.0.0.1:4433" });
    setTunnels([tunnel]);
    setSelectedId("t1");
    render(TunnelConfigDialog, { open: true, tunnel, onclose: closeFn });

    await waitFor(() => {
      expect(screen.getByLabelText("Name of the Connection")).toBeInTheDocument();
    });

    // Modify fields but do NOT save
    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Should Not Persist" },
    });

    await fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await vi.advanceTimersByTimeAsync(100);

    await waitFor(() => {
      expect(closeFn).toHaveBeenCalled();
    });

    // Store should be unchanged
    const tunnels = getTunnels();
    const original = tunnels.find((t) => t.id === "t1");
    expect(original).toBeDefined();
    expect(original!.name).toBe("Untouched");
    expect(original!.remote).toBe("10.0.0.1:4433");
  });
});
