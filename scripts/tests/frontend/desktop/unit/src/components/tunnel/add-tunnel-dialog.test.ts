import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../../../testing-library";

const readClipboardTextDirectMock = vi.hoisted(() => vi.fn<() => Promise<string>>());
const qkeyParseMock = vi.hoisted(() => vi.fn());

function deferred<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => { resolve = res; });
  return { promise, resolve };
}
let runtimeAvailable = false;

vi.mock("$lib/clipboard", () => ({
  readClipboardTextDirect: () => readClipboardTextDirectMock(),
}));

vi.mock("$lib/stores/tauri-bridge.svelte", async () => {
  const actual = await vi.importActual<typeof import("$lib/stores/tauri-bridge.svelte")>("$lib/stores/tauri-bridge.svelte");
  return {
    ...actual,
    isTauri: () => runtimeAvailable,
    qkeyParse: (...args: unknown[]) => qkeyParseMock(...args),
  };
});

import AddTunnelDialog from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/AddTunnelDialog.svelte";
import ImportQKeyDialog from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/ImportQKeyDialog.svelte";
import {
  getSelectedId,
  getTunnels,
  setSelectedId,
  setTunnels,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";

describe("desktop tunnel creation and import dialogs", () => {
  beforeEach(() => {
    runtimeAvailable = false;
    readClipboardTextDirectMock.mockReset();
    readClipboardTextDirectMock.mockResolvedValue("");
    qkeyParseMock.mockReset();
    setTunnels([]);
    setSelectedId(null);
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("rejects invalid remote and does not create a tunnel", async () => {
    render(AddTunnelDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Test" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "not a remote" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create Tunnel" }));
    await vi.advanceTimersByTimeAsync(90);

    expect(getTunnels()).toHaveLength(0);
    expect(screen.getByText(/Invalid remote/i)).toBeInTheDocument();
  });

  test("creates a tunnel with default SNI for ipv4 remotes", async () => {
    render(AddTunnelDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Berlin" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "203.0.113.11:4433" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create Tunnel" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getTunnels()).toHaveLength(1);
    });
    expect(getTunnels()[0]).toMatchObject({
      name: "Berlin",
      remote: "203.0.113.11:4433",
      sni: "cdn.cloudflare.com",
      qkey: "",
      hasToken: false,
    });
    expect(getSelectedId()).toBe(getTunnels()[0]?.id ?? null);
  });

  test("does not create a tunnel after the delayed action owner unmounts", async () => {
    render(AddTunnelDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "Unmounted" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "203.0.113.12:4433" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create Tunnel" }));
    cleanup();
    await vi.advanceTimersByTimeAsync(100);

    expect(getTunnels()).toHaveLength(0);
  });

  test("rejects unbracketed ipv6 remotes and url-like remotes", async () => {
    render(AddTunnelDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("Name of the Connection"), {
      target: { value: "IPv6" },
    });
    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "2001:db8::1:4433" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create Tunnel" }));
    await vi.advanceTimersByTimeAsync(90);
    expect(getTunnels()).toHaveLength(0);
    expect(screen.getByText(/Invalid remote/i)).toBeInTheDocument();

    await fireEvent.input(screen.getByLabelText("Remote [IP-Address:Port]"), {
      target: { value: "https://vpn.example.com:4433" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Create Tunnel" }));
    await vi.advanceTimersByTimeAsync(90);
    expect(getTunnels()).toHaveLength(0);
    expect(screen.getByText(/Invalid remote/i)).toBeInTheDocument();
  });

  test("keeps import disabled in browser mode", async () => {
    render(ImportQKeyDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-TESTONLY" },
    });

    expect(screen.getByRole("button", { name: "Import" })).toBeDisabled();
  });

  test("pastes clipboard content into import textarea", async () => {
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED-123");
    render(ImportQKeyDialog, { open: true, onclose: vi.fn() });

    await fireEvent.pointerDown(screen.getByRole("button", { name: "Paste" }));

    await waitFor(() => {
      expect((screen.getByLabelText("QKey String") as HTMLTextAreaElement).value).toBe("QKey-PASTED-123");
    });
  });

  test("adds a tunnel when qkey_parse succeeds inside desktop runtime", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockResolvedValue({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });

    render(ImportQKeyDialog, { open: true, onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "prefix qkey-ABC_def-123== suffix" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getTunnels()).toHaveLength(1);
    });
    expect(getTunnels()[0]).toMatchObject({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
      qkey: "QKey-ABC_def-123==",
    });
  });

  test("does not import when qkey_parse resolves after unmount", async () => {
    runtimeAvailable = true;
    const pending = deferred({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });
    qkeyParseMock.mockReturnValue(pending.promise);

    render(ImportQKeyDialog, { open: true, onclose: vi.fn() });
    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "prefix qkey-ABC_def-123== suffix" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await vi.advanceTimersByTimeAsync(90);
    await waitFor(() => expect(qkeyParseMock).toHaveBeenCalled());

    cleanup();
    pending.resolve({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });
    await pending.promise;
    await vi.advanceTimersByTimeAsync(0);

    expect(getTunnels()).toHaveLength(0);
  });

});
