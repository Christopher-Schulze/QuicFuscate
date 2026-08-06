import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "../../../testing-library";

const readClipboardTextDirectMock = vi.hoisted(() => vi.fn<() => Promise<string>>());
const qkeyParseMock = vi.hoisted(() => vi.fn());
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

import EditQKeyDialog from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/EditQKeyDialog.svelte";
import {
  getTunnels,
  setTunnels,
} from "../../../../../../../../apps/svelte-desktop/src/lib/stores/app.svelte";
import { desktopCreatedAt } from "../../timestamp-fixtures";

function seedTunnels(): void {
  const now = desktopCreatedAt();
  setTunnels([
    {
      id: "t1",
      name: "One",
      remote: "manual1.example.com:4433",
      sni: "manual1.example.com",
      qkey: "",
      createdAt: now,
      hasToken: false,
    },
    {
      id: "t2",
      name: "Two",
      remote: "manual2.example.com:4433",
      sni: "manual2.example.com",
      qkey: "",
      createdAt: now,
      hasToken: false,
    },
  ]);
}

describe("desktop qkey edit dialog", () => {
  beforeEach(() => {
    runtimeAvailable = false;
    readClipboardTextDirectMock.mockReset();
    readClipboardTextDirectMock.mockResolvedValue("");
    qkeyParseMock.mockReset();
    seedTunnels();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    cleanup();
    vi.runAllTimers();
    vi.useRealTimers();
  });

  test("is disabled in browser mode", async () => {
    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "set", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-ABC_def-123==" },
    });

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });

  test("pastes clipboard content into edit textarea", async () => {
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED-EDIT");
    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "set", onclose: vi.fn() });

    await fireEvent.pointerDown(screen.getByRole("button", { name: "Paste" }));

    await waitFor(() => {
      expect((screen.getByLabelText("QKey String") as HTMLTextAreaElement).value).toBe("QKey-PASTED-EDIT");
    });
  });

  test("suppresses the synthetic click after pointer paste within the bounded window", async () => {
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED-EDIT");
    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "set", onclose: vi.fn() });
    const paste = screen.getByRole("button", { name: "Paste" });

    await fireEvent.pointerDown(paste);
    await fireEvent.click(paste);
    await waitFor(() => expect(readClipboardTextDirectMock).toHaveBeenCalledTimes(1));

    await vi.advanceTimersByTimeAsync(401);
    await fireEvent.click(paste);
    await waitFor(() => expect(readClipboardTextDirectMock).toHaveBeenCalledTimes(2));
  });

  test("updates only the selected tunnel when qkey_parse succeeds", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockResolvedValue({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });

    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "replace", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "prefix qkey-ABC_def-123== suffix" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getTunnels()[0]).toMatchObject({
        qkey: "QKey-ABC_def-123==",
        hasToken: true,
        remote: "vpn.example.com:4433",
        sni: "cdn.example.com",
      });
    });
    expect(getTunnels()[1]).toMatchObject({
      qkey: "",
      remote: "manual2.example.com:4433",
      sni: "manual2.example.com",
    });
  });

  test("keeps existing remote and sni when parser returns empty values", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockResolvedValue({
      remote: "",
      sni: "",
      hasToken: true,
    });

    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "set", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-ABC_def-123==" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(getTunnels()[0]).toMatchObject({
        qkey: "QKey-ABC_def-123==",
        hasToken: true,
        remote: "manual1.example.com:4433",
        sni: "manual1.example.com",
      });
    });
  });

  test("rejects parsed payload with invalid remote endpoint and keeps tunnel unchanged", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockResolvedValue({
      remote: "https://vpn.example.com:4433",
      sni: "cdn.example.com",
      hasToken: true,
    });

    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "replace", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-ABC_def-123==" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(screen.getByText("QKey contains invalid remote endpoint")).toBeInTheDocument();
    });
    expect(getTunnels()[0]).toMatchObject({
      qkey: "",
      remote: "manual1.example.com:4433",
      sni: "manual1.example.com",
    });
  });

  test("shows parser failure and keeps tunnel unchanged", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockRejectedValue("Invalid QKey");

    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "set", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-ABC_def-123==" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(screen.getByText("Invalid QKey")).toBeInTheDocument();
    });
    expect(getTunnels()[0]).toMatchObject({
      qkey: "",
      hasToken: false,
      remote: "manual1.example.com:4433",
      sni: "manual1.example.com",
    });
  });

  test("rejects parsed payload with invalid sni and keeps tunnel unchanged", async () => {
    runtimeAvailable = true;
    qkeyParseMock.mockResolvedValue({
      remote: "vpn.example.com:4433",
      sni: "cdn.example.com:443",
      hasToken: true,
    });

    render(EditQKeyDialog, { open: true, tunnelId: "t1", mode: "replace", onclose: vi.fn() });

    await fireEvent.input(screen.getByLabelText("QKey String"), {
      target: { value: "QKey-ABC_def-123==" },
    });
    await fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await vi.advanceTimersByTimeAsync(90);

    await waitFor(() => {
      expect(screen.getByText("QKey contains invalid SNI")).toBeInTheDocument();
    });
    expect(getTunnels()[0]).toMatchObject({
      qkey: "",
      remote: "manual1.example.com:4433",
      sni: "manual1.example.com",
    });
  });
});
