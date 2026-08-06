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

import ImportQKeyDialog from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/ImportQKeyDialog.svelte";

function renderDialog() {
  return render(ImportQKeyDialog, {
    props: { open: true, onclose: vi.fn() },
  });
}

beforeEach(() => {
  runtimeAvailable = true;
  readClipboardTextDirectMock.mockReset();
  qkeyParseMock.mockReset();
});

afterEach(() => {
  cleanup();
  vi.runAllTimers();
  vi.useRealTimers();
});

describe("tunnel/ImportQKeyDialog", () => {
  test("renders dialog title", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    expect(screen.getByText("Import QKey")).toBeInTheDocument();
  });

  test("renders Import and Cancel buttons", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    expect(screen.getByText("Import")).toBeInTheDocument();
    expect(screen.getByText("Cancel")).toBeInTheDocument();
  });

  test("Import button is disabled when textarea is empty", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    const importBtn = screen.getByText("Import");
    expect(importBtn).toBeDisabled();
  });

  test("renders Paste button", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    expect(screen.getByText("Paste")).toBeInTheDocument();
  });

  test("suppresses the synthetic click after pointer paste within the bounded window", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    readClipboardTextDirectMock.mockResolvedValue("QKey-PASTED");
    renderDialog();
    const paste = screen.getByRole("button", { name: "Paste" });

    await fireEvent.pointerDown(paste);
    await fireEvent.click(paste);
    await waitFor(() => expect(readClipboardTextDirectMock).toHaveBeenCalledTimes(1));

    await vi.advanceTimersByTimeAsync(401);
    await fireEvent.click(paste);
    await waitFor(() => expect(readClipboardTextDirectMock).toHaveBeenCalledTimes(2));
  });

  test("renders QKey security warning", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    expect(screen.getByText(/bearer credentials/i)).toBeInTheDocument();
  });

  test("renders textarea for QKey input", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDialog();
    const textarea = document.querySelector("textarea#import-qkey-text");
    expect(textarea).not.toBeNull();
  });

  test("Import button disabled when runtime not available", () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    runtimeAvailable = false;
    renderDialog();
    const importBtn = screen.getByText("Import");
    expect(importBtn).toBeDisabled();
  });
});
