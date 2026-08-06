import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "./testing-library";
import ConfirmDialog from "../../../../../packages/ui/ConfirmDialog.svelte";

function renderDialog(overrides: Record<string, unknown> = {}) {
  return render(ConfirmDialog, {
    props: {
      open: true,
      title: "Delete item?",
      message: "This action cannot be undone.",
      onconfirm: vi.fn(),
      oncancel: vi.fn(),
      ...overrides,
    },
  });
}

describe("ConfirmDialog lifecycle", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  test("renders title and message when open", () => {
    renderDialog();
    expect(screen.getByText("Delete item?")).not.toBeNull();
    expect(screen.getByText("This action cannot be undone.")).not.toBeNull();
  });

  test("renders default confirm and cancel labels", () => {
    renderDialog();
    expect(screen.getByText("Confirm")).not.toBeNull();
    expect(screen.getByText("Cancel")).not.toBeNull();
  });

  test("renders custom confirm and cancel labels", () => {
    renderDialog({ confirmLabel: "Yes, delete", cancelLabel: "Keep it" });
    expect(screen.getByText("Yes, delete")).not.toBeNull();
    expect(screen.getByText("Keep it")).not.toBeNull();
  });

  test("applies destructive styling when destructive prop is true", () => {
    renderDialog({ destructive: true });
    const buttons = document.body.querySelectorAll("button");
    const confirmBtn = Array.from(buttons).find((b) => b.textContent?.includes("Confirm"));
    expect(confirmBtn).toBeDefined();
    expect(confirmBtn!.className).toContain("action-disconnect-btn");
  });

  test("applies save styling when destructive is false", () => {
    renderDialog({ destructive: false });
    const buttons = document.body.querySelectorAll("button");
    const confirmBtn = Array.from(buttons).find((b) => b.textContent?.includes("Confirm"));
    expect(confirmBtn).toBeDefined();
    expect(confirmBtn!.className).toContain("action-save-btn");
  });

  test("does not invoke a delayed action after unmount", async () => {
    const onconfirm = vi.fn();
    const oncancel = vi.fn();
    render(ConfirmDialog, {
      props: {
        open: true,
        title: "Confirm",
        message: "Continue?",
        onconfirm,
        oncancel,
      },
    });

    await fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    cleanup();
    vi.advanceTimersByTime(100);

    expect(onconfirm).not.toHaveBeenCalled();
    expect(oncancel).not.toHaveBeenCalled();
  });

  test("runs the active delayed action once", async () => {
    const onconfirm = vi.fn();
    render(ConfirmDialog, {
      props: {
        open: true,
        title: "Confirm",
        message: "Continue?",
        onconfirm,
        oncancel: vi.fn(),
      },
    });

    await fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    vi.advanceTimersByTime(88);

    expect(onconfirm).toHaveBeenCalledTimes(1);
  });
});
