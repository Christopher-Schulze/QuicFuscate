import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";

// The toast-store.svelte.ts uses Svelte 5 $state runes which require
// the Svelte compiler. The vite-plugin-svelte handles .svelte.ts files.
import {
  addToast,
  getToasts,
  removeToast,
  getToneStyle,
  notify,
  notifySuccess,
  notifyWarning,
  notifyError,
  getAnchor,
  setAnchor,
  type ToastTone,
  type ToneStyle,
} from "../../../../../packages/ui/toast-store.svelte";

beforeEach(() => {
  vi.useFakeTimers();
  // Clear any leftover toasts from previous tests
  for (const t of getToasts()) {
    removeToast(t.id);
  }
});

afterEach(() => {
  // Clean up remaining toasts
  for (const t of getToasts()) {
    removeToast(t.id);
  }
  vi.useRealTimers();
});

describe("addToast", () => {
  test("creates a toast with correct message and tone", () => {
    addToast("Hello", "success");
    const toasts = getToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0].message).toBe("Hello");
    expect(toasts[0].tone).toBe("success");
  });

  test("generates a unique id", () => {
    addToast("First", "info");
    addToast("Second", "info");
    const toasts = getToasts();
    expect(toasts).toHaveLength(2);
    expect(toasts[0].id).not.toBe(toasts[1].id);
  });

  test("keeps ids unique with a fixed clock and repeated random output", () => {
    vi.setSystemTime(new Date("2026-08-06T12:00:00.000Z"));
    vi.spyOn(Math, "random").mockReturnValue(0);

    for (let index = 0; index < 128; index += 1) {
      addToast(`Toast ${index}`, "info", 60_000);
    }

    const ids = getToasts().map((toast) => toast.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("defaults tone to info when not specified", () => {
    addToast("Default tone");
    const toasts = getToasts();
    expect(toasts[0].tone).toBe("info");
  });

  test("multiple toasts accumulate", () => {
    addToast("A", "info");
    addToast("B", "warning");
    addToast("C", "error");
    expect(getToasts()).toHaveLength(3);
  });

  test("auto-removes toast after duration", () => {
    addToast("Temp", "info", 1000);
    expect(getToasts()).toHaveLength(1);
    vi.advanceTimersByTime(1000);
    expect(getToasts()).toHaveLength(0);
  });

  test("uses default duration of 2800ms", () => {
    addToast("Default duration", "info");
    expect(getToasts()).toHaveLength(1);
    vi.advanceTimersByTime(2799);
    expect(getToasts()).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(getToasts()).toHaveLength(0);
  });
});

describe("removeToast", () => {
  test("removes a toast by id", () => {
    addToast("To remove", "info");
    const id = getToasts()[0].id;
    removeToast(id);
    vi.advanceTimersByTime(10_000);
    expect(getToasts()).toHaveLength(0);
  });

  test("does nothing if id does not exist", () => {
    addToast("Keep me", "info");
    removeToast("nonexistent-id");
    expect(getToasts()).toHaveLength(1);
  });

  test("removes only the targeted toast", () => {
    addToast("First", "info");
    addToast("Second", "warning");
    addToast("Third", "error");
    const secondId = getToasts()[1].id;
    removeToast(secondId);
    const remaining = getToasts();
    expect(remaining).toHaveLength(2);
    expect(remaining[0].message).toBe("First");
    expect(remaining[1].message).toBe("Third");
  });
});

describe("getToasts", () => {
  test("returns empty array initially", () => {
    expect(getToasts()).toEqual([]);
  });

  test("returns current toast list", () => {
    addToast("One", "info");
    addToast("Two", "success");
    const toasts = getToasts();
    expect(toasts).toHaveLength(2);
    expect(toasts[0].message).toBe("One");
    expect(toasts[1].message).toBe("Two");
  });
});

describe("notify convenience functions", () => {
  test("notify adds toast with info tone", () => {
    notify("Info message");
    const toasts = getToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0].message).toBe("Info message");
    expect(toasts[0].tone).toBe("info");
  });

  test("notifySuccess adds toast with success tone", () => {
    notifySuccess("Success message");
    const toasts = getToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0].message).toBe("Success message");
    expect(toasts[0].tone).toBe("success");
  });

  test("notifyWarning adds toast with warning tone", () => {
    notifyWarning("Warning message");
    const toasts = getToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0].message).toBe("Warning message");
    expect(toasts[0].tone).toBe("warning");
  });

  test("notifyError adds toast with error tone", () => {
    notifyError("Error message");
    const toasts = getToasts();
    expect(toasts).toHaveLength(1);
    expect(toasts[0].message).toBe("Error message");
    expect(toasts[0].tone).toBe("error");
  });
});

describe("getToneStyle", () => {
  const tones: ToastTone[] = ["info", "success", "warning", "error"];

  test.each(tones)("returns a ToneStyle object for %s", (tone) => {
    const style = getToneStyle(tone);
    expect(style).toBeDefined();
    expect(style.color).toEqual(expect.any(String));
    expect(style.border).toEqual(expect.any(String));
    expect(style.background).toEqual(expect.any(String));
    expect(style.shadow).toEqual(expect.any(String));
    expect(style.edge).toEqual(expect.any(String));
    expect(style.sheen).toEqual(expect.any(String));
  });

  test("info and success have different colors", () => {
    const info = getToneStyle("info");
    const success = getToneStyle("success");
    expect(info.color).not.toBe(success.color);
  });

  test("warning and error share the same color", () => {
    const warning = getToneStyle("warning");
    const error = getToneStyle("error");
    expect(warning.color).toBe(error.color);
  });
});

describe("anchor management", () => {
  test("getAnchor returns null initially", () => {
    expect(getAnchor()).toBeNull();
  });

  test("setAnchor sets position", () => {
    setAnchor({ x: 100, y: 200 });
    expect(getAnchor()).toEqual({ x: 100, y: 200 });
    // Clean up
    setAnchor(null);
  });

  test("setAnchor(null) clears position", () => {
    setAnchor({ x: 50, y: 50 });
    setAnchor(null);
    expect(getAnchor()).toBeNull();
  });
});
