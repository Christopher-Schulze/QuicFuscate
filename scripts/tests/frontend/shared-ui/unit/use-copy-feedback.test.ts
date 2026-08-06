import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { createCopyFeedback } from "../../../../../packages/ui/use-copy-feedback.svelte";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("createCopyFeedback", () => {
  test("initial state is not copied", () => {
    const fb = createCopyFeedback();
    expect(fb.copied).toBe(false);
    expect(fb.copiedKey).toBeNull();
    fb.destroy();
  });

  test("trigger sets copied to true after successful clipboard write", async () => {
    const fb = createCopyFeedback();
    await fb.trigger("hello");
    expect(fb.copied).toBe(true);
    expect(fb.copiedKey).toBeNull();
    fb.destroy();
  });

  test("trigger resets copied after default duration (1500ms)", async () => {
    const fb = createCopyFeedback();
    await fb.trigger("hello");
    expect(fb.copied).toBe(true);
    vi.advanceTimersByTime(1500);
    expect(fb.copied).toBe(false);
    fb.destroy();
  });

  test("trigger respects custom duration", async () => {
    const fb = createCopyFeedback(500);
    await fb.trigger("test");
    expect(fb.copied).toBe(true);
    vi.advanceTimersByTime(499);
    expect(fb.copied).toBe(true);
    vi.advanceTimersByTime(1);
    expect(fb.copied).toBe(false);
    fb.destroy();
  });

  test("triggerKeyed sets copiedKey and copied", async () => {
    const fb = createCopyFeedback<string>();
    await fb.triggerKeyed("secret", "item-1");
    expect(fb.copied).toBe(true);
    expect(fb.copiedKey).toBe("item-1");
    fb.destroy();
  });

  test("isKeyCopied returns true for the active key", async () => {
    const fb = createCopyFeedback<string>();
    await fb.triggerKeyed("data", "key-a");
    expect(fb.isKeyCopied("key-a")).toBe(true);
    expect(fb.isKeyCopied("key-b")).toBe(false);
    fb.destroy();
  });

  test("triggerKeyed resets copiedKey after duration", async () => {
    const fb = createCopyFeedback<string>(800);
    await fb.triggerKeyed("data", "my-key");
    expect(fb.copiedKey).toBe("my-key");
    vi.advanceTimersByTime(800);
    expect(fb.copiedKey).toBeNull();
    expect(fb.copied).toBe(false);
    fb.destroy();
  });

  test("reset immediately clears all state", async () => {
    const fb = createCopyFeedback<string>();
    await fb.triggerKeyed("text", "k1");
    expect(fb.copied).toBe(true);
    fb.reset();
    expect(fb.copied).toBe(false);
    expect(fb.copiedKey).toBeNull();
    fb.destroy();
  });

  test("trigger sets copied to false when clipboard fails", async () => {
    // Override the mock to reject
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValueOnce(
      new Error("denied"),
    );
    const fb = createCopyFeedback();
    await fb.trigger("fail");
    expect(fb.copied).toBe(false);
    fb.destroy();
  });

  test("does not mutate or retain a timer when clipboard resolves after destroy", async () => {
    let resolveClipboard!: () => void;
    vi.spyOn(navigator.clipboard, "writeText").mockImplementationOnce(
      () => new Promise<void>((resolve) => { resolveClipboard = resolve; }),
    );
    const fb = createCopyFeedback();
    const pending = fb.trigger("late");

    fb.destroy();
    resolveClipboard();
    await pending;
    vi.advanceTimersByTime(2_000);

    expect(fb.copied).toBe(false);
    expect(fb.copiedKey).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });
});
