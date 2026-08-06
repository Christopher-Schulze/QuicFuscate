import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { createOwnedAnimationFrame, createOwnedTimeout } from "../../../../../packages/ui/owned-scheduling";

describe("owned scheduling", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  test("replaces a delayed callback and prevents execution after destroy", () => {
    const callback = vi.fn();
    const replacement = vi.fn();
    const owner = createOwnedTimeout();

    owner.schedule(callback, 100);
    owner.schedule(replacement, 100);
    vi.advanceTimersByTime(99);
    expect(callback).not.toHaveBeenCalled();
    expect(replacement).not.toHaveBeenCalled();

    vi.advanceTimersByTime(1);
    expect(callback).not.toHaveBeenCalled();
    expect(replacement).toHaveBeenCalledTimes(1);

    owner.schedule(callback, 100);
    owner.destroy();
    vi.advanceTimersByTime(100);
    expect(callback).not.toHaveBeenCalled();
  });

  test("cancels and destroy-guards animation frame callbacks", () => {
    let nextFrameId = 1;
    let pendingCallback: FrameRequestCallback | null = null;
    const request = vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
      pendingCallback = callback;
      return nextFrameId++;
    });
    const cancel = vi.spyOn(window, "cancelAnimationFrame").mockImplementation(() => undefined);
    const callback = vi.fn();
    const replacement = vi.fn();
    const owner = createOwnedAnimationFrame();

    owner.schedule(callback);
    owner.schedule(replacement);
    expect(request).toHaveBeenCalledTimes(2);
    expect(cancel).toHaveBeenCalledTimes(1);

    pendingCallback?.(16.5);
    expect(callback).not.toHaveBeenCalled();
    expect(replacement).toHaveBeenCalledWith(16.5);

    owner.schedule(callback);
    owner.destroy();
    expect(cancel).toHaveBeenCalledTimes(2);
    pendingCallback?.(33);
    expect(callback).not.toHaveBeenCalled();
  });
});
