import { describe, expect, test, vi } from "vitest";
import { getFrontendClockHarness } from "../../test-clock";

describe("frontend deterministic clock harness", () => {
  test("keeps wall-clock jumps independent from monotonic elapsed time", () => {
    const clock = getFrontendClockHarness();
    clock.installClockSources();
    clock.setWallTime(1_710_000_000_000);
    clock.setMonotonicTime(1_000);

    expect(Date.now()).toBe(1_710_000_000_000);
    expect(performance.now()).toBe(1_000);

    clock.advanceWallTime(-86_400_000);
    clock.advanceMonotonicTime(1_000);

    expect(Date.now()).toBe(1_709_913_600_000);
    expect(performance.now()).toBe(2_000);
  });

  test("advances timers and flushes or cancels owned animation frames", async () => {
    const clock = getFrontendClockHarness();
    clock.useFakeTimers();
    const timer = vi.fn();
    setTimeout(timer, 100);

    await clock.advanceTimersBy(99);
    expect(timer).not.toHaveBeenCalled();
    await clock.advanceTimersBy(1);
    expect(timer).toHaveBeenCalledOnce();

    clock.installAnimationFrame();
    const flushed = vi.fn();
    window.requestAnimationFrame(flushed);
    clock.flushAnimationFrame(2_000);
    expect(flushed).toHaveBeenCalledWith(2_000);

    const canceled = vi.fn();
    const frameId = window.requestAnimationFrame(canceled);
    window.cancelAnimationFrame(frameId);
    clock.flushAnimationFrame(2_001);
    expect(canceled).not.toHaveBeenCalled();
    expect(clock.pendingAnimationFrameCount()).toBe(0);
  });

  test("dispatches controlled visibility transitions", () => {
    const clock = getFrontendClockHarness();
    const states: string[] = [];
    const listener = (): void => states.push(document.visibilityState);
    document.addEventListener("visibilitychange", listener);

    try {
      clock.setVisibility("hidden");
      clock.setVisibility("visible");
      expect(states).toEqual(["hidden", "visible"]);
    } finally {
      document.removeEventListener("visibilitychange", listener);
    }
  });
});
