import { vi } from "vitest";

export type TestVisibilityState = "hidden" | "visible";

export type FrontendClockHarness = {
  installClockSources(): void;
  useFakeTimers(options?: Parameters<typeof vi.useFakeTimers>[0]): void;
  setWallTime(milliseconds: number): void;
  advanceWallTime(milliseconds: number): void;
  setMonotonicTime(milliseconds: number): void;
  advanceMonotonicTime(milliseconds: number): void;
  advanceTimersBy(milliseconds: number): Promise<void>;
  installAnimationFrame(): void;
  flushAnimationFrame(timestamp?: number): void;
  pendingAnimationFrameCount(): number;
  setVisibility(state: TestVisibilityState): void;
  restore(): void;
};

const DEFAULT_WALL_TIME_MS = 1_710_000_000_000;
const DEFAULT_MONOTONIC_TIME_MS = 1_000;

let activeHarness: FrontendClockHarness | null = null;

function assertFinite(value: number, label: string): void {
  if (!Number.isFinite(value)) throw new Error(`${label} must be finite`);
}

function createFrontendClockHarness(): FrontendClockHarness {
  let wallTimeMs = DEFAULT_WALL_TIME_MS;
  let monotonicTimeMs = DEFAULT_MONOTONIC_TIME_MS;
  let fakeTimersInstalled = false;
  let restoreDateNow: (() => void) | null = null;
  let restorePerformanceNow: (() => void) | null = null;
  let originalVisibilityDescriptor: PropertyDescriptor | undefined;
  let visibilityDescriptorCaptured = false;
  let originalRequestAnimationFrame: PropertyDescriptor | undefined;
  let originalCancelAnimationFrame: PropertyDescriptor | undefined;
  let animationFrameDescriptorsCaptured = false;
  let animationFrameInstalled = false;
  let nextAnimationFrameId = 1;
  const animationFrames = new Map<number, FrameRequestCallback>();

  function installClockSources(): void {
    if (!restoreDateNow) {
      const dateNow = vi.spyOn(Date, "now").mockImplementation(() => wallTimeMs);
      restoreDateNow = () => dateNow.mockRestore();
    }
    if (!restorePerformanceNow) {
      const performanceNow = vi.spyOn(performance, "now").mockImplementation(() => monotonicTimeMs);
      restorePerformanceNow = () => performanceNow.mockRestore();
    }
  }

  function useFakeTimers(options?: Parameters<typeof vi.useFakeTimers>[0]): void {
    if (fakeTimersInstalled) return;
    restoreDateNow?.();
    restoreDateNow = null;
    restorePerformanceNow?.();
    restorePerformanceNow = null;
    vi.useFakeTimers(options);
    fakeTimersInstalled = true;
    installClockSources();
  }

  function setWallTime(milliseconds: number): void {
    assertFinite(milliseconds, "wall time");
    wallTimeMs = milliseconds;
  }

  function advanceWallTime(milliseconds: number): void {
    assertFinite(milliseconds, "wall time delta");
    setWallTime(wallTimeMs + milliseconds);
  }

  function setMonotonicTime(milliseconds: number): void {
    assertFinite(milliseconds, "monotonic time");
    monotonicTimeMs = milliseconds;
  }

  function advanceMonotonicTime(milliseconds: number): void {
    assertFinite(milliseconds, "monotonic time delta");
    setMonotonicTime(monotonicTimeMs + milliseconds);
  }

  async function advanceTimersBy(milliseconds: number): Promise<void> {
    assertFinite(milliseconds, "timer delta");
    if (milliseconds < 0) throw new Error("timer delta must not be negative");
    if (!fakeTimersInstalled) throw new Error("fake timers are not installed");
    await vi.advanceTimersByTimeAsync(milliseconds);
  }

  function installAnimationFrame(): void {
    if (animationFrameInstalled) return;
    if (!animationFrameDescriptorsCaptured) {
      originalRequestAnimationFrame = Object.getOwnPropertyDescriptor(window, "requestAnimationFrame");
      originalCancelAnimationFrame = Object.getOwnPropertyDescriptor(window, "cancelAnimationFrame");
      animationFrameDescriptorsCaptured = true;
    }
    Object.defineProperty(window, "requestAnimationFrame", {
      configurable: true,
      writable: true,
      value: (callback: FrameRequestCallback): number => {
        const id = nextAnimationFrameId;
        nextAnimationFrameId += 1;
        animationFrames.set(id, callback);
        return id;
      },
    });
    Object.defineProperty(window, "cancelAnimationFrame", {
      configurable: true,
      writable: true,
      value: (id: number): void => {
        animationFrames.delete(id);
      },
    });
    animationFrameInstalled = true;
  }

  function flushAnimationFrame(timestamp = monotonicTimeMs): void {
    assertFinite(timestamp, "animation frame timestamp");
    const callbacks = [...animationFrames.entries()];
    animationFrames.clear();
    for (const [, callback] of callbacks) callback(timestamp);
  }

  function pendingAnimationFrameCount(): number {
    return animationFrames.size;
  }

  function setVisibility(state: TestVisibilityState): void {
    if (!visibilityDescriptorCaptured) {
      originalVisibilityDescriptor = Object.getOwnPropertyDescriptor(document, "visibilityState");
      visibilityDescriptorCaptured = true;
    }
    Object.defineProperty(document, "visibilityState", {
      configurable: true,
      value: state,
    });
    document.dispatchEvent(new Event("visibilitychange"));
  }

  function restore(): void {
    animationFrames.clear();
    if (animationFrameInstalled) {
      if (originalRequestAnimationFrame) {
        Object.defineProperty(window, "requestAnimationFrame", originalRequestAnimationFrame);
      } else {
        delete (window as Window & { requestAnimationFrame?: unknown }).requestAnimationFrame;
      }
      if (originalCancelAnimationFrame) {
        Object.defineProperty(window, "cancelAnimationFrame", originalCancelAnimationFrame);
      } else {
        delete (window as Window & { cancelAnimationFrame?: unknown }).cancelAnimationFrame;
      }
      animationFrameInstalled = false;
    }
    if (visibilityDescriptorCaptured) {
      if (originalVisibilityDescriptor) {
        Object.defineProperty(document, "visibilityState", originalVisibilityDescriptor);
      } else {
        delete (document as Document & { visibilityState?: string }).visibilityState;
      }
      visibilityDescriptorCaptured = false;
      originalVisibilityDescriptor = undefined;
    }
    restoreDateNow?.();
    restoreDateNow = null;
    restorePerformanceNow?.();
    restorePerformanceNow = null;
    if (fakeTimersInstalled) {
      vi.useRealTimers();
      fakeTimersInstalled = false;
    }
  }

  return {
    installClockSources,
    useFakeTimers,
    setWallTime,
    advanceWallTime,
    setMonotonicTime,
    advanceMonotonicTime,
    advanceTimersBy,
    installAnimationFrame,
    flushAnimationFrame,
    pendingAnimationFrameCount,
    setVisibility,
    restore,
  };
}

export function beginFrontendClockHarness(): FrontendClockHarness {
  activeHarness?.restore();
  activeHarness = createFrontendClockHarness();
  return activeHarness;
}

export function getFrontendClockHarness(): FrontendClockHarness {
  if (!activeHarness) throw new Error("frontend clock harness is not active");
  return activeHarness;
}

export function resetFrontendClockHarness(): void {
  activeHarness?.restore();
  activeHarness = null;
}
