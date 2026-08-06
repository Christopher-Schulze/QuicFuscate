export interface OwnedTimeout {
  schedule(callback: () => void, delayMs: number): void;
  cancel(): void;
  destroy(): void;
}

export interface OwnedAnimationFrame {
  schedule(callback: FrameRequestCallback): void;
  cancel(): void;
  destroy(): void;
}

export function createOwnedTimeout(): OwnedTimeout {
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;

  function cancel(): void {
    if (timeoutId === null) return;
    clearTimeout(timeoutId);
    timeoutId = null;
  }

  function schedule(callback: () => void, delayMs: number): void {
    if (destroyed) return;
    cancel();
    timeoutId = setTimeout(() => {
      timeoutId = null;
      if (!destroyed) callback();
    }, delayMs);
  }

  function destroy(): void {
    destroyed = true;
    cancel();
  }

  return { schedule, cancel, destroy };
}

export function createOwnedAnimationFrame(): OwnedAnimationFrame {
  let frameId: number | null = null;
  let destroyed = false;

  function cancel(): void {
    if (frameId === null || typeof window === "undefined") return;
    window.cancelAnimationFrame(frameId);
    frameId = null;
  }

  function schedule(callback: FrameRequestCallback): void {
    if (destroyed || typeof window === "undefined") return;
    cancel();
    frameId = window.requestAnimationFrame((timestamp) => {
      frameId = null;
      if (!destroyed) callback(timestamp);
    });
  }

  function destroy(): void {
    destroyed = true;
    cancel();
  }

  return { schedule, cancel, destroy };
}
