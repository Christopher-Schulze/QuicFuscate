import "@testing-library/jest-dom/vitest";
import { beforeEach, vi } from "vitest";

function ensurePortalStage(): void {
  if (document.getElementById("qf-app-stage")) return;
  const stage = document.createElement("div");
  stage.id = "qf-app-stage";
  document.body.appendChild(stage);
}

beforeEach(() => {
  if (!globalThis.crypto) {
    (globalThis as { crypto?: Crypto }).crypto = {} as Crypto;
  }
  if (!globalThis.crypto.randomUUID) {
    Object.defineProperty(globalThis.crypto, "randomUUID", {
      configurable: true,
      writable: true,
      value: () => `test-${Math.random().toString(16).slice(2)}-${Date.now().toString(16)}`,
    });
  }

  if (!("ResizeObserver" in globalThis)) {
    class ResizeObserverMock {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    }
    Object.defineProperty(globalThis, "ResizeObserver", {
      configurable: true,
      writable: true,
      value: ResizeObserverMock,
    });
  }

  Object.defineProperty(Element.prototype, "scrollIntoView", {
    configurable: true,
    writable: true,
    value: vi.fn(),
  });
  Object.defineProperty(Element.prototype, "animate", {
    configurable: true,
    writable: true,
    value: vi.fn(() => ({
      cancel: vi.fn(),
      finished: Promise.resolve(),
      play: vi.fn(),
      pause: vi.fn(),
    })),
  });

  Object.defineProperty(window.navigator, "clipboard", {
    configurable: true,
    value: {
      writeText: vi.fn(async () => undefined),
      readText: vi.fn(async () => ""),
    },
  });

  if (typeof window.matchMedia !== "function") {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      writable: true,
      value: vi.fn((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });
  }

  ensurePortalStage();
});
