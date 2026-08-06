import { cleanup } from "@testing-library/svelte";
import { afterEach, beforeEach, vi } from "vitest";
import { createDeterministicTestUuid } from "../../test-identity";

function ensurePortalStage(): void {
  if (document.getElementById("qf-app-stage")) return;
  const stage = document.createElement("div");
  stage.id = "qf-app-stage";
  document.body.appendChild(stage);
}

const createCanvasContextMock = () =>
  ({
    clearRect: () => {},
    fill: () => {},
    fillRect: () => {},
    beginPath: () => {},
    moveTo: () => {},
    lineTo: () => {},
    stroke: () => {},
    drawImage: () => {},
    arc: () => {},
    setTransform: () => {},
    save: () => {},
    restore: () => {},
    fillStyle: "#000",
    strokeStyle: "#000",
    lineWidth: 1,
    lineCap: "",
    lineJoin: "",
    globalAlpha: 1,
  }) as CanvasRenderingContext2D;

beforeEach(() => {
  if (!globalThis.crypto) {
    (globalThis as { crypto?: Crypto }).crypto = {} as Crypto;
  }
  if (!globalThis.crypto.randomUUID) {
    Object.defineProperty(globalThis.crypto, "randomUUID", {
      configurable: true,
      writable: true,
      value: createDeterministicTestUuid,
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

  if (!window.matchMedia) {
    Object.defineProperty(window, "matchMedia", {
      configurable: true,
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => false,
      }),
    });
  }

  Object.defineProperty(HTMLCanvasElement.prototype, "getContext", {
    configurable: true,
    writable: true,
    value: createCanvasContextMock,
  });

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

  ensurePortalStage();
});

afterEach(async () => {
  cleanup();
  vi.useRealTimers();
  await new Promise((resolve) => window.setTimeout(resolve, 0));
});
