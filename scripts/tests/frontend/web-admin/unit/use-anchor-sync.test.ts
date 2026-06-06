import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";

const setAnchorMock = vi.hoisted(() => vi.fn());

vi.mock("@quicfuscate/ui", () => ({
  setAnchor: setAnchorMock,
  getAnchor: vi.fn(() => null),
  getToasts: vi.fn(() => []),
  addToast: vi.fn(),
  removeToast: vi.fn(),
  getToneStyle: vi.fn(),
  notify: vi.fn(),
  notifySuccess: vi.fn(),
  notifyWarning: vi.fn(),
  notifyError: vi.fn(),
  cn: vi.fn((...args: string[]) => args.filter(Boolean).join(" ")),
  ripple: vi.fn(),
  createCopyFeedback: vi.fn(),
}));

vi.mock("../../../../../packages/ui/index.ts", () => ({
  setAnchor: setAnchorMock,
  getAnchor: vi.fn(() => null),
  getToasts: vi.fn(() => []),
  addToast: vi.fn(),
  removeToast: vi.fn(),
  getToneStyle: vi.fn(),
  notify: vi.fn(),
  notifySuccess: vi.fn(),
  notifyWarning: vi.fn(),
  notifyError: vi.fn(),
  cn: vi.fn((...args: string[]) => args.filter(Boolean).join(" ")),
  ripple: vi.fn(),
  createCopyFeedback: vi.fn(),
}));

import { useAnchorSync } from "../../../../../apps/svelte-admin/src/lib/use-anchor-sync";

function makeElement(rect: Partial<DOMRect> = {}): HTMLDivElement {
  const el = document.createElement("div");
  const fullRect: DOMRect = {
    left: 0, top: 0, right: 100, bottom: 100,
    width: 100, height: 50,
    x: 0, y: 0,
    toJSON: () => ({}),
    ...rect,
  };
  el.getBoundingClientRect = () => fullRect;
  return el;
}

describe("useAnchorSync", () => {
  beforeEach(() => {
    setAnchorMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  test("returns void and does nothing when element is undefined", () => {
    const cleanup = useAnchorSync(undefined);
    expect(cleanup).toBeUndefined();
    expect(setAnchorMock).not.toHaveBeenCalled();
  });

  test("calls setAnchor immediately with element center position", () => {
    const el = makeElement({ left: 40, top: 20, width: 80, height: 60 });
    document.body.appendChild(el);

    const cleanup = useAnchorSync(el);

    // x = round(left + width/2) = round(40 + 40) = 80
    // y = round(top + height/2) = round(20 + 30) = 50
    expect(setAnchorMock).toHaveBeenCalledWith({ x: 80, y: 50 });

    if (cleanup) cleanup();
    document.body.removeChild(el);
  });

  test("uses main element center for x when element is inside <main>", () => {
    const main = document.createElement("main");
    const el = makeElement({ left: 10, top: 20, width: 60, height: 40 });
    // main covers left=0, width=400 => center x = 200
    main.getBoundingClientRect = () => ({
      left: 0, top: 0, right: 400, bottom: 300,
      width: 400, height: 300,
      x: 0, y: 0,
      toJSON: () => ({}),
    });
    main.appendChild(el);
    document.body.appendChild(main);

    const cleanup = useAnchorSync(el);

    // x = round(0 + 400/2) = 200, y = round(20 + 40/2) = 40
    expect(setAnchorMock).toHaveBeenCalledWith({ x: 200, y: 40 });

    if (cleanup) cleanup();
    document.body.removeChild(main);
  });

  test("re-syncs on window resize event", () => {
    const el = makeElement({ left: 50, top: 10, width: 100, height: 20 });
    document.body.appendChild(el);

    const cleanup = useAnchorSync(el);
    setAnchorMock.mockClear();

    window.dispatchEvent(new Event("resize"));

    // x = round(50 + 50) = 100, y = round(10 + 10) = 20
    expect(setAnchorMock).toHaveBeenCalledWith({ x: 100, y: 20 });

    if (cleanup) cleanup();
    document.body.removeChild(el);
  });

  test("cleanup removes event listeners so resize no longer triggers sync", () => {
    const el = makeElement({ left: 0, top: 0, width: 100, height: 100 });
    document.body.appendChild(el);

    const cleanup = useAnchorSync(el);
    if (cleanup) cleanup();
    setAnchorMock.mockClear();

    window.dispatchEvent(new Event("resize"));

    expect(setAnchorMock).not.toHaveBeenCalled();

    document.body.removeChild(el);
  });

  test("cleanup disconnects ResizeObserver", () => {
    const disconnectMock = vi.fn();
    const observeMock = vi.fn();

    const OriginalResizeObserver = globalThis.ResizeObserver;
    class MockResizeObserver {
      callback: ResizeObserverCallback;
      constructor(cb: ResizeObserverCallback) { this.callback = cb; }
      observe = observeMock;
      unobserve = vi.fn();
      disconnect = disconnectMock;
    }
    Object.defineProperty(globalThis, "ResizeObserver", {
      configurable: true, writable: true,
      value: MockResizeObserver,
    });

    const el = makeElement({ left: 0, top: 0, width: 50, height: 50 });
    document.body.appendChild(el);

    const cleanup = useAnchorSync(el);
    if (cleanup) cleanup();

    expect(disconnectMock).toHaveBeenCalled();

    Object.defineProperty(globalThis, "ResizeObserver", {
      configurable: true, writable: true,
      value: OriginalResizeObserver,
    });
    document.body.removeChild(el);
  });
});
