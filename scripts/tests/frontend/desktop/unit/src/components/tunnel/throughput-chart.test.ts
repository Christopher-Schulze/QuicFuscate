import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { render } from "../../../testing-library";

import ThroughputChart from "../../../../../../../../apps/svelte-desktop/src/lib/components/tunnel/ThroughputChart.svelte";

describe("tunnel/ThroughputChart", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test("renders a canvas element", () => {
    const { container } = render(ThroughputChart, { downBps: 0, upBps: 0, isActive: false });
    const canvas = container.querySelector("canvas");
    expect(canvas).not.toBeNull();
  });

  test("renders a container div with relative positioning class", () => {
    const { container } = render(ThroughputChart, { downBps: 0, upBps: 0, isActive: false });
    const wrapper = container.querySelector("div.relative");
    expect(wrapper).not.toBeNull();
  });

  test("does not render scale labels when inactive", () => {
    const { container } = render(ThroughputChart, { downBps: 0, upBps: 0, isActive: false });
    // Scale labels are only rendered when isActive is true
    const labels = container.querySelectorAll("span.tabular-nums");
    expect(labels.length).toBe(0);
  });

  test("renders scale labels when active", () => {
    const { container } = render(ThroughputChart, { downBps: 100000, upBps: 50000, isActive: true });
    // When isActive, the component renders 5 scale labels (max, 75%, 50%, 25%, 0)
    const labels = container.querySelectorAll("span");
    expect(labels.length).toBeGreaterThanOrEqual(1);
  });

  test("renders the '0' label at the bottom of the scale when active", () => {
    const { container } = render(ThroughputChart, { downBps: 0, upBps: 0, isActive: true });
    const spans = container.querySelectorAll("span");
    const texts = Array.from(spans).map((s) => s.textContent?.trim());
    expect(texts).toContain("0");
  });

  test("canvas has inset-0 positioning classes", () => {
    const { container } = render(ThroughputChart, { downBps: 0, upBps: 0, isActive: false });
    const canvas = container.querySelector("canvas");
    expect(canvas?.classList.contains("inset-0")).toBe(true);
  });

  test("cancels the render loop and resets samples when the document is hidden", () => {
    const original = Object.getOwnPropertyDescriptor(document, "visibilityState");
    const cancel = vi.spyOn(window, "cancelAnimationFrame");
    try {
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
      render(ThroughputChart, { downBps: 100_000, upBps: 50_000, isActive: true });
      Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
      document.dispatchEvent(new Event("visibilitychange"));
      expect(cancel).toHaveBeenCalled();
    } finally {
      cancel.mockRestore();
      if (original) Object.defineProperty(document, "visibilityState", original);
      else delete (document as Document & { visibilityState?: string }).visibilityState;
    }
  });
});
