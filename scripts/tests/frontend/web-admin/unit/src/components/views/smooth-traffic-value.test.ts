import { describe, expect, test, vi, beforeEach } from "vitest";
import { render } from "../../../testing-library";
import { getFrontendClockHarness } from "../../../../../test-clock";
import { tick } from "svelte";

import SmoothTrafficValue from "../../../../../../../../apps/svelte-admin/src/lib/components/views/SmoothTrafficValue.svelte";

describe("SmoothTrafficValue", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  test("renders formatted value for zero bits per second", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: 0 },
    });
    // On initial render, displayBits is set directly to target (no animation)
    expect(container.textContent).toContain("0.00 bit/s");
  });

  test("renders formatted value for small traffic", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: 500 },
    });
    expect(container.textContent).toContain("500 bit/s");
  });

  test("renders formatted value for megabit range", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: 5_000_000 },
    });
    expect(container.textContent).toContain("5.00 Mbit/s");
  });

  test("renders formatted value for gigabit range", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: 1_000_000_000 },
    });
    expect(container.textContent).toContain("1.00 Gbit/s");
  });

  test("clamps negative values to zero", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: -100 },
    });
    expect(container.textContent).toContain("0.00 bit/s");
  });

  test("renders kilobit range correctly", () => {
    const { container } = render(SmoothTrafficValue, {
      props: { bitsPerSecond: 15_000 },
    });
    expect(container.textContent).toContain("15.0 Kbit/s");
  });

  test("cancels animation and snaps to the target when the document is hidden", async () => {
    const clock = getFrontendClockHarness();
    clock.installAnimationFrame();
    clock.setVisibility("visible");
    const view = render(SmoothTrafficValue, { props: { bitsPerSecond: 0 } });
    await view.rerender({ bitsPerSecond: 5_000_000 });
    expect(clock.pendingAnimationFrameCount()).toBeGreaterThan(0);

    clock.setVisibility("hidden");
    await tick();
    expect(clock.pendingAnimationFrameCount()).toBe(0);
    expect(view.container.textContent).toContain("5.00 Mbit/s");
  });
});
