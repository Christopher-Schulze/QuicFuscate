import { describe, expect, test, vi, beforeEach, afterEach } from "vitest";
import { ripple } from "../../../../../packages/ui/ripple";

beforeEach(() => {
  vi.useFakeTimers();
  // Clean up any injected ripple styles from previous tests
  document.getElementById("__ripple-styles")?.remove();
});

afterEach(() => {
  vi.useRealTimers();
});

function createButton(): HTMLButtonElement {
  const btn = document.createElement("button");
  btn.style.width = "100px";
  btn.style.height = "40px";
  document.body.appendChild(btn);
  return btn;
}

function firePointerDown(el: HTMLElement, x = 50, y = 20): void {
  const rect = el.getBoundingClientRect();
  el.dispatchEvent(
    new PointerEvent("pointerdown", {
      bubbles: true,
      clientX: rect.left + x,
      clientY: rect.top + y,
    }),
  );
}

describe("ripple action", () => {
  test("injects global ripple stylesheet on first use", () => {
    const btn = createButton();
    const handle = ripple(btn);
    expect(document.getElementById("__ripple-styles")).not.toBeNull();
    handle.destroy();
    btn.remove();
  });

  test("does not duplicate stylesheet on multiple calls", () => {
    const btn1 = createButton();
    const btn2 = createButton();
    const h1 = ripple(btn1);
    const h2 = ripple(btn2);
    const styleEls = document.querySelectorAll("#__ripple-styles");
    expect(styleEls.length).toBe(1);
    h1.destroy();
    h2.destroy();
    btn1.remove();
    btn2.remove();
  });

  test("appends ripple container to the node", () => {
    const btn = createButton();
    const handle = ripple(btn);
    const container = btn.querySelector(".__ripple-container");
    expect(container).not.toBeNull();
    handle.destroy();
    btn.remove();
  });

  test("creates ripple circle on pointerdown", () => {
    const btn = createButton();
    const handle = ripple(btn, { color: "light" });
    firePointerDown(btn);
    const circles = btn.querySelectorAll(".__ripple-circle");
    expect(circles.length).toBe(1);
    handle.destroy();
    btn.remove();
  });

  test("does not create ripple when disabled", () => {
    const btn = createButton();
    const handle = ripple(btn, { disabled: true });
    firePointerDown(btn);
    const circles = btn.querySelectorAll(".__ripple-circle");
    expect(circles.length).toBe(0);
    handle.destroy();
    btn.remove();
  });

  test("removes ripple circle after timeout (duration + 100ms buffer)", () => {
    const btn = createButton();
    const handle = ripple(btn, { duration: 300 });
    firePointerDown(btn);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(1);
    vi.advanceTimersByTime(400);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(0);
    handle.destroy();
    btn.remove();
  });

  test("destroy removes event listener and container", () => {
    const btn = createButton();
    const handle = ripple(btn);
    handle.destroy();
    const container = btn.querySelector(".__ripple-container");
    expect(container).toBeNull();
    // Pointer down after destroy should not create ripple
    firePointerDown(btn);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(0);
    btn.remove();
  });

  test("destroy clears pending safety cleanup and active circles", () => {
    const btn = createButton();
    const handle = ripple(btn, { duration: 300 });
    firePointerDown(btn);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(1);

    handle.destroy();
    vi.advanceTimersByTime(1000);

    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(0);
    btn.remove();
  });

  test("update changes options (e.g. enables disabled)", () => {
    const btn = createButton();
    const handle = ripple(btn, { disabled: true });
    firePointerDown(btn);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(0);
    handle.update({ disabled: false, color: "dark" });
    firePointerDown(btn);
    expect(btn.querySelectorAll(".__ripple-circle").length).toBe(1);
    handle.destroy();
    btn.remove();
  });
});
