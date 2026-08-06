// Svelte action for material-design ripple effect
// Usage: <button use:ripple>Click me</button>
// Usage: <button use:ripple={{ color: "dark" }}>Click me</button>

export type RippleColor = "light" | "dark" | "auto";

export interface RippleOptions {
  /** "light" = white ripple, "dark" = black ripple, "auto" = detect from background */
  color?: RippleColor;
  /** Duration in ms (default: 600) */
  duration?: number;
  /** Disable the ripple */
  disabled?: boolean;
}

const RIPPLE_LIGHT = "rgba(255, 255, 255, 0.35)";
const RIPPLE_DARK = "rgba(0, 0, 0, 0.12)";
const DEFAULT_DURATION = 600;

function resolveColor(color: RippleColor, el: HTMLElement): string {
  if (color === "light") return RIPPLE_LIGHT;
  if (color === "dark") return RIPPLE_DARK;

  // auto-detect: check computed background luminance
  const bg = getComputedStyle(el).backgroundColor;
  const match = bg.match(/\d+/g);
  if (match && match.length >= 3) {
    const [r, g, b] = match.map(Number);
    // Relative luminance approximation
    const luminance = 0.299 * r + 0.587 * g + 0.114 * b;
    return luminance > 128 ? RIPPLE_DARK : RIPPLE_LIGHT;
  }
  return RIPPLE_LIGHT;
}

function injectStyles(): void {
  if (document.getElementById("__ripple-styles")) return;

  const style = document.createElement("style");
  style.id = "__ripple-styles";
  style.textContent = `
@keyframes ripple-expand {
  0% {
    transform: scale(0);
    opacity: 1;
  }
  100% {
    transform: scale(4);
    opacity: 0;
  }
}
.__ripple-container {
  position: absolute;
  inset: 0;
  overflow: hidden;
  pointer-events: none;
  border-radius: inherit;
  z-index: 0;
}
.__ripple-circle {
  position: absolute;
  border-radius: 50%;
  transform: scale(0);
  animation: ripple-expand var(--ripple-duration, 600ms) ease-out forwards;
  pointer-events: none;
}`;
  document.head.appendChild(style);
}

function createRipple(
  el: HTMLElement,
  container: HTMLElement,
  event: PointerEvent,
  opts: RippleOptions,
  activeCircles: Set<HTMLSpanElement>,
  safetyTimers: Set<ReturnType<typeof setTimeout>>,
): void {
  const rect = el.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;

  // Diameter = largest distance from click point to any corner * 2
  const dx = Math.max(x, rect.width - x);
  const dy = Math.max(y, rect.height - y);
  const diameter = Math.sqrt(dx * dx + dy * dy) * 2;

  const duration = opts.duration ?? DEFAULT_DURATION;
  const color = resolveColor(opts.color ?? "auto", el);

  const circle = document.createElement("span");
  circle.className = "__ripple-circle";
  circle.style.width = `${diameter}px`;
  circle.style.height = `${diameter}px`;
  circle.style.left = `${x - diameter / 2}px`;
  circle.style.top = `${y - diameter / 2}px`;
  circle.style.backgroundColor = color;
  circle.style.setProperty("--ripple-duration", `${duration}ms`);

  container.appendChild(circle);
  activeCircles.add(circle);

  let safetyTimer: ReturnType<typeof setTimeout> | null = null;
  const removeCircle = (): void => {
    if (safetyTimer !== null) {
      clearTimeout(safetyTimer);
      safetyTimers.delete(safetyTimer);
      safetyTimer = null;
    }
    activeCircles.delete(circle);
    circle.remove();
  };

  circle.addEventListener("animationend", removeCircle, { once: true });

  // Safety fallback: remove after duration + 100ms buffer
  const timer = setTimeout(() => {
    safetyTimers.delete(timer);
    safetyTimer = null;
    removeCircle();
  }, duration + 100);
  safetyTimer = timer;
  safetyTimers.add(timer);
}

export function ripple(
  node: HTMLElement,
  options?: RippleOptions,
): { update: (opts?: RippleOptions) => void; destroy: () => void } {
  injectStyles();

  let opts: RippleOptions = options ?? {};
  const activeCircles = new Set<HTMLSpanElement>();
  const safetyTimers = new Set<ReturnType<typeof setTimeout>>();

  // Ensure host element has position for the absolute container
  const pos = getComputedStyle(node).position;
  if (pos === "static" || pos === "") {
    node.style.position = "relative";
  }
  // Ensure overflow hidden for border-radius clipping
  node.style.overflow = "hidden";

  const container = document.createElement("span");
  container.className = "__ripple-container";
  node.appendChild(container);

  function handlePointerDown(event: PointerEvent): void {
    if (opts.disabled) return;
    createRipple(node, container, event, opts, activeCircles, safetyTimers);
  }

  node.addEventListener("pointerdown", handlePointerDown);

  return {
    update(newOpts?: RippleOptions) {
      opts = newOpts ?? {};
    },
    destroy() {
      node.removeEventListener("pointerdown", handlePointerDown);
      for (const timer of safetyTimers) clearTimeout(timer);
      safetyTimers.clear();
      for (const circle of activeCircles) circle.remove();
      activeCircles.clear();
      if (container.parentNode) container.remove();
    },
  };
}
