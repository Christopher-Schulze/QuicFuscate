<script lang="ts">
  import { isBrowserDocumentVisible } from "@quicfuscate/time";

  // ---------------------------------------------------------------------------
  // ThroughputChart - Canvas-based real-time dual-series throughput visualizer
  // ---------------------------------------------------------------------------

  // -- Constants --------------------------------------------------------------
  const HISTORY_SECONDS = 90;
  const UPDATES_PER_SECOND = 19;
  const SAMPLE_INTERVAL_MS = 1000 / UPDATES_PER_SECOND; // ~52ms
  const SAMPLE_COUNT = HISTORY_SECONDS * UPDATES_PER_SECOND; // 1710
  const MINIMAL_SMOOTHING_ALPHA = 0.14;
  const MAX_RENDER_POINTS = 720;

  const DOWN_COLOR = "rgba(92,103,245,0.96)";
  const UP_COLOR = "rgba(131,103,245,0.94)";
  const GRID_COLOR = "rgba(42,46,68,0.14)";

  const NICE_STEPS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000];

  // -- Props ------------------------------------------------------------------
  interface Props {
    downBps: number;
    upBps: number;
    isActive: boolean;
  }

  let { downBps, upBps, isActive }: Props = $props();

  // -- Reactive state ---------------------------------------------------------
  let canvasEl: HTMLCanvasElement | undefined = $state(undefined);
  let containerEl: HTMLDivElement | undefined = $state(undefined);
  let cssW = $state(0);
  let cssH = $state(0);
  let currentScale = $state(1); // Mbit/s

  // -- Circular buffers (non-reactive, mutation only) -------------------------
  const downBuf = new Float32Array(SAMPLE_COUNT);
  const upBuf = new Float32Array(SAMPLE_COUNT);
  let writeIdx = 0;
  let sampleCount = 0;
  let smoothedDown = 0;
  let smoothedUp = 0;

  function resetSamples(): void {
    smoothedDown = 0;
    smoothedUp = 0;
    sampleCount = 0;
    writeIdx = 0;
    currentScale = 1;
  }

  // -- Grid cache -------------------------------------------------------------
  let gridCanvas: OffscreenCanvas | HTMLCanvasElement | null = null;
  let gridDirty = true;
  let lastGridW = 0;
  let lastGridH = 0;

  // -- Derived: scale labels --------------------------------------------------
  const scaleLabels = $derived.by(() => {
    const m = currentScale;
    return [m, m * 0.75, m * 0.5, m * 0.25, 0].map(formatScaleMbps);
  });

  // -- Format helper ----------------------------------------------------------
  function formatScaleMbps(mbps: number): string {
    if (mbps === 0) return "0";
    if (mbps >= 1000) return `${(mbps / 1000).toFixed(mbps % 1000 === 0 ? 0 : 1)} Gbit/s`;
    if (mbps >= 1) return `${Number.isInteger(mbps) ? mbps : mbps.toFixed(1)} Mbit/s`;
    return `${(mbps * 1000).toFixed(0)} Kbit/s`;
  }

  // -- Coordinate helpers -----------------------------------------------------
  function toPxX(x: number, w: number): number {
    return (x / 100) * w;
  }
  function toPxY(y: number, h: number): number {
    return (y / 28) * h;
  }

  // -- Grid rendering (cached) ------------------------------------------------
  function renderGrid(w: number, h: number, dpr: number): void {
    const physW = Math.round(w * dpr);
    const physH = Math.round(h * dpr);

    if (gridCanvas && lastGridW === physW && lastGridH === physH && !gridDirty) return;

    if (typeof OffscreenCanvas !== "undefined") {
      gridCanvas = new OffscreenCanvas(physW, physH);
    } else {
      gridCanvas = document.createElement("canvas");
      gridCanvas.width = physW;
      gridCanvas.height = physH;
    }
    lastGridW = physW;
    lastGridH = physH;

    const gctx = gridCanvas.getContext("2d");
    if (!gctx) return;

    gctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    gctx.clearRect(0, 0, w, h);

    const scaleY = h / 28;
    gctx.strokeStyle = GRID_COLOR;
    gctx.lineWidth = Math.max(0.3, 0.14 * scaleY);
    gctx.lineCap = "round";

    // 6 horizontal lines
    for (let i = 0; i < 6; i++) {
      const y = toPxY((28 / 6) * (i + 1), h);
      gctx.beginPath();
      gctx.moveTo(0, y);
      gctx.lineTo(w, y);
      gctx.stroke();
    }
    // 9 vertical lines (last closes right side of grid)
    for (let i = 0; i < 9; i++) {
      const x = toPxX((80 / 8) * (i + 1), w);
      gctx.beginPath();
      gctx.moveTo(x, 0);
      gctx.lineTo(x, h);
      gctx.stroke();
    }

    gridDirty = false;
  }

  // -- Trace rendering --------------------------------------------------------
  function buildPoints(
    buf: Float32Array,
    count: number,
    head: number,
    maxVal: number,
    yMin: number,
    yMax: number,
    w: number,
    h: number,
  ): { x: number; y: number }[] {
    const n = Math.min(count, SAMPLE_COUNT);
    if (n === 0) return [];

    const step = n > MAX_RENDER_POINTS ? Math.floor(n / MAX_RENDER_POINTS) : 1;
    const pts: { x: number; y: number }[] = [];
    const yRange = yMax - yMin;

    for (let i = 0; i < n; i += step) {
      const idx = (head - n + i + SAMPLE_COUNT) % SAMPLE_COUNT;
      const val = buf[idx];
      const ratio = maxVal > 0 ? Math.min(1, val / maxVal) : 0;
      const xNorm = (i / (n - 1 || 1)) * 80;
      const yNorm = yMax - ratio * yRange;
      pts.push({ x: toPxX(xNorm, w), y: toPxY(yNorm, h) });
    }
    return pts;
  }

  function drawTrace(
    ctx: CanvasRenderingContext2D,
    pts: { x: number; y: number }[],
    color: string,
    alpha: number,
    scaleY: number,
  ): void {
    if (pts.length < 2) return;
    ctx.save();
    ctx.globalAlpha = alpha;
    ctx.strokeStyle = color;
    ctx.lineWidth = Math.max(0.45, 0.44 * scaleY);
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i = 1; i < pts.length; i++) {
      ctx.lineTo(pts[i].x, pts[i].y);
    }
    ctx.stroke();
    ctx.restore();
  }

  function drawEndpoint(
    ctx: CanvasRenderingContext2D,
    pt: { x: number; y: number },
    color: string,
    glowColor: string,
    outerR: number,
    innerR: number,
    strokeColor: string,
    strokeW: number,
  ): void {
    // outer glow
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, outerR, 0, Math.PI * 2);
    ctx.fillStyle = glowColor;
    ctx.fill();
    // inner
    ctx.beginPath();
    ctx.arc(pt.x, pt.y, innerR, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = strokeW;
    ctx.stroke();
  }

  // -- Scale hysteresis -------------------------------------------------------
  function computeScale(rawMaxBps: number, prev: number): number {
    const rawMaxMbps = rawMaxBps / 125000; // bytes/s -> Mbit/s
    const paddedMax = rawMaxMbps * 1.08;
    if (paddedMax <= prev * 0.92 && paddedMax >= prev * 0.56) return prev;
    // find next nice step
    for (const s of NICE_STEPS) {
      if (s >= paddedMax) return s;
    }
    return NICE_STEPS[NICE_STEPS.length - 1];
  }

  // -- Main render frame ------------------------------------------------------
  function renderFrame(): void {
    if (!canvasEl) return;
    const ctx = canvasEl.getContext("2d", { alpha: true, desynchronized: true });
    if (!ctx) return;

    const w = cssW;
    const h = cssH;
    if (w <= 0 || h <= 0) return;

    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const physW = Math.round(w * dpr);
    const physH = Math.round(h * dpr);

    if (canvasEl.width !== physW || canvasEl.height !== physH) {
      canvasEl.width = physW;
      canvasEl.height = physH;
      gridDirty = true;
    }

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    // Grid
    renderGrid(w, h, dpr);
    if (gridCanvas) {
      ctx.drawImage(gridCanvas as HTMLCanvasElement, 0, 0, w, h);
    }

    // Compute raw max for scale
    let rawMax = 0;
    const n = Math.min(sampleCount, SAMPLE_COUNT);
    for (let i = 0; i < n; i++) {
      if (downBuf[i] > rawMax) rawMax = downBuf[i];
      if (upBuf[i] > rawMax) rawMax = upBuf[i];
    }
    const newScale = computeScale(rawMax, currentScale);
    if (newScale !== currentScale) currentScale = newScale;

    const maxBps = currentScale * 125000; // Mbit/s -> bytes/s
    const scaleY = h / 28;

    // Only draw traces and endpoints when there's actual data
    if (sampleCount < 2) return;

    // Down trace (y: 5-28)
    const downPts = buildPoints(downBuf, sampleCount, writeIdx, maxBps, 5, 28, w, h);
    drawTrace(ctx, downPts, DOWN_COLOR, 1.0, scaleY);

    // Up trace (y: 9-28)
    const upPts = buildPoints(upBuf, sampleCount, writeIdx, maxBps, 9, 28, w, h);
    drawTrace(ctx, upPts, UP_COLOR, 0.95, scaleY);

    // Endpoints - only when actively receiving data
    if (!isActive) return;

    if (downPts.length > 0) {
      const last = downPts[downPts.length - 1];
      drawEndpoint(
        ctx,
        last,
        DOWN_COLOR,
        "rgba(92,103,245,0.2)",
        Math.max(1, 1.65 * scaleY),
        Math.max(0.7, 0.78 * scaleY),
        "rgba(255,255,255,0.9)",
        Math.max(0.2, 0.14 * scaleY),
      );
    }
    if (upPts.length > 0) {
      const last = upPts[upPts.length - 1];
      drawEndpoint(
        ctx,
        last,
        UP_COLOR,
        "rgba(131,103,245,0.18)",
        Math.max(1, 1.45 * scaleY),
        Math.max(0.7, 0.66 * scaleY),
        "rgba(255,255,255,0.88)",
        Math.max(0.2, 0.12 * scaleY),
      );
    }
  }

  // -- Lifecycle via $effect --------------------------------------------------
  $effect(() => {
    if (!containerEl) return;

    let samplingId: ReturnType<typeof setInterval> | null = null;
    let rafId: number | null = null;
    let running = true;
    let tabVisible = isBrowserDocumentVisible();

    // Capture initial size
    cssW = containerEl.clientWidth;
    cssH = containerEl.clientHeight;
    gridDirty = true;

    // ResizeObserver
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const cr = entry.contentRect;
        if (cr.width !== cssW || cr.height !== cssH) {
          cssW = cr.width;
          cssH = cr.height;
          gridDirty = true;
        }
      }
    });
    ro.observe(containerEl);

    // Visibility
    function onVisChange(): void {
      tabVisible = isBrowserDocumentVisible();
      resetSamples();
      if (!tabVisible && rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      if (tabVisible && rafId === null && running) {
        rafLoop();
      }
    }
    document.addEventListener("visibilitychange", onVisChange);

    // Sampling - only when active, reset when inactive
    samplingId = setInterval(() => {
      if (!tabVisible) return;
      if (!isActive) {
        // Reset buffers when not active - no phantom lines
        resetSamples();
        return;
      }
      // Exponential smoothing
      smoothedDown += MINIMAL_SMOOTHING_ALPHA * (downBps - smoothedDown);
      smoothedUp += MINIMAL_SMOOTHING_ALPHA * (upBps - smoothedUp);
      downBuf[writeIdx] = smoothedDown;
      upBuf[writeIdx] = smoothedUp;
      writeIdx = (writeIdx + 1) % SAMPLE_COUNT;
      if (sampleCount < SAMPLE_COUNT) sampleCount++;
    }, SAMPLE_INTERVAL_MS);

    // RAF loop
    function rafLoop(): void {
      if (!running) return;
      renderFrame();
      if (tabVisible && running) {
        rafId = requestAnimationFrame(rafLoop);
      }
    }
    if (tabVisible) rafLoop();

    return () => {
      running = false;
      if (samplingId !== null) clearInterval(samplingId);
      if (rafId !== null) cancelAnimationFrame(rafId);
      ro.disconnect();
      document.removeEventListener("visibilitychange", onVisChange);
    };
  });
</script>

<div class="relative h-full w-full" bind:this={containerEl}>
  <canvas
    bind:this={canvasEl}
    class="absolute inset-0 h-full w-full"
    style="image-rendering: auto;"
  ></canvas>
  <!-- Y-axis scale labels - nice round numbers at each grid line -->
  {#if isActive}
    <div class="absolute right-[4px] top-0 bottom-0 flex flex-col justify-between items-end pointer-events-none py-[2px]">
      {#each scaleLabels as label (label)}
        <span class="text-[8px] font-semibold text-black/40 tabular-nums leading-none">{label}</span>
      {/each}
    </div>
  {/if}
</div>
