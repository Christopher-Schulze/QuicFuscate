<script lang="ts" module>
  let nextSparklineId = 0;

  function createSparklineGradientId(): string {
    const id = nextSparklineId;
    nextSparklineId += 1;
    return `sparkline-grad-${id.toString(36)}`;
  }
</script>

<script lang="ts">
  import { cn } from "@quicfuscate/ui";

  interface Props {
    data: number[];
    width?: number;
    height?: number;
    color?: string;
    fillColor?: string;
    className?: string;
  }

  let {
    data,
    width = 120,
    height = 32,
    color = "var(--color-accent)",
    fillColor = "var(--color-accent-dim)",
    className,
  }: Props = $props();

  const gradientId = createSparklineGradientId();

  const pathData = $derived.by(() => {
    if (data.length < 2) return null;
    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;
    const padding = 2;
    const chartWidth = width - padding * 2;
    const chartHeight = height - padding * 2;

    const points = data.map((value, index) => {
      const x = padding + (index / (data.length - 1)) * chartWidth;
      const y = padding + chartHeight - ((value - min) / range) * chartHeight;
      return `${x},${y}`;
    });

    const pathD = `M ${points.join(" L ")}`;
    const areaD = `${pathD} L ${width - padding},${height - padding} L ${padding},${height - padding} Z`;
    return { pathD, areaD };
  });
</script>

{#if pathData}
  <svg
    {width}
    {height}
    class={cn("overflow-visible", className)}
    viewBox="0 0 {width} {height}"
    preserveAspectRatio="none"
  >
    <defs>
      <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color={fillColor} stop-opacity="0.45" />
        <stop offset="100%" stop-color={fillColor} stop-opacity="0" />
      </linearGradient>
    </defs>
    <path d={pathData.areaD} fill="url(#{gradientId})" />
    <path
      d={pathData.pathD}
      fill="none"
      stroke={color}
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
    />
  </svg>
{:else}
  <div
    class={cn("bg-surface-2 rounded", className)}
    style="width:{width}px;height:{height}px;"
  ></div>
{/if}
