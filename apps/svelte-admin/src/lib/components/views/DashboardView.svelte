<script lang="ts">
  import { onDestroy } from "svelte";
  import { cn, ripple } from "@quicfuscate/ui";
  import { addToast } from "@quicfuscate/ui";
  import {
    evaluateByteRateSample,
    isBrowserDocumentVisible,
    readBrowserMonotonicMilliseconds,
    type ByteCounterSample,
  } from "@quicfuscate/time";
  import { useAnchorSync } from "$lib/use-anchor-sync";
  import KpiCard from "$lib/components/views/KpiCard.svelte";
  import IpAccessPanel from "$lib/components/panels/IpAccessPanel.svelte";
  import { getJson, getText, ApiError } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import { createErrorToastHandler } from "$lib/error-toast";
  import {
    handleAuthError,
    setStatus,
    getStatus,
    setStatusLoading,
    setMetrics,
    getMetrics,
    setMetricsLoading,
  } from "$lib/stores/app.svelte";
  import { formatBitsPerSecond, formatUptime, formatMetricCount, formatMetricValue } from "$lib/format";
  import { parsePrometheusText } from "$lib/prometheus-text";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import type { MetricsMap } from "$lib/types";

  let statusReady = $state(false);
  let metricsReady = $state(false);
  let trafficBps = $state({ in: 0, out: 0 });
  let prevSample: ByteCounterSample | null = null;
  let serverPanelCleared = $state(false);
  let actionsEl: HTMLDivElement | undefined = $state();
  let viewActive = true;
  const statusRequests = createRequestCoordinator();
  const metricsRequests = createRequestCoordinator();
  const errorToast = createErrorToastHandler(() => viewActive);
  let ipRefreshFn: (() => Promise<void>) | null = null;

  $effect(() => useAnchorSync(actionsEl));

  onDestroy(errorToast.destroy);
  let metricsHistory = $state<{ bytesIn: number[]; bytesOut: number[]; clients: number[] }>(
    { bytesIn: [], bytesOut: [], clients: [] },
  );

  function resetTrafficSample(): void {
    prevSample = null;
    trafficBps = { in: 0, out: 0 };
    metricsHistory = { bytesIn: [], bytesOut: [], clients: [] };
  }

  const status = $derived(getStatus());
  const metrics = $derived(getMetrics());
  const metricMap = $derived(metrics ?? {});

  const serverListenValue = $derived(serverPanelCleared ? "-" : (status?.listen ?? "-"));
  const serverUptimeValue = $derived(serverPanelCleared ? "-" : (status ? formatUptime(status.uptime_secs) : "-"));
  const serverClientsValue = $derived(serverPanelCleared ? "-" : (status ? String(status.clients_active) : "-"));
  const serverRejectedValue = $derived(serverPanelCleared ? "-" : (
    typeof metricMap.quicfuscate_connections_rejected === "number"
      ? formatMetricCount(metricMap.quicfuscate_connections_rejected)
      : "-"
  ));
  const serverInboundValue = $derived(serverPanelCleared ? "-" : (() => {
    const raw = metricMap.quicfuscate_bytes_in_total;
    if (raw == null || raw <= 0) return "-";
    return formatMetricValue("quicfuscate_bytes_in_total", raw);
  })());
  const serverOutboundValue = $derived(serverPanelCleared ? "-" : (() => {
    const raw = metricMap.quicfuscate_bytes_out_total;
    if (raw == null || raw <= 0) return "-";
    return formatMetricValue("quicfuscate_bytes_out_total", raw);
  })());

  function fetchStatus(options: RequestOptions = {}): Promise<void> {
    return statusRequests.request(async (token: RequestToken) => {
      setStatusLoading(true);
      try {
        const resp = await getJson("/api/status", adminApiSchemas.status);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "No status");
        if (!statusRequests.isCurrent(token)) return;
        const data = resp.data;
        setStatus(data);

        if (!isBrowserDocumentVisible()) {
          resetTrafficSample();
          return;
        }
        const sample = evaluateByteRateSample(prevSample, {
          atMilliseconds: readBrowserMonotonicMilliseconds(),
          bytesIn: data.bytes_in,
          bytesOut: data.bytes_out,
        });
        prevSample = sample.nextSample;
        trafficBps = { in: sample.inBps, out: sample.outBps };
        if (!sample.accepted) {
          metricsHistory = { bytesIn: [], bytesOut: [], clients: [] };
          return;
        }

        const maxHistory = 20;
        metricsHistory = {
          bytesIn: [...metricsHistory.bytesIn, sample.inBps].slice(-maxHistory),
          bytesOut: [...metricsHistory.bytesOut, sample.outBps].slice(-maxHistory),
          clients: [...metricsHistory.clients, data.clients_active].slice(-maxHistory),
        };
      } catch (e: unknown) {
        if (!statusRequests.isCurrent(token)) return;
        if (!handleAuthError(e)) errorToast.show(e, "Failed to load status");
      } finally {
        if (statusRequests.isCurrent(token)) {
          setStatusLoading(false);
          statusReady = true;
        }
      }
    }, options);
  }

  function fetchMetrics(options: RequestOptions = {}): Promise<void> {
    return metricsRequests.request(async (token: RequestToken) => {
      setMetricsLoading(true);
      try {
        const resp = await getJson("/api/metrics/json", adminApiSchemas.metrics);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load metrics");
        if (!metricsRequests.isCurrent(token)) return;
        setMetrics(Object.keys(resp.data.metrics).length > 0 ? resp.data.metrics : null);
      } catch (e: unknown) {
        if (!metricsRequests.isCurrent(token)) return;
        if (handleAuthError(e)) {
          // auth error handled
        } else if (e instanceof ApiError && e.status === 404) {
          try {
            const text = await getText("/api/metrics");
            if (!metricsRequests.isCurrent(token)) return;
            const map = parsePrometheusText(text);
            setMetrics(Object.keys(map).length > 0 ? map : null);
          } catch (fe: unknown) {
            if (!metricsRequests.isCurrent(token)) return;
            if (!handleAuthError(fe)) errorToast.show(fe, "Failed to load metrics");
          }
        } else {
          errorToast.show(e, "Failed to load metrics");
        }
      } finally {
        if (metricsRequests.isCurrent(token)) {
          setMetricsLoading(false);
          metricsReady = true;
        }
      }
    }, options);
  }

  function handleRefresh() {
    addToast("Refreshed", "info");
    serverPanelCleared = false;
    void fetchStatus({ invalidate: true });
    void fetchMetrics({ invalidate: true });
    if (ipRefreshFn) void ipRefreshFn();
  }

  function clearServerPanel() {
    statusRequests.invalidate();
    metricsRequests.invalidate();
    setStatusLoading(false);
    setMetricsLoading(false);
    metricsHistory = { bytesIn: [], bytesOut: [], clients: [] };
    serverPanelCleared = true;
  }

  // Polling
  $effect(() => {
    const handleVisibilityChange = (): void => {
      resetTrafficSample();
      if (!isBrowserDocumentVisible()) {
        statusRequests.invalidate();
        metricsRequests.invalidate();
        return;
      }
      void fetchStatus({ invalidate: true });
      void fetchMetrics({ invalidate: true });
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    void fetchStatus();
    void fetchMetrics();
    const statusTick = setInterval(() => { if (isBrowserDocumentVisible()) void fetchStatus(); }, 1200);
    const slow = setInterval(() => { if (isBrowserDocumentVisible()) void fetchMetrics(); }, 15000);
    return () => {
      viewActive = false;
      statusRequests.dispose();
      metricsRequests.dispose();
      clearInterval(statusTick);
      clearInterval(slow);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  });
</script>

<div class="app-pane-scroll flex flex-1 min-h-0 overflow-y-auto">
  <div class="w-full px-6 py-6 space-y-5">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="text-[14px] font-bold text-text-primary">Dashboard</div>
      <div bind:this={actionsEl} class="flex items-center gap-2.5">
        <button
          use:ripple={{ color: "dark" }}
          type="button"
          onclick={handleRefresh}
          class="action-btn-base action-refresh-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
        >Refresh</button>
        <div
          class={cn(
            "status-chip dashboard-heading-sans",
            status ? "border-positive/35 text-positive" : "border-negative/35 text-negative",
          )}
        >
          <span class={cn("h-2 w-2 rounded-full", status ? "bg-positive shadow-[0_0_10px_rgba(22,163,74,0.55)]" : "bg-negative shadow-[0_0_10px_rgba(220,38,38,0.55)]")}></span>
          {status ? "Online" : "Offline"}
        </div>
      </div>
    </div>

    <!-- Server KPI -->
    <section class="rounded-xl glass border border-edge/70">
      <div class="pane-header flex items-start justify-between">
        <div class="text-[11px] text-black font-semibold dashboard-heading-sans">Server</div>
        <button
          use:ripple={{ color: "dark" }}
          type="button"
          onclick={clearServerPanel}
          class="action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
        >Clear</button>
      </div>
      <div class="pane-body grid grid-cols-4 gap-y-5 gap-x-8">
        <KpiCard label="Listen" value={serverListenValue} loading={!serverPanelCleared && !statusReady} />
        <KpiCard label="Uptime" value={serverUptimeValue} loading={!serverPanelCleared && !statusReady} />
        <KpiCard
          label="Upstream"
          value={serverPanelCleared ? "-" : formatBitsPerSecond(trafficBps.in)}
          trafficBitsPerSecond={serverPanelCleared ? undefined : trafficBps.in}
          loading={!serverPanelCleared && !statusReady}
          sparkline={serverPanelCleared ? [] : metricsHistory.bytesIn}
        />
        <KpiCard
          label="Downstream"
          value={serverPanelCleared ? "-" : formatBitsPerSecond(trafficBps.out)}
          trafficBitsPerSecond={serverPanelCleared ? undefined : trafficBps.out}
          loading={!serverPanelCleared && !statusReady}
          sparkline={serverPanelCleared ? [] : metricsHistory.bytesOut}
        />
        <KpiCard label="Clients" value={serverClientsValue} loading={!serverPanelCleared && !statusReady} />
        <KpiCard label="Rejected" value={serverRejectedValue} loading={!serverPanelCleared && !metricsReady} />
        <KpiCard label="Inbound Total" value={serverInboundValue} loading={!serverPanelCleared && !metricsReady} />
        <KpiCard label="Outbound Total" value={serverOutboundValue} loading={!serverPanelCleared && !metricsReady} />
      </div>
    </section>

    <!-- IP Access Control -->
    <IpAccessPanel onRefresh={(fn) => { ipRefreshFn = fn; }} />
  </div>
</div>
