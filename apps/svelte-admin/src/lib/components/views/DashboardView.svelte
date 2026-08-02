<script lang="ts">
  import { fly, scale } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { ShieldAlert, ShieldCheck, Lock, Activity } from "@lucide/svelte";
  import { cn, ripple } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import { useAnchorSync } from "$lib/use-anchor-sync";
  import Sparkline from "$lib/components/ui/Sparkline.svelte";
  import SmoothTrafficValue from "$lib/components/views/SmoothTrafficValue.svelte";
  import KpiCard from "$lib/components/views/KpiCard.svelte";
  import { getJson, getText, postJson, ApiError, isAuthError, sanitizeErrorMessage } from "$lib/api";
  import { extractBlockedIps, mergeBlockedIps, optimisticBlock, optimisticUnblock } from "$lib/blocked-ips";
  import {
    setAuthRequired,
    setAuthError,
    setStatus,
    getStatus,
    setStatusLoading,
    setClients,
    getClients,
    setClientsLoading,
    setMetrics,
    getMetrics,
    setMetricsLoading,
  } from "$lib/stores/app.svelte";
  import { formatBitsPerSecond, formatUptime, formatMetricCount, formatMetricValue } from "$lib/format";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import type { AdminResponse, ClientInfo, MetricsMap, StatusData, PendingIpAction } from "$lib/types";

  type MetricsResponse = { metrics?: MetricsMap | null };

  let blockedIps = $state<string[]>([]);
  let ipActionPending = $state<Record<string, PendingIpAction | undefined>>({});
  let statusReady = $state(false);
  let clientsReady = $state(false);
  let blockedReady = $state(false);
  let metricsReady = $state(false);
  let trafficBps = $state({ in: 0, out: 0 });
  let prevSample: { bytesIn: number; bytesOut: number; tsMs: number } | null = null;
  let serverPanelCleared = $state(false);
  let lastErrorMsg = "";
  let actionsEl: HTMLDivElement | undefined = $state();
  let viewActive = true;
  const statusRequests = createRequestCoordinator();
  const clientsRequests = createRequestCoordinator();
  const metricsRequests = createRequestCoordinator();
  const blockedRequests = createRequestCoordinator();

  $effect(() => useAnchorSync(actionsEl));

  function showErrorToast(e: unknown, fallback: string) {
    if (!viewActive) return;
    const msg = sanitizeErrorMessage(
      e instanceof Error ? e.message : String(e),
      fallback,
    );
    // De-duplicate: don't show same error repeatedly
    if (msg === lastErrorMsg) return;
    lastErrorMsg = msg;
    addToast(msg, "error");
    // Reset after 10s to allow the same error to show again if it reoccurs later
    setTimeout(() => { if (lastErrorMsg === msg) lastErrorMsg = ""; }, 10000);
  }
  let metricsHistory = $state<{ bytesIn: number[]; bytesOut: number[]; clients: number[] }>(
    { bytesIn: [], bytesOut: [], clients: [] },
  );

  const status = $derived(getStatus());
  const clients = $derived(getClients());
  const metrics = $derived(getMetrics());
  const metricMap = $derived(metrics ?? {});

  const blockedSet = $derived(new Set(blockedIps));
  const connectedIps = $derived(clients.map((c) => c.ip).filter((ip) => !blockedSet.has(ip)));
  const ipPanelInitialLoading = $derived(!(clientsReady && blockedReady));

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

  function beginIpAction(ip: string, action: PendingIpAction): boolean {
    if (ipActionPending[ip]) return false;
    ipActionPending = { ...ipActionPending, [ip]: action };
    return true;
  }

  function endIpAction(ip: string) {
    const next = { ...ipActionPending };
    delete next[ip];
    ipActionPending = next;
  }

  function fetchStatus(options: RequestOptions = {}): Promise<void> {
    return statusRequests.request(async (token: RequestToken) => {
      setStatusLoading(true);
      try {
        const resp = await getJson<AdminResponse<StatusData>>("/api/status");
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "No status");
        if (!statusRequests.isCurrent(token)) return;
        const data = resp.data;
        setStatus(data);

        const nowMs = performance.now();
        let inBps = 0;
        let outBps = 0;
        if (prevSample) {
          const dt = Math.max((nowMs - prevSample.tsMs) / 1000, 0.001);
          inBps = (Math.max(0, data.bytes_in - prevSample.bytesIn) * 8) / dt;
          outBps = (Math.max(0, data.bytes_out - prevSample.bytesOut) * 8) / dt;
        }
        prevSample = { bytesIn: data.bytes_in, bytesOut: data.bytes_out, tsMs: nowMs };
        trafficBps = { in: inBps, out: outBps };

        const maxHistory = 20;
        metricsHistory = {
          bytesIn: [...metricsHistory.bytesIn, inBps].slice(-maxHistory),
          bytesOut: [...metricsHistory.bytesOut, outBps].slice(-maxHistory),
          clients: [...metricsHistory.clients, data.clients_active].slice(-maxHistory),
        };
      } catch (e: unknown) {
        if (!statusRequests.isCurrent(token)) return;
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
        else showErrorToast(e, "Failed to load status");
      } finally {
        if (statusRequests.isCurrent(token)) {
          setStatusLoading(false);
          statusReady = true;
        }
      }
    }, options);
  }

  function fetchClients(options: RequestOptions = {}): Promise<void> {
    return clientsRequests.request(async (token: RequestToken) => {
      setClientsLoading(true);
      try {
        const resp = await getJson<AdminResponse<ClientInfo[]>>("/api/clients");
        if (!resp.success) throw new Error(resp.message ?? "Failed to load clients");
        if (!clientsRequests.isCurrent(token)) return;
        setClients(Array.isArray(resp.data) ? resp.data : []);
      } catch (e: unknown) {
        if (!clientsRequests.isCurrent(token)) return;
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
        else showErrorToast(e, "Failed to load clients");
      } finally {
        if (clientsRequests.isCurrent(token)) {
          setClientsLoading(false);
          clientsReady = true;
        }
      }
    }, options);
  }

  function fetchMetrics(options: RequestOptions = {}): Promise<void> {
    return metricsRequests.request(async (token: RequestToken) => {
      setMetricsLoading(true);
      try {
        const resp = await getJson<AdminResponse<MetricsResponse>>("/api/metrics/json");
        if (!resp.success) throw new Error(resp.message ?? "Failed to load metrics");
        if (!metricsRequests.isCurrent(token)) return;
        const incoming = resp.data?.metrics;
        const sanitized: MetricsMap = {};
        if (incoming && typeof incoming === "object") {
          for (const [key, raw] of Object.entries(incoming)) {
            if (!key) continue;
            const value = Number(raw);
            if (!Number.isFinite(value)) continue;
            sanitized[key] = value;
          }
        }
        setMetrics(Object.keys(sanitized).length > 0 ? sanitized : null);
      } catch (e: unknown) {
        if (!metricsRequests.isCurrent(token)) return;
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
        else if (e instanceof ApiError && e.status === 404) {
          try {
            const text = await getText("/api/metrics");
            if (!metricsRequests.isCurrent(token)) return;
            const map = parsePrometheusText(text);
            setMetrics(Object.keys(map).length > 0 ? map : null);
          } catch (fe: unknown) {
            if (!metricsRequests.isCurrent(token)) return;
            if (isAuthError(fe)) { setAuthError(null); setAuthRequired(true); }
            else showErrorToast(fe, "Failed to load metrics");
          }
        } else {
          showErrorToast(e, "Failed to load metrics");
        }
      } finally {
        if (metricsRequests.isCurrent(token)) {
          setMetricsLoading(false);
          metricsReady = true;
        }
      }
    }, options);
  }

  function parsePrometheusText(raw: string): MetricsMap {
    const map: MetricsMap = {};
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length < 2) continue;
      const match = parts[0].match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{.*\})?$/);
      if (!match) continue;
      const value = Number(parts[1]);
      if (!Number.isFinite(value)) continue;
      map[match[1]] = (map[match[1]] ?? 0) + value;
    }
    return map;
  }

  function fetchBlocked(options: RequestOptions = {}): Promise<void> {
    return blockedRequests.request(async (token: RequestToken) => {
      try {
        const resp = await getJson<AdminResponse<{ ips?: unknown; blocked?: unknown }>>("/api/blocked");
        if (!resp.success) throw new Error(resp.message ?? "Failed to load blocked IPs");
        if (!blockedRequests.isCurrent(token)) return;
        const serverBlocked = extractBlockedIps(resp.data);
        blockedIps = mergeBlockedIps(serverBlocked, ipActionPending);
      } catch (e: unknown) {
        if (!blockedRequests.isCurrent(token)) return;
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
        else showErrorToast(e, "Failed to load blocked IPs");
      } finally {
        if (blockedRequests.isCurrent(token)) blockedReady = true;
      }
    }, options);
  }

  async function blockIp(ip: string) {
    if (!viewActive || !beginIpAction(ip, "block")) return;
    blockedRequests.invalidate();
    blockedIps = optimisticBlock(blockedIps, ip);
    try {
      const resp = await postJson<AdminResponse<unknown>, { ip: string }>("/api/block", { ip });
      if (!resp.success) throw new Error(resp.message ?? "Block failed");
      addToast(`Blocked ${ip}`, "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        blockedIps = optimisticUnblock(blockedIps, ip);
      }
    } finally {
      if (!viewActive) return;
      endIpAction(ip);
      void fetchBlocked({ invalidate: true });
    }
  }

  async function unblockIp(ip: string) {
    if (!viewActive || !beginIpAction(ip, "unblock")) return;
    blockedRequests.invalidate();
    blockedIps = optimisticUnblock(blockedIps, ip);
    try {
      const resp = await postJson<AdminResponse<unknown>, { ip: string }>("/api/unblock", { ip });
      if (!resp.success) throw new Error(resp.message ?? "Unblock failed");
      addToast(`Unblocked ${ip}`, "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else {
        blockedIps = optimisticBlock(blockedIps, ip);
      }
    } finally {
      if (!viewActive) return;
      endIpAction(ip);
      void fetchBlocked({ invalidate: true });
    }
  }

  function handleRefresh() {
    addToast("Refreshed", "info");
    serverPanelCleared = false;
    void fetchStatus({ invalidate: true });
    void fetchClients({ invalidate: true });
    void fetchMetrics({ invalidate: true });
    void fetchBlocked({ invalidate: true });
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
    void fetchStatus();
    void fetchClients();
    void fetchMetrics();
    void fetchBlocked();
    const statusTick = setInterval(() => { void fetchStatus(); }, 1200);
    const fast = setInterval(() => { void fetchClients(); void fetchBlocked(); }, 5000);
    const slow = setInterval(() => { void fetchMetrics(); }, 15000);
    return () => {
      viewActive = false;
      statusRequests.dispose();
      clientsRequests.dispose();
      metricsRequests.dispose();
      blockedRequests.dispose();
      clearInterval(statusTick);
      clearInterval(fast);
      clearInterval(slow);
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
    <section class="rounded-xl glass border border-edge/70 flex flex-col">
      <div class="pane-header border-b border-edge flex items-center justify-between">
        <div class="text-[11px] text-black font-semibold dashboard-heading-sans">IP Access Control</div>
      </div>
      <div class="pane-body p-3">
        {#if ipPanelInitialLoading}
          <div class="space-y-2">
            <Skeleton class="h-3 w-full" />
            <Skeleton class="h-3 w-full" />
            <Skeleton class="h-3 w-full" />
            <Skeleton class="h-3 w-full" />
            <Skeleton class="h-3 w-full" />
            <Skeleton class="h-3 w-3/4" />
          </div>
        {:else if connectedIps.length === 0 && blockedIps.length === 0}
          <div class="text-[12px] font-medium text-black text-center py-8 opacity-50 flex items-center justify-center gap-2">
            <Activity class="w-4 h-4" />
            No IP activity detected
          </div>
        {:else}
          <div class="grid grid-cols-2 gap-4">
            <!-- Connected IPs -->
            <div class="flex flex-col min-h-[60px] max-h-[320px]">
              <div class="text-[9px] uppercase tracking-[0.08em] font-semibold text-black/40 dashboard-heading-sans px-1 pb-1.5 shrink-0">Connected</div>
              <div class="flex flex-col gap-1.5 overflow-y-auto overflow-x-hidden ip-scroll-col flex-1">
                {#if connectedIps.length === 0}
                  <div class="text-[11px] text-black/40 text-center py-4">No active connections</div>
                {:else}
                  {#each connectedIps as ip (ip)}
                    <div
                      in:fly={{ y: -10, duration: 220, easing: cubicOut }}
                      out:scale={{ start: 0.97, duration: 120, opacity: 0 }}
                      class="glass-firewall-row rounded-[10px] w-full px-3 py-[7px] flex items-center justify-between gap-2 group"
                    >
                      <div class="flex items-center gap-2 min-w-0">
                        <div class="w-4 h-4 flex items-center justify-center shrink-0">
                          <div class="w-2 h-2 rounded-full bg-cyan-400 pulse-signal"></div>
                        </div>
                        <span class="text-[11.5px] font-semibold dashboard-heading-sans tracking-[0.01em] truncate text-black">{ip}</span>
                      </div>
                      <button
                        use:ripple={{ color: "dark" }}
                        onclick={() => blockIp(ip)}
                        disabled={ipActionPending[ip] === "block"}
                        class={cn(
                          "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
                          "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
                          "text-red-500/60 hover:text-red-500 hover:shadow-[0_0_12px_rgba(239,68,68,0.25)]",
                          ipActionPending[ip] === "block" && "opacity-40 cursor-not-allowed",
                        )}
                        aria-label="Block IP"
                      >
                        {#if ipActionPending[ip] === "block"}
                          <div class="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                        {:else}
                          <ShieldAlert class="w-[18px] h-[18px]" strokeWidth={2} />
                        {/if}
                      </button>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>
            <!-- Blocked IPs -->
            <div class="flex flex-col min-h-[60px] max-h-[320px]">
              <div class="text-[9px] uppercase tracking-[0.08em] font-semibold text-black/40 dashboard-heading-sans px-1 pb-1.5 shrink-0">Blocked</div>
              <div class="flex flex-col gap-1.5 overflow-y-auto overflow-x-hidden ip-scroll-col flex-1">
                {#if blockedIps.length === 0}
                  <div class="text-[11px] text-black/40 text-center py-4">No blocked IPs</div>
                {:else}
                  {#each blockedIps as ip (ip)}
                    <div
                      in:fly={{ y: -10, duration: 220, easing: cubicOut }}
                      out:scale={{ start: 0.97, duration: 120, opacity: 0 }}
                      class="glass-firewall-row rounded-[10px] w-full px-3 py-[7px] flex items-center justify-between gap-2 group"
                    >
                      <div class="flex items-center gap-2 min-w-0">
                        <div class="w-4 h-4 flex items-center justify-center shrink-0">
                          <Lock class="w-4 h-4 text-red-500/75" strokeWidth={2.5} />
                        </div>
                        <span
                          class="text-[11.5px] font-semibold dashboard-heading-sans tracking-[0.01em] truncate text-black/40"
                          style="text-decoration: line-through; text-decoration-color: rgba(0,0,0,0.35); text-decoration-thickness: 1.5px;"
                        >{ip}</span>
                      </div>
                      <button
                        use:ripple={{ color: "dark" }}
                        onclick={() => unblockIp(ip)}
                        disabled={ipActionPending[ip] === "unblock"}
                        class={cn(
                          "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
                          "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
                          "text-green-600/70 hover:text-green-600 hover:shadow-[0_0_12px_rgba(34,197,94,0.25)]",
                          ipActionPending[ip] === "unblock" && "opacity-40 cursor-not-allowed",
                        )}
                        aria-label="Unblock IP"
                      >
                        {#if ipActionPending[ip] === "unblock"}
                          <div class="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                        {:else}
                          <ShieldCheck class="w-[18px] h-[18px]" strokeWidth={2} />
                        {/if}
                      </button>
                    </div>
                  {/each}
                {/if}
              </div>
            </div>
          </div>
        {/if}
      </div>
    </section>
  </div>
</div>
