<script lang="ts">
  import { onDestroy } from "svelte";
  import { fly, scale } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { ShieldAlert, ShieldCheck, Lock, Activity, Gauge } from "@lucide/svelte";
  import { cn, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import { Dialog } from "bits-ui";
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import {
    evaluateByteRateSample,
    isBrowserDocumentVisible,
    readBrowserMonotonicMilliseconds,
    type ByteCounterSample,
  } from "@quicfuscate/time";
  import { useAnchorSync } from "$lib/use-anchor-sync";
  import Sparkline from "$lib/components/ui/Sparkline.svelte";
  import SmoothTrafficValue from "$lib/components/views/SmoothTrafficValue.svelte";
  import KpiCard from "$lib/components/views/KpiCard.svelte";
  import { getJson, getText, postJson, ApiError, isAuthError, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import { mergeBlockedIps, optimisticBlock, optimisticUnblock } from "$lib/blocked-ips";
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
  import { formatBitsPerSecond, formatUptime, formatMetricCount, formatMetricValue, formatBytesHuman } from "$lib/format";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import type { MetricsMap, PendingIpAction, ClientInfo, BandwidthStats } from "$lib/types";

  let blockedIps = $state<string[]>([]);
  let ipActionPending = $state<Record<string, PendingIpAction | undefined>>({});
  let statusReady = $state(false);
  let clientsReady = $state(false);
  let blockedReady = $state(false);
  let metricsReady = $state(false);
  let trafficBps = $state({ in: 0, out: 0 });
  let prevSample: ByteCounterSample | null = null;
  let serverPanelCleared = $state(false);
  let lastErrorMsg = "";
  let actionsEl: HTMLDivElement | undefined = $state();
  let viewActive = true;
  const statusRequests = createRequestCoordinator();
  const clientsRequests = createRequestCoordinator();
  const metricsRequests = createRequestCoordinator();
  const blockedRequests = createRequestCoordinator();
  const errorResetTimer = createOwnedTimeout();

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
    errorResetTimer.schedule(() => { if (lastErrorMsg === msg) lastErrorMsg = ""; }, 10000);
  }

  onDestroy(errorResetTimer.destroy);
  let metricsHistory = $state<{ bytesIn: number[]; bytesOut: number[]; clients: number[] }>(
    { bytesIn: [], bytesOut: [], clients: [] },
  );

  function resetTrafficSample(): void {
    prevSample = null;
    trafficBps = { in: 0, out: 0 };
    metricsHistory = { bytesIn: [], bytesOut: [], clients: [] };
  }

  const status = $derived(getStatus());
  const clients = $derived(getClients());
  const metrics = $derived(getMetrics());
  const metricMap = $derived(metrics ?? {});

  const blockedSet = $derived(new Set(blockedIps));
  const connectedClients = $derived(clients.filter((c) => !blockedSet.has(c.ip)));
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
        const resp = await getJson("/api/clients", adminApiSchemas.clients);
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
        const resp = await getJson("/api/metrics/json", adminApiSchemas.metrics);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load metrics");
        if (!metricsRequests.isCurrent(token)) return;
        setMetrics(Object.keys(resp.data.metrics).length > 0 ? resp.data.metrics : null);
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
        const resp = await getJson("/api/blocked", adminApiSchemas.blockedIps);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load blocked IPs");
        if (!blockedRequests.isCurrent(token)) return;
        blockedIps = mergeBlockedIps(resp.data.ips, ipActionPending);
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
      const resp = await postJson("/api/block", { ip }, adminApiSchemas.blockIp);
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
      const resp = await postJson("/api/unblock", { ip }, adminApiSchemas.unblockIp);
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

  // --- Per-client bandwidth dialog ---
  let bandwidthDialogOpen = $state(false);
  let bandwidthClientId = $state<string | null>(null);
  let bandwidthClientIp = $state<string>("");
  let bandwidthStats = $state<BandwidthStats | null>(null);
  let bandwidthLoading = $state(false);
  let bandwidthSaving = $state(false);
  let bandwidthError = $state("");
  // Editable policy fields
  let editRate = $state("");
  let editBurst = $state("");
  let editDailyQuota = $state("");
  let editMonthlyQuota = $state("");
  let editWeight = $state("1");

  function resetBandwidthForm() {
    bandwidthStats = null;
    bandwidthLoading = false;
    bandwidthSaving = false;
    bandwidthError = "";
    editRate = "";
    editBurst = "";
    editDailyQuota = "";
    editMonthlyQuota = "";
    editWeight = "1";
  }

  function openBandwidthDialog(client: ClientInfo) {
    bandwidthClientId = client.id;
    bandwidthClientIp = client.ip;
    resetBandwidthForm();
    bandwidthDialogOpen = true;
    void fetchBandwidth(client.id);
  }

  async function fetchBandwidth(clientId: string) {
    if (!viewActive) return;
    bandwidthLoading = true;
    bandwidthError = "";
    try {
      const resp = await getJson(`/api/clients/${encodeURIComponent(clientId)}/bandwidth`, adminApiSchemas.clientBandwidth);
      if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load bandwidth");
      if (!viewActive) return;
      bandwidthStats = resp.data.bandwidth;
      const p = resp.data.bandwidth.policy;
      editRate = String(p.rate_bytes_per_second);
      editBurst = String(p.burst_bytes);
      editDailyQuota = String(p.daily_quota_bytes);
      editMonthlyQuota = String(p.monthly_quota_bytes);
      editWeight = String(p.weight);
    } catch (e: unknown) {
      if (!viewActive) return;
      if (e instanceof ApiError && e.status === 404) {
        bandwidthError = "Bandwidth policy not configured for this client.";
      } else if (isAuthError(e)) {
        setAuthError(null);
        setAuthRequired(true);
      } else {
        bandwidthError = sanitizeErrorMessage(e instanceof Error ? e.message : String(e), "Failed to load bandwidth");
      }
    } finally {
      if (viewActive) bandwidthLoading = false;
    }
  }

  async function saveBandwidth() {
    if (!viewActive || !bandwidthClientId || bandwidthSaving) return;
    const rate = parseInt(editRate, 10);
    const burst = parseInt(editBurst, 10);
    const dailyQuota = parseInt(editDailyQuota, 10);
    const monthlyQuota = parseInt(editMonthlyQuota, 10);
    const weight = parseInt(editWeight, 10);
    if (!Number.isFinite(rate) || rate < 0 || !Number.isFinite(burst) || burst < 0
      || !Number.isFinite(dailyQuota) || dailyQuota < 0 || !Number.isFinite(monthlyQuota) || monthlyQuota < 0
      || !Number.isFinite(weight) || weight < 1) {
      bandwidthError = "All fields must be non-negative integers (weight >= 1).";
      return;
    }
    bandwidthSaving = true;
    bandwidthError = "";
    try {
      const resp = await postJson(
        `/api/clients/${encodeURIComponent(bandwidthClientId)}/bandwidth`,
        { rate_bytes_per_second: rate, burst_bytes: burst, daily_quota_bytes: dailyQuota, monthly_quota_bytes: monthlyQuota, weight },
        adminApiSchemas.setClientBandwidth,
      );
      if (!resp.success) throw new Error(resp.message ?? "Failed to set bandwidth");
      if (!viewActive) return;
      addToast("Bandwidth updated", "success");
      void fetchBandwidth(bandwidthClientId);
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else bandwidthError = sanitizeErrorMessage(e instanceof Error ? e.message : String(e), "Failed to set bandwidth");
    } finally {
      if (viewActive) bandwidthSaving = false;
    }
  }

  async function resetClientQuota() {
    if (!viewActive || !bandwidthClientId || bandwidthSaving) return;
    bandwidthSaving = true;
    bandwidthError = "";
    try {
      const resp = await postJson(
        `/api/clients/${encodeURIComponent(bandwidthClientId)}/quota/reset`,
        {},
        adminApiSchemas.resetClientQuota,
      );
      if (!resp.success) throw new Error(resp.message ?? "Failed to reset quota");
      if (!viewActive) return;
      addToast("Quota reset", "success");
      void fetchBandwidth(bandwidthClientId);
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else bandwidthError = sanitizeErrorMessage(e instanceof Error ? e.message : String(e), "Failed to reset quota");
    } finally {
      if (viewActive) bandwidthSaving = false;
    }
  }

  // Polling
  $effect(() => {
    const handleVisibilityChange = (): void => {
      resetTrafficSample();
      if (!isBrowserDocumentVisible()) {
        statusRequests.invalidate();
        clientsRequests.invalidate();
        metricsRequests.invalidate();
        blockedRequests.invalidate();
        return;
      }
      void fetchStatus({ invalidate: true });
      void fetchClients({ invalidate: true });
      void fetchMetrics({ invalidate: true });
      void fetchBlocked({ invalidate: true });
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    void fetchStatus();
    void fetchClients();
    void fetchMetrics();
    void fetchBlocked();
    const statusTick = setInterval(() => { if (isBrowserDocumentVisible()) void fetchStatus(); }, 1200);
    const fast = setInterval(() => {
      if (!isBrowserDocumentVisible()) return;
      void fetchClients();
      void fetchBlocked();
    }, 5000);
    const slow = setInterval(() => { if (isBrowserDocumentVisible()) void fetchMetrics(); }, 15000);
    return () => {
      viewActive = false;
      statusRequests.dispose();
      clientsRequests.dispose();
      metricsRequests.dispose();
      blockedRequests.dispose();
      clearInterval(statusTick);
      clearInterval(fast);
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
        {:else if connectedClients.length === 0 && blockedIps.length === 0}
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
                {#if connectedClients.length === 0}
                  <div class="text-[11px] text-black/40 text-center py-4">No active connections</div>
                {:else}
                  {#each connectedClients as client (client.id)}
                    <div
                      in:fly={{ y: -10, duration: 220, easing: cubicOut }}
                      out:scale={{ start: 0.97, duration: 120, opacity: 0 }}
                      class="glass-firewall-row rounded-[10px] w-full px-3 py-[7px] flex items-center justify-between gap-2 group"
                    >
                      <div class="flex items-center gap-2 min-w-0">
                        <div class="w-4 h-4 flex items-center justify-center shrink-0">
                          <div class="w-2 h-2 rounded-full bg-cyan-400 pulse-signal"></div>
                        </div>
                        <span class="text-[11.5px] font-semibold dashboard-heading-sans tracking-[0.01em] truncate text-black">{client.ip}</span>
                      </div>
                      <div class="flex items-center gap-1 shrink-0">
                        <button
                          use:ripple={{ color: "dark" }}
                          onclick={() => openBandwidthDialog(client)}
                          class={cn(
                            "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
                            "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
                            "text-accent/60 hover:text-accent hover:shadow-[0_0_12px_rgba(124,58,237,0.20)]",
                            bandwidthClientId === client.id && "opacity-40 cursor-not-allowed",
                          )}
                          aria-label="Bandwidth settings"
                          title="Bandwidth & Quota"
                        >
                          <Gauge class="w-[16px] h-[16px]" strokeWidth={2} />
                        </button>
                        <button
                          use:ripple={{ color: "dark" }}
                          onclick={() => blockIp(client.ip)}
                          disabled={ipActionPending[client.ip] === "block"}
                          class={cn(
                            "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
                            "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
                            "text-red-500/60 hover:text-red-500 hover:shadow-[0_0_12px_rgba(239,68,68,0.25)]",
                            ipActionPending[client.ip] === "block" && "opacity-40 cursor-not-allowed",
                          )}
                          aria-label="Block IP"
                        >
                          {#if ipActionPending[client.ip] === "block"}
                            <div class="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                          {:else}
                            <ShieldAlert class="w-[18px] h-[18px]" strokeWidth={2} />
                          {/if}
                        </button>
                      </div>
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

<!-- Bandwidth & Quota Dialog -->
<Dialog.Root bind:open={bandwidthDialogOpen}>
  <Dialog.Portal to="#qf-app-stage">
    <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" style="backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);" />
    <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[360px] animate-in fade-in-0 zoom-in-95 duration-200">
      <div class="dialog-header-pad">
        <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Bandwidth &amp; Quota</Dialog.Title>
      </div>
      <div class="dialog-body-pad space-y-3">
        <div class="text-[10px] font-semibold uppercase tracking-[0.12em] text-black/55">{bandwidthClientIp}</div>
        {#if bandwidthLoading}
          <div class="flex items-center justify-center py-6">
            <div class="h-4 w-4 border-2 border-accent border-t-transparent rounded-full animate-spin"></div>
          </div>
        {:else if bandwidthError}
          <div class="text-[11px] text-red-500 leading-relaxed">{bandwidthError}</div>
        {:else if bandwidthStats}
          <!-- Current usage -->
          <div class="rounded-lg border border-edge/70 bg-white/70 px-3 py-2.5 space-y-1.5 text-[10.5px]">
            <div class="flex justify-between">
              <span class="text-black/60">Daily used</span>
              <span class="font-semibold text-black">{formatBytesHuman(bandwidthStats.daily_used_bytes)} / {formatBytesHuman(bandwidthStats.daily_used_bytes + bandwidthStats.daily_remaining_bytes)}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-black/60">Monthly used</span>
              <span class="font-semibold text-black">{formatBytesHuman(bandwidthStats.monthly_used_bytes)} / {formatBytesHuman(bandwidthStats.monthly_used_bytes + bandwidthStats.monthly_remaining_bytes)}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-black/60">Uplink avail.</span>
              <span class="font-semibold text-black">{formatBytesHuman(bandwidthStats.uplink_available_bytes)}</span>
            </div>
            <div class="flex justify-between">
              <span class="text-black/60">Downlink avail.</span>
              <span class="font-semibold text-black">{formatBytesHuman(bandwidthStats.downlink_available_bytes)}</span>
            </div>
          </div>
          <!-- Editable policy -->
          <div class="space-y-2.5">
            <TextInput label="Rate (bytes/s)" value={editRate} onchange={(v) => editRate = v} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
            <TextInput label="Burst (bytes)" value={editBurst} onchange={(v) => editBurst = v} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
            <TextInput label="Daily quota (bytes)" value={editDailyQuota} onchange={(v) => editDailyQuota = v} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
            <TextInput label="Monthly quota (bytes)" value={editMonthlyQuota} onchange={(v) => editMonthlyQuota = v} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
            <TextInput label="Weight (>=1)" value={editWeight} onchange={(v) => editWeight = v} labelClassName="text-[11px] font-semibold text-black dashboard-heading-sans" />
          </div>
        {:else}
          <div class="text-[11px] text-black/50 text-center py-4">No bandwidth data</div>
        {/if}
      </div>
      <div class="dialog-footer-pad">
        <button
          type="button"
          use:ripple={{ color: "light" }}
          class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1"
          onclick={() => { bandwidthDialogOpen = false; }}
        >Close</button>
        {#if bandwidthStats && !bandwidthError}
          <button
            type="button"
            use:ripple={{ color: "light" }}
            class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-neutral-btn flex-1"
            onclick={() => { void resetClientQuota(); }}
            disabled={bandwidthSaving}
          >Reset Quota</button>
          <button
            type="button"
            use:ripple={{ color: "light" }}
            class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-save-btn flex-1 min-w-[100px] justify-center"
            onclick={() => { void saveBandwidth(); }}
            disabled={bandwidthSaving}
          >
            {#if bandwidthSaving}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
            Save
          </button>
        {/if}
      </div>
    </Dialog.Content>
  </Dialog.Portal>
</Dialog.Root>
