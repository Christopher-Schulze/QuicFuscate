<script lang="ts">
  import { onDestroy } from "svelte";
  import { fly, scale } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { ShieldAlert, ShieldCheck, Lock, Activity, Gauge, LogOut } from "@lucide/svelte";
  import { cn, ripple } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import { Dialog } from "bits-ui";
  import TextInput from "$lib/components/ui/TextInput.svelte";
  import { isBrowserDocumentVisible } from "@quicfuscate/time";
  import { getJson, postJson, ApiError, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import { mergeBlockedIps, optimisticBlock, optimisticUnblock } from "$lib/blocked-ips";
  import { createErrorToastHandler } from "$lib/error-toast";
  import { handleAuthError, getClients, setClients, setClientsLoading } from "$lib/stores/app.svelte";
  import { formatBytesHuman } from "$lib/format";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import type { PendingIpAction, ClientInfo, BandwidthStats } from "$lib/types";

  interface Props {
    onRefresh?: (fn: () => Promise<void>) => void;
  }

  let { onRefresh }: Props = $props();

  let blockedIps = $state<string[]>([]);
  let ipActionPending = $state<Record<string, PendingIpAction | undefined>>({});
  let kickPending = $state<Record<string, boolean | undefined>>({});
  let clientsReady = $state(false);
  let blockedReady = $state(false);
  let viewActive = true;
  const clientsRequests = createRequestCoordinator();
  const blockedRequests = createRequestCoordinator();
  const errorToast = createErrorToastHandler(() => viewActive);

  const clients = $derived(getClients());
  const blockedSet = $derived(new Set(blockedIps));
  const connectedClients = $derived(clients.filter((c) => !blockedSet.has(c.ip)));
  const ipPanelInitialLoading = $derived(!(clientsReady && blockedReady));

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
        if (!handleAuthError(e)) errorToast.show(e, "Failed to load clients");
      } finally {
        if (clientsRequests.isCurrent(token)) {
          setClientsLoading(false);
          clientsReady = true;
        }
      }
    }, options);
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
        if (!handleAuthError(e)) errorToast.show(e, "Failed to load blocked IPs");
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
      if (!handleAuthError(e)) {
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
      if (!handleAuthError(e)) {
        blockedIps = optimisticBlock(blockedIps, ip);
      }
    } finally {
      if (!viewActive) return;
      endIpAction(ip);
      void fetchBlocked({ invalidate: true });
    }
  }

  async function kickClient(client: ClientInfo) {
    if (!viewActive || kickPending[client.id]) return;
    kickPending = { ...kickPending, [client.id]: true };
    try {
      const resp = await postJson(
        `/api/clients/${encodeURIComponent(client.id)}/kick`,
        {},
        adminApiSchemas.kickClient,
      );
      if (!resp.success) throw new Error(resp.message ?? "Kick failed");
      addToast(`Disconnected ${client.ip}`, "success");
      void fetchClients({ invalidate: true });
    } catch (e: unknown) {
      if (!viewActive) return;
      if (!handleAuthError(e)) errorToast.show(e, "Failed to kick client");
    } finally {
      if (!viewActive) return;
      const next = { ...kickPending };
      delete next[client.id];
      kickPending = next;
    }
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
      } else if (handleAuthError(e)) {
        // auth error handled
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
      if (!handleAuthError(e)) bandwidthError = sanitizeErrorMessage(e instanceof Error ? e.message : String(e), "Failed to set bandwidth");
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
      if (!handleAuthError(e)) bandwidthError = sanitizeErrorMessage(e instanceof Error ? e.message : String(e), "Failed to reset quota");
    } finally {
      if (viewActive) bandwidthSaving = false;
    }
  }

  // Register refresh function with parent
  $effect(() => {
    onRefresh?.(async () => {
      await Promise.all([
        fetchClients({ invalidate: true }),
        fetchBlocked({ invalidate: true }),
      ]);
    });
  });

  // Polling + visibility
  $effect(() => {
    const handleVisibilityChange = (): void => {
      if (!isBrowserDocumentVisible()) {
        clientsRequests.invalidate();
        blockedRequests.invalidate();
        return;
      }
      void fetchClients({ invalidate: true });
      void fetchBlocked({ invalidate: true });
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    void fetchClients();
    void fetchBlocked();
    const fast = setInterval(() => {
      if (!isBrowserDocumentVisible()) return;
      void fetchClients();
      void fetchBlocked();
    }, 5000);
    return () => {
      viewActive = false;
      clientsRequests.dispose();
      blockedRequests.dispose();
      clearInterval(fast);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  });

  onDestroy(errorToast.destroy);
</script>

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
                      onclick={() => kickClient(client)}
                      disabled={kickPending[client.id] === true}
                      class={cn(
                        "w-8 h-8 rounded-[10px] flex items-center justify-center glass-pane-pill cursor-pointer overflow-hidden shrink-0",
                        "transition-all duration-200 ease-[cubic-bezier(0.22,1,0.36,1)]",
                        "text-orange-500/60 hover:text-orange-500 hover:shadow-[0_0_12px_rgba(249,115,22,0.25)]",
                        kickPending[client.id] === true && "opacity-40 cursor-not-allowed",
                      )}
                      aria-label="Disconnect client"
                      title="Disconnect"
                    >
                      {#if kickPending[client.id] === true}
                        <div class="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin"></div>
                      {:else}
                        <LogOut class="w-[16px] h-[16px]" strokeWidth={2} />
                      {/if}
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
