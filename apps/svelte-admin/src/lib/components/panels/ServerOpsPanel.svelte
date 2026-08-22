<script lang="ts">
  import { onDestroy } from "svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { RefreshCw, Power, Activity } from "@lucide/svelte";
  import { cn, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { addToast } from "@quicfuscate/ui";
  import { isBrowserDocumentVisible } from "@quicfuscate/time";
  import { ApiError, isAuthError, getJson, postJson, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import { setAuthRequired, setAuthError, confirmDialog } from "$lib/stores/app.svelte";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import { formatDurationMs } from "$lib/format";
  import type { DrainStatusData } from "$lib/types";

  let busyReload = $state(false);
  let busyDrain = $state(false);
  let busyShutdown = $state(false);
  let drainStatus = $state<DrainStatusData | null>(null);
  let drainStatusReady = $state(false);
  let viewActive = true;
  let lastErrorMsg = "";
  const drainRequests = createRequestCoordinator();
  const errorResetTimer = createOwnedTimeout();
  const dialogActionDelay = createOwnedTimeout();

  function showErrorToast(e: unknown, fallback: string) {
    if (!viewActive) return;
    const msg = sanitizeErrorMessage(
      e instanceof Error ? e.message : String(e),
      fallback,
    );
    if (msg === lastErrorMsg) return;
    lastErrorMsg = msg;
    addToast(msg, "error");
    errorResetTimer.schedule(() => { if (lastErrorMsg === msg) lastErrorMsg = ""; }, 10000);
  }

  function fetchDrainStatus(options: RequestOptions = {}): Promise<void> {
    return drainRequests.request(async (token: RequestToken) => {
      try {
        const resp = await getJson("/api/drain/status", adminApiSchemas.drainStatus);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load drain status");
        if (!drainRequests.isCurrent(token)) return;
        drainStatus = resp.data;
      } catch (e: unknown) {
        if (!drainRequests.isCurrent(token)) return;
        if (e instanceof ApiError && e.status === 404) {
          drainStatus = null;
          return;
        }
        if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
        else showErrorToast(e, "Failed to load drain status");
      } finally {
        if (drainRequests.isCurrent(token)) drainStatusReady = true;
      }
    }, options);
  }

  async function handleReload() {
    if (!viewActive || busyReload) return;
    busyReload = true;
    try {
      const resp = await postJson("/api/reload", {}, adminApiSchemas.serverReload);
      if (!resp.success) throw new Error(resp.message ?? "Reload failed");
      if (!viewActive) return;
      addToast("Server reloaded", "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else showErrorToast(e, "Reload failed");
    } finally {
      if (viewActive) busyReload = false;
    }
  }

  async function handleDrain() {
    if (!viewActive || busyDrain) return;
    const accepted = await confirmDialog({
      title: "Drain Server",
      message: "Stop accepting new connections and let existing sessions finish. The server will reject new clients until it is restarted.",
      confirmLabel: "Drain",
      cancelLabel: "Cancel",
    });
    if (!accepted || !viewActive) return;
    busyDrain = true;
    try {
      const resp = await postJson("/api/drain", {}, adminApiSchemas.serverDrain);
      if (!resp.success) throw new Error(resp.message ?? "Drain failed");
      if (!viewActive) return;
      addToast("Drain scheduled", "success");
      void fetchDrainStatus({ invalidate: true });
    } catch (e: unknown) {
      if (!viewActive) return;
      if (e instanceof ApiError && e.status === 404) {
        addToast("Drain is not enabled on this server", "warning");
        return;
      }
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else showErrorToast(e, "Drain failed");
    } finally {
      if (viewActive) busyDrain = false;
    }
  }

  async function handleShutdown() {
    if (!viewActive || busyShutdown) return;
    const accepted = await confirmDialog({
      title: "Shutdown Server",
      message: "Schedule a full server shutdown. All connections will be terminated and the server process will exit.",
      confirmLabel: "Shutdown",
      cancelLabel: "Cancel",
    });
    if (!accepted || !viewActive) return;
    busyShutdown = true;
    try {
      const resp = await postJson("/api/shutdown", {}, adminApiSchemas.serverShutdown);
      if (!resp.success) throw new Error(resp.message ?? "Shutdown failed");
      if (!viewActive) return;
      addToast("Shutdown scheduled", "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (e instanceof ApiError && e.status === 404) {
        addToast("Shutdown is not enabled on this server", "warning");
        return;
      }
      if (isAuthError(e)) { setAuthError(null); setAuthRequired(true); }
      else showErrorToast(e, "Shutdown failed");
    } finally {
      if (viewActive) busyShutdown = false;
    }
  }

  const isDraining = $derived(drainStatus?.state === "draining");

  $effect(() => {
    void fetchDrainStatus();
    const interval = setInterval(() => {
      if (isBrowserDocumentVisible()) void fetchDrainStatus();
    }, 5000);
    return () => {
      viewActive = false;
      drainRequests.dispose();
      clearInterval(interval);
    };
  });

  onDestroy(() => {
    errorResetTimer.destroy();
    dialogActionDelay.destroy();
  });
</script>

<section class="rounded-xl glass">
  <div class="pane-header border-b border-edge">
    <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Server Operations</div>
  </div>
  <div class="pane-body pane-first-item-offset space-y-3">
    {#if drainStatusReady && drainStatus}
      <div
        in:fly={{ y: -6, duration: 240, easing: cubicOut }}
        out:fly={{ y: -6, duration: 200, easing: cubicOut }}
        class="flex items-center gap-2 text-[11px]"
      >
        <Activity class={cn("h-3.5 w-3.5 shrink-0", isDraining ? "text-amber-500" : "text-emerald-500")} strokeWidth={2} />
        <span class="text-black/70 dashboard-heading-sans">
          {isDraining
            ? `Draining ${formatDurationMs(drainStatus.drain_elapsed_ms)} ${String.fromCharCode(183)} ${drainStatus.active_connections} active`
            : `Running ${String.fromCharCode(183)} ${drainStatus.active_connections} active`}
        </span>
      </div>
    {/if}
    <div class="inline-flex items-center gap-2 whitespace-nowrap">
      <button
        type="button"
        use:ripple={{ color: "light" }}
        onclick={() => { void handleReload(); }}
        disabled={busyReload}
        class={cn(
          "action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
          busyReload ? "cursor-wait" : "cursor-pointer",
        )}
      >
        {#if busyReload}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{:else}<RefreshCw class="h-3 w-3" strokeWidth={2.5} />{/if}
        Reload
      </button>
      <button
        type="button"
        use:ripple={{ color: "light" }}
        onclick={() => { void handleDrain(); }}
        disabled={busyDrain || isDraining}
        class={cn(
          "action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
          (busyDrain || isDraining) ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
        )}
      >
        {#if busyDrain}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{:else}<Activity class="h-3 w-3" strokeWidth={2.5} />{/if}
        {isDraining ? "Draining" : "Drain"}
      </button>
      <button
        type="button"
        use:ripple={{ color: "light" }}
        onclick={() => { void handleShutdown(); }}
        disabled={busyShutdown}
        class={cn(
          "action-btn-base action-revoke-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
          busyShutdown ? "cursor-wait" : "cursor-pointer",
        )}
      >
        {#if busyShutdown}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{:else}<Power class="h-3 w-3" strokeWidth={2.5} />{/if}
        Shutdown
      </button>
    </div>
  </div>
</section>
