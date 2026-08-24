<script lang="ts">
  import { Dialog } from "bits-ui";
  import { onDestroy, untrack } from "svelte";
  import { fly } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import { Shield, ShieldCheck, AlertTriangle, Eye, EyeOff, Check, RotateCw } from "@lucide/svelte";
  import { cn, createCopyFeedback, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import { Skeleton, addToast } from "@quicfuscate/ui";
  import { useAnchorSync } from "$lib/use-anchor-sync";
  import { formatTimestamp, formatTimestampIso } from "$lib/format";
  import { isBrowserDocumentVisible } from "@quicfuscate/time";
  import { ApiError, getJson, postJson } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import {
    handleAuthError,
    setLogsDirty,
    confirmDialog,
  } from "$lib/stores/app.svelte";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import { createErrorToastHandler } from "$lib/error-toast";
  import type { LogEntry, LogMode } from "$lib/types";

  const MODE_DESCRIPTIONS: Record<LogMode, { title: string; desc: string; icon: typeof Eye; color: string }> = {
    verbose: { title: "Verbose", desc: "Full debug logging with all metadata. Best for development and troubleshooting.", icon: Eye, color: "text-amber-600" },
    normal: { title: "Normal", desc: "Info-level logging. Standard operation mode with reasonable detail.", icon: Eye, color: "text-text-secondary" },
    minimal: { title: "Minimal", desc: "Warnings and errors only. Client metadata [IPs, session IDs] stripped from entries.", icon: EyeOff, color: "text-text-tertiary" },
    "no-log": { title: "No-Log", desc: "Strict zero-log privacy mode.", icon: ShieldCheck, color: "text-emerald-600" },
  };

  const NO_LOG_FEATURES = [
    { label: "In-Memory Buffer", desc: "Server log buffer is a capped ring in RAM. No log files are written by the app." },
    { label: "Logs Endpoint Empty", desc: "Admin logs API returns an empty result and resets the cursor." },
    { label: "Buffer Cleared", desc: "Switching to No-Log clears the in-memory ring buffer immediately." },
    { label: "App Logging Disabled", desc: "Application logging is set to Off [best-effort]. It does not guarantee OS-level suppression." },
  ];

  const MAX_PERSIST_ATTEMPTS = 2;

  let mode = $state<LogMode>("normal");
  let savedMode = $state<LogMode>("normal");
  let modeSelectionVersion = $state(0);
  let logs = $state<LogEntry[]>([]);
  let saving = $state(false);
  let loadingLogs = $state(true);
  let logsReady = $state(false);
  let backendOnline = $state(false);
  let cursor = $state(0);
  let viewActive = true;
  const modeRequests = createRequestCoordinator();
  const logsRequests = createRequestCoordinator();
  const statusRequests = createRequestCoordinator();
  let clearDialogOpen = $state(false);
  let modeLabels: Record<string, HTMLElement | undefined> = $state({});
  let modeContainer: HTMLDivElement | undefined = $state();

  const modePillStyle = $derived.by(() => {
    const lbl = modeLabels[mode];
    const container = modeContainer;
    if (!lbl || !container) return "opacity: 0;";
    const containerRect = container.getBoundingClientRect();
    const lblRect = lbl.getBoundingClientRect();
    const top = lblRect.top - containerRect.top;
    const height = lblRect.height;
    return `top: ${top}px; height: ${height}px; opacity: 1;`;
  });
  const copyFb = createCopyFeedback(1100);
  let bottomEl: HTMLDivElement | undefined = $state();
  let actionsEl: HTMLDivElement | undefined = $state();
  const errorToast = createErrorToastHandler(() => viewActive);
  const dialogActionDelay = createOwnedTimeout();

  $effect(() => useAnchorSync(actionsEl));

  onDestroy(() => {
    errorToast.destroy();
    dialogActionDelay.destroy();
  });

  const entryCountLabel = $derived(logs.length === 1 ? "1 entry" : `${logs.length} entries`);
  const isDirty = $derived(mode !== savedMode);

  $effect(() => { setLogsDirty(isDirty); });
  $effect(() => { return () => setLogsDirty(false); });
  $effect(() => { bottomEl?.scrollIntoView({ behavior: "smooth" }); });

  function fetchMode(options: RequestOptions = {}): Promise<LogMode> {
    let nextMode = savedMode;
    const selectionVersionAtStart = modeSelectionVersion;
    return modeRequests.request(async (token: RequestToken) => {
      try {
        const resp = await getJson("/api/config/logging", adminApiSchemas.loggingRead);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load logging mode");
        if (!modeRequests.isCurrent(token)) return;
        const next = resp.data.mode;
        if (selectionVersionAtStart === modeSelectionVersion) mode = next;
        savedMode = next;
        nextMode = next;
      } catch (e: unknown) {
        if (!modeRequests.isCurrent(token)) return;
        if (!handleAuthError(e)) errorToast.show(e, "Failed to load logging mode");
      }
    }, options).then(() => nextMode);
  }

  function fetchLogsOnce(modeOverride?: LogMode, reset = false, options: RequestOptions = {}): Promise<void> {
    return logsRequests.request(async (token: RequestToken) => {
      const effectiveMode = modeOverride ?? mode;
      const requestCursor = reset ? 0 : cursor;
      if (effectiveMode === "no-log") {
        if (!logsRequests.isCurrent(token)) return;
        cursor = 0;
        logs = [];
        loadingLogs = false;
        logsReady = true;
        return;
      }
      try {
        const resp = await getJson(`/api/logs?cursor=${requestCursor}`, adminApiSchemas.logs);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "Failed to load logs");
        const next = resp.data;
        if (!logsRequests.isCurrent(token)) return;
        if (next.lines.length) {
          cursor = next.cursor;
          if (reset) {
            logs = next.lines.length > 500 ? next.lines.slice(-500) : next.lines;
          } else {
            const merged = [...logs, ...next.lines];
            logs = merged.length > 500 ? merged.slice(-500) : merged;
          }
        } else if (next.cursor >= 0) {
          cursor = next.cursor;
          if (reset) logs = [];
        }
      } catch (e: unknown) {
        if (!logsRequests.isCurrent(token)) return;
        if (!handleAuthError(e)) errorToast.show(e, "Failed to load logs");
      } finally {
        if (logsRequests.isCurrent(token)) {
          loadingLogs = false;
          logsReady = true;
        }
      }
    }, options);
  }

  function fetchOnlineStatus(options: RequestOptions = {}): Promise<void> {
    return statusRequests.request(async (token: RequestToken) => {
      try {
        const resp = await getJson("/api/status", adminApiSchemas.status);
        if (!statusRequests.isCurrent(token)) return;
        backendOnline = Boolean(resp?.success && resp?.data);
      } catch (e: unknown) {
        if (!statusRequests.isCurrent(token)) return;
        if (!handleAuthError(e)) errorToast.show(e, "Failed to check server status");
        backendOnline = false;
      }
    }, options);
  }

  async function refreshAll() {
    if (!viewActive) return;
    loadingLogs = true;
    const latestMode = await fetchMode({ invalidate: true });
    if (!viewActive) return;
    await Promise.allSettled([
      fetchOnlineStatus({ invalidate: true }),
      fetchLogsOnce(latestMode, true, { invalidate: true }),
    ]);
  }

  async function handleRefresh() {
    if (isDirty) {
      const discard = await confirmDialog({
        title: "Unsaved Changes",
        message: "You have unsaved logging changes. Refresh and discard them?",
        confirmLabel: "Discard",
        cancelLabel: "Cancel",
      });
      if (!discard) return;
    }
    if (!viewActive) return;
    addToast("Refreshed", "info");
    void refreshAll();
  }

  async function applyMode(newMode: LogMode) {
    if (!viewActive) return;
    modeRequests.invalidate();
    logsRequests.invalidate();
    modeSelectionVersion += 1;
    saving = true;
    try {
      for (let attempt = 1; attempt <= MAX_PERSIST_ATTEMPTS; attempt++) {
        try {
          const resp = await postJson("/api/config/logging", { mode: newMode }, adminApiSchemas.loggingWrite);
          if (!resp.success) throw new Error(resp.message ?? "Failed to save logging mode");
          const verify = await getJson("/api/config/logging", adminApiSchemas.loggingRead);
          if (verify.data?.mode !== newMode) throw new Error("Failed to verify logging mode");
          break;
        } catch (e) {
          if (attempt >= MAX_PERSIST_ATTEMPTS) throw e;
          if (e instanceof ApiError && e.status != null && e.status < 500) throw e;
        }
      }
      if (!viewActive) return;
      mode = newMode;
      savedMode = newMode;
      addToast("Changes saved", "success");
      void fetchLogsOnce(newMode, true, { invalidate: true });
    } catch (e: unknown) {
      if (!viewActive) return;
      if (!handleAuthError(e)) { addToast("Failed to save logging mode", "error"); }
    } finally {
      if (viewActive) saving = false;
    }
  }

  function selectMode(nextMode: LogMode) {
    modeSelectionVersion += 1;
    modeRequests.invalidate();
    logsRequests.invalidate();
    mode = nextMode;
  }

  async function confirmClearLogs() {
    if (!viewActive) return;
    const previousLogs = logs;
    logsRequests.invalidate();
    clearDialogOpen = false;
    cursor = 0;
    logs = [];
    try {
      const resp = await postJson("/api/logs/clear", {}, adminApiSchemas.logsClear);
      if (!resp.success) throw new Error(resp.message ?? "Failed to clear logs");
      if (!viewActive) return;
      await fetchLogsOnce(mode, true, { invalidate: true });
    } catch (e: unknown) {
      if (!viewActive) return;
      if (handleAuthError(e)) return;
      logs = previousLogs;
      addToast("Failed to clear logs", "error");
    }
  }

  async function handleCopyAll() {
    if (logs.length === 0) return;
    const text = logs.map(l => `[${formatTimestampIso(l.ts)}] [${l.level.toUpperCase()}] ${l.msg}`).join("\n");
    await copyFb.trigger(text);
  }

  let busyRotate = $state(false);

  async function handleRotateLogs() {
    if (!viewActive || busyRotate) return;
    busyRotate = true;
    try {
      const resp = await postJson("/api/logs/rotate", {}, adminApiSchemas.logsRotate);
      if (!resp.success) throw new Error(resp.message ?? "Log rotation failed");
      if (!viewActive) return;
      addToast("Log rotation triggered", "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (!handleAuthError(e)) errorToast.show(e, "Log rotation failed");
    } finally {
      if (viewActive) busyRotate = false;
    }
  }

  $effect(() => {
    const handleVisibilityChange = (): void => {
      if (!isBrowserDocumentVisible()) {
        modeRequests.invalidate();
        logsRequests.invalidate();
        statusRequests.invalidate();
        return;
      }
      void fetchMode({ invalidate: true }).then((latestMode) => {
        if (viewActive && isBrowserDocumentVisible()) {
          void fetchLogsOnce(latestMode, false, { invalidate: true });
        }
      });
      void fetchOnlineStatus({ invalidate: true });
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    untrack(() => {
      void fetchMode();
      void fetchOnlineStatus();
      void fetchLogsOnce();
    });
    const logPoll = window.setInterval(() => {
      if (isBrowserDocumentVisible()) void fetchLogsOnce();
    }, 1200);
    const statusPoll = window.setInterval(() => {
      if (isBrowserDocumentVisible()) void fetchOnlineStatus();
    }, 5000);
    return () => {
      viewActive = false;
      modeRequests.dispose();
      statusRequests.dispose();
      logsRequests.dispose();
      window.clearInterval(logPoll);
      window.clearInterval(statusPoll);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  });
</script>

<div class="flex flex-1 min-h-0 overflow-hidden dashboard-heading-sans">
  <div class="w-full h-full min-h-0 px-6 pt-6 pb-0 flex flex-col gap-5">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="text-[14px] font-bold text-text-primary">Logs</div>
      <div bind:this={actionsEl} class="flex items-center gap-2.5">
        <button
          use:ripple={{ color: "dark", disabled: saving || !isDirty }}
          type="button"
          disabled={saving || !isDirty}
          onclick={() => { void applyMode(mode); }}
          class={cn(
            "action-btn-base action-save-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
            (saving || !isDirty) ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
          )}
        >
          {#if saving}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{/if}
          Save
        </button>
        <button
          use:ripple={{ color: "dark" }}
          type="button"
          onclick={() => { void handleRefresh(); }}
          class="action-btn-base action-refresh-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5 cursor-pointer"
        >Refresh</button>
        <div
          class={cn(
            "status-chip dashboard-heading-sans",
            backendOnline ? "border-positive/35 text-positive" : "border-negative/35 text-negative",
          )}
        >
          <span class={cn("h-2 w-2 rounded-full", backendOnline ? "bg-positive shadow-[0_0_10px_rgba(22,163,74,0.55)]" : "bg-negative shadow-[0_0_10px_rgba(220,38,38,0.55)]")}></span>
          {backendOnline ? "Online" : "Offline"}
        </div>
      </div>
    </div>

    <!-- Logging Mode -->
    <section class="rounded-xl glass border border-edge/70">
      <div class="pane-header border-b border-edge">
        <div class="text-[11px] text-black font-semibold dashboard-heading-sans">Logging Mode</div>
      </div>
      <div class="pane-body pane-first-item-offset space-y-1.5">
        <div bind:this={modeContainer} role="radiogroup" aria-label="Logging mode selection" class="relative">
          <!-- Sliding glass pill indicator -->
          <div
            class="absolute left-0 right-0 rounded-lg pointer-events-none z-0"
            style="
              transition: top 340ms cubic-bezier(0.22, 1.36, 0.38, 1), height 240ms cubic-bezier(0.22, 1.36, 0.38, 1), opacity 200ms;
              background: rgba(255,255,255,0.65);
              backdrop-filter: blur(24px) saturate(200%);
              -webkit-backdrop-filter: blur(24px) saturate(200%);
              border: 1px solid rgba(255,255,255,0.60);
              box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
              will-change: top, opacity;
              transform: translateZ(0);
              {modePillStyle}
            "
          ></div>
          {#each (["verbose", "normal", "minimal", "no-log"] as LogMode[]) as m (m)}
            {@const info = MODE_DESCRIPTIONS[m]}
            {@const isSelected = mode === m}
            <button
              bind:this={modeLabels[m]}
              type="button"
              role="radio"
              aria-checked={isSelected}
              aria-label={info.title}
              data-testid={`log-mode-${m}`}
              class="block w-full cursor-pointer text-left"
              onfocus={() => selectMode(m)}
              onclick={() => selectMode(m)}
            >
              <div
                class={cn(
                  "relative w-full flex items-center gap-3 px-4 py-3 rounded-lg text-left cursor-pointer border select-none",
                  isSelected ? "border-edge/70" : "border-transparent transition-colors",
                )}
              >
                <info.icon class={cn("relative z-10 h-4 w-4 shrink-0", isSelected ? info.color : "text-text-ghost")} strokeWidth={2} />
                <div class="relative z-10 flex-1 min-w-0">
                  <div class={cn("text-[12px] font-medium dashboard-heading-sans", isSelected ? "text-text-primary" : "text-text-secondary")}>{info.title}</div>
                  <div class="text-[10px] text-text-tertiary leading-snug">{info.desc}</div>
                </div>
              </div>
            </button>
          {/each}
        </div>
      </div>
    </section>

    {#if mode === "no-log"}
      <div in:fly={{ y: 8, duration: 240, easing: cubicOut }} out:fly={{ y: -8, duration: 240, easing: cubicOut }} class="space-y-5">
        <section class="rounded-xl glass border border-edge/70">
          <div class="px-5 pt-4 pb-4 flex items-start gap-3.5">
            <div class="mt-0.5 p-2 rounded-lg bg-emerald-500/10 shrink-0">
              <Shield class="h-5 w-5 text-emerald-600" strokeWidth={2} />
            </div>
            <div class="flex-1 min-w-0 space-y-3">
              <div class="text-[13px] font-semibold text-text-primary">Zero-Log Privacy Mode</div>
              <div class="text-[11px] text-text-secondary leading-relaxed">
                When enabled, the admin logs endpoint is disabled and the in-memory log buffer is cleared.
                The server also sets application logging to Off. This is best-effort and does not guarantee
                suppression of OS-level logging outside the application.
              </div>
              <div class="grid grid-cols-2 gap-x-5 gap-y-2.5">
                {#each NO_LOG_FEATURES as f (f.label)}
                  <div class="flex items-start gap-2">
                    <ShieldCheck class="h-3 w-3 text-emerald-500 mt-0.5 shrink-0" strokeWidth={2.5} />
                    <div>
                      <div class="text-[11px] font-medium text-text-primary">{f.label}</div>
                      <div class="text-[10px] text-text-tertiary leading-snug">{f.desc}</div>
                    </div>
                  </div>
                {/each}
              </div>
            </div>
          </div>
          <div class="px-5 py-3 border-t border-edge/70 flex items-start gap-2">
            <AlertTriangle class="h-3 w-3 text-amber-500 shrink-0 mt-[2px]" strokeWidth={2.5} />
            <div class="text-[11px] text-text-tertiary leading-relaxed">
              No-Log mode disables all diagnostic output. Server issues will not produce visible logs.
              Use only when privacy is the absolute priority.
            </div>
          </div>
        </section>
        <section class="rounded-xl glass border border-edge/70">
          <div class="pane-body pt-4 text-center">
            <div class="text-[11px] text-text-tertiary dashboard-heading-sans">
              Log output is disabled in No-Log mode. Switch to Normal or Verbose to view server logs.
            </div>
          </div>
        </section>
      </div>
    {:else}
      <section in:fly={{ y: 8, duration: 240, easing: cubicOut }} out:fly={{ y: -8, duration: 240, easing: cubicOut }} class="rounded-xl glass border border-edge/70 flex flex-col flex-1 min-h-0">
        <div class="pane-header border-b border-edge flex items-center justify-between">
          <div class="text-[11px] text-black font-semibold dashboard-heading-sans">Live Output</div>
          <div class="flex items-center gap-3">
            <div class="text-[10px] text-text-ghost dashboard-heading-sans">{entryCountLabel}</div>
            <button
              use:ripple={{ color: "dark", disabled: logs.length === 0 }}
              type="button"
              onclick={handleCopyAll}
              disabled={logs.length === 0}
              class={cn(
                "action-btn-base action-copy-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
                logs.length === 0 ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
              )}
            >
              <span class="relative z-10 inline-grid place-items-center">
                <span class="invisible">Copy</span>
                {#key copyFb.copied}
                  <span
                    in:fly={{ y: 4, duration: 240, easing: cubicOut }}
                    out:fly={{ y: -4, duration: 240, easing: cubicOut }}
                    class="absolute inset-0 inline-flex items-center justify-center"
                    style="transform-origin: center;"
                  >
                    {#if copyFb.copied}
                      <Check class="h-3.5 w-3.5" />
                    {:else}
                      Copy
                    {/if}
                  </span>
                {/key}
              </span>
            </button>
            <button
              use:ripple={{ color: "dark", disabled: busyRotate }}
              type="button"
              onclick={() => { void handleRotateLogs(); }}
              disabled={busyRotate}
              title="Rotate log file"
              class={cn(
                "action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
                busyRotate ? "cursor-wait" : "cursor-pointer",
              )}
            >
              {#if busyRotate}<span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>{:else}<RotateCw class="h-3 w-3" strokeWidth={2.5} />{/if}
              Rotate
            </button>
            <button
              use:ripple={{ color: "dark", disabled: logs.length === 0 }}
              type="button"
              onclick={() => { clearDialogOpen = true; }}
              disabled={logs.length === 0}
              class={cn(
                "action-btn-base action-neutral-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
                logs.length === 0 ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
              )}
            >Clear</button>
          </div>
        </div>
        <div class="pane-body pane-first-item-offset flex-1 min-h-0">
          <div
            class="rounded-xl glass-pane-pill px-3 py-2 h-full min-h-0"
            style="will-change: transform, opacity; transform: translateZ(0);"
          >
            <div class="h-full min-h-0 overflow-y-auto">
              {#if logs.length === 0 && loadingLogs && !logsReady}
                <div class="px-2 py-2 space-y-2">
                  {#each { length: 8 } as _, i}
                    <Skeleton width="100%" height="14px" />
                  {/each}
                </div>
              {:else if logs.length === 0}
                <div class="text-[12px] text-text-tertiary py-8 text-center dashboard-heading-sans">
                  {mode === "minimal" ? "Only warnings and errors will appear here." : "Waiting for log entries..."}
                </div>
              {:else}
                <div class="space-y-0">
                  {#each logs as entry, i (`${entry.ts}-${i}`)}
                    <div
                      class={cn(
                        "flex items-start gap-3 px-2 py-[3px] rounded text-[11px]",
                        entry.level === "error" && "bg-negative-muted/30",
                        entry.level === "warn" && "bg-warning-muted/30",
                      )}
                    >
                      <span class="text-text-ghost/60 shrink-0 tabular-nums w-[64px] dashboard-heading-sans">
                        {formatTimestamp(entry.ts)}
                      </span>
                      <span class={cn(
                        "w-[40px] text-center text-[9px] font-medium py-0.5 rounded shrink-0 dashboard-heading-sans",
                        entry.level === "error" ? "text-negative" :
                        entry.level === "warn" ? "text-warning" :
                        entry.level === "debug" ? "text-text-ghost" : "text-text-tertiary",
                      )}>{entry.level}</span>
                      <span class="text-text-secondary flex-1 break-words dashboard-heading-sans">{entry.msg}</span>
                    </div>
                  {/each}
                  <div bind:this={bottomEl}></div>
                </div>
              {/if}
            </div>
          </div>
        </div>
      </section>
    {/if}

    <!-- Clear Dialog -->
    <Dialog.Root bind:open={clearDialogOpen}>
      <Dialog.Portal to="#qf-app-stage">
        <Dialog.Overlay class="absolute inset-0 z-50 bg-black/18 animate-in fade-in-0 duration-150" />
        <Dialog.Content class="dialog-surface dialog-typography absolute left-1/2 top-1/2 z-50 -translate-x-1/2 -translate-y-1/2 glass border border-edge shadow-xl rounded-[18px] w-[340px] animate-in fade-in-0 zoom-in-95 duration-200">
          <div class="dialog-header-pad">
            <Dialog.Title class="text-[13px] font-semibold text-black dashboard-heading-sans">Clear Live Output</Dialog.Title>
          </div>
          <div class="dialog-body-pad space-y-2">
            <div class="text-[12px] text-black">This removes all currently visible log entries from the live output panel.</div>
            <div class="text-[11px] text-black">Do you want to continue?</div>
          </div>
          <div class="dialog-footer-pad">
            <button use:ripple={{ color: "light" }} class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-refresh-btn flex-1" onclick={() => { dialogActionDelay.schedule(() => { clearDialogOpen = false; }, 88); }}>Cancel</button>
            <button use:ripple={{ color: "dark" }} class="action-neutral-btn flex-1" onclick={() => { dialogActionDelay.schedule(() => { void confirmClearLogs(); }, 88); }}>Clear</button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  </div>
</div>
