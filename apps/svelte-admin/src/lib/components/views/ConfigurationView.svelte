<script lang="ts">
  import { cn, ripple } from "@quicfuscate/ui";
  import { addToast } from "@quicfuscate/ui";
  import { isBrowserDocumentVisible } from "@quicfuscate/time";
  import { useAnchorSync } from "$lib/use-anchor-sync";
  import QKeyPanel from "$lib/components/panels/QKeyPanel.svelte";
  import StealthPanel from "$lib/components/panels/StealthPanel.svelte";
  import AdminSettingsPanel from "$lib/components/panels/AdminSettingsPanel.svelte";
  import ServerOpsPanel from "$lib/components/panels/ServerOpsPanel.svelte";
  import ReferenceGuide from "$lib/components/panels/ReferenceGuide.svelte";
  import { getJson, postJson, ApiError, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import {
    handleAuthError,
    setConfigDirty,
    getStatus,
    setStatus,
    setStatusLoading,
    confirmDialog,
  } from "$lib/stores/app.svelte";
  import {
    normalizeTomlTextForUi,
    setSectionValue,
    readSectionValue,
    readStealthFlag,
    stealthPresetFromMode,
    fecPresetFromConfig,
    normalizeCcSelection,
    parseMtu,
    canonicalizeConfigForCompare,
    DEFAULT_STEALTH_MANUAL,
  } from "$lib/config-helpers";
  import { createRequestCoordinator, type RequestOptions, type RequestToken } from "$lib/request-coordinator";
  import type { StealthPresetUi, StealthManualSettings, CcSelection } from "$lib/types";

  const MAX_PERSIST_ATTEMPTS = 2;

  function isRetriablePersistenceError(error: unknown): boolean {
    if (error instanceof ApiError) {
      const status = error.status;
      return status == null || status >= 500;
    }
    return true;
  }

  const status = $derived(getStatus());

  let loading = $state(false);
  let saving = $state(false);
  let configText = $state("");
  let dirty = $state(false);

  let stealthPreset = $state<StealthPresetUi>("auto");
  let fecPreset = $state<"auto" | "off">("auto");
  let stealthManual = $state<StealthManualSettings>({ ...DEFAULT_STEALTH_MANUAL });
  let transportCc = $state<CcSelection>("bbr3");
  let transportMtuText = $state("1400");

  let adminRefreshFn: (() => Promise<void>) | null = null;
  let actionsEl: HTMLDivElement | undefined = $state();
  let viewActive = true;
  const configRequests = createRequestCoordinator();
  const statusRequests = createRequestCoordinator();

  $effect(() => useAnchorSync(actionsEl));

  function applyConfigToUi(rawConfig: string) {
    const text = normalizeTomlTextForUi(rawConfig);
    const normalizedText = setSectionValue(text, "transport", "enable_pacing", "true");
    configText = normalizedText;
    stealthPreset = stealthPresetFromMode(readSectionValue(normalizedText, "stealth", "mode"));
    stealthManual = {
      enable_domain_fronting: readStealthFlag(normalizedText, "enable_domain_fronting"),
      enable_http3_masquerading: readStealthFlag(normalizedText, "enable_http3_masquerading"),
      use_tls_cover: readStealthFlag(normalizedText, "use_tls_cover"),
      use_qpack_headers: readStealthFlag(normalizedText, "use_qpack_headers"),
      enable_traffic_padding: readStealthFlag(normalizedText, "enable_traffic_padding"),
      enable_timing_obfuscation: readStealthFlag(normalizedText, "enable_timing_obfuscation"),
      enable_protocol_mimicry: readStealthFlag(normalizedText, "enable_protocol_mimicry"),
      enable_doh: readStealthFlag(normalizedText, "enable_doh"),
    };
    fecPreset = fecPresetFromConfig(normalizedText);
    transportCc = normalizeCcSelection(readSectionValue(normalizedText, "transport", "cc_algorithm"));
    transportMtuText = readSectionValue(normalizedText, "transport", "mtu")?.trim() ?? "";
    dirty = false;
    setConfigDirty(false);
  }

  function fetchConfig(options: RequestOptions = {}): Promise<void> {
    return configRequests.request(async (token: RequestToken) => {
      loading = true;
      try {
        const resp = await getJson("/api/config", adminApiSchemas.configRead);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "No config");
        if (!configRequests.isCurrent(token)) return;
        applyConfigToUi(resp.data.config);
      } catch (e: unknown) {
        if (!configRequests.isCurrent(token)) return;
        handleAuthError(e);
      } finally {
        if (configRequests.isCurrent(token)) loading = false;
      }
    }, options);
  }

  function fetchStatus(options: RequestOptions = {}): Promise<void> {
    return statusRequests.request(async (token: RequestToken) => {
      setStatusLoading(true);
      try {
        const resp = await getJson("/api/status", adminApiSchemas.status);
        if (!resp.success || !resp.data) throw new Error(resp.message ?? "No status");
        if (!statusRequests.isCurrent(token)) return;
        setStatus(resp.data);
      } catch (e: unknown) {
        if (!statusRequests.isCurrent(token)) return;
        handleAuthError(e);
      } finally {
        if (statusRequests.isCurrent(token)) setStatusLoading(false);
      }
    }, options);
  }

  function markConfigEdit(): void {
    configRequests.invalidate();
    loading = false;
  }

  async function saveConfig() {
    if (!viewActive) return;
    configRequests.invalidate();
    saving = true;
    try {
      const normalized = normalizeTomlTextForUi(configText);
      let persistedConfigText: string | null = null;
      for (let attempt = 1; attempt <= MAX_PERSIST_ATTEMPTS; attempt++) {
        try {
          const resp = await postJson("/api/config", { config: normalized }, adminApiSchemas.configWrite);
          if (!resp.success) throw new Error(resp.message ?? "Save failed");
          const verifyResp = await getJson("/api/config", adminApiSchemas.configRead);
          if (!verifyResp.success || !verifyResp.data) throw new Error(verifyResp.message ?? "Save verification failed");
          const savedCanonical = canonicalizeConfigForCompare(verifyResp.data.config);
          const expectedCanonical = canonicalizeConfigForCompare(normalized);
          if (savedCanonical !== expectedCanonical) throw new Error("Save verification failed");
          persistedConfigText = verifyResp.data.config;
          break;
        } catch (e) {
          if (attempt >= MAX_PERSIST_ATTEMPTS || !isRetriablePersistenceError(e)) throw e;
        }
      }
      if (!viewActive) return;
      applyConfigToUi(persistedConfigText ?? normalized);
      addToast("Changes saved", "success");
    } catch (e: unknown) {
      if (!viewActive) return;
      if (!handleAuthError(e)) { addToast("Failed to save configuration", "error"); }
    } finally {
      if (viewActive) saving = false;
    }
  }

  function applyStealthPreset(preset: StealthPresetUi) {
    markConfigEdit();
    const normalizedMode =
      preset === "performance" ? "performance"
        : preset === "stealth" ? "stealth"
          : preset === "antidpi" ? "anti-dpi"
            : preset === "manual" ? "manual"
              : preset === "off" ? "off"
                : "intelligent";
    stealthPreset = preset;
    configText = setSectionValue(configText, "stealth", "mode", `"${normalizedMode}"`);
    dirty = true;
    setConfigDirty(true);
  }

  function applyStealthManualFlag(key: keyof StealthManualSettings, value: boolean) {
    markConfigEdit();
    stealthManual = { ...stealthManual, [key]: value };
    configText = setSectionValue(configText, "stealth", key, value ? "true" : "false");
    dirty = true;
    setConfigDirty(true);
  }

  function applyFecPreset(preset: "auto" | "off") {
    markConfigEdit();
    fecPreset = preset;
    configText = setSectionValue(configText, "fec", "mode", preset === "off" ? '"off"' : '"auto"');
    configText = setSectionValue(configText, "adaptive_fec", "initial_mode", preset === "off" ? '"off"' : '"auto"');
    configText = setSectionValue(configText, "adaptive_fec", "force_on", "false");
    dirty = true;
    setConfigDirty(true);
  }

  function applyTransportCc(cc: CcSelection) {
    if (cc === "__custom__") return;
    markConfigEdit();
    transportCc = cc;
    configText = setSectionValue(configText, "transport", "cc_algorithm", `"${cc}"`);
    dirty = true;
    setConfigDirty(true);
  }

  function applyTransportMtu(mtu: number) {
    markConfigEdit();
    transportMtuText = String(mtu);
    configText = setSectionValue(configText, "transport", "mtu", String(mtu));
    dirty = true;
    setConfigDirty(true);
  }

  async function handleRefresh() {
    if (dirty) {
      const discard = await confirmDialog({
        title: "Unsaved Changes",
        message: "You have unsaved configuration changes. Refresh and discard them?",
        confirmLabel: "Discard",
        cancelLabel: "Cancel",
      });
      if (!discard) return;
    }
    if (!viewActive) return;
    addToast("Refreshed", "info");
    await Promise.allSettled([
      fetchStatus({ invalidate: true }),
      fetchConfig({ invalidate: true }),
      adminRefreshFn?.(),
    ]);
  }

  const saveDisabled = $derived(saving || !dirty || loading || (transportMtuText.trim().length > 0 && parseMtu(transportMtuText) == null));

  // Init
  $effect(() => {
    const handleVisibilityChange = (): void => {
      if (!isBrowserDocumentVisible()) {
        statusRequests.invalidate();
        configRequests.invalidate();
        return;
      }
      void fetchStatus({ invalidate: true });
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);
    void fetchStatus();
    void fetchConfig();
    const interval = setInterval(() => {
      if (isBrowserDocumentVisible()) void fetchStatus();
    }, 5000);
    return () => {
      viewActive = false;
      statusRequests.dispose();
      configRequests.dispose();
      clearInterval(interval);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  });

  $effect(() => {
    setConfigDirty(dirty);
    return () => setConfigDirty(false);
  });
</script>

<div class="app-pane-scroll flex flex-1 min-h-0 overflow-y-auto">
  <div class="w-full px-6 py-6 space-y-5 config-black-text">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div class="text-[14px] font-bold text-text-primary">Configuration</div>
      <div bind:this={actionsEl} class="relative flex items-center gap-2.5">
        <button
          use:ripple={{ color: "dark", disabled: saveDisabled }}
          type="button"
          disabled={saveDisabled}
          onclick={() => { void saveConfig(); }}
          class={cn(
            "action-btn-base action-save-btn inline-flex items-center justify-center font-medium h-7 px-3 text-[11px] gap-1.5",
            saveDisabled ? "opacity-35 cursor-not-allowed" : "cursor-pointer",
          )}
        >
          {#if saving}
            <span class="h-3 w-3 border-2 border-current border-t-transparent rounded-full animate-spin"></span>
          {/if}
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
            status ? "border-positive/35 text-positive" : "border-negative/35 text-negative",
          )}
        >
          <span class={cn("h-2 w-2 rounded-full", status ? "bg-positive shadow-[0_0_10px_rgba(22,163,74,0.55)]" : "bg-negative shadow-[0_0_10px_rgba(220,38,38,0.55)]")}></span>
          {status ? "Online" : "Offline"}
        </div>
      </div>
    </div>

    <AdminSettingsPanel onRefresh={(fn) => { adminRefreshFn = fn; }} />

    <ServerOpsPanel />

    <StealthPanel
      {stealthPreset}
      {fecPreset}
      {stealthManual}
      {transportCc}
      {transportMtuText}
      onStealthChange={applyStealthPreset}
      onFecChange={applyFecPreset}
      onManualFlagChange={applyStealthManualFlag}
      onCcChange={applyTransportCc}
      onMtuChange={(v) => {
        markConfigEdit();
        transportMtuText = v;
        const n = parseMtu(v);
        if (n != null) applyTransportMtu(n);
      }}
    />

    <QKeyPanel />

    <div class="mt-auto pt-4">
      <ReferenceGuide />
    </div>
  </div>
</div>
