<script lang="ts">
  import { onDestroy } from "svelte";
  import { addToast, ConfirmDialog, createOwnedTimeout, ripple } from "@quicfuscate/ui";
  import {
    getTunnels, getSelectedId, setSelectedId,
    getTunnelStates, updateTunnelStates, setTunnelStates,
    getTunnelStats, getSettings, getError, setError,
    getQkeyPolicies, setQkeyPolicies, getThroughput,
    updateTunnels,
  } from "$lib/stores/app.svelte";
  import { isTauri, engineConnect, engineDisconnect, engineRotate, qkeyParse } from "$lib/stores/tauri-bridge.svelte";
  import { resolveDomainFrontingSniDisplay } from "$lib/domain-fronting-policy";
  import { fly, scale } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import TunnelListItem from "./TunnelListItem.svelte";
  import TunnelStats from "./TunnelStats.svelte";
  import AddTunnelDialog from "./AddTunnelDialog.svelte";
  import ImportQKeyDialog from "./ImportQKeyDialog.svelte";
  import EditQKeyDialog from "./EditQKeyDialog.svelte";
  import TunnelConfigDialog from "./TunnelConfigDialog.svelte";
  import { normalizeMode } from "$lib/format";
  import type { TunnelConfig, TunnelPolicyView } from "$lib/types";

  const DEFAULT_POLICY: TunnelPolicyView = {
    stealth: "auto", fec: "auto", mtu: "server", cc: "server",
    sniDisplay: "QKey Policy", customDetails: [], source: "server",
  };

  let createOpen = $state(false);
  let importOpen = $state(false);
  let editQkeyTunnelId = $state<string | null>(null);
  let configTunnelId = $state<string | null>(null);
  let pendingDeleteId = $state<string | null>(null);
  let pendingDisconnectId = $state<string | null>(null);
  let pendingSwitchTargetId = $state<string | null>(null);
  let switchingTunnelId = $state<string | null>(null);
  const dialogActionDelay = createOwnedTimeout();

  const tunnels = $derived(getTunnels());
  const selectedId = $derived(getSelectedId());
  const tunnelStates = $derived(getTunnelStates());
  const tunnelStats = $derived(getTunnelStats());
  const settings = $derived(getSettings());
  const qkeyPolicies = $derived(getQkeyPolicies());
  const throughput = $derived(getThroughput());

  const activeTunnelId = $derived(
    Object.entries(tunnelStates).find(([, s]) => s === "active")?.[0] ?? null
  );
  const activeTunnel = $derived(
    activeTunnelId ? tunnels.find((t) => t.id === activeTunnelId) ?? null : null
  );

  const selectedTunnel = $derived(
    tunnels.length === 0 ? null : tunnels.find((t) => t.id === selectedId) ?? null
  );
  const selectedState = $derived(selectedTunnel ? (tunnelStates[selectedTunnel.id] ?? "inactive") : "inactive");
  const selectedStats = $derived(selectedTunnel ? (tunnelStats[selectedTunnel.id] ?? null) : null);
  const selectedThroughput = $derived(selectedTunnel ? (throughput[selectedTunnel.id] ?? null) : null);
  const selectedHasQKey = $derived(Boolean(selectedTunnel && (
    selectedTunnel.circuit
      ? selectedTunnel.circuit.hops.length > 0
        && selectedTunnel.circuit.hops.every((hop) => hop.qkey.trim().length > 0)
        && (!selectedTunnel.alternateCircuit
          || selectedTunnel.alternateCircuit.hops.every((hop) => hop.qkey.trim().length > 0))
      : selectedTunnel.qkey.trim().length > 0
  )));
  const selectedPolicy = $derived(selectedTunnel ? (qkeyPolicies[selectedTunnel.id] ?? DEFAULT_POLICY) : DEFAULT_POLICY);

  const selectedSniDisplay = $derived.by(() => {
    if (!selectedTunnel) return "-";
    const runtimeSni = (selectedStats?.currentSni ?? "").trim();
    if (runtimeSni.length > 0) return runtimeSni;
    const overrideSni = (selectedTunnel.debugSniOverride ?? "").trim();
    if (overrideSni.length > 0) return overrideSni;
    const configuredSni = (selectedTunnel.sni ?? "").trim();
    if (configuredSni.length > 0) return configuredSni;
    const policySni = (selectedPolicy.sniDisplay ?? "").trim();
    return policySni.length > 0 ? policySni : "-";
  });

  const selectedActionDisabled = $derived(
    selectedState === "activating" || selectedState === "deactivating"
    || !selectedHasQKey || Boolean(switchingTunnelId)
  );

  const pendingDelete = $derived(pendingDeleteId ? tunnels.find((t) => t.id === pendingDeleteId) ?? null : null);
  const pendingDisconnect = $derived(pendingDisconnectId ? tunnels.find((t) => t.id === pendingDisconnectId) ?? null : null);
  const pendingSwitchTarget = $derived(pendingSwitchTargetId ? tunnels.find((t) => t.id === pendingSwitchTargetId) ?? null : null);
  const configTunnel = $derived(configTunnelId ? tunnels.find((t) => t.id === configTunnelId) ?? null : null);
  const editQkeyTunnel = $derived(editQkeyTunnelId ? tunnels.find((t) => t.id === editQkeyTunnelId) ?? null : null);
  const editQkeyMode = $derived(editQkeyTunnel?.qkey.trim() ? "replace" : "set");

  // Parse QKey policies
  function parseExtraPolicy(extra: unknown): { mtu: string; cc: string; customDetails: string[] } {
    if (typeof extra !== "string" || !extra.trim()) return { mtu: "server", cc: "server", customDetails: [] };
    try {
      const parsed = JSON.parse(extra) as Record<string, unknown>;
      return {
        mtu: typeof parsed.mtu === "string" ? parsed.mtu : "server",
        cc: typeof parsed.cc === "string" ? parsed.cc : "server",
        customDetails: Array.isArray(parsed.customDetails) ? parsed.customDetails.filter((d): d is string => typeof d === "string") : [],
      };
    } catch { return { mtu: "server", cc: "server", customDetails: [] }; }
  }

  const qkeyFingerprint = $derived(tunnels.map((t) =>
    `${t.id}:${(t.circuit?.hops.map((hop) => hop.qkey.slice(0, 16)).join(":") ?? t.qkey.slice(0, 16))}`,
  ).join("|"));

  $effect(() => {
    void qkeyFingerprint;
    if (!isTauri()) { setQkeyPolicies({}); return; }
    const parseable = tunnels
      .map((tunnel) => ({
        tunnel,
        qkey: tunnel.circuit?.hops.at(-1)?.qkey.trim() ?? tunnel.qkey.trim(),
      }))
      .filter(({ qkey }) => qkey.length > 0);
    if (parseable.length === 0) { setQkeyPolicies({}); return; }
    let cancelled = false;
    (async () => {
      try {
        const entries = await Promise.all(
          parseable.map(async ({ tunnel, qkey }) => {
            try {
              const parsed = await qkeyParse(qkey);
              const stealth = normalizeMode(parsed.stealth as string | null);
              const fec = normalizeMode(parsed.fec as string | null);
              const extraPolicy = parseExtraPolicy(parsed.extra);
              const sniDisplay = resolveDomainFrontingSniDisplay(
                parsed.extra as string | null, typeof parsed.sni === "string" ? parsed.sni : "",
              );
              const isManual = stealth === "manual" || fec === "manual";
              const customDetails = extraPolicy.customDetails.length > 0
                ? extraPolicy.customDetails
                : isManual ? ["Custom config [server-managed]"] : [];
              return [tunnel.id, { stealth, fec, mtu: extraPolicy.mtu, cc: extraPolicy.cc, sniDisplay, customDetails, source: "qkey" as const }] as const;
            } catch { return [tunnel.id, DEFAULT_POLICY] as const; }
          }),
        );
        if (cancelled) return;
        setQkeyPolicies(Object.fromEntries(entries));
      } catch { if (!cancelled) setQkeyPolicies({}); }
    })();
    return () => { cancelled = true; };
  });

  async function confirmDelete() {
    if (!pendingDelete) return;
    const id = pendingDelete.id;
    const state = tunnelStates[id];
    if (state === "active" || state === "activating") {
      try { await engineDisconnect(); } catch { /* best-effort disconnect before delete */ }
    }
    updateTunnels((prev) => prev.filter((t) => t.id !== id));
    if (selectedId === id) setSelectedId(null);
    pendingDeleteId = null;
  }

  async function confirmDisconnect() {
    if (!pendingDisconnect) return;
    const tunnel = pendingDisconnect;
    pendingDisconnectId = null;
    updateTunnelStates((prev) => ({ ...prev, [tunnel.id]: "deactivating" }));
    setError(null);
    if (!isTauri()) {
      updateTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
      return;
    }
    try {
      await engineDisconnect();
      addToast("Disconnected from tunnel", "success");
    } catch (e: unknown) {
      setError(String(e ?? "Disconnect failed"));
      addToast("Disconnect failed", "error");
    } finally {
      updateTunnelStates((prev) => ({ ...prev, [tunnel.id]: "inactive" }));
    }
  }

  async function confirmSwitchTunnel() {
    if (!pendingSwitchTarget) return;
    const target = pendingSwitchTarget;
    pendingSwitchTargetId = null;
    const sourceId = activeTunnelId;
    if (!sourceId || sourceId === target.id) { setSelectedId(target.id); return; }
    const qkey = (target.circuit?.hops[0]?.qkey ?? target.qkey).trim();
    if (!qkey) {
      addToast("QKey missing on target tunnel. Set a QKey before switching.", "warning");
      dialogActionDelay.schedule(() => {
        editQkeyTunnelId = target.id;
      }, 88);
      return;
    }
    switchingTunnelId = target.id;
    setSelectedId(target.id);
    setError(null);
    updateTunnelStates((prev) => ({ ...prev, [sourceId]: "deactivating", [target.id]: "activating" }));
    if (!isTauri()) {
      updateTunnelStates((prev) => ({ ...prev, [sourceId]: "inactive", [target.id]: "inactive" }));
      setError("Tunnel switch requires the desktop app runtime");
      addToast("Tunnel switch requires the desktop app runtime", "error");
      switchingTunnelId = null;
      return;
    }
    let disconnected = false;
    try {
      await engineDisconnect();
      disconnected = true;
      const sniOverride = (target.debugSniOverride ?? "").trim();
      await engineConnect(
        target.id,
        qkey,
        settings,
        sniOverride.length > 0 ? sniOverride : undefined,
        target.circuit,
        target.alternateCircuit,
      );
      const allIds = Object.keys(tunnelStates);
      const next: Record<string, "inactive" | "activating" | "active" | "deactivating"> = {};
      for (const k of allIds) next[k] = "inactive";
      next[target.id] = "active";
      setTunnelStates(next);
      addToast(`Switched connection to "${target.name}"`, "success");
    } catch (e: unknown) {
      setError(String(e ?? "Tunnel switch failed"));
      if (!disconnected) updateTunnelStates((prev) => ({ ...prev, [sourceId]: "active", [target.id]: "inactive" }));
      else updateTunnelStates((prev) => ({ ...prev, [sourceId]: "inactive", [target.id]: "inactive" }));
      addToast(String(e ?? "Tunnel switch failed"), "error");
    } finally { switchingTunnelId = null; }
  }

  async function handleToggleConnection() {
    if (!selectedTunnel) return;
    const state = selectedState;
    if (state === "activating" || state === "deactivating") return;
    if (state === "active") { pendingDisconnectId = selectedTunnel.id; return; }
    const qkey = (selectedTunnel.circuit?.hops[0]?.qkey ?? selectedTunnel.qkey).trim();
    if (!qkey) {
      addToast("QKey missing. Set a QKey before connecting.", "warning");
      dialogActionDelay.schedule(() => {
        editQkeyTunnelId = selectedTunnel.id;
      }, 88);
      return;
    }
    // Check if another tunnel is active => switch flow
    if (activeTunnelId && activeTunnelId !== selectedTunnel.id) {
      pendingSwitchTargetId = selectedTunnel.id;
      return;
    }
    updateTunnelStates((prev) => ({ ...prev, [selectedTunnel.id]: "activating" }));
    setError(null);
    if (!isTauri()) {
      updateTunnelStates((prev) => ({ ...prev, [selectedTunnel.id]: "inactive" }));
      setError("Connect requires the desktop app runtime");
      addToast("Connect requires the desktop app runtime", "error");
      return;
    }
    try {
      const sniOverride = (selectedTunnel.debugSniOverride ?? "").trim();
      await engineConnect(
        selectedTunnel.id,
        qkey,
        settings,
        sniOverride.length > 0 ? sniOverride : undefined,
        selectedTunnel.circuit,
        selectedTunnel.alternateCircuit,
      );
      const allIds = Object.keys(tunnelStates);
      const next: Record<string, "inactive" | "activating" | "active" | "deactivating"> = {};
      for (const k of allIds) next[k] = "inactive";
      next[selectedTunnel.id] = "active";
      setTunnelStates(next);
      setSelectedId(selectedTunnel.id);
      addToast("Connected to tunnel", "success");
    } catch (e: unknown) {
      updateTunnelStates((prev) => ({ ...prev, [selectedTunnel.id]: "inactive" }));
      setError(String(e ?? "Connect failed"));
      addToast(String(e ?? "Connect failed"), "error");
    }
  }

  async function handleRotateCircuit() {
    if (!selectedTunnel?.circuit || selectedState !== "active" || switchingTunnelId) return;
    const rotationTarget = selectedTunnel.alternateCircuit;
    if (!rotationTarget) {
      addToast("No authenticated alternate circuit is configured.", "warning");
      return;
    }
    if (selectedTunnel.circuit.maxParallelCircuits !== 2) {
      addToast("Circuit rotation requires a parallel-circuit limit of 2.", "warning");
      return;
    }
    const qkey = rotationTarget.hops[0]?.qkey.trim() ?? "";
    if (!qkey || !rotationTarget.hops.every((hop) => hop.qkey.trim().length > 0)) {
      addToast("Every circuit hop needs a QKey before rotation.", "warning");
      return;
    }
    if (!isTauri()) {
      addToast("Circuit rotation requires the desktop app runtime", "error");
      return;
    }
    switchingTunnelId = selectedTunnel.id;
    setError(null);
    try {
      const sniOverride = (selectedTunnel.debugSniOverride ?? "").trim();
      await engineRotate(
        selectedTunnel.id,
        qkey,
        settings,
        rotationTarget,
        sniOverride.length > 0 ? sniOverride : undefined,
      );
      const previousPrimary = selectedTunnel.circuit;
      updateTunnels((current) => current.map((tunnel) => tunnel.id === selectedTunnel.id
        ? { ...tunnel, circuit: rotationTarget, alternateCircuit: previousPrimary }
        : tunnel));
      addToast("Circuit rotated after readiness verification", "success");
    } catch (error: unknown) {
      const message = String(error ?? "Circuit rotation failed");
      setError(message);
      addToast(message, "error");
    } finally {
      switchingTunnelId = null;
    }
  }

  const SIDEBAR_PILL = "background: rgba(255,255,255,0.65); backdrop-filter: blur(24px) saturate(200%); -webkit-backdrop-filter: blur(24px) saturate(200%); border: 1px solid rgba(255,255,255,0.60); box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);";

  function openCreateDialog() {
    dialogActionDelay.schedule(() => {
      createOpen = true;
    }, 88);
  }

  function openImportDialog() {
    dialogActionDelay.schedule(() => {
      importOpen = true;
    }, 88);
  }

  function openEditQkeyDialog(id: string) {
    dialogActionDelay.schedule(() => {
      editQkeyTunnelId = id;
    }, 88);
  }

  $effect(() => {
    const handleNewTunnel = () => openCreateDialog();
    const handleToggleConnect = () => { if (selectedTunnel) void handleToggleConnection(); };
    const handleDisconnect = () => {
      if (selectedTunnel && selectedState === "active") pendingDisconnectId = selectedTunnel.id;
    };
    window.addEventListener("qf:new-tunnel", handleNewTunnel);
    window.addEventListener("qf:toggle-connect", handleToggleConnect);
    window.addEventListener("qf:disconnect-active", handleDisconnect);
    return () => {
      window.removeEventListener("qf:new-tunnel", handleNewTunnel);
      window.removeEventListener("qf:toggle-connect", handleToggleConnect);
      window.removeEventListener("qf:disconnect-active", handleDisconnect);
    };
  });

  onDestroy(dialogActionDelay.destroy);
</script>

{#if createOpen}
  <AddTunnelDialog bind:open={createOpen} onclose={() => { createOpen = false; }} />
{/if}
{#if importOpen}
  <ImportQKeyDialog bind:open={importOpen} onclose={() => { importOpen = false; }} />
{/if}
{#if editQkeyTunnel}
  <EditQKeyDialog open={true} tunnelId={editQkeyTunnel.id} mode={editQkeyMode} onclose={() => { editQkeyTunnelId = null; }} />
{/if}
{#if configTunnel}
  <TunnelConfigDialog open={true} tunnel={configTunnel} onclose={() => { configTunnelId = null; }} />
{/if}

{#if pendingDelete}
  <ConfirmDialog
    open={true}
    title="Delete Tunnel"
    message={`Delete tunnel "${pendingDelete.name}" permanently?`}
    confirmLabel="Delete"
    cancelLabel="Cancel"
    destructive
    portalTarget="#qf-app-stage"
    onconfirm={confirmDelete}
    oncancel={() => { pendingDeleteId = null; }}
  />
{/if}
{#if pendingDisconnect}
  <ConfirmDialog
    open={true}
    title="Disconnect Tunnel"
    message={`Disconnect "${pendingDisconnect.name}" now?`}
    confirmLabel="Disconnect"
    cancelLabel="Cancel"
    destructive
    portalTarget="#qf-app-stage"
    onconfirm={() => { void confirmDisconnect(); }}
    oncancel={() => { pendingDisconnectId = null; }}
  />
{/if}
{#if pendingSwitchTarget}
  <ConfirmDialog
    open={true}
    title="Switch Tunnel Connection"
    message={activeTunnel
      ? `Switch from "${activeTunnel.name}" to "${pendingSwitchTarget.name}"? Current connection will disconnect and reconnect to the selected tunnel.`
      : "Switch to selected tunnel now?"}
    confirmLabel="Switch"
    cancelLabel="Cancel"
    portalTarget="#qf-app-stage"
    onconfirm={() => { void confirmSwitchTunnel(); }}
    oncancel={() => { if (!switchingTunnelId) pendingSwitchTargetId = null; }}
  />
{/if}

<div class="flex flex-col flex-1 min-h-0">
  <!-- Toolbar -->
  <div class="px-5 pt-6 pb-3 flex items-center justify-between">
    <div class="flex items-center gap-3">
      <span class="text-lg font-bold text-black dashboard-heading-sans tracking-tight">Tunnels</span>
      <span
        class="text-[10px] font-semibold text-black/75 tabular-nums inline-flex items-center rounded-md border px-2 py-[1px] leading-none"
        style={SIDEBAR_PILL}
      >{tunnels.length}</span>
    </div>
    <div class="flex items-center gap-2">
      <button
        type="button"
        use:ripple
        aria-label="Open tunnel composer"
        onclick={openCreateDialog}
        class="inline-flex items-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-save-btn min-w-0"
      >Create</button>
      <button
        type="button"
        use:ripple
        aria-label="Open QKey vault"
        onclick={openImportDialog}
        class="relative isolate overflow-hidden inline-flex items-center justify-center rounded-lg px-3 h-[30px] border text-[11px] font-semibold transition-all action-copy-btn min-w-0"
      >Import QKey</button>
    </div>
  </div>

  <div class="flex-1 min-h-0 px-5 pb-[13px] flex flex-col gap-3">
    <div class="flex-1 min-h-0 overflow-y-auto overflow-x-hidden">
      {#if tunnels.length === 0}
        <div class="flex h-full flex-col items-center justify-center gap-1 px-4">
          <span class="text-[32px] font-light text-text-ghost/30 leading-none tabular-nums">0</span>
          <span class="text-[11px] font-semibold text-text-ghost dashboard-heading-sans">Tunnels</span>
        </div>
      {:else}
        <div class="grid grid-cols-2 gap-3 auto-rows-[1fr]">
          {#each tunnels as tunnel (tunnel.id)}
            <div in:fly={{ y: 12, duration: 220, easing: cubicOut }} out:scale={{ start: 0.97, duration: 150, opacity: 0 }}>
            <TunnelListItem
              {tunnel}
              isSelected={selectedId === tunnel.id}
              policy={qkeyPolicies[tunnel.id] ?? DEFAULT_POLICY}
              onselect={() => setSelectedId(tunnel.id)}
              onconfigure={() => { configTunnelId = tunnel.id; }}
              onremove={() => { pendingDeleteId = tunnel.id; }}
            />
            </div>
          {/each}
        </div>
      {/if}
    </div>

    <TunnelStats
      tunnel={selectedTunnel}
      state={selectedState}
      stats={selectedStats}
      policy={selectedPolicy}
      throughput={selectedThroughput}
      sniDisplay={selectedSniDisplay}
      actionDisabled={selectedActionDisabled}
      hasQKey={selectedHasQKey}
      ontoggle={handleToggleConnection}
      oneditqkey={() => { if (selectedTunnel) openEditQkeyDialog(selectedTunnel.id); }}
      onrotate={handleRotateCircuit}
      rotationDisabled={Boolean(switchingTunnelId)}
    />
  </div>
</div>
