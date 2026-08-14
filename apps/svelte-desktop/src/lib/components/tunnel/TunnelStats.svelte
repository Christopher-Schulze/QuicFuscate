<script lang="ts">
  import { ripple } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";
  import { countryCodeToFlag, formatBytes, formatDuration, formatRate, normalizeMode } from "$lib/format";
  import { displayStealthMode, displayFecMode, displayCcMode, displayMtu } from "$lib/policy-display";
  import { Zap, Clock3, ArrowDownUp, RefreshCw } from "@lucide/svelte";
  import ConnectButton from "$lib/components/ui/ConnectButton.svelte";
  import ThroughputChart from "$lib/components/tunnel/ThroughputChart.svelte";
  import type { TunnelConfig, TunnelState, TunnelStats as TStats, TunnelPolicyView } from "$lib/types";

  interface Props {
    tunnel: TunnelConfig | null;
    state: TunnelState;
    stats: TStats | null;
    policy: TunnelPolicyView;
    throughput: { downBps: number; upBps: number } | null;
    sniDisplay: string;
    actionDisabled: boolean;
    hasQKey: boolean;
    ontoggle: () => void;
    oneditqkey: () => void;
    onrotate: () => void;
    rotationDisabled: boolean;
  }

  let { tunnel, state, stats, policy, throughput, sniDisplay, actionDisabled, hasQKey, ontoggle, oneditqkey, onrotate, rotationDisabled }: Props = $props();

  const flag = $derived(tunnel ? countryCodeToFlag(tunnel.countryCode) : "");
  const statusLabel = $derived(
    state === "active" ? "Connected"
    : state === "activating" ? "Connecting"
    : state === "deactivating" ? "Stopping"
    : "Idle"
  );
  const statusClass = $derived(
    state === "active" ? "text-positive"
    : state === "activating" || state === "deactivating" ? "text-warning"
    : "text-black/55"
  );
  const latencyLabel = $derived(stats ? `${stats.latencyMs.toFixed(1)} ms` : "-");
  const uptime = $derived(stats ? formatDuration(stats.uptimeSecs) : "-");
  const downRate = $derived(throughput ? formatRate(throughput.downBps) : "-");
  const upRate = $derived(throughput ? formatRate(throughput.upBps) : "-");
  const downTotal = $derived(stats ? formatBytes(stats.rxBytes) : "-");
  const upTotal = $derived(stats ? formatBytes(stats.txBytes) : "-");
  const connectState = $derived(
    state === "active" ? "connected" as const
    : state === "activating" ? "connecting" as const
    : state === "deactivating" ? "disconnecting" as const
    : "idle" as const
  );

  import { WHITE_PILL, PILL_BACKDROP } from "$lib/pill-styles";

  function isFecOff(raw: string | null | undefined): boolean {
    const v = normalizeMode(raw, "");
    return v === "off" || v === "zero";
  }

  const stealthPolicyRaw = $derived(normalizeMode(policy.stealth));
  const stealthRuntimeRaw = $derived(normalizeMode(stats?.stealthMode, ""));
  const stealthIsIntelligent = $derived(stealthPolicyRaw === "auto" || stealthPolicyRaw === "intelligent");
  const stealthLiveRaw = $derived(stealthRuntimeRaw || stealthPolicyRaw);
  const stealthDisplayRaw = $derived(
    stealthIsIntelligent && (stealthLiveRaw === "auto" || stealthLiveRaw === "intelligent" || !stealthLiveRaw)
      ? "performance" : stealthLiveRaw
  );
  const stealthMode = $derived(tunnel ? displayStealthMode(stealthDisplayRaw) : "-");
  const fecRuntimeRaw = $derived(normalizeMode(stats?.fecMode, ""));
  const fecPolicyRaw = $derived(normalizeMode(policy.fec));
  const fecIsOff = $derived(isFecOff(fecRuntimeRaw) || isFecOff(fecPolicyRaw));
  const fecBadgeLabel = $derived(fecIsOff ? "Off" : "Auto");
  const fecActivity = $derived(!tunnel ? "-" : fecIsOff ? "-" : `${Math.min(100, Math.max(0, stats?.fecActivityPercent ?? 0)).toFixed(1)}%`);
  const qkeyActionLabel = $derived(hasQKey ? "Change QKey" : "Set QKey");
  const tokenLabel = $derived(!tunnel ? "-" : tunnel.hasToken ? "Present" : "None");
  const lossLabel = $derived(stats ? `${stats.lossPercent.toFixed(2)}%` : "-");
  const lossWarn = $derived(Boolean(stats && stats.lossPercent > 3));
  const policySourceLabel = $derived(policy.source === "qkey" ? "QKey" : "Default");
  const recoveredLabel = $derived(stats ? `${stats.fecRecoveredPackets}` : "-");
</script>

<section class="relative z-10 flex-none shrink-0 basis-[272px] h-[272px] max-h-[272px] min-h-[272px] overflow-hidden rounded-[14px] border border-[rgba(255,255,255,0.86)] glass-pane-pill px-4 py-3 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_10px_24px_rgba(34,38,62,0.11),0_2px_6px_rgba(0,0,0,0.05)]">
  <div class="flex h-full flex-col overflow-hidden">

    <!-- Header: flag pill + name only (IP moved to left column as first pill) -->
    <div class="shrink-0 h-[32px] flex items-center justify-between gap-2 min-w-0 relative">
      <div class="flex items-center gap-1.5 min-w-0 overflow-hidden">
        {#if tunnel}
          <span class={cn(WHITE_PILL, "shrink-0 gap-1 !py-[2px]")} style={PILL_BACKDROP}>
            <span class="text-[10px] leading-none">{flag || "🌐"}</span>
            <span class="text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75">{tunnel.countryCode ?? "XX"}</span>
          </span>
          <span class="min-w-0 truncate text-[12px] font-semibold text-black dashboard-heading-sans">{tunnel.name}</span>
        {:else}
          <span class="text-[12px] font-semibold text-black/30 dashboard-heading-sans">No tunnel selected</span>
        {/if}
      </div>
      <span class={cn("text-[10px] font-semibold shrink-0 min-w-[52px] text-right tabular-nums", state === "inactive" ? "invisible" : statusClass)}>{statusLabel}</span>
      <div class="absolute bottom-0 left-0 right-0 h-px bg-gradient-to-r from-black/[0.09] via-black/[0.05] to-transparent pointer-events-none" aria-hidden="true"></div>
    </div>

    <!-- Content grid: left=200px fixed controls, right=chart gets remaining space (~8% narrower than before) -->
    <div class="grid flex-1 min-h-0 grid-cols-[200px_1fr] items-stretch gap-2.5 pt-2">

      <!-- Left column: 3 groups distributed evenly (pills / stealth-fec / connect) -->
      <div class="min-w-0 flex flex-col justify-between">
        <!-- Top: info pills -->
        <div class="flex flex-col items-start gap-[5px]">
          {#if tunnel}
            <span title={tunnel.remote} class={cn(WHITE_PILL, "max-w-full gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
              <span class="text-[8px] font-bold text-black/50 shrink-0">IP</span>
              <span class="min-w-0 truncate text-[9px] font-semibold text-black tabular-nums">{tunnel.remote}</span>
            </span>
            <span title={sniDisplay} class={cn(WHITE_PILL, "max-w-full gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
              <span class="text-[8px] font-bold text-black/50 shrink-0">SNI</span>
              <span class="min-w-0 truncate text-[9px] font-semibold text-black">{sniDisplay}</span>
            </span>
            <div class="flex items-center gap-[5px]">
              <span class={cn(WHITE_PILL, "max-w-full gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
                <span class="text-[8px] font-bold text-black/50 shrink-0">CC</span>
                <span class="text-[9px] font-semibold text-black">{displayCcMode(policy.cc)}</span>
              </span>
              <span class={cn(WHITE_PILL, "max-w-full gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
                <span class="text-[8px] font-bold text-black/50 shrink-0">MTU</span>
                <span class="text-[9px] font-semibold text-black">{displayMtu(policy.mtu)}</span>
              </span>
            </div>
          {/if}
        </div>
        <!-- Middle: Stealth/FEC card -->
        <div class="relative h-[64px] w-full rounded-[10px] border border-[rgba(255,255,255,0.82)] bg-white/72 shadow-[inset_0_1px_0_rgba(255,255,255,0.88),0_1px_3px_rgba(18,26,44,0.08)] flex overflow-hidden">
          <div class="relative flex-1 min-w-0 px-2.5 pt-[8px] pb-[8px] flex flex-col overflow-hidden">
            {#if tunnel && stealthIsIntelligent}
              <span class="absolute right-1.5 top-[6px] inline-flex h-[13px] items-center justify-center rounded-[4px] border min-w-[13px] px-[2px] text-[7px] font-bold leading-none border-[rgba(255,255,255,0.82)] bg-white/82 text-[rgb(22,163,74)] shadow-[inset_0_1px_0_rgba(255,255,255,0.86),0_1px_2px_rgba(18,26,44,0.12)]">I</span>
            {/if}
            <span class="text-[9px] font-semibold text-black tracking-[0.03em] leading-none truncate pr-4">Stealth Mode</span>
            <span class="mt-auto w-full text-[10px] font-semibold truncate text-center text-[#6366f1] leading-none">{stealthMode}</span>
            <span class="mt-[3px] flex items-center justify-center gap-[2px] leading-none invisible" aria-hidden="true">
              <span class="text-[7px] font-semibold">-</span>
            </span>
          </div>
          <div class="w-px self-stretch my-[10px] bg-gradient-to-b from-transparent via-black/[0.09] to-transparent shrink-0" aria-hidden="true"></div>
          <div class="relative flex-1 min-w-0 px-2.5 pt-[8px] pb-[8px] flex flex-col overflow-hidden">
            {#if tunnel}
              <span class="absolute right-1.5 top-[6px] inline-flex h-[13px] items-center justify-center rounded-[4px] border min-w-[18px] px-1 text-[7px] font-semibold leading-none border-[rgba(255,255,255,0.82)] bg-white/82 text-black/65 shadow-[inset_0_1px_0_rgba(255,255,255,0.86),0_1px_2px_rgba(18,26,44,0.12)]">{fecBadgeLabel}</span>
            {/if}
            <span class="text-[9px] font-semibold text-black tracking-[0.03em] leading-none truncate pr-6">FEC</span>
            <span class="mt-auto w-full text-[10px] font-semibold text-center text-[#6366f1] leading-none tabular-nums">{fecActivity}</span>
            <span class={cn("mt-[3px] flex items-center justify-center gap-[2px] leading-none", stats ? "visible" : "invisible")}>
              <span class="text-[7px] font-semibold text-black/38">Loss</span>
              <span class={cn("text-[8px] font-semibold tabular-nums", lossWarn ? "text-warning" : "text-black/55")}>{lossLabel}</span>
            </span>
          </div>
        </div>
        <!-- Bottom: Connect button flush with chart bottom -->
        <div class="flex w-full gap-1.5">
          <ConnectButton
            state={connectState}
            onclick={ontoggle}
            disabled={actionDisabled}
            {hasQKey}
            class="min-w-0 flex-1"
            buttonClass="w-full h-[32px]"
          />
          {#if tunnel?.circuit && state === "active"}
            <button
              type="button"
              use:ripple
              onclick={onrotate}
              disabled={rotationDisabled || tunnel.circuit.maxParallelCircuits !== 2}
              aria-label="Rotate circuit"
              title="Build a fresh circuit generation, verify readiness, then switch"
              class="action-refresh-btn inline-flex h-[32px] w-[32px] shrink-0 items-center justify-center rounded-lg border disabled:cursor-not-allowed disabled:opacity-45"
            >
              <RefreshCw class="h-3.5 w-3.5" strokeWidth={2.1} />
            </button>
          {/if}
        </div>
      </div>

      <!-- Right column: chart fills all remaining width -->
      <div class="w-full h-full flex flex-col rounded-[8px] border border-black/[0.06] bg-white/50 shadow-[inset_0_1px_0_rgba(255,255,255,0.9),0_1px_2px_rgba(18,26,44,0.05)] overflow-hidden">
        <!-- Chart header: uptime + LED, h-[22px] fixed -->
        <div class="shrink-0 h-[22px] flex items-center justify-between px-3 border-b border-black/[0.04]">
          <span class="flex items-center gap-1.5">
            <Clock3 class="w-[9px] h-[9px] text-black/55 shrink-0" strokeWidth={2.35} />
            <span class="text-[9px] font-semibold text-black/60 tabular-nums min-w-[38px]">{uptime}</span>
          </span>
          <span
            class="h-[8px] w-[8px] rounded-full shrink-0 transition-colors duration-300"
            class:status-dot-active={state === 'active'}
            class:status-dot-transition={state === 'activating' || state === 'deactivating'}
            class:status-dot-idle={state === 'inactive'}
            aria-hidden="true"
          ></span>
        </div>
        <!-- Chart body: flex-1, fills all remaining vertical space -->
        <div class="relative flex-1 min-h-0 overflow-hidden bg-[linear-gradient(180deg,rgba(255,255,255,0.95)_0%,rgba(250,249,255,0.85)_50%,rgba(248,246,254,0.8)_100%)]">
          <ThroughputChart
            downBps={throughput?.downBps ?? 0}
            upBps={throughput?.upBps ?? 0}
            isActive={state !== "inactive"}
          />
          <div
            class="absolute inset-0 flex items-center justify-center bg-[rgba(248,248,252,0.55)] transition-opacity duration-300 pointer-events-none"
            class:opacity-100={state === 'inactive'}
            class:opacity-0={state !== 'inactive'}
          >
            <span class="text-[8px] font-semibold text-black/22 tracking-[0.08em] uppercase select-none">No Signal</span>
          </div>
        </div>
        <!-- Chart footer: stats row, fixed grid columns - no layout shift ever -->
        <div class="shrink-0 h-[22px] grid grid-cols-4 items-center px-2 border-t border-black/[0.04] bg-white/40">
          <div class="flex items-center gap-1 justify-start overflow-hidden">
            <span class="font-bold text-[10px] leading-none text-[rgba(99,102,241,0.82)] shrink-0">&#8595;</span>
            <span class="text-[9px] font-semibold text-[rgba(99,102,241,0.9)] tabular-nums truncate">{downRate}</span>
          </div>
          <div class="flex items-center gap-1 justify-start overflow-hidden">
            <span class="font-bold text-[10px] leading-none text-[rgba(139,92,246,0.78)] shrink-0">&#8593;</span>
            <span class="text-[9px] font-semibold text-[rgba(139,92,246,0.85)] tabular-nums truncate">{upRate}</span>
          </div>
          <div class="flex items-center gap-1 justify-start overflow-hidden">
            <Zap class="w-[9px] h-[9px] text-black fill-black shrink-0" strokeWidth={1.5} />
            <span class="text-[9px] font-semibold text-black/60 tabular-nums truncate">{latencyLabel}</span>
          </div>
          <div class="flex items-center gap-1 justify-start overflow-hidden">
            <ArrowDownUp class="w-[9px] h-[9px] text-black shrink-0" strokeWidth={2.6} />
            <span class="text-[9px] font-semibold text-black/65 tabular-nums truncate">{downTotal}</span>
            <span class="text-[8px] text-black/30 select-none shrink-0">/</span>
            <span class="text-[9px] font-semibold text-black/65 tabular-nums truncate">{upTotal}</span>
          </div>
        </div>
      </div>

    </div>
  </div>
</section>

<style>
  /* Status LED pulse - breathing animation for connection state indicator.
     Location: TunnelStats > chart header row, right side.
     Active = green breathing pulse, Transition = faster amber pulse, Idle = static red. */
  @keyframes status-pulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.35); opacity: 0.85; }
  }
  .status-dot-active {
    background-color: #22c55e;
    box-shadow: 0 0 8px 2px rgba(34, 197, 94, 0.65);
    animation: status-pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    will-change: transform, opacity;
  }
  .status-dot-transition {
    background-color: #f59e0b;
    box-shadow: 0 0 8px 2px rgba(245, 158, 11, 0.6);
    animation: status-pulse 1.6s cubic-bezier(0.4, 0, 0.6, 1) infinite;
    will-change: transform, opacity;
  }
  .status-dot-idle {
    background-color: rgba(180, 180, 190, 0.4);
  }
</style>
