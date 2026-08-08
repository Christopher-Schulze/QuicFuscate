<script lang="ts">
  import { SlidersHorizontal } from "@lucide/svelte";
  import { ripple } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";
  import { countryCodeToFlag } from "$lib/format";
  import { parseRemote } from "$lib/tunnel-validators";
  import { WHITE_PILL, PILL_BACKDROP } from "$lib/pill-styles";
  import { displayStealthMode, displayFecMode, displayCcMode, displayMtu } from "$lib/policy-display";
  import type { TunnelConfig, TunnelPolicyView } from "$lib/types";

  interface Props {
    tunnel: TunnelConfig;
    isSelected: boolean;
    policy: TunnelPolicyView;
    onselect: () => void;
    onconfigure: () => void;
    onremove: () => void;
  }

  let { tunnel, isSelected, policy, onselect, onconfigure, onremove }: Props = $props();

  const flag = $derived(countryCodeToFlag(tunnel.countryCode));
  // Splitting on ":" is only correct for host:port; for the bracketed IPv6 form
  // [2001:db8::1]:4433 it renders "[". parseRemote already handles both.
  const sniDisplay = $derived(tunnel.sni || parseRemote(tunnel.remote)?.server || "-");
</script>

<div
  data-tunnel-card
  data-tunnel-id={tunnel.id}
  class="relative h-full text-left tunnel-card-shell"
>
  <button
    use:ripple={{ color: "light" }}
    type="button"
    data-selected={isSelected ? "true" : undefined}
    onclick={onselect}
    class={cn(
      "relative z-10 flex h-full w-full flex-col overflow-hidden rounded-[12px] tunnel-card-surface cursor-pointer text-left",
      "glass-pane-pill border px-3 py-3 transition-[border-color,background,box-shadow] duration-200",
      "border-[rgba(240,238,246,0.98)] bg-[rgba(255,255,255,0.8)] shadow-[0_6px_14px_rgba(25,30,48,0.08),0_1px_2px_rgba(0,0,0,0.04)]",
    )}
  >
    <div class="relative min-w-0 w-full flex h-full flex-col justify-between pr-[40px]">
      <div class="flex items-start gap-2">
        <div class="min-w-0">
          <div class="text-[12px] font-semibold text-black dashboard-heading-sans truncate pl-1">
            {tunnel.name}
          </div>
          <div class="mt-1 flex items-center gap-1.5 min-w-0">
            <span class={cn(WHITE_PILL, "shrink-0 gap-1")} style={PILL_BACKDROP}>
              <span class="text-[10px] leading-none">{flag || "🌐"}</span>
              <span class="text-[8px] font-semibold tracking-[0.08em] dashboard-heading-sans text-black/75">
                {tunnel.countryCode ?? "XX"}
              </span>
            </span>
            <span class={cn(WHITE_PILL, "gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
              <span class="text-[8px] font-bold text-black/50 shrink-0">IP</span>
              <span class="min-w-0 truncate text-[9px] font-semibold text-black tabular-nums">{tunnel.remote}</span>
            </span>
          </div>
          <div class="mt-1 flex items-center gap-1.5 min-w-0">
            <span class={cn(WHITE_PILL, "gap-1.5 overflow-hidden")} style={PILL_BACKDROP}>
              <span class="text-[8px] font-bold text-black/50 shrink-0">SNI</span>
              <span class="min-w-0 truncate text-[9px] font-semibold text-black">{sniDisplay}</span>
            </span>
          </div>
        </div>
      </div>
      <div class="flex items-end gap-2 pt-1">
        <div class="pb-0.5 flex items-center gap-1.5 min-w-0">
          <span
            class={cn(WHITE_PILL, "max-w-full gap-1 text-[9px]")}
            style={PILL_BACKDROP}
          >
            <span class="text-[8px] font-bold text-black/50">Stealth</span>
            <span class="font-semibold text-black">{displayStealthMode(policy.stealth)}</span>
            <span class="text-black/20">|</span>
            <span class="text-[8px] font-bold text-black/50">FEC</span>
            <span class="font-semibold text-black">{displayFecMode(policy.fec)}</span>
            <span class="text-black/20">|</span>
            <span class="text-[8px] font-bold text-black/50">CC</span>
            <span class="font-semibold text-black">{displayCcMode(policy.cc)}</span>
            <span class="text-black/20">|</span>
            <span class="text-[8px] font-bold text-black/50">MTU</span>
            <span class="font-semibold text-black">{displayMtu(policy.mtu)}</span>
          </span>
        </div>
      </div>
    </div>
  </button>
  <span
    class="absolute right-[16px] top-[12px] z-20 flex h-[20px] w-[20px] items-center justify-center pointer-events-none"
    class:indicator-enter={isSelected}
    class:indicator-exit={!isSelected}
  >
    <span
      class="absolute h-[18px] w-[18px] rounded-[7px] bg-[rgba(95,103,246,0.22)] blur-[1px]"
      class:indicator-glow={isSelected}
      class:indicator-glow-out={!isSelected}
    ></span>
    <span
      class="tunnel-card-indicator"
      class:indicator-dot={isSelected}
      class:indicator-dot-out={!isSelected}
    ></span>
  </span>
  <button
    use:ripple={{ color: "light" }}
    type="button"
    onclick={(event) => { event.stopPropagation(); onconfigure(); }}
    aria-label="Open configuration"
    title="Configuration"
    class="absolute right-[16px] bottom-[12px] z-20 shrink-0 inline-flex h-[20px] w-[20px] items-center justify-center rounded-[7px] cursor-pointer border border-[rgba(255,255,255,0.76)] bg-[rgba(255,255,255,0.75)] text-[rgba(0,0,0,0.70)] shadow-[inset_0_1px_0_rgba(255,255,255,0.85),0_1px_2px_rgba(18,26,44,0.08)]"
  >
    <SlidersHorizontal class="h-[10px] w-[10px] text-black" strokeWidth={2} />
  </button>
</div>

<style>
  @keyframes indicator-scale-in {
    0% { opacity: 0; transform: scale(0.16); }
    70% { opacity: 1; transform: scale(1.2); }
    100% { opacity: 1; transform: scale(1); }
  }
  @keyframes indicator-glow-pulse {
    0% { opacity: 0; transform: scale(0.5); }
    62% { opacity: 0.46; transform: scale(1.2); }
    100% { opacity: 0.22; transform: scale(1); }
  }
  @keyframes indicator-container-in {
    0% { opacity: 0; transform: scale(0.32); }
    68% { opacity: 1; transform: scale(1.14); }
    100% { opacity: 1; transform: scale(1); }
  }
  .indicator-enter {
    animation: indicator-container-in 340ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
  }
  .indicator-glow {
    animation: indicator-glow-pulse 340ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
  }
  .indicator-dot {
    animation: indicator-scale-in 340ms cubic-bezier(0.2, 0.8, 0.2, 1) both;
  }
  /* Exit animations: reverse of enter */
  @keyframes indicator-container-out {
    0% { opacity: 1; transform: scale(1); }
    100% { opacity: 0; transform: scale(0.32); }
  }
  @keyframes indicator-scale-out {
    0% { opacity: 1; transform: scale(1); }
    100% { opacity: 0; transform: scale(0.16); }
  }
  @keyframes indicator-glow-out-kf {
    0% { opacity: 0.22; transform: scale(1); }
    100% { opacity: 0; transform: scale(0.5); }
  }
  .indicator-exit {
    animation: indicator-container-out 260ms cubic-bezier(0.4, 0, 1, 1) both;
  }
  .indicator-glow-out {
    animation: indicator-glow-out-kf 260ms cubic-bezier(0.4, 0, 1, 1) both;
  }
  .indicator-dot-out {
    animation: indicator-scale-out 260ms cubic-bezier(0.4, 0, 1, 1) both;
  }
</style>
