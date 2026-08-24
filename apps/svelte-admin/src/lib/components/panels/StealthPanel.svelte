<script lang="ts">
  import { Select, Switch } from "@quicfuscate/ui";
  import { CONGESTION_CONTROL_OPTIONS, parseCongestionControlAlgorithm } from "@quicfuscate/ui/congestion-control";
  import { slide } from "svelte/transition";
  import { cubicOut } from "svelte/easing";
  import type { StealthPresetUi, StealthManualSettings, CcSelection } from "$lib/types";
  import { parseMtu } from "$lib/config-helpers";

  interface Props {
    stealthPreset: StealthPresetUi;
    fecPreset: "auto" | "off";
    stealthManual: StealthManualSettings;
    transportCc: CcSelection;
    transportMtuText: string;
    onStealthChange: (v: StealthPresetUi) => void;
    onFecChange: (v: "auto" | "off") => void;
    onManualFlagChange: (key: keyof StealthManualSettings, value: boolean) => void;
    onCcChange: (v: CcSelection) => void;
    onMtuChange: (v: string) => void;
  }

  let {
    stealthPreset,
    fecPreset,
    stealthManual,
    transportCc,
    transportMtuText,
    onStealthChange,
    onFecChange,
    onManualFlagChange,
    onCcChange,
    onMtuChange,
  }: Props = $props();

  const STEALTH_OPTIONS = [
    { value: "auto", label: "Auto" },
    { value: "performance", label: "Performance" },
    { value: "stealth", label: "Stealth" },
    { value: "antidpi", label: "AntiDPI" },
    { value: "manual", label: "Manual" },
    { value: "off", label: "Off" },
  ];

  const FEC_OPTIONS = [
    { value: "auto", label: "Auto" },
    { value: "off", label: "Off" },
  ];

  const MANUAL_FLAGS: [keyof StealthManualSettings, string][] = [
    ["enable_domain_fronting", "Domain Fronting"],
    ["enable_http3_masquerading", "HTTP3 Masquerading"],
    ["use_tls_cover", "TLS Cover Extras"],
    ["use_qpack_headers", "QPACK Headers"],
    ["enable_traffic_padding", "Traffic Padding"],
    ["enable_timing_obfuscation", "Timing Obfuscation"],
    ["enable_protocol_mimicry", "Protocol Mimicry"],
    ["enable_doh", "DoH"],
  ];
</script>

<section class="rounded-xl glass border border-edge/70 px-5 pt-4 pb-5">
  <div class="mb-3 text-[11px] font-semibold text-black dashboard-heading-sans">Connection Presets</div>
  <div class="grid grid-cols-2 gap-x-8 pane-first-item-offset">
    <div class="flex min-w-0 flex-col gap-3">
      <div class="grid grid-cols-[64px_156px] items-center gap-2">
        <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Stealth</div>
        <Select
          value={stealthPreset}
          options={STEALTH_OPTIONS}
          onchange={(v) => onStealthChange(v as StealthPresetUi)}
          ariaLabel="Stealth preset"
        />
      </div>
      <div class="grid grid-cols-[64px_156px] items-center gap-2">
        <div class="text-[11px] font-semibold text-black dashboard-heading-sans">FEC</div>
        <Select
          value={fecPreset}
          options={FEC_OPTIONS}
          onchange={(v) => onFecChange(v as "auto" | "off")}
          ariaLabel="FEC preset"
        />
      </div>
    </div>
    <div class="flex min-w-0 flex-col gap-3">
      <div class="flex w-full items-center justify-between gap-3">
        <div class="text-[11px] font-semibold text-black whitespace-nowrap dashboard-heading-sans">Congestion Control</div>
        <div class="w-[156px] shrink-0">
          <Select
            class="w-full"
            value={transportCc}
            options={transportCc === "__custom__" ? [...CONGESTION_CONTROL_OPTIONS, { value: "__custom__", label: "Custom [from TOML]" }] : CONGESTION_CONTROL_OPTIONS}
            onchange={(v) => {
              const selected = parseCongestionControlAlgorithm(v);
              if (selected !== null) onCcChange(selected);
            }}
            ariaLabel="Congestion control"
          />
        </div>
      </div>
      <div class="flex w-full items-center justify-between gap-3">
        <div class="text-[11px] font-semibold text-black whitespace-nowrap dashboard-heading-sans">MTU</div>
        <input
          type="text"
          inputmode="numeric"
          aria-label="MTU"
          value={transportMtuText}
          maxlength={4}
          oninput={(e) => onMtuChange((e.target as HTMLInputElement).value.slice(0, 4))}
          class="w-[156px] shrink-0 h-8 min-h-8 px-2.5 rounded-md glass-nav-pill glass-select-edge text-[11px] text-black mono border-0 outline-none shadow-none ring-0 bg-transparent"
        />
      </div>
    </div>
  </div>

  {#if stealthPreset === "manual"}
    <div transition:slide={{ duration: 300, easing: cubicOut }} class="overflow-hidden border-t border-edge/60">
      <div class="mt-3 pt-3 pb-3">
        <div class="grid grid-cols-3 gap-2.5">
          {#each MANUAL_FLAGS as [key, label] (key)}
            <div class="flex w-full items-center justify-between rounded-lg glass-nav-pill px-2.5 py-1.5">
              <div class="text-[11px] text-black">{label}</div>
              <Switch
                checked={stealthManual[key]}
                onchange={(v) => onManualFlagChange(key, v)}
                {label}
              />
            </div>
          {/each}
        </div>
      </div>
    </div>
  {/if}
</section>
