<script lang="ts">
  const stealthItems = [
    { label: "dynamic", desc: "Starts like performance and escalates." },
    { label: "performance", desc: "Cheap browser baseline. Costly stealth stays off." },
    { label: "stealth", desc: "Balanced masking with adaptive padding." },
    { label: "Stealth MAX", desc: "Aggressive anti-censorship and detection resistance." },
    { label: "manual", desc: "Feature flags controlled explicitly." },
    { label: "off", desc: "No stealth features." },
  ];

  const ccItems = [
    { label: "Reno", desc: "TCP New Reno (RFC 6582) - conservative AIMD baseline." },
    { label: "BBR2", desc: "BBR v2 (IETF draft) - loss-aware model-based CC." },
    { label: "BBR3", desc: "Stealth-BBR3 with browser profile shaping (recommended)." },
  ];
</script>

<section class="rounded-xl glass border border-edge/70">
  <div class="px-5 pt-4 pb-4 dashboard-heading-sans">
    <div class="flex items-center gap-2 mb-4">
      <div class="text-[11px] font-semibold text-black dashboard-heading-sans">Reference Guide</div>
      <div class="h-px flex-1 bg-edge/55"></div>
    </div>

    <div class="grid grid-cols-2 gap-0">
      <!-- Left: Stealth -->
      <div class="pr-5 border-r border-white/50">
        <div class="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-2.5 dashboard-heading-sans">Stealth</div>
        {#each stealthItems as item (item.label)}
          <div class="flex items-baseline gap-1.5 py-[3px]">
            <span class="text-[10px] font-semibold text-black/75 shrink-0 dashboard-heading-sans w-[92px]">{item.label}</span>
            <span class="text-[10px] text-black/40 leading-[14px] dashboard-heading-sans">{item.desc}</span>
          </div>
        {/each}
      </div>
      <!-- Right: CC -->
      <div class="pl-5 pt-0 border-t-0 border-white/50">
        <div class="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-2.5 dashboard-heading-sans">Congestion Control</div>
        {#each ccItems as item (item.label)}
          <div class="flex items-baseline gap-1.5 py-[3px]">
            <span class="text-[10px] font-semibold text-black/75 shrink-0 dashboard-heading-sans w-[72px]">{item.label}</span>
            <span class="text-[10px] text-black/40 leading-[14px] dashboard-heading-sans">{item.desc}</span>
          </div>
        {/each}
      </div>
    </div>

    <div class="grid grid-cols-2 gap-0 mt-3 pt-3 border-t border-white/50">
      <div class="pr-5 border-r border-white/50">
        <div class="text-[11px] font-bold tracking-[0.08em] text-accent/70 mb-2.5 dashboard-heading-sans">FEC</div>
        <div class="flex items-baseline gap-1.5 py-[3px] dashboard-heading-sans">
          <span class="text-[10px] font-semibold text-black/75 shrink-0 w-[72px]">Auto</span>
          <span class="text-[10px] text-black/40 leading-[14px]">Adaptive FEC tunes redundancy.</span>
        </div>
      </div>
      <div class="pl-5">
        <div class="h-[22px] mb-1" aria-hidden="true"></div>
        <div class="flex items-baseline gap-1.5 py-[3px] dashboard-heading-sans">
          <span class="text-[10px] font-semibold text-black/75 shrink-0 w-[72px]">Off</span>
          <span class="text-[10px] text-black/40 leading-[14px]">FEC fully deactivated.</span>
        </div>
      </div>
    </div>
  </div>
</section>
