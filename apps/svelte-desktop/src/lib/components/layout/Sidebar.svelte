<script lang="ts">
  import { Lock, SlidersHorizontal, Terminal, Info } from "@lucide/svelte";
  import { cn } from "@quicfuscate/ui";
  import { getActiveTab, setActiveTab } from "$lib/stores/app.svelte";
  import type { NavTab } from "$lib/types";
  import { t } from "@quicfuscate/i18n";
  import appLogo from "../../../../../../assets/logo/QuicFuscate_clean.png";

  const TABS: { id: NavTab; label: string; icon: typeof Lock }[] = [
    { id: "tunnels", label: t("desktop.nav.tunnels"), icon: Lock },
    { id: "settings", label: t("desktop.nav.settings"), icon: SlidersHorizontal },
    { id: "logs", label: t("desktop.nav.logs"), icon: Terminal },
    { id: "about", label: t("desktop.nav.about"), icon: Info },
  ];

  const TAB_HEIGHT = 32;
  const TAB_GAP = 4;

  const activeIndex = $derived(TABS.findIndex((t) => t.id === getActiveTab()));
  const pillTop = $derived(activeIndex >= 0 ? activeIndex * (TAB_HEIGHT + TAB_GAP) : 0);
</script>

<nav
  aria-label={t("desktop.nav.primary")}
  data-ripple="off"
  class="w-[152px] shrink-0 glass-sidebar px-3 py-4 flex flex-col h-[calc(100%-13px)] self-start rounded-b-[16px] overflow-hidden"
>
  <div data-tauri-drag-region class="h-3 shrink-0"></div>

  <div class="px-2 pb-4 flex flex-col items-center justify-center gap-1">
    <img
      src={appLogo}
      alt={t("desktop.brand.logo")}
      class="h-[44px] w-[44px] object-contain select-none"
      draggable="false"
    />
  </div>

  <div class="flex flex-col gap-1 relative flex-1">
    <div
      class="absolute left-0 right-0 h-[32px] rounded-lg pointer-events-none z-0"
      style="
        top: {pillTop}px;
        transition: top 340ms cubic-bezier(0.22, 1.36, 0.38, 1);
        background: rgba(255,255,255,0.65);
        backdrop-filter: blur(24px) saturate(200%);
        -webkit-backdrop-filter: blur(24px) saturate(200%);
        border: 1px solid rgba(255,255,255,0.60);
        box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
        will-change: top;
        transform: translateZ(0);
      "
    ></div>
    {#each TABS as tab (tab.id)}
      {@const isActive = tab.id === getActiveTab()}
      <button
        aria-label={tab.label}
        onclick={() => setActiveTab(tab.id)}
        class={cn(
          "relative w-full px-3 py-2 rounded-md text-left text-[12px] h-[32px]",
          "cursor-pointer flex items-center gap-2 transition-colors z-[1]",
          isActive
            ? "text-text-primary font-semibold"
            : "text-text-secondary",
        )}
      >
        <tab.icon class="relative z-10 h-[14px] w-[14px] opacity-80" strokeWidth={isActive ? 2 : 1.6} />
        <span class="relative z-10">{tab.label}</span>
      </button>
    {/each}
  </div>
</nav>
