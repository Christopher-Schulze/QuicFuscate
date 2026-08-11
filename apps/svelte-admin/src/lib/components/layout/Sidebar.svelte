<script lang="ts">
  import {
    LayoutDashboard,
    SlidersHorizontal,
    Terminal,
    Info,
    Power,
  } from "@lucide/svelte";
  import { cn } from "@quicfuscate/ui";
  import {
    getActiveTab,
    setActiveTab,
    getConfigDirty,
    setConfigDirty,
    getLogsDirty,
    setLogsDirty,
    setAuthRequired,
    setAuthError,
    confirmDialog,
  } from "$lib/stores/app.svelte";
  import { postJson, sanitizeErrorMessage } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";
  import type { NavTab } from "$lib/types";
  import appLogo from "../../../../../../assets/logo/QuicFuscate_clean.png";

  interface Props {
    lockToConfig?: boolean;
  }

  let { lockToConfig = false }: Props = $props();

  const TABS: { id: NavTab; label: string; icon: typeof LayoutDashboard }[] = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "configuration", label: "Configuration", icon: SlidersHorizontal },
    { id: "logs", label: "Logs", icon: Terminal },
    { id: "about", label: "About", icon: Info },
  ];

  // Sliding pill: track Y offset per tab via bind:this on each button
  let navButtons: Record<string, HTMLButtonElement | undefined> = $state({});
  let navContainer: HTMLDivElement | undefined = $state();

  const pillStyle = $derived.by(() => {
    const tab = getActiveTab();
    const btn = navButtons[tab];
    const container = navContainer;
    if (!btn || !container) return "opacity: 0;";
    const containerRect = container.getBoundingClientRect();
    const btnRect = btn.getBoundingClientRect();
    const top = btnRect.top - containerRect.top;
    const height = btnRect.height;
    return `transform: translateY(${top}px); height: ${height}px; opacity: 1;`;
  });

  async function confirmUnsavedLeave(): Promise<boolean> {
    const active = getActiveTab();
    if (active === "configuration" && getConfigDirty()) {
      const proceed = await confirmDialog({
        title: "Unsaved Changes",
        message: "You have unsaved configuration changes. Leave without saving?",
        confirmLabel: "Leave",
        cancelLabel: "Cancel",
      });
      if (!proceed) return false;
      setConfigDirty(false);
      return true;
    }
    if (active === "logs" && getLogsDirty()) {
      const proceed = await confirmDialog({
        title: "Unsaved Changes",
        message: "You have unsaved logging changes. Leave without saving?",
        confirmLabel: "Leave",
        cancelLabel: "Cancel",
      });
      if (!proceed) return false;
      setLogsDirty(false);
      return true;
    }
    return true;
  }

  async function handleLogout() {
    if (!(await confirmUnsavedLeave())) return;
    try {
      await postJson("/api/logout", {}, adminApiSchemas.logout);
      setAuthRequired(true);
    } catch (e: unknown) {
      const msg = sanitizeErrorMessage(
        e instanceof Error ? e.message : String(e),
        "Logout failed",
      );
      setAuthError(msg);
      setAuthRequired(true);
    }
  }

  async function handleTabClick(tabId: NavTab) {
    if (lockToConfig && tabId !== "configuration") return;
    if (tabId === getActiveTab()) return;
    const active = getActiveTab();
    if (active === "configuration" && getConfigDirty()) {
      if (!(await confirmUnsavedLeave())) return;
    } else if (active === "logs" && getLogsDirty()) {
      if (!(await confirmUnsavedLeave())) return;
    }
    setActiveTab(tabId);
  }
</script>

<nav
  aria-label="Primary"
  data-ripple="off"
  class="w-[152px] shrink-0 glass-sidebar px-3 py-4 flex flex-col h-full rounded-b-[16px] overflow-hidden"
>
  <div data-tauri-drag-region class="h-3 shrink-0"></div>

  <div class="px-2 pb-4 flex flex-col items-center justify-center gap-1">
    <img
      src={appLogo}
      alt="QuicFuscate logo"
      class="h-[44px] w-[44px] object-contain select-none"
      draggable="false"
    />
  </div>

  <div bind:this={navContainer} class="flex flex-col gap-1 relative flex-1">
    <!-- Sliding glass pill indicator -->
    <div
      class="absolute left-0 right-0 rounded-lg pointer-events-none z-0"
      style="
        transition: transform 340ms cubic-bezier(0.22, 1.36, 0.38, 1), height 240ms cubic-bezier(0.22, 1.36, 0.38, 1), opacity 200ms;
        background: rgba(255,255,255,0.65);
        backdrop-filter: blur(24px) saturate(200%);
        -webkit-backdrop-filter: blur(24px) saturate(200%);
        border: 1px solid rgba(255,255,255,0.60);
        box-shadow: inset 0 1px 0.5px rgba(255,255,255,0.55), 0 3px 10px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.03);
        will-change: top, opacity;
        transform: translateZ(0);
        {pillStyle}
      "
    ></div>

    {#each TABS as t (t.id)}
      {@const isActive = t.id === getActiveTab()}
      {@const disabled = lockToConfig && t.id !== "configuration"}
      <button
        bind:this={navButtons[t.id]}
        {disabled}
        aria-label={t.label}
        onclick={() => { void handleTabClick(t.id); }}
        class={cn(
          "relative w-full px-3 py-2 rounded-md text-left text-[12px]",
          "cursor-pointer flex items-center gap-2 transition-colors z-[1]",
          disabled && "opacity-45 cursor-not-allowed",
          isActive
            ? "text-text-primary font-semibold"
            : "text-text-secondary",
        )}
      >
        <t.icon class="relative z-10 h-[14px] w-[14px] opacity-80" strokeWidth={isActive ? 2 : 1.6} />
        <span class="relative z-10">{t.label}</span>
      </button>
    {/each}

    <button
      onclick={() => { void handleLogout(); }}
      class={cn(
        "relative w-full px-3 py-2 rounded-md text-left text-[12px]",
        "cursor-pointer flex items-center gap-2 z-[1]",
        "text-text-secondary transition-colors",
      )}
    >
      <Power class="h-[14px] w-[14px] opacity-80" />
      <span>Logout</span>
    </button>
  </div>
</nav>
