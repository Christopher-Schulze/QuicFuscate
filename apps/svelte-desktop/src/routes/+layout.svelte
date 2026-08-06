<script lang="ts">
  import "../app.css";
  import faviconUrl from "$lib/assets/favicon.png";
  import { Toast, addToast, createOwnedTimeout } from "@quicfuscate/ui";
  import Sidebar from "$lib/components/layout/Sidebar.svelte";
  import ErrorBanner from "$lib/components/ui/ErrorBanner.svelte";
  import FatalErrorScreen from "$lib/components/ui/FatalErrorScreen.svelte";
  import { getError, setError, getHydrationDone, getActiveTab, setActiveTab } from "$lib/stores/app.svelte";
  import {
    isTauri,
    loadPersistedState,
    startSettingsListener,
    startEnginePollers,
    persistState,
  } from "$lib/stores/tauri-bridge.svelte";
  import { createPersistenceQueue } from "$lib/persistence-queue";
  import {
    getTunnels,
    getSelectedId,
    getSettings,
  } from "$lib/stores/app.svelte";
  import { toErrorMessage } from "$lib/format";

  let { children } = $props();
  let hydrated = $state(false);
  let fatalError = $state<string | null>(null);
  let renderEpoch = $state(0);

  const error = $derived(getError());
  const hydrationDone = $derived(getHydrationDone());

  // Debounced persist
  const persistDebounce = createOwnedTimeout();
  const persistQueue = createPersistenceQueue(persistState);
  const tunnels = $derived(getTunnels());
  const selectedId = $derived(getSelectedId());
  const settings = $derived(getSettings());

  function isIgnorableRuntimeMessage(message: string): boolean {
    return message.includes("ResizeObserver loop") || message.includes("Script error.");
  }

  function shouldIgnoreShortcutTarget(target: EventTarget | null): boolean {
    if (!(target instanceof HTMLElement)) return false;
    return target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable;
  }

  function resetFatalError() {
    fatalError = null;
    setError(null);
    renderEpoch += 1;
  }

  $effect(() => {
    hydrated = true;
    document.body.style.visibility = "visible";
  });

  $effect(() => {
    void tunnels;
    void selectedId;
    void settings;
    if (!hydrationDone) {
      persistDebounce.cancel();
      return;
    }
    persistDebounce.schedule(persistQueue.queue, 400);
  });

  function persistNow(): void {
    persistDebounce.cancel();
    persistQueue.queue();
  }

  // Persist on visibility change and before unload
  $effect(() => {
    if (!isTauri()) return;
    const handleVisibility = () => {
      if (document.visibilityState === "hidden") persistNow();
    };
    const handleBeforeUnload = () => {
      persistNow();
    };
    document.addEventListener("visibilitychange", handleVisibility);
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibility);
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  });

  $effect(() => {
    const handleWindowError = (event: ErrorEvent) => {
      if (!event.error) return;
      const message = toErrorMessage(event.error);
      if (isIgnorableRuntimeMessage(message)) return;
      fatalError = message;
    };
    const handleUnhandledRejection = (event: PromiseRejectionEvent) => {
      if (!(event.reason instanceof Error)) return;
      const message = toErrorMessage(event.reason);
      if (isIgnorableRuntimeMessage(message)) return;
      fatalError = message;
    };
    window.addEventListener("error", handleWindowError);
    window.addEventListener("unhandledrejection", handleUnhandledRejection);
    return () => {
      window.removeEventListener("error", handleWindowError);
      window.removeEventListener("unhandledrejection", handleUnhandledRejection);
    };
  });

  $effect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (!(event.metaKey || event.ctrlKey)) return;
      if (shouldIgnoreShortcutTarget(event.target)) return;
      const key = event.key.toLowerCase();
      switch (key) {
        case "1":
          event.preventDefault();
          setActiveTab("tunnels");
          return;
        case "2":
          event.preventDefault();
          setActiveTab("settings");
          return;
        case "3":
          event.preventDefault();
          setActiveTab("logs");
          return;
        case "4":
          event.preventDefault();
          setActiveTab("about");
          return;
        case "n":
          event.preventDefault();
          setActiveTab("tunnels");
          window.dispatchEvent(new CustomEvent("qf:new-tunnel"));
          return;
        case "c":
          event.preventDefault();
          setActiveTab("tunnels");
          window.dispatchEvent(new CustomEvent("qf:toggle-connect"));
          return;
        case "d":
          event.preventDefault();
          setActiveTab("tunnels");
          window.dispatchEvent(new CustomEvent("qf:disconnect-active"));
          return;
        case "/":
          event.preventDefault();
          addToast("Shortcuts: Cmd/Ctrl+1-4 navigate, Cmd/Ctrl+N new tunnel, Cmd/Ctrl+C connect, Cmd/Ctrl+D disconnect.", "info");
          return;
        default:
          return;
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  });

  // Bootstrap
  $effect(() => {
    void loadPersistedState();
    const stopSettings = startSettingsListener();
    const stopPollers = startEnginePollers();
    return () => {
      stopSettings?.();
      stopPollers();
      persistQueue.stop();
      persistDebounce.destroy();
    };
  });
</script>

<svelte:head>
  <link rel="icon" href={faviconUrl} />
  <title>QuicFuscate</title>
</svelte:head>

<div
  id="qf-app-stage"
  data-hydrated={hydrated ? "true" : "false"}
  class="desktop-stage flex flex-col h-full w-full bg-transparent overflow-hidden text-text-primary select-none"
>
  <Toast />
  <div class="flex flex-1 min-h-0">
    <Sidebar />
    <main class="flex-1 flex flex-col min-h-0 bg-transparent">
      {#if error}
        <ErrorBanner error={error} ondismiss={() => setError(null)} />
      {/if}
      <div class="flex flex-col flex-1 min-h-0 content-typography">
        {#if fatalError}
          <FatalErrorScreen error={fatalError} onretry={resetFatalError} />
        {:else}
          {#key renderEpoch}
            {@render children()}
          {/key}
        {/if}
      </div>
    </main>
  </div>
</div>
