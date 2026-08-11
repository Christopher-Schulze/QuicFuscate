<script lang="ts">
  import "../app.css";
  import faviconUrl from "$lib/assets/favicon.png";
  import { Toast, addToast, createOwnedTimeout } from "@quicfuscate/ui";
  import Sidebar from "$lib/components/layout/Sidebar.svelte";
  import ErrorBanner from "$lib/components/ui/ErrorBanner.svelte";
  import FatalErrorScreen from "$lib/components/ui/FatalErrorScreen.svelte";
  import {
    getError,
    setError,
    getHydrationDone,
    getActiveTab,
    setActiveTab,
    getPersistenceStatus,
    setPersistenceStatus,
  } from "$lib/stores/app.svelte";
  import {
    isTauri,
    loadPersistedState,
    startSettingsListener,
    startEnginePollers,
    persistState,
  } from "$lib/stores/tauri-bridge.svelte";
  import {
    createPersistenceQueue,
    type PersistenceFlushResult,
    type PersistenceQueueState,
  } from "$lib/persistence-queue";
  import {
    PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS,
    registerPersistenceCloseGuard,
  } from "$lib/persistence-lifecycle";
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
  let observedHydratedState = false;

  const error = $derived(getError());
  const hydrationDone = $derived(getHydrationDone());
  const persistenceStatus = $derived(getPersistenceStatus());
  const persistenceEnabled = $derived(
    persistenceStatus.phase !== "loading"
      && persistenceStatus.phase !== "browser"
      && persistenceStatus.phase !== "load-error",
  );

  // Debounced persist
  const persistDebounce = createOwnedTimeout();
  const persistQueue = createPersistenceQueue(persistState, { onChange: applyPersistenceQueueState });
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

  function applyPersistenceQueueState(state: PersistenceQueueState): void {
    const current = getPersistenceStatus();
    if (current.phase === "loading" || current.phase === "browser" || current.phase === "load-error") return;
    if (state.error) {
      setPersistenceStatus({ phase: "save-error", dirty: true, error: state.error });
      return;
    }
    if (state.saving) {
      setPersistenceStatus({ phase: "saving", dirty: true, error: null });
      return;
    }
    if (state.dirty) {
      setPersistenceStatus({ phase: "dirty", dirty: true, error: null });
      return;
    }
    setPersistenceStatus({ phase: "ready", dirty: false, error: null });
  }

  $effect(() => {
    hydrated = true;
    document.body.style.visibility = "visible";
  });

  $effect(() => {
    void tunnels;
    void selectedId;
    void settings;
    if (!hydrationDone || !persistenceEnabled) {
      persistDebounce.cancel();
      observedHydratedState = false;
      return;
    }
    if (!observedHydratedState) {
      observedHydratedState = true;
      return;
    }
    persistDebounce.schedule(persistQueue.queue, 400);
  });

  async function flushPersistence(timeoutMilliseconds: number): Promise<PersistenceFlushResult> {
    persistDebounce.cancel();
    return await persistQueue.flush(timeoutMilliseconds);
  }

  function retrySave(): void {
    void flushPersistence(PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS);
  }

  function retryLoad(): void {
    void loadPersistedState();
  }

  function useCurrentState(): void {
    setPersistenceStatus({ phase: "ready", dirty: false, error: null });
    void flushPersistence(PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS);
  }

  // Hidden windows receive the same bounded flush contract as explicit close requests.
  $effect(() => {
    if (!isTauri()) return;
    const handleVisibility = () => {
      if (document.visibilityState === "hidden" && persistenceEnabled) {
        void flushPersistence(PERSISTENCE_CLOSE_TIMEOUT_MILLISECONDS);
      }
    };
    document.addEventListener("visibilitychange", handleVisibility);
    return () => {
      document.removeEventListener("visibilitychange", handleVisibility);
    };
  });

  $effect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    let unlisten: (() => void) | null = null;
    (async () => {
      try {
        const off = await registerPersistenceCloseGuard(
          async (timeoutMilliseconds) => {
            const current = getPersistenceStatus();
            if (current.phase === "loading" || current.phase === "load-error") {
              return {
                status: "failed",
                message: "Stored desktop state must finish loading, be recovered, or be explicitly replaced before closing.",
              };
            }
            return await flushPersistence(timeoutMilliseconds);
          },
          setError,
        );
        if (cancelled) {
          off();
          return;
        }
        unlisten = off;
      } catch (cause) {
        setError(`Desktop close protection could not start: ${toErrorMessage(cause)}`);
      }
    })();
    return () => {
      cancelled = true;
      unlisten?.();
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
      {#if persistenceStatus.phase === "load-error"}
        <ErrorBanner
          error={`Stored desktop state could not be loaded: ${persistenceStatus.error}. Retry loading or explicitly replace it with the current state.`}
          primaryActionLabel="Retry Load"
          onprimaryaction={retryLoad}
          secondaryActionLabel="Use Current State"
          onsecondaryaction={useCurrentState}
        />
      {:else if persistenceStatus.phase === "save-error"}
        <ErrorBanner
          error={`Changes are not saved: ${persistenceStatus.error}`}
          primaryActionLabel="Retry Save"
          onprimaryaction={retrySave}
        />
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
