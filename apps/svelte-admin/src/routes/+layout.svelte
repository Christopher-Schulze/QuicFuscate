<script lang="ts">
  import "../app.css";
  import type { Snippet } from "svelte";
  import favicon from "$lib/assets/favicon.png";
  import { Toast, ConfirmDialog, ErrorBoundary } from "@quicfuscate/ui";
  import FatalErrorScreen from "$lib/components/ui/FatalErrorScreen.svelte";
  import Sidebar from "$lib/components/layout/Sidebar.svelte";
  import LoginModal from "$lib/components/LoginModal.svelte";
  import DashboardView from "$lib/components/views/DashboardView.svelte";
  import ConfigurationView from "$lib/components/views/ConfigurationView.svelte";
  import LogsView from "$lib/components/views/LogsView.svelte";
  import AboutView from "$lib/components/views/AboutView.svelte";
  import {
    getActiveTab,
    getAuthRequired,
    getAuthError,
    setAuthError,
    getRequiresPasswordChange,
    setRequiresPasswordChange,
    setAdminUser,
    setActiveTab,
    getConfigDirty,
    getLogsDirty,
    getConfirmDialogRequest,
    resolveConfirmDialog,
    cancelConfirmDialog,
    confirmDialog,
  } from "$lib/stores/app.svelte";
  import { ApiError, getJson, PASSWORD_CHANGE_EVENT } from "$lib/api";
  import { adminApiSchemas } from "$lib/admin-api-contracts";

  interface Props { children: Snippet; }
  let { children }: Props = $props();
  let hydrated = $state(false);

  const activeTab = $derived.by(() => getActiveTab());
  const authRequired = $derived.by(() => getAuthRequired());
  const authError = $derived.by(() => getAuthError());
  const requiresPasswordChange = $derived.by(() => getRequiresPasswordChange());
  const confirmRequest = $derived.by(() => getConfirmDialogRequest());
  const effectiveTab = $derived.by(() => (
    getRequiresPasswordChange() ? "configuration" : getActiveTab()
  ));

  // Confirmation policy: a newer request cancels the older caller, and teardown cancels the visible request.
  $effect(() => {
    const requestId = confirmRequest?.id;
    if (requestId === undefined) return;
    return () => cancelConfirmDialog(requestId);
  });

  function toErrorDetails(error: unknown): string {
    if (error instanceof Error) {
      return [error.name, error.message, error.stack].filter(Boolean).join("\n\n");
    }
    if (typeof error === "string") return error;
    try {
      return JSON.stringify(error, null, 2);
    } catch {
      return String(error);
    }
  }

  $effect(() => {
    setAuthError(null);
  });

  $effect(() => {
    hydrated = true;
    document.body.style.visibility = "visible";
  });

  // Global auth probe
  $effect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await getJson("/api/admin/auth", adminApiSchemas.adminAuthRead);
        if (cancelled) return;
        if (!resp.success || !resp.data) return;
        setAdminUser(resp.data.user || "admin");
        const lock = Boolean(resp.data.requires_password_change);
        setRequiresPasswordChange(lock);
        if (lock) setActiveTab("configuration");
      } catch (e: unknown) {
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) return;
      }
    })();
    return () => { cancelled = true; };
  });

  // Listen for 423 password change required
  $effect(() => {
    const onLock = () => {
      setRequiresPasswordChange(true);
      setActiveTab("configuration");
    };
    window.addEventListener(PASSWORD_CHANGE_EVENT, onLock);
    return () => {
      window.removeEventListener(PASSWORD_CHANGE_EVENT, onLock);
    };
  });

  // Unsaved changes guard: intercept reload/close when dirty with async confirmation
  function detectUnsavedScope(): string | null {
    const c = getConfigDirty();
    const l = getLogsDirty();
    if (c && l) return "configuration and logging";
    if (c) return "configuration";
    if (l) return "logging";
    return null;
  }

  function buildUnsavedConfirm(scope: string, action: "reload" | "close") {
    const verb = action === "reload" ? "Reload" : "Close";
    return {
      title: "Unsaved Changes",
      message: `You have unsaved ${scope} changes. ${verb} without saving?`,
      confirmLabel: verb,
      cancelLabel: "Cancel",
    };
  }

  $effect(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      const key = e.key.toLowerCase();
      const isReload = e.key === "F5" || ((e.metaKey || e.ctrlKey) && key === "r");
      const isClose = (e.metaKey || e.ctrlKey) && key === "w";
      if (!isReload && !isClose) return;
      const scope = detectUnsavedScope();
      if (!scope) return;
      e.preventDefault();
      e.stopPropagation();
      void (async () => {
        const accepted = await confirmDialog(
          buildUnsavedConfirm(scope, isReload ? "reload" : "close"),
        );
        if (!accepted) return;
        if (isReload) { window.location.reload(); return; }
        window.close();
      })();
    };
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (getConfigDirty() || getLogsDirty()) {
        e.preventDefault();
        e.returnValue = "";
      }
    };
    window.addEventListener("keydown", handleKeydown, true);
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("keydown", handleKeydown, true);
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  });
</script>

<svelte:head>
  <link rel="icon" href={favicon} />
</svelte:head>

<div
  id="qf-app-stage"
  data-hydrated={hydrated ? "true" : "false"}
  class="desktop-stage flex flex-col bg-transparent overflow-hidden"
>
  {#snippet appCrashFallback(error: unknown, reset: () => void)}
    <div class="flex flex-1 min-h-0">
      <FatalErrorScreen
        title="Something went wrong"
        description="An unexpected admin UI error occurred. Retry the page, copy the details, or reload the app."
        details={toErrorDetails(error)}
        onretry={reset}
        onreload={() => window.location.reload()}
      />
    </div>
  {/snippet}

  <ErrorBoundary fallback={appCrashFallback}>
    <LoginModal
      open={authRequired}
      error={authError}
      onClearError={() => setAuthError(null)}
    />
    <Toast />

    {#if confirmRequest}
      <ConfirmDialog
        open={true}
        title={confirmRequest.title}
        message={confirmRequest.message}
        confirmLabel={confirmRequest.confirmLabel}
        cancelLabel={confirmRequest.cancelLabel}
        portalTarget="#qf-app-stage"
        onconfirm={() => resolveConfirmDialog(confirmRequest.id, true)}
        oncancel={() => resolveConfirmDialog(confirmRequest.id, false)}
      />
    {/if}

    <div class="flex flex-1 min-h-0">
      <Sidebar lockToConfig={requiresPasswordChange} />
      <main class="flex-1 flex flex-col min-h-0 bg-transparent overflow-hidden">
        <div class="flex flex-col flex-1 min-h-0 content-typography">
          {#if effectiveTab === "dashboard"}
            <DashboardView />
          {:else if effectiveTab === "configuration"}
            <ConfigurationView />
          {:else if effectiveTab === "logs"}
            <LogsView />
          {:else if effectiveTab === "about"}
            <AboutView />
          {/if}
        </div>
      </main>
    </div>
    <div class="hidden">{@render children()}</div>
  </ErrorBoundary>
</div>
