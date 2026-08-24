<script lang="ts">
  import { ripple } from "@quicfuscate/ui";
  import { getSettings, updateSettings } from "$lib/stores/app.svelte";
  import { isTauri, readUpdaterRuntimeEnabled } from "$lib/stores/tauri-bridge.svelte";
  import { Switch, Select } from "@quicfuscate/ui";
  import { cn } from "@quicfuscate/ui";
  import {
    checkForUpdates,
    createTauriUpdaterDriver,
    downloadAndInstallUpdate,
    toTerminalUpdaterErrorState,
    updaterEnabledByPolicy,
    type UpdateUiState,
    type UpdaterHandle,
  } from "$lib/updater";

  // Hard-locked until code-signing and release infrastructure is production-ready
  const UPDATER_UI_LOCKED = true;

  const settings = $derived(getSettings());
  const runtimeAvailable = $derived(isTauri());
  let updaterRuntimeEnabled = $state(false);
  let updaterState = $state<UpdateUiState>({
    status: "disabled",
    reason: "Updater is disabled by policy until signed binaries are published.",
  });
  let pendingUpdate = $state<UpdaterHandle | null>(null);

  const LOG_LEVELS = [
    { value: "error", label: "error" },
    { value: "warn", label: "warn" },
    { value: "info", label: "info" },
    { value: "debug", label: "debug" },
    { value: "trace", label: "trace" },
  ];

  function setLogLevel(level: string) {
    const normalized =
      level === "error" || level === "warn" || level === "debug" || level === "trace" ? level : "info";
    updateSettings((prev) => ({
      ...prev,
      general: { ...prev.general, logLevel: normalized as typeof prev.general.logLevel },
    }));
  }

  const SECTION = "rounded-xl glass border border-edge/70 overflow-hidden";
  const HEADER = "pane-header border-b border-edge px-4 py-2.5";
  const ROW = "flex items-center justify-between px-4 py-3 border-b border-edge/55 last:border-b-0";
  const LABEL = "text-[11px] font-semibold text-black dashboard-heading-sans";
  const DESC = "text-[10px] text-black dashboard-heading-sans mt-0.5";
  const updaterPolicy = $derived(
    updaterEnabledByPolicy(
      runtimeAvailable,
      UPDATER_UI_LOCKED ? false : settings.general.updaterEnabled,
      updaterRuntimeEnabled,
    )
  );
  const updaterStatusText = $derived.by(() => {
    switch (updaterState.status) {
      case "disabled":
        return updaterState.reason;
      case "idle":
        return "Idle";
      case "checking":
        return "Checking for updates";
      case "no-update":
        return "No update available";
      case "available":
        return `Update ${updaterState.version} available [current ${updaterState.currentVersion}]`;
      case "downloading": {
        const total = updaterState.totalBytes ? ` / ${updaterState.totalBytes}` : "";
        return `Downloading ${updaterState.progressBytes}${total} bytes`;
      }
      case "installing":
        return "Installing update package";
      case "ready":
        return "Update installed. Restart the app to apply it.";
      case "signature-failure":
        return `Signature failure: ${updaterState.message}`;
      case "error":
        return `Update error: ${updaterState.message}`;
      default:
        return "Updater status unavailable";
    }
  });

  $effect(() => {
    if (!runtimeAvailable) {
      updaterRuntimeEnabled = false;
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const enabled = await readUpdaterRuntimeEnabled();
        if (!cancelled) updaterRuntimeEnabled = Boolean(enabled);
      } catch {
        if (!cancelled) updaterRuntimeEnabled = false;
      }
    })();
    return () => {
      cancelled = true;
    };
  });

  $effect(() => {
    if (updaterPolicy.enabled) {
      if (updaterState.status === "disabled") {
        updaterState = { status: "idle" };
      }
      return;
    }
    pendingUpdate = null;
    updaterState = { status: "disabled", reason: updaterPolicy.reason ?? "Updater disabled." };
  });

  async function checkUpdates() {
    if (!updaterPolicy.enabled) {
      updaterState = { status: "disabled", reason: updaterPolicy.reason ?? "Updater disabled." };
      return;
    }
    pendingUpdate = null;
    updaterState = { status: "checking" };
    try {
      const driver = await createTauriUpdaterDriver();
      const update = await driver.check();
      if (!update) {
        updaterState = { status: "no-update" };
        return;
      }
      const availability = await checkForUpdates({ check: async () => update });
      if (availability.kind === "available") {
        pendingUpdate = update;
        updaterState = {
          status: "available",
          version: availability.version,
          currentVersion: availability.currentVersion,
          date: availability.date,
          body: availability.body,
          mandatory: availability.mandatory,
        };
        return;
      }
      updaterState = { status: "no-update" };
    } catch (error) {
      updaterState = toTerminalUpdaterErrorState(error);
    }
  }

  async function installPendingUpdate() {
    if (!pendingUpdate) return;
    let totalBytes: number | undefined;
    try {
      updaterState = { status: "downloading", progressBytes: 0 };
      await downloadAndInstallUpdate(pendingUpdate, (progress) => {
        if (progress.event === "started") {
          totalBytes = progress.contentLength;
          updaterState = { status: "downloading", progressBytes: 0, totalBytes };
          return;
        }
        if (progress.event === "progress") {
          updaterState = {
            status: "downloading",
            progressBytes: progress.chunkLength,
            totalBytes,
          };
          return;
        }
        updaterState = { status: "installing" };
      });
      updaterState = { status: "ready" };
    } catch (error) {
      updaterState = toTerminalUpdaterErrorState(error);
    }
  }
</script>

<div class="flex-1 h-full min-h-0 overflow-hidden">
  <div class="h-[calc(100%-13px)] w-full px-6 pt-4 pb-0 flex flex-col self-start">
    <div class="flex items-center justify-between">
      <div class="text-[14px] font-semibold text-text-primary dashboard-heading-sans">Configuration</div>
    </div>

    <div class="mt-3 flex flex-1 min-h-0 flex-col gap-2.5">
      <!-- Logging -->
      <section class={cn(SECTION, "shrink-0")}>
        <div class={HEADER}>
          <span class="text-[11px] font-semibold text-black dashboard-heading-sans">Logging</span>
        </div>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Log Level</div>
            <div class={DESC}>Affects desktop engine logs</div>
          </div>
          <Select
            options={LOG_LEVELS}
            value={settings.general.logLevel}
            onchange={setLogLevel}
            label="Log level"
            class="w-[96px]"
          />
        </div>
      </section>

      <!-- Startup -->
      <section class={cn(SECTION, "shrink-0")}>
        <div class={HEADER}>
          <span class="text-[11px] font-semibold text-black dashboard-heading-sans">Startup</span>
        </div>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Auto-connect on launch</div>
            <div class={DESC}>When enabled, the selected tunnel is connected when the app starts.</div>
          </div>
          <Switch
            checked={settings.general.autoConnectOnLaunch}
            label="Auto-connect on launch"
            onchange={(checked) =>
              updateSettings((prev) => ({
                ...prev,
                general: { ...prev.general, autoConnectOnLaunch: checked },
              }))
            }
          />
        </div>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Start at login</div>
            <div class={DESC}>Registers app autostart with the operating system.</div>
          </div>
          <Switch
            checked={settings.general.startAtLogin}
            label="Start at login"
            onchange={(checked) =>
              updateSettings((prev) => ({
                ...prev,
                general: { ...prev.general, startAtLogin: checked },
              }))
            }
          />
        </div>
      </section>

      <!-- Updates -->
      <section class={cn(SECTION, UPDATER_UI_LOCKED ? "opacity-65" : "", "relative shrink-0")}>
        <div class={HEADER}>
          <span class="text-[11px] font-semibold text-black dashboard-heading-sans">Updates</span>
        </div>
        <span
          aria-hidden="true"
          class="pointer-events-none absolute right-4 top-[11px] text-[11px] font-bold text-black"
        >Disabled in current source-first release</span>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Updater enabled</div>
            <div class={DESC}>Deferred until signed binaries and release signing are shipped.</div>
          </div>
          <Switch
            checked={UPDATER_UI_LOCKED ? false : settings.general.updaterEnabled}
            disabled={UPDATER_UI_LOCKED}
            label="Updater enabled"
            onchange={(checked) =>
              UPDATER_UI_LOCKED
                ? null
                : updateSettings((prev) => ({
                    ...prev,
                    general: { ...prev.general, updaterEnabled: checked },
                  }))
            }
          />
        </div>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Updater status</div>
            <div class={DESC}>No-update, available, download/install, and signature-failure states.</div>
          </div>
          <span class="w-[300px] max-w-[300px] text-right text-[11px] text-black whitespace-nowrap overflow-hidden text-ellipsis">
            {updaterStatusText}
          </span>
        </div>
        <div class={ROW}>
          <div>
            <div class={LABEL}>Actions</div>
            <div class={DESC}>Use check/install only when updater policy is enabled.</div>
          </div>
          <div class="flex items-center gap-2">
            <button
              type="button"
              use:ripple={{ color: "light" }}
              disabled={UPDATER_UI_LOCKED || !updaterPolicy.enabled || updaterState.status === "checking"}
              onclick={() => { void checkUpdates(); }}
              class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-neutral-btn h-auto min-w-0 disabled:opacity-55 disabled:cursor-not-allowed"
            >Check now</button>
            <button
              type="button"
              use:ripple={{ color: "light" }}
              disabled={UPDATER_UI_LOCKED || !pendingUpdate || updaterState.status === "downloading" || updaterState.status === "installing"}
              onclick={() => { void installPendingUpdate(); }}
              class="inline-flex items-center rounded-lg px-3 py-1.5 border text-[11px] font-semibold transition-all action-neutral-btn h-auto min-w-0 disabled:opacity-55 disabled:cursor-not-allowed"
            >Install</button>
          </div>
        </div>
      </section>
    </div>
  </div>
</div>
