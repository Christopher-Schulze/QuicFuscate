export type UpdateChannel = "stable" | "beta";

export type UpdateAvailability =
  | { kind: "none" }
  | {
      kind: "available";
      version: string;
      currentVersion: string;
      date?: string;
      body?: string;
      mandatory: boolean;
    };

export type UpdateProgress =
  | { event: "started"; contentLength?: number }
  | { event: "progress"; chunkLength: number }
  | { event: "finished" };

export type UpdateUiState =
  | { status: "disabled"; reason: string }
  | { status: "idle" }
  | { status: "checking" }
  | { status: "no-update" }
  | {
      status: "available";
      version: string;
      currentVersion: string;
      date?: string;
      body?: string;
      mandatory: boolean;
    }
  | { status: "downloading"; progressBytes: number; totalBytes?: number }
  | { status: "installing" }
  | { status: "ready" }
  | { status: "signature-failure"; message: string }
  | { status: "error"; message: string };

interface PluginDownloadEvent {
  event: "Started" | "Progress" | "Finished";
  data: { contentLength?: number; chunkLength?: number };
}

export interface UpdaterHandle {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
  downloadAndInstall: (onEvent?: (progress: PluginDownloadEvent) => void) => Promise<void>;
}

export interface UpdaterDriver {
  check: () => Promise<UpdaterHandle | null>;
}

import { toErrorMessage } from "$lib/format";
import { parseUpdaterResult } from "$lib/ipc-contracts";

function isSignatureFailure(message: string): boolean {
  const normalized = message.toLowerCase();
  return normalized.includes("signature") || normalized.includes("pubkey") || normalized.includes("public key");
}

export async function createTauriUpdaterDriver(): Promise<UpdaterDriver> {
  const plugin = await import("@tauri-apps/plugin-updater");
  return {
    check: async (): Promise<UpdaterHandle | null> => {
      const result = await plugin.check();
      if (result === null || result === undefined) return null;
      // Casting the plugin result meant a drifted or malformed object could reach the
      // version display, and an install could be offered for an update object with no
      // working install callable.
      const validated = parseUpdaterResult(result);
      if (!validated) {
        throw new Error("The updater returned a malformed update object; refusing to use it.");
      }
      return {
        currentVersion: validated.currentVersion,
        version: validated.version,
        date: validated.date,
        body: validated.body,
        downloadAndInstall: (onEvent?: (progress: PluginDownloadEvent) => void) =>
          (result as UpdaterHandle).downloadAndInstall(onEvent),
      };
    },
  };
}

export function updaterEnabledByPolicy(
  isTauriRuntime: boolean,
  updaterEnabled: boolean,
  updaterRuntimeEnabled: boolean,
): { enabled: boolean; reason?: string } {
  if (!isTauriRuntime) {
    return { enabled: false, reason: "Updater is only available inside the desktop runtime." };
  }
  if (!updaterEnabled) {
    return {
      enabled: false,
      reason: "Updater is disabled by policy until signed binaries are published.",
    };
  }
  if (!updaterRuntimeEnabled) {
    return {
      enabled: false,
      reason: "Updater plugin is not active. Set QUICFUSCATE_DESKTOP_UPDATER_ACTIVE=true and restart.",
    };
  }
  return { enabled: true };
}

export async function checkForUpdates(
  driver: UpdaterDriver,
  mandatoryVersionPrefixes: string[] = [],
): Promise<UpdateAvailability> {
  const update = await driver.check();
  if (!update) {
    return { kind: "none" };
  }

  const mandatory = mandatoryVersionPrefixes.some((prefix) => update.version.startsWith(prefix));
  return {
    kind: "available",
    version: update.version,
    currentVersion: update.currentVersion,
    date: update.date,
    body: update.body,
    mandatory,
  };
}

export async function downloadAndInstallUpdate(
  update: UpdaterHandle,
  onProgress: (progress: UpdateProgress) => void,
): Promise<void> {
  let downloadedBytes = 0;
  await update.downloadAndInstall((progress) => {
    if (progress.event === "Started") {
      onProgress({ event: "started", contentLength: progress.data.contentLength });
      return;
    }
    if (progress.event === "Progress") {
      downloadedBytes += progress.data.chunkLength ?? 0;
      onProgress({ event: "progress", chunkLength: downloadedBytes });
      return;
    }
    onProgress({ event: "finished" });
  });
}

export function toTerminalUpdaterErrorState(error: unknown): UpdateUiState {
  const message = toErrorMessage(error);
  if (isSignatureFailure(message)) {
    return { status: "signature-failure", message };
  }
  return { status: "error", message };
}
