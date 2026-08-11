import {
  getTunnels,
  setTunnels,
  getSelectedId,
  setSelectedId,
  getSettings,
  setSettings,
  updateSettings,
  getTunnelStates,
  setTunnelStates,
  updateTunnelStats,
  appendLogs,
  setError,
  setHydrationDone,
  getTunnelStats,
  setThroughput,
  getThroughput,
  setActiveTunnelId,
  getActiveTunnelId,
  setPersistenceStatus,
} from "./app.svelte";
import type { TunnelConfig, AppSettings, GeneralSettings, HardwareSettings } from "$lib/types";
import { parseTauriLogLine, type RawTauriLogLine } from "$lib/timestamp-boundary";
import {
  evaluateByteRateSample,
  isBrowserDocumentVisible,
  parseUnixMilliseconds,
  readBrowserMonotonicMilliseconds,
  type ByteCounterSample,
} from "@quicfuscate/time";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { parseEngineStats, parseEngineStatus } from "$lib/ipc-contracts";
import { toErrorMessage } from "$lib/format";

/** Shape returned by the Tauri `load_state` command. */
interface PersistedState {
  schemaVersion?: number;
  tunnels?: unknown;
  selectedTunnelId?: string | null;
  settings?: {
    general?: Partial<GeneralSettings>;
    hardware?: Partial<HardwareSettings>;
  } | null;
}

export type PersistenceLoadResult =
  | { status: "browser" | "missing" | "loaded" }
  | { status: "failed"; message: string };

export const PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS = 5_000;

async function loadNativePersistedState(): Promise<PersistedState | null> {
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(new Error(
        `Native desktop state loading did not complete within ${PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS} ms.`,
      ));
    }, PERSISTENCE_LOAD_TIMEOUT_MILLISECONDS);
  });
  try {
    return await Promise.race([
      tauriInvoke<PersistedState | null>("load_state"),
      timeout,
    ]);
  } finally {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

type PersistedTunnel = {
  id?: unknown; name?: unknown; remote?: unknown; sni?: unknown;
  qkey?: unknown; createdAt?: unknown; hasToken?: unknown;
  countryCode?: unknown; location?: unknown; debugSniOverride?: unknown;
};

export function normalizePersistedTunnels(input: unknown): {
  tunnels: TunnelConfig[];
  invalidTimestampCount: number;
} {
  if (!Array.isArray(input)) return { tunnels: [], invalidTimestampCount: 0 };
  const result: TunnelConfig[] = [];
  let invalidTimestampCount = 0;
  for (const raw of input as PersistedTunnel[]) {
    if (!raw || typeof raw !== "object") continue;
    const id = typeof raw.id === "string" ? raw.id.trim() : "";
    const remote = typeof raw.remote === "string" ? raw.remote.trim() : "";
    const sni = typeof raw.sni === "string" ? raw.sni.trim() : "";
    if (!id || !remote || !sni) continue;
    const name = typeof raw.name === "string" && raw.name.trim().length > 0 ? raw.name.trim() : remote;
    const qkey = typeof raw.qkey === "string" ? raw.qkey : "";
    const createdAt = parseUnixMilliseconds(raw.createdAt, "tauri-persisted-tunnel");
    if (!createdAt.ok) {
      invalidTimestampCount += 1;
      continue;
    }
    const hasToken = Boolean(raw.hasToken);
    const countryCode =
      typeof raw.countryCode === "string" && /^[A-Za-z]{2}$/.test(raw.countryCode.trim())
        ? raw.countryCode.trim().toUpperCase() : undefined;
    const location = typeof raw.location === "string" && raw.location.trim().length > 0
      ? raw.location.trim() : undefined;
    const debugSniOverride =
      typeof raw.debugSniOverride === "string" && raw.debugSniOverride.trim().length > 0
        ? raw.debugSniOverride.trim() : undefined;
    result.push({ id, name, remote, sni, qkey, createdAt: createdAt.value, hasToken, countryCode, location, debugSniOverride });
  }
  return { tunnels: result, invalidTimestampCount };
}

export async function persistState(): Promise<void> {
  if (!isTauri()) return;
  await tauriInvoke("save_state", {
    data: {
      schemaVersion: 1,
      tunnels: getTunnels(),
      selectedTunnelId: getSelectedId(),
      settings: getSettings(),
    },
  });
}

export async function loadPersistedState(): Promise<PersistenceLoadResult> {
  setHydrationDone(false);
  setPersistenceStatus({ phase: "loading", dirty: false, error: null });
  if (!isTauri()) {
    setPersistenceStatus({ phase: "browser", dirty: false, error: null });
    setHydrationDone(true);
    return { status: "browser" };
  }
  try {
    const loaded = await loadNativePersistedState();
    if (!loaded) {
      setPersistenceStatus({ phase: "ready", dirty: false, error: null });
      return { status: "missing" };
    }
    const loadedTunnels = normalizePersistedTunnels(loaded.tunnels);
    if (loadedTunnels.invalidTimestampCount > 0) {
      setError(
        `${loadedTunnels.invalidTimestampCount} persisted tunnel(s) were skipped because their creation timestamp was invalid.`,
      );
    }
    const loadedSettings = isRecord(loaded.settings) ? loaded.settings as PersistedState["settings"] : null;
    const loadedSelected = typeof loaded.selectedTunnelId === "string" ? loaded.selectedTunnelId : null;
    setTunnels(loadedTunnels.tunnels);
    if (loadedSettings) {
      updateSettings((prev: AppSettings): AppSettings => ({
        general: { ...prev.general, ...(isRecord(loadedSettings.general) ? loadedSettings.general : {}) },
        hardware: { ...prev.hardware, ...(isRecord(loadedSettings.hardware) ? loadedSettings.hardware : {}) },
      }));
    }
    const selectedIsValid = !!loadedSelected && loadedTunnels.tunnels.some((t) => t.id === loadedSelected);
    if (selectedIsValid) setSelectedId(loadedSelected);
    else if (loadedTunnels.tunnels.length > 0) setSelectedId(loadedTunnels.tunnels[0].id);
    else setSelectedId(null);
    setPersistenceStatus({ phase: "ready", dirty: false, error: null });
    return { status: "loaded" };
  } catch (cause) {
    const message = toErrorMessage(cause, "Stored desktop state could not be loaded");
    setPersistenceStatus({ phase: "load-error", dirty: false, error: message });
    return { status: "failed", message };
  }
  finally { setHydrationDone(true); }
}

export function startSettingsListener(): (() => void) | null {
  if (!isTauri()) return null;
  let cancelled = false;
  let unlisten: (() => void) | null = null;
  (async () => {
    try {
      const { listen } = await import("@tauri-apps/api/event");
      const off = await listen<{ settings?: PersistedState["settings"] }>("qf://settings-changed", (event) => {
        const ps = event.payload?.settings;
        if (!isRecord(ps)) return;
        const general = isRecord(ps.general) ? ps.general as Partial<GeneralSettings> : {};
        const hardware = isRecord(ps.hardware) ? ps.hardware as Partial<HardwareSettings> : {};
        updateSettings((prev: AppSettings): AppSettings => ({
          general: { ...prev.general, ...general },
          hardware: { ...prev.hardware, ...hardware },
        }));
      });
      if (cancelled) { off(); return; }
      unlisten = off;
    } catch { /* Best-effort. */ }
  })();
  return () => { cancelled = true; unlisten?.(); };
}

let logCursor = 0;
let logCursorEpoch = 0;
let nextPollerOwner = 0;
let activePollerOwner = 0;

export function startEnginePollers(): () => void {
  if (!isTauri()) return () => {};
  const owner = ++nextPollerOwner;
  activePollerOwner = owner;
  let stopped = false;
  let statusInFlight = false;
  let statsInFlight = false;
  let logsInFlight = false;
  let statusStateVersion = 0;
  let previousStatusSignature = "";
  const throughputSamples: Record<string, ByteCounterSample> = {};
  const isCurrent = (): boolean => !stopped && activePollerOwner === owner;
  const resetThroughput = (): void => {
    for (const key of Object.keys(throughputSamples)) delete throughputSamples[key];
    setThroughput({});
  };

  const pollStatus = async (): Promise<void> => {
    if (!isCurrent() || statusInFlight || !isBrowserDocumentVisible()) return;
    statusInFlight = true;
    try {
      if (!isCurrent()) return;
      // `invoke<T>` is a cast, so the shape is checked here rather than trusted.
      const rawStatus = await tauriInvoke<unknown>("engine_status");
      if (!isCurrent() || !isBrowserDocumentVisible()) return;
      const status = parseEngineStatus(rawStatus);
      if (!status) {
        setError("Engine status could not be read: the native response was malformed.");
        return;
      }
      const activeTunnelId = status.activeTunnelId;
      const signature = `${status.state}:${activeTunnelId ?? ""}:${status.lastError ?? ""}`;
      if (signature !== previousStatusSignature) {
        previousStatusSignature = signature;
        statusStateVersion += 1;
      }
      setActiveTunnelId(activeTunnelId);
      const tunnels = getTunnels();
      const current = getTunnelStates();
      const next: Record<string, "inactive" | "activating" | "active" | "deactivating"> = {};
      for (const t of tunnels) {
        const currentState = current[t.id];
        if (currentState === "activating" || currentState === "deactivating") {
          next[t.id] = currentState;
          continue;
        }
        if (activeTunnelId && t.id === activeTunnelId && status.state === "Connected") next[t.id] = "active";
        else next[t.id] = "inactive";
      }
      setTunnelStates(next);
      if (status.lastError) setError(status.lastError);
    } catch { /* ignore */ }
    finally { statusInFlight = false; }
  };

  const pollStats = async (): Promise<void> => {
    if (!isCurrent() || statsInFlight || !isBrowserDocumentVisible()) return;
    statsInFlight = true;
    const stateVersionAtStart = statusStateVersion;
    const activeTunnelIdAtStart = getActiveTunnelId();
    try {
      if (!isCurrent()) return;
      const rawStats = await tauriInvoke<unknown>("engine_stats");
      if (!isCurrent() || stateVersionAtStart !== statusStateVersion || activeTunnelIdAtStart !== getActiveTunnelId()) return;
      if (!isBrowserDocumentVisible()) {
        resetThroughput();
        return;
      }
      if (!activeTunnelIdAtStart || rawStats === null || rawStats === undefined) {
        updateTunnelStats(() => ({}));
        resetThroughput();
        return;
      }
      // A malformed sample is dropped rather than partially trusted. `?? 0` only
      // substitutes for null and undefined, so NaN, Infinity, and negative counters
      // used to reach the store and then the throughput calculation below, producing
      // a figure that looks measured and is not.
      const stats = parseEngineStats(rawStats);
      if (!stats) {
        setError("Engine statistics were discarded: the native response was malformed.");
        resetThroughput();
        return;
      }
      updateTunnelStats((prev) => ({
        ...prev,
        [activeTunnelIdAtStart]: {
          latencyMs: stats.latencyMs,
          lossPercent: stats.lossPercent,
          rxBytes: stats.rxBytes,
          txBytes: stats.txBytes,
          rxPackets: stats.rxPackets,
          txPackets: stats.txPackets,
          uptimeSecs: stats.uptimeSecs,
          stealthMode: stats.stealthMode,
          fecMode: stats.fecMode,
          fecActivityPercent: stats.fecActivityPercent,
          fecRecoveredPackets: stats.fecRecoveredPackets,
          currentSni: stats.currentSni,
        },
      }));

      // Compute throughput from the shared monotonic sample contract.
      const now = readBrowserMonotonicMilliseconds();
      const currentStats = getTunnelStats();
      const nextThroughput = { ...getThroughput() };
      for (const [id, s] of Object.entries(currentStats)) {
        if (!s) {
          delete nextThroughput[id];
          delete throughputSamples[id];
          continue;
        }
        const current: ByteCounterSample = {
          atMilliseconds: now,
          bytesIn: s.rxBytes,
          bytesOut: s.txBytes,
        };
        const result = evaluateByteRateSample(throughputSamples[id] ?? null, current);
        if (result.nextSample) throughputSamples[id] = result.nextSample;
        else delete throughputSamples[id];
        if (result.accepted) {
          nextThroughput[id] = {
            downBps: Math.max(0, Math.round(result.inBps)),
            upBps: Math.max(0, Math.round(result.outBps)),
          };
        } else {
          delete nextThroughput[id];
        }
      }
      setThroughput(nextThroughput);
    } catch { /* ignore */ }
    finally { statsInFlight = false; }
  };

  const pollLogs = async (): Promise<void> => {
    if (!isCurrent() || logsInFlight || !isBrowserDocumentVisible()) return;
    logsInFlight = true;
    const cursorAtStart = logCursor;
    const cursorEpochAtStart = logCursorEpoch;
    try {
      if (!isCurrent()) return;
      const resp = await tauriInvoke<{ cursor: number; lines: RawTauriLogLine[] }>(
        "engine_logs_since", { cursor: cursorAtStart },
      );
      if (!isCurrent() || cursorEpochAtStart !== logCursorEpoch || !isBrowserDocumentVisible()) return;
      const nextCursor = resp?.cursor ?? cursorAtStart;
      if (nextCursor < cursorAtStart || nextCursor < logCursor) return;
      if (!resp || !Array.isArray(resp.lines) || resp.lines.length === 0) {
        logCursor = nextCursor;
        return;
      }
      logCursor = nextCursor;
      const parsedLines = resp.lines.map(parseTauriLogLine).filter((line): line is NonNullable<typeof line> => line !== null);
      appendLogs(parsedLines);
    } catch { /* ignore */ }
    finally { logsInFlight = false; }
  };

  const statusInterval = setInterval(() => { if (isBrowserDocumentVisible()) void pollStatus(); }, 500);
  const statsInterval = setInterval(() => { if (isBrowserDocumentVisible()) void pollStats(); }, 900);
  const logsInterval = setInterval(() => { if (isBrowserDocumentVisible()) void pollLogs(); }, 350);
  const handleVisibilityChange = (): void => {
    if (!isBrowserDocumentVisible()) {
      resetThroughput();
      return;
    }
    void pollStatus();
    void pollStats();
    void pollLogs();
  };
  document.addEventListener("visibilitychange", handleVisibilityChange);

  return () => {
    stopped = true;
    if (activePollerOwner === owner) activePollerOwner = 0;
    clearInterval(statusInterval);
    clearInterval(statsInterval);
    clearInterval(logsInterval);
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    resetThroughput();
  };
}

export async function engineConnect(tunnelId: string, qkeyData: string, settings: unknown, sniOverride?: string): Promise<void> {
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("engine_connect", {
    tunnel_id: tunnelId,
    qkey_data: qkeyData,
    sni_override: sniOverride && sniOverride.length > 0 ? sniOverride : null,
    settings,
  });
}

export async function engineDisconnect(): Promise<void> {
  const { invoke } = await import("@tauri-apps/api/core");
  await invoke("engine_disconnect");
}

export async function qkeyParse(qkeyData: string): Promise<Record<string, unknown>> {
  const { invoke } = await import("@tauri-apps/api/core");
  return await invoke<Record<string, unknown>>("qkey_parse", { qkey_data: qkeyData });
}

export async function detectCpuFeatures(): Promise<string[]> {
  if (!isTauri()) return [];
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    return await invoke<string[]>("detect_cpu_features");
  } catch { return []; }
}

export async function engineLogsClear(): Promise<void> {
  if (!isTauri()) return;
  logCursor = 0;
  logCursorEpoch += 1;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("engine_logs_clear");
  } catch { /* no-op */ }
}

export { isTauri };
