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
} from "./app.svelte";
import type { TunnelConfig, AppSettings, GeneralSettings, HardwareSettings } from "$lib/types";
import { parseTauriLogLine, type RawTauriLogLine } from "$lib/timestamp-boundary";
import { parseUnixMilliseconds } from "@quicfuscate/time";
import { invoke as tauriInvoke } from "@tauri-apps/api/core";

/** Shape returned by the Tauri `load_state` command. */
interface PersistedState {
  schemaVersion?: number;
  tunnels?: unknown;
  selectedTunnelId?: string;
  settings?: {
    general?: Partial<GeneralSettings>;
    hardware?: Partial<HardwareSettings>;
  } | null;
}

/** Shape returned by the Tauri `engine_stats` command. */
interface RawEngineStats {
  latencyMs?: number;
  lossPercent?: number;
  bytesIn?: number;
  bytesOut?: number;
  packetsIn?: number;
  packetsOut?: number;
  uptimeSecs?: number;
  stealthMode?: string;
  fecMode?: string;
  fecActivityPercent?: number;
  fecRecoveredPackets?: number;
  currentSni?: string;
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
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("save_state", {
      data: {
        schemaVersion: 1,
        tunnels: getTunnels(),
        selectedTunnelId: getSelectedId(),
        settings: getSettings(),
      },
    });
  } catch { /* Best-effort persistence. */ }
}

export async function loadPersistedState(): Promise<void> {
  if (!isTauri()) { setHydrationDone(true); return; }
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    const loaded = await invoke<PersistedState | null>("load_state");
    if (!loaded) { setHydrationDone(true); return; }
    const loadedTunnels = normalizePersistedTunnels(loaded.tunnels);
    if (loadedTunnels.invalidTimestampCount > 0) {
      setError(
        `${loadedTunnels.invalidTimestampCount} persisted tunnel(s) were skipped because their creation timestamp was invalid.`,
      );
    }
    const loadedSettings = isRecord(loaded.settings) ? loaded.settings as PersistedState["settings"] : null;
    const loadedSelected = typeof loaded.selectedTunnelId === "string" ? loaded.selectedTunnelId : null;
    if (loadedTunnels.tunnels.length > 0) setTunnels(loadedTunnels.tunnels);
    if (loadedSettings) {
      updateSettings((prev: AppSettings): AppSettings => ({
        general: { ...prev.general, ...(isRecord(loadedSettings.general) ? loadedSettings.general : {}) },
        hardware: { ...prev.hardware, ...(isRecord(loadedSettings.hardware) ? loadedSettings.hardware : {}) },
      }));
    }
    const selectedIsValid = !!loadedSelected && loadedTunnels.tunnels.some((t) => t.id === loadedSelected);
    if (selectedIsValid) setSelectedId(loadedSelected);
    else if (loadedTunnels.tunnels.length > 0) setSelectedId(loadedTunnels.tunnels[0].id);
  } catch { /* Ignore: dev browser mode or missing file. */ }
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
  const throughputSamples: Record<string, { ts: number; rx: number; tx: number }> = {};
  const isCurrent = (): boolean => !stopped && activePollerOwner === owner;

  const pollStatus = async (): Promise<void> => {
    if (!isCurrent() || statusInFlight) return;
    statusInFlight = true;
    try {
      if (!isCurrent()) return;
      const status = await tauriInvoke<{ state: string; activeTunnelId?: string | null; lastError?: string | null }>("engine_status");
      if (!isCurrent()) return;
      const activeTunnelId = status.activeTunnelId ?? null;
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
    if (!isCurrent() || statsInFlight) return;
    statsInFlight = true;
    const stateVersionAtStart = statusStateVersion;
    const activeTunnelIdAtStart = getActiveTunnelId();
    try {
      if (!isCurrent()) return;
      const stats = await tauriInvoke<RawEngineStats | null>("engine_stats");
      if (!isCurrent() || stateVersionAtStart !== statusStateVersion || activeTunnelIdAtStart !== getActiveTunnelId()) return;
      if (!activeTunnelIdAtStart || !stats) {
        updateTunnelStats(() => ({}));
        return;
      }
      updateTunnelStats((prev) => ({
        ...prev,
        [activeTunnelIdAtStart]: {
          latencyMs: stats.latencyMs ?? 0,
          lossPercent: stats.lossPercent ?? 0,
          rxBytes: stats.bytesIn ?? 0,
          txBytes: stats.bytesOut ?? 0,
          rxPackets: stats.packetsIn ?? 0,
          txPackets: stats.packetsOut ?? 0,
          uptimeSecs: stats.uptimeSecs ?? 0,
          stealthMode: stats.stealthMode ?? "auto",
          fecMode: stats.fecMode ?? "auto",
          fecActivityPercent: stats.fecActivityPercent ?? 0,
          fecRecoveredPackets: stats.fecRecoveredPackets ?? 0,
          currentSni: typeof stats.currentSni === "string" && stats.currentSni.trim().length > 0
            ? stats.currentSni.trim() : undefined,
        },
      }));

      // Compute throughput
      const now = Date.now();
      const currentStats = getTunnelStats();
      const nextThroughput = { ...getThroughput() };
      for (const [id, s] of Object.entries(currentStats)) {
        if (!s) { delete nextThroughput[id]; delete throughputSamples[id]; continue; }
        const prev = throughputSamples[id];
        if (prev) {
          const dtMs = now - prev.ts;
          const downBytes = s.rxBytes - prev.rx;
          const upBytes = s.txBytes - prev.tx;
          if (dtMs > 0 && downBytes >= 0 && upBytes >= 0) {
            nextThroughput[id] = {
              downBps: Math.max(0, Math.round((downBytes * 8 * 1000) / dtMs)),
              upBps: Math.max(0, Math.round((upBytes * 8 * 1000) / dtMs)),
            };
          }
        }
        throughputSamples[id] = { ts: now, rx: s.rxBytes, tx: s.txBytes };
      }
      setThroughput(nextThroughput);
    } catch { /* ignore */ }
    finally { statsInFlight = false; }
  };

  const pollLogs = async (): Promise<void> => {
    if (!isCurrent() || logsInFlight) return;
    logsInFlight = true;
    const cursorAtStart = logCursor;
    const cursorEpochAtStart = logCursorEpoch;
    try {
      if (!isCurrent()) return;
      const resp = await tauriInvoke<{ cursor: number; lines: RawTauriLogLine[] }>(
        "engine_logs_since", { cursor: cursorAtStart },
      );
      if (!isCurrent() || cursorEpochAtStart !== logCursorEpoch) return;
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

  const statusInterval = setInterval(() => { void pollStatus(); }, 500);
  const statsInterval = setInterval(() => { void pollStats(); }, 900);
  const logsInterval = setInterval(() => { void pollLogs(); }, 350);

  return () => {
    stopped = true;
    if (activePollerOwner === owner) activePollerOwner = 0;
    clearInterval(statusInterval);
    clearInterval(statsInterval);
    clearInterval(logsInterval);
    for (const key of Object.keys(throughputSamples)) {
      delete throughputSamples[key];
    }
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
