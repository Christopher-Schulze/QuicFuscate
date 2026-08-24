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
import type {
  TunnelConfig,
  CircuitConfig,
  AppSettings,
  GeneralSettings,
  HardwareSettings,
} from "$lib/types";
import { parseTauriLogLine } from "$lib/timestamp-boundary";
import {
  evaluateByteRateSample,
  isBrowserDocumentVisible,
  parseUnixMilliseconds,
  readBrowserMonotonicMilliseconds,
  type ByteCounterSample,
} from "@quicfuscate/time";
import { commands } from "$lib/bindings";
import type { ParsedQKey, PersistedState_Deserialize } from "$lib/bindings";
import { parseEngineStats, parseEngineStatus } from "$lib/ipc-contracts";
import { toErrorMessage } from "$lib/format";
import { unwrapSpectaCommand } from "$lib/specta-result";

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

async function loadNativePersistedState(): Promise<unknown> {
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
      unwrapSpectaCommand(commands.loadState()),
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
  circuit?: unknown; alternateCircuit?: unknown;
};

function normalizePersistedCircuit(input: unknown): CircuitConfig | null | undefined {
  if (input === undefined || input === null) return undefined;
  if (!isRecord(input) || !Array.isArray(input.hops) || input.hops.length < 1 || input.hops.length > 8) {
    return null;
  }
  const rawHops = input.hops;
  const hops = rawHops.map((raw, index) => {
    if (!isRecord(raw)) return null;
    const text = (key: string): string => typeof raw[key] === "string" ? raw[key].trim() : "";
    const id = text("id");
    const label = text("label");
    const remote = text("remote");
    const sni = text("sni");
    const qkeyId = text("qkeyId").toLowerCase();
    const qkey = typeof raw.qkey === "string" ? raw.qkey.trim() : "";
    const expectedRole = index + 1 === rawHops.length ? "exit" : "relay";
    if (!id || !label || !remote || !sni || raw.role !== expectedRole || !/^[0-9a-f]{12}$/.test(qkeyId)) {
      return null;
    }
    const optional = (key: string): string | undefined => {
      const value = text(key);
      return value || undefined;
    };
    const rawPolicy = raw.policy;
    let policy: CircuitConfig["hops"][number]["policy"];
    if (rawPolicy !== undefined && rawPolicy !== null) {
      if (!isRecord(rawPolicy)) return null;
      const fecMode = rawPolicy.fecMode;
      if (fecMode !== undefined && fecMode !== "off" && fecMode !== "auto") return null;
      const rawPersona = rawPolicy.persona;
      let persona: NonNullable<CircuitConfig["hops"][number]["policy"]>["persona"];
      if (rawPersona !== undefined && rawPersona !== null) {
        if (!isRecord(rawPersona)) return null;
        const browsers = ["chrome", "firefox", "safari", "edge"];
        const operatingSystems = ["windows", "macos", "linux", "ios", "android"];
        if (!browsers.includes(String(rawPersona.browser))
          || !operatingSystems.includes(String(rawPersona.os))) return null;
        persona = {
          browser: rawPersona.browser as NonNullable<typeof persona>["browser"],
          os: rawPersona.os as NonNullable<typeof persona>["os"],
        };
      }
      const optionalBoolean = (key: string): boolean | undefined => {
        const value = rawPolicy[key];
        return typeof value === "boolean" ? value : undefined;
      };
      policy = {
        persona,
        fecMode,
        enableTrafficPadding: optionalBoolean("enableTrafficPadding"),
        enableTimingObfuscation: optionalBoolean("enableTimingObfuscation"),
        enableCoverPing: optionalBoolean("enableCoverPing"),
      };
    }
    const positiveInteger = (key: string, fallback: number): number => {
      const value = raw[key];
      return typeof value === "number" && Number.isSafeInteger(value) && value > 0
        ? value : fallback;
    };
    return {
      id,
      label,
      remote,
      sni,
      qkeyId,
      qkey,
      role: expectedRole,
      provider: optional("provider"),
      region: optional("region"),
      jurisdiction: optional("jurisdiction"),
      failureDomain: optional("failureDomain"),
      verifyPeer: raw.verifyPeer !== false,
      caFile: optional("caFile"),
      connectTimeoutMs: positiveInteger("connectTimeoutMs", 10_000),
      idleTimeoutMs: positiveInteger("idleTimeoutMs", 30_000),
      policy,
      hasToken: Boolean(raw.hasToken),
    };
  });
  if (hops.some((hop) => hop === null)) return null;
  const maxHops = typeof input.maxHops === "number" && Number.isInteger(input.maxHops)
    ? input.maxHops : 3;
  const maxParallelCircuits = typeof input.maxParallelCircuits === "number"
    && Number.isInteger(input.maxParallelCircuits) ? input.maxParallelCircuits : 2;
  if (maxHops < hops.length || maxHops > 8 || maxParallelCircuits < 1 || maxParallelCircuits > 2) {
    return null;
  }
  const rawDiversity = isRecord(input.diversity) ? input.diversity : {};
  return {
    hops: hops as CircuitConfig["hops"],
    maxHops,
    maxParallelCircuits,
    allowSingleHopFallback: input.allowSingleHopFallback === true,
    diversity: {
      provider: rawDiversity.provider === true,
      region: rawDiversity.region === true,
      jurisdiction: rawDiversity.jurisdiction === true,
      failureDomain: rawDiversity.failureDomain === true,
    },
  };
}

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
    const circuit = normalizePersistedCircuit(raw.circuit);
    const alternateCircuit = normalizePersistedCircuit(raw.alternateCircuit);
    if (circuit === null || alternateCircuit === null || (alternateCircuit && !circuit)) continue;
    result.push({
      id,
      name,
      remote,
      sni,
      qkey,
      createdAt: createdAt.value,
      hasToken,
      countryCode,
      location,
      debugSniOverride,
      circuit,
      alternateCircuit,
    });
  }
  return { tunnels: result, invalidTimestampCount };
}

export async function persistState(): Promise<void> {
  if (!isTauri()) return;
  const data: PersistedState_Deserialize = {
    schemaVersion: 1,
    tunnels: getTunnels(),
    selectedTunnelId: getSelectedId(),
    settings: getSettings(),
  };
  await unwrapSpectaCommand(commands.saveState(data));
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
    const loadedRaw = await loadNativePersistedState();
    if (loadedRaw === null || loadedRaw === undefined) {
      setPersistenceStatus({ phase: "ready", dirty: false, error: null });
      return { status: "missing" };
    }
    if (!isRecord(loadedRaw)) {
      throw new Error("Stored desktop state was malformed.");
    }
    const loaded = loadedRaw;
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
      // Generated command wrappers are still an untrusted IPC boundary.
      // `parseEngineStatus` rejects malformed native payloads instead of trusting the type.
      const rawStatus = await unwrapSpectaCommand(commands.engineStatus());
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
      const rawStats = await unwrapSpectaCommand(commands.engineStats());
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
          circuitGeneration: stats.circuitGeneration,
          circuitState: stats.circuitState,
          effectiveTunnelMtu: stats.effectiveTunnelMtu,
          hops: stats.hops,
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
      const resp = await unwrapSpectaCommand(commands.engineLogsSince(cursorAtStart));
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

export async function engineConnect(
  tunnelId: string,
  qkeyData: string,
  settings: unknown,
  sniOverride?: string,
  circuit?: CircuitConfig,
  alternateCircuit?: CircuitConfig,
): Promise<void> {
  await unwrapSpectaCommand(
    commands.engineConnect({
      tunnelId,
      qkeyData,
      sniOverride: sniOverride && sniOverride.length > 0 ? sniOverride : null,
      circuit: circuit ?? null,
      alternateCircuit: alternateCircuit ?? null,
      settings,
    }),
  );
}

export async function engineRotate(
  tunnelId: string,
  qkeyData: string,
  settings: unknown,
  circuit: CircuitConfig,
  sniOverride?: string,
): Promise<void> {
  await unwrapSpectaCommand(
    commands.engineRotate(
      tunnelId,
      qkeyData,
      sniOverride && sniOverride.length > 0 ? sniOverride : null,
      circuit,
      settings,
    ),
  );
}

export async function engineDisconnect(): Promise<void> {
  await unwrapSpectaCommand(commands.engineDisconnect());
}

export async function qkeyParse(qkeyData: string): Promise<ParsedQKey> {
  return await unwrapSpectaCommand(commands.qkeyParse(qkeyData));
}

export async function detectCpuFeatures(): Promise<string[]> {
  if (!isTauri()) return [];
  try {
    return await unwrapSpectaCommand(commands.detectCpuFeatures());
  } catch {
    return [];
  }
}

export async function readUpdaterRuntimeEnabled(): Promise<boolean> {
  if (!isTauri()) return false;
  try {
    return (await unwrapSpectaCommand(commands.updaterRuntimeEnabled())) === true;
  } catch {
    return false;
  }
}

export async function engineLogsClear(): Promise<void> {
  if (!isTauri()) return;
  logCursor = 0;
  logCursorEpoch += 1;
  try {
    await unwrapSpectaCommand(commands.engineLogsClear());
  } catch { /* no-op */ }
}

export { isTauri };
