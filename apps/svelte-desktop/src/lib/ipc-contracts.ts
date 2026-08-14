/**
 * Runtime validation for values crossing the Tauri IPC boundary.
 *
 * `invoke<T>()` is a cast, not a check: the native side can drift, a serialization
 * change can reshape a field, and the frontend would accept the result as typed data
 * anyway. The consequences are not merely type errors. A `NaN` or negative counter
 * survived `?? 0`, which only substitutes for null and undefined, and then reached the
 * throughput calculation; an unknown log level entered a closed union and rendered as
 * an unsupported value.
 *
 * These helpers reject rather than coerce. A malformed field is a signal that the two
 * sides disagree, and silently repairing it hides exactly that.
 */

/** A finite number within an inclusive range, or null. */
export function finiteNumber(value: unknown, min: number, max: number): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  if (value < min || value > max) return null;
  return value;
}

/** A non-negative counter. Counters are monotonic byte and packet totals. */
export function counter(value: unknown): number | null {
  return finiteNumber(value, 0, Number.MAX_SAFE_INTEGER);
}

/** A percentage in 0..=100. */
export function percentage(value: unknown): number | null {
  return finiteNumber(value, 0, 100);
}

/** A non-empty string no longer than `maxLength`, trimmed. */
export function boundedString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return null;
  return trimmed;
}

/** A value belonging to a closed set, or null. */
export function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | null {
  if (typeof value !== "string") return null;
  return (allowed as readonly string[]).includes(value) ? (value as T) : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Longest identifier or free-text field accepted from the native side. */
const MAX_IPC_STRING = 512;

export interface EngineStatusContract {
  state: string;
  activeTunnelId: string | null;
  lastError: string | null;
}

/**
 * Validate an `engine_status` response.
 *
 * `state` is required because every downstream branch keys off it; the two optional
 * fields are nulled when malformed rather than rejecting the whole response, since a
 * bad error string must not hide a valid state transition.
 */
export function parseEngineStatus(raw: unknown): EngineStatusContract | null {
  if (!isRecord(raw)) return null;
  const state = boundedString(raw.state, MAX_IPC_STRING);
  if (state === null) return null;
  return {
    state,
    activeTunnelId: boundedString(raw.activeTunnelId, MAX_IPC_STRING),
    lastError: boundedString(raw.lastError, MAX_IPC_STRING * 8),
  };
}

export interface EngineStatsContract {
  latencyMs: number;
  lossPercent: number;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
  uptimeSecs: number;
  stealthMode: string;
  fecMode: string;
  fecActivityPercent: number;
  fecRecoveredPackets: number;
  currentSni?: string;
  circuitGeneration: number;
  circuitState: string;
  effectiveTunnelMtu: number;
  hops: CircuitHopStatsContract[];
}

export interface CircuitHopStatsContract {
  index: number;
  role: "relay" | "exit";
  established: boolean;
  latencyMs: number;
  datagramBudget: number;
}

/**
 * Validate an `engine_stats` response.
 *
 * Every numeric field falls back to a neutral value only when it is absent. A present
 * but invalid value, including `NaN`, `Infinity`, a negative counter, or a string,
 * makes the whole sample invalid: mixing a trusted counter with a nonsense one
 * produces a throughput figure that looks real and is not.
 */
export function parseEngineStats(raw: unknown): EngineStatsContract | null {
  if (!isRecord(raw)) return null;

  const numeric = (
    key: string,
    parse: (value: unknown) => number | null,
  ): number | null | undefined => {
    if (raw[key] === undefined || raw[key] === null) return 0;
    return parse(raw[key]);
  };

  const latencyMs = numeric("latencyMs", (v) => finiteNumber(v, 0, 3_600_000));
  const lossPercent = numeric("lossPercent", percentage);
  const rxBytes = numeric("bytesIn", counter);
  const txBytes = numeric("bytesOut", counter);
  const rxPackets = numeric("packetsIn", counter);
  const txPackets = numeric("packetsOut", counter);
  const uptimeSecs = numeric("uptimeSecs", counter);
  const fecActivityPercent = numeric("fecActivityPercent", percentage);
  const fecRecoveredPackets = numeric("fecRecoveredPackets", counter);
  const circuitGeneration = numeric("circuitGeneration", counter);
  const effectiveTunnelMtu = numeric("effectiveTunnelMtu", (v) => finiteNumber(v, 0, 65_535));

  const numbers = [
    latencyMs, lossPercent, rxBytes, txBytes, rxPackets,
    txPackets, uptimeSecs, fecActivityPercent, fecRecoveredPackets,
    circuitGeneration, effectiveTunnelMtu,
  ];
  if (numbers.some((value) => value === null || value === undefined)) return null;

  const optionalMode = (value: unknown, fallback: string): string | null => {
    if (value === undefined || value === null) return fallback;
    return boundedString(value, MAX_IPC_STRING);
  };
  const stealthMode = optionalMode(raw.stealthMode, "auto");
  const fecMode = optionalMode(raw.fecMode, "auto");
  const circuitState = optionalMode(raw.circuitState, "idle");
  if (stealthMode === null || fecMode === null || circuitState === null) return null;

  const rawHops = raw.hops ?? [];
  if (!Array.isArray(rawHops) || rawHops.length > 8) return null;
  const hops: CircuitHopStatsContract[] = [];
  for (const [expectedIndex, rawHop] of rawHops.entries()) {
    if (!isRecord(rawHop)) return null;
    const index = finiteNumber(rawHop.index, 0, 7);
    const role = oneOf(rawHop.role, ["relay", "exit"] as const);
    const latency = finiteNumber(rawHop.latencyMs, 0, 3_600_000);
    const budget = finiteNumber(rawHop.datagramBudget, 0, 65_535);
    if (
      index !== expectedIndex ||
      role === null ||
      typeof rawHop.established !== "boolean" ||
      latency === null ||
      budget === null
    ) return null;
    hops.push({
      index,
      role,
      established: rawHop.established,
      latencyMs: latency,
      datagramBudget: budget,
    });
  }

  // An absent SNI is normal; a present but malformed one is not silently dropped,
  // because the displayed identity would then differ from what the engine reported.
  let currentSni: string | undefined;
  if (raw.currentSni !== undefined && raw.currentSni !== null) {
    const parsed = boundedString(raw.currentSni, MAX_IPC_STRING);
    if (parsed === null) return null;
    currentSni = parsed;
  }

  return {
    latencyMs: latencyMs as number,
    lossPercent: lossPercent as number,
    rxBytes: rxBytes as number,
    txBytes: txBytes as number,
    rxPackets: rxPackets as number,
    txPackets: txPackets as number,
    uptimeSecs: uptimeSecs as number,
    stealthMode,
    fecMode,
    fecActivityPercent: fecActivityPercent as number,
    fecRecoveredPackets: fecRecoveredPackets as number,
    currentSni,
    circuitGeneration: circuitGeneration as number,
    circuitState,
    effectiveTunnelMtu: effectiveTunnelMtu as number,
    hops,
  };
}

/** Update metadata as this application is willing to consume it. */
export interface UpdaterMetadata {
  currentVersion: string;
  version: string;
  date?: string;
  body?: string;
}

/**
 * Validate a plugin update result before it becomes a local update contract.
 *
 * The version fields must be present and the install callable must actually be a
 * function. Casting the plugin result meant a drifted or malformed object could reach
 * the version display, and an install could be offered for an update object that
 * cannot install.
 */
export function parseUpdaterResult(raw: unknown): (UpdaterMetadata & { downloadAndInstall: unknown }) | null {
  if (!isRecord(raw)) return null;
  const currentVersion = boundedString(raw.currentVersion, MAX_IPC_STRING);
  const version = boundedString(raw.version, MAX_IPC_STRING);
  if (currentVersion === null || version === null) return null;
  if (typeof raw.downloadAndInstall !== "function") return null;

  const optionalText = (value: unknown, maxLength: number): string | undefined | null => {
    if (value === undefined || value === null) return undefined;
    return boundedString(value, maxLength);
  };
  const date = optionalText(raw.date, MAX_IPC_STRING);
  const body = optionalText(raw.body, MAX_IPC_STRING * 32);
  if (date === null || body === null) return null;

  return { currentVersion, version, date, body, downloadAndInstall: raw.downloadAndInstall };
}
