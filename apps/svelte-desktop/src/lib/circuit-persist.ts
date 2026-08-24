import type { CircuitConfig, CircuitHopConfig } from "@quicfuscate/types/desktop";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readText(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  return typeof value === "string" ? value.trim() : "";
}

function readOptionalText(
  record: Record<string, unknown>,
  camel: string,
  snake: string,
): string | undefined {
  const camelValue = readText(record, camel);
  if (camelValue) return camelValue;
  const snakeValue = readText(record, snake);
  return snakeValue || undefined;
}

function readBooleanFlag(
  record: Record<string, unknown>,
  camel: string,
  snake: string,
): boolean {
  return record[camel] === true || record[snake] === true;
}

function readOptionalBoolean(
  record: Record<string, unknown>,
  camel: string,
  snake: string,
): boolean | undefined {
  const camelValue = record[camel];
  if (typeof camelValue === "boolean") return camelValue;
  const snakeValue = record[snake];
  return typeof snakeValue === "boolean" ? snakeValue : undefined;
}

function readPositiveInteger(
  record: Record<string, unknown>,
  camel: string,
  snake: string,
  fallback: number,
): number {
  const camelValue = record[camel];
  if (typeof camelValue === "number" && Number.isSafeInteger(camelValue) && camelValue > 0) {
    return camelValue;
  }
  const snakeValue = record[snake];
  if (typeof snakeValue === "number" && Number.isSafeInteger(snakeValue) && snakeValue > 0) {
    return snakeValue;
  }
  return fallback;
}

function normalizeHopPolicy(
  rawPolicy: unknown,
): CircuitHopConfig["policy"] | null | undefined {
  if (rawPolicy === undefined || rawPolicy === null) return undefined;
  if (!isRecord(rawPolicy)) return null;
  const fecMode = rawPolicy.fecMode ?? rawPolicy.fec_mode;
  if (fecMode !== undefined && fecMode !== "off" && fecMode !== "auto") return null;
  const rawPersona = rawPolicy.persona;
  let persona: NonNullable<CircuitHopConfig["policy"]>["persona"];
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
  return {
    persona,
    fecMode,
    enableTrafficPadding: readOptionalBoolean(rawPolicy, "enableTrafficPadding", "enable_traffic_padding"),
    enableTimingObfuscation: readOptionalBoolean(rawPolicy, "enableTimingObfuscation", "enable_timing_obfuscation"),
    enableCoverPing: readOptionalBoolean(rawPolicy, "enableCoverPing", "enable_cover_ping"),
  };
}

export function normalizePersistedCircuit(input: unknown): CircuitConfig | null | undefined {
  if (input === undefined || input === null) return undefined;
  if (!isRecord(input) || !Array.isArray(input.hops) || input.hops.length < 1 || input.hops.length > 8) {
    return null;
  }
  const rawHops = input.hops;
  const hops = rawHops.map((raw, index) => {
    if (!isRecord(raw)) return null;
    const id = readText(raw, "id");
    const label = readText(raw, "label");
    const remote = readText(raw, "remote");
    const sni = readText(raw, "sni");
    const qkeyId = readOptionalText(raw, "qkeyId", "qkey_id")?.toLowerCase() ?? "";
    const qkey = typeof raw.qkey === "string" ? raw.qkey.trim() : "";
    const expectedRole = index + 1 === rawHops.length ? "exit" : "relay";
    if (!id || !label || !remote || !sni || raw.role !== expectedRole || !/^[0-9a-f]{12}$/.test(qkeyId)) {
      return null;
    }
    const policy = normalizeHopPolicy(raw.policy);
    if (policy === null) return null;
    return {
      id,
      label,
      remote,
      sni,
      qkeyId,
      qkey,
      role: expectedRole,
      provider: readOptionalText(raw, "provider", "provider"),
      region: readOptionalText(raw, "region", "region"),
      jurisdiction: readOptionalText(raw, "jurisdiction", "jurisdiction"),
      failureDomain: readOptionalText(raw, "failureDomain", "failure_domain"),
      verifyPeer: raw.verifyPeer !== false && raw.verify_peer !== false,
      caFile: readOptionalText(raw, "caFile", "ca_file"),
      connectTimeoutMs: readPositiveInteger(raw, "connectTimeoutMs", "connect_timeout_ms", 10_000),
      idleTimeoutMs: readPositiveInteger(raw, "idleTimeoutMs", "idle_timeout_ms", 30_000),
      policy,
      hasToken: Boolean(raw.hasToken ?? raw.has_token),
    } satisfies CircuitHopConfig;
  });
  if (hops.some((hop) => hop === null)) return null;
  const maxHops = typeof input.maxHops === "number" && Number.isInteger(input.maxHops)
    ? input.maxHops
    : typeof input.max_hops === "number" && Number.isInteger(input.max_hops)
      ? input.max_hops
      : 3;
  const maxParallelCircuits = typeof input.maxParallelCircuits === "number"
    && Number.isInteger(input.maxParallelCircuits)
    ? input.maxParallelCircuits
    : typeof input.max_parallel_circuits === "number"
      && Number.isInteger(input.max_parallel_circuits)
      ? input.max_parallel_circuits
      : 2;
  if (maxHops < hops.length || maxHops > 8 || maxParallelCircuits < 1 || maxParallelCircuits > 2) {
    return null;
  }
  const rawDiversity = isRecord(input.diversity) ? input.diversity : {};
  const allowSingleHopFallback = input.allowSingleHopFallback === true
    || input.allow_single_hop_fallback === true;
  return {
    hops: hops as CircuitHopConfig[],
    maxHops,
    maxParallelCircuits,
    allowSingleHopFallback,
    diversity: {
      provider: readBooleanFlag(rawDiversity, "provider", "provider"),
      region: readBooleanFlag(rawDiversity, "region", "region"),
      jurisdiction: readBooleanFlag(rawDiversity, "jurisdiction", "jurisdiction"),
      failureDomain: readBooleanFlag(rawDiversity, "failureDomain", "failure_domain"),
    },
  };
}
