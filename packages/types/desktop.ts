import type { UnixMilliseconds } from "@quicfuscate/time";

/** Per-tunnel activation state */
export type TunnelState = "inactive" | "activating" | "active" | "deactivating";

export type DesktopCreatedAt =
  | UnixMilliseconds<"tauri-persisted-tunnel">
  | UnixMilliseconds<"desktop-created">;
export type TauriLogTimestamp = UnixMilliseconds<"tauri-log">;

/** Tunnel configuration - imported via QKey or manual entry. */
export interface TunnelConfig {
  id: string;
  name: string;
  /** Remote server address (host:port) */
  remote: string;
  /** TLS SNI host */
  sni: string;
  /** Optional desktop-only debug override for TLS SNI (default off). */
  debugSniOverride?: string;
  /** Metadata */
  countryCode?: string;
  location?: string;
  /** Unix epoch milliseconds. Source is Tauri persistence or explicit desktop creation. */
  createdAt: DesktopCreatedAt;
  hasToken: boolean;
  /** Canonical credential */
  qkey: string;
  /** Canonical ordered circuit. Absence is the legacy one-hop shorthand. */
  circuit?: CircuitConfig;
  /** Distinct ready standby circuit. Absence disables make-before-break failover. */
  alternateCircuit?: CircuitConfig;
}

export interface CircuitConfig {
  hops: CircuitHopConfig[];
  maxHops: number;
  maxParallelCircuits: number;
  allowSingleHopFallback: boolean;
  diversity: CircuitDiversityPolicy;
}

export interface CircuitHopConfig {
  id: string;
  label: string;
  remote: string;
  sni: string;
  qkeyId: string;
  qkey: string;
  role: "relay" | "exit";
  provider?: string;
  region?: string;
  jurisdiction?: string;
  failureDomain?: string;
  verifyPeer?: boolean;
  caFile?: string;
  connectTimeoutMs?: number;
  idleTimeoutMs?: number;
  policy?: CircuitHopPolicy;
  hasToken: boolean;
}

export interface CircuitHopPolicy {
  persona?: {
    browser: "chrome" | "firefox" | "safari" | "edge";
    os: "windows" | "macos" | "linux" | "ios" | "android";
  };
  fecMode?: "off" | "auto";
  enableTrafficPadding?: boolean;
  enableTimingObfuscation?: boolean;
  enableCoverPing?: boolean;
}

export interface CircuitDiversityPolicy {
  provider: boolean;
  region: boolean;
  jurisdiction: boolean;
  failureDomain: boolean;
}

/** Live tunnel statistics (while active) */
export interface TunnelStats {
  latencyMs: number;
  lossPercent: number;
  rxBytes: number;
  txBytes: number;
  rxPackets: number;
  txPackets: number;
  uptimeSecs: number;
  fecMode: string;
  stealthMode: string;
  fecActivityPercent: number;
  fecRecoveredPackets: number;
  currentSni?: string;
  circuitGeneration: number;
  circuitState: string;
  effectiveTunnelMtu: number;
  hops: CircuitHopStats[];
}

export interface CircuitHopStats {
  index: number;
  role: "relay" | "exit";
  established: boolean;
  latencyMs: number;
  datagramBudget: number;
}

/** Client-level application settings */
export interface AppSettings {
  general: GeneralSettings;
  hardware: HardwareSettings;
}

export interface GeneralSettings {
  logLevel: "error" | "warn" | "info" | "debug" | "trace";
  autoConnectOnLaunch: boolean;
  startAtLogin: boolean;
  updaterEnabled: boolean;
  updaterChannel: "stable" | "beta";
}

export interface HardwareSettings {
  detectedFeatures: string[];
}

/** Log entry from engine */
export interface LogEntry {
  /** Unix epoch milliseconds, or null when Tauri marked the timestamp invalid. */
  timestamp: TauriLogTimestamp | null;
  timestampValid: boolean;
  timestampError: string | null;
  level: "trace" | "debug" | "info" | "warn" | "error";
  message: string;
  target?: string;
}

/** Navigation tabs */
export type NavTab = "tunnels" | "settings" | "logs" | "about";

/** Tunnel policy view parsed from QKey */
export interface TunnelPolicyView {
  stealth: string;
  fec: string;
  mtu: string;
  cc: string;
  sniDisplay: string;
  customDetails: string[];
  source: "server" | "qkey";
}
