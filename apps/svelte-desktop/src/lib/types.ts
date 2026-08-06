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
