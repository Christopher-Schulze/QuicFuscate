import type {
  TunnelConfig,
  TunnelState,
  TunnelStats,
  AppSettings,
  LogEntry,
  NavTab,
  TunnelPolicyView,
} from "$lib/types";

// --- Navigation ---
let _activeTab = $state<NavTab>("tunnels");
export function getActiveTab(): NavTab { return _activeTab; }
export function setActiveTab(tab: NavTab): void { _activeTab = tab; }

// --- Tunnels ---
let _tunnels = $state<TunnelConfig[]>([]);
export function getTunnels(): TunnelConfig[] { return _tunnels; }
export function setTunnels(tunnels: TunnelConfig[]): void { _tunnels = tunnels; }
export function updateTunnels(fn: (prev: TunnelConfig[]) => TunnelConfig[]): void {
  _tunnels = fn(_tunnels);
}

// --- Selected Tunnel ---
let _selectedId = $state<string | null>(null);
export function getSelectedId(): string | null { return _selectedId; }
export function setSelectedId(id: string | null): void { _selectedId = id; }

// --- Tunnel States ---
let _tunnelStates = $state<Record<string, TunnelState>>({});
export function getTunnelStates(): Record<string, TunnelState> { return _tunnelStates; }
export function setTunnelStates(states: Record<string, TunnelState>): void { _tunnelStates = states; }
export function updateTunnelStates(fn: (prev: Record<string, TunnelState>) => Record<string, TunnelState>): void {
  _tunnelStates = fn(_tunnelStates);
}
// --- Tunnel Stats ---
let _tunnelStats = $state<Record<string, TunnelStats | null>>({});
export function getTunnelStats(): Record<string, TunnelStats | null> { return _tunnelStats; }
export function setTunnelStats(stats: Record<string, TunnelStats | null>): void { _tunnelStats = stats; }
export function updateTunnelStats(fn: (prev: Record<string, TunnelStats | null>) => Record<string, TunnelStats | null>): void {
  _tunnelStats = fn(_tunnelStats);
}

// --- Active Tunnel ID (cached from engine_status polling) ---
let _activeTunnelId = $state<string | null>(null);
export function getActiveTunnelId(): string | null { return _activeTunnelId; }
export function setActiveTunnelId(id: string | null): void { _activeTunnelId = id; }

// --- Error ---
let _error = $state<string | null>(null);
export function getError(): string | null { return _error; }
export function setError(error: string | null): void { _error = error; }

// --- Logs ---
let _logs = $state<LogEntry[]>([]);
export function getLogs(): LogEntry[] { return _logs; }
export function setLogs(logs: LogEntry[]): void { _logs = logs; }
export function appendLogs(entries: LogEntry[]): void {
  const next = _logs.concat(entries);
  _logs = next.length > 2000 ? next.slice(next.length - 2000) : next;
}

// --- Settings ---
let _settings = $state<AppSettings>({
  general: {
    logLevel: "info",
    autoConnectOnLaunch: false,
    startAtLogin: false,
    updaterEnabled: false,
    updaterChannel: "stable",
  },
  hardware: {
    detectedFeatures: [],
  },
});
export function getSettings(): AppSettings { return _settings; }
export function setSettings(settings: AppSettings): void { _settings = settings; }
export function updateSettings(fn: (prev: AppSettings) => AppSettings): void {
  _settings = fn(_settings);
}

// --- Hydration ---
let _hydrationDone = $state(false);
export function getHydrationDone(): boolean { return _hydrationDone; }
export function setHydrationDone(v: boolean): void { _hydrationDone = v; }

// --- Persistence ---
export type PersistenceStatus =
  | { phase: "loading"; dirty: false; error: null }
  | { phase: "browser"; dirty: false; error: null }
  | { phase: "ready"; dirty: false; error: null }
  | { phase: "dirty"; dirty: true; error: null }
  | { phase: "saving"; dirty: true; error: null }
  | { phase: "save-error"; dirty: true; error: string }
  | { phase: "load-error"; dirty: false; error: string };

let _persistenceStatus = $state<PersistenceStatus>({ phase: "loading", dirty: false, error: null });
export function getPersistenceStatus(): PersistenceStatus { return _persistenceStatus; }
export function setPersistenceStatus(status: PersistenceStatus): void { _persistenceStatus = status; }

// --- QKey Policy Cache ---
let _qkeyPolicies = $state<Record<string, TunnelPolicyView>>({});
export function getQkeyPolicies(): Record<string, TunnelPolicyView> { return _qkeyPolicies; }
export function setQkeyPolicies(v: Record<string, TunnelPolicyView>): void { _qkeyPolicies = v; }

// --- Throughput Cache ---
let _throughput = $state<Record<string, { downBps: number; upBps: number }>>({});
export function getThroughput(): Record<string, { downBps: number; upBps: number }> { return _throughput; }
export function setThroughput(v: Record<string, { downBps: number; upBps: number }>): void { _throughput = v; }
