import type {
  NavTab,
  StatusData,
  ClientInfo,
  MetricsMap,
  QKeyEntry,
  ConfirmDialogRequest,
} from "$lib/types";
import { isAuthError } from "$lib/api";

// Navigation
let _activeTab = $state<NavTab>("dashboard");

export function getActiveTab(): NavTab {
  return _activeTab;
}

export function setActiveTab(tab: NavTab): void {
  _activeTab = tab;
}

// Auth
let _authRequired = $state(false);
let _authError = $state<string | null>(null);
let _adminUser = $state<string | null>(null);
let _requiresPasswordChange = $state(false);

export function getAuthRequired(): boolean {
  return _authRequired;
}
export function setAuthRequired(v: boolean): void {
  _authRequired = v;
}

export function getAuthError(): string | null {
  return _authError;
}
export function setAuthError(v: string | null): void {
  _authError = v;
}

/**
 * Handles an authentication error by clearing the auth-error message and
 * triggering the auth-required flow. Returns true when the error was an
 * auth error (and was handled), false otherwise - so callers can branch:
 *
 *   if (!handleAuthError(e)) { showFallbackToast(); }
 */
export function handleAuthError(e: unknown): boolean {
  if (!isAuthError(e)) return false;
  _authError = null;
  _authRequired = true;
  return true;
}

export function setAdminUser(v: string | null): void {
  _adminUser = v;
}

export function getRequiresPasswordChange(): boolean {
  return _requiresPasswordChange;
}
export function setRequiresPasswordChange(v: boolean): void {
  _requiresPasswordChange = v;
}

// Status
let _status = $state<StatusData | null>(null);
let _statusLoading = $state(false);

export function getStatus(): StatusData | null {
  return _status;
}
export function setStatus(v: StatusData | null): void {
  _status = v;
}
export function setStatusLoading(v: boolean): void {
  _statusLoading = v;
}

// Clients
let _clients = $state<ClientInfo[]>([]);
let _clientsLoading = $state(false);

export function getClients(): ClientInfo[] {
  return _clients;
}
export function setClients(v: ClientInfo[]): void {
  _clients = v;
}
export function setClientsLoading(v: boolean): void {
  _clientsLoading = v;
}

// Metrics
let _metrics = $state<MetricsMap | null>(null);
let _metricsLoading = $state(false);

export function getMetrics(): MetricsMap | null {
  return _metrics;
}
export function setMetrics(v: MetricsMap | null): void {
  _metrics = v;
}
export function setMetricsLoading(v: boolean): void {
  _metricsLoading = v;
}

// QKeys
let _qkeyList = $state<QKeyEntry[]>([]);
let _qkeyListLoading = $state(false);

export function getQkeyList(): QKeyEntry[] {
  return _qkeyList;
}
export function setQkeyList(v: QKeyEntry[]): void {
  _qkeyList = v;
}
export function getQkeyListLoading(): boolean {
  return _qkeyListLoading;
}
export function setQkeyListLoading(v: boolean): void {
  _qkeyListLoading = v;
}

// Dirty flags
let _configDirty = $state(false);
let _logsDirty = $state(false);

export function getConfigDirty(): boolean {
  return _configDirty;
}
export function setConfigDirty(v: boolean): void {
  _configDirty = v;
}

export function getLogsDirty(): boolean {
  return _logsDirty;
}
export function setLogsDirty(v: boolean): void {
  _logsDirty = v;
}

// Confirm dialog
interface ConfirmDialogState extends ConfirmDialogRequest {
  id: number;
}

interface PendingConfirmDialog {
  id: number;
  resolve: (accepted: boolean) => void;
}

let _confirmDialogRequest = $state<ConfirmDialogState | null>(null);
let _pendingConfirmDialog: PendingConfirmDialog | null = null;
let _nextConfirmDialogId = 0;

export function getConfirmDialogRequest(): ConfirmDialogState | null {
  return _confirmDialogRequest;
}

export function confirmDialog(request: ConfirmDialogRequest): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    if (_pendingConfirmDialog) {
      settleConfirmDialog(_pendingConfirmDialog.id, false);
    }
    const id = ++_nextConfirmDialogId;
    _pendingConfirmDialog = { id, resolve };
    _confirmDialogRequest = { ...request, id };
  });
}

export function resolveConfirmDialog(requestId: number, accepted: boolean): void {
  settleConfirmDialog(requestId, accepted);
}

export function cancelConfirmDialog(requestId: number): void {
  settleConfirmDialog(requestId, false);
}

function settleConfirmDialog(requestId: number, accepted: boolean): void {
  if (!_pendingConfirmDialog || _pendingConfirmDialog.id !== requestId) return;
  const pending = _pendingConfirmDialog;
  _pendingConfirmDialog = null;
  _confirmDialogRequest = null;
  pending.resolve(accepted);
}
