import {
  parseAdminLogEntries,
  parseAdminQKeyCreateResponse,
  parseAdminQKeyEntries,
  type ParsedQKeyCreateResponse,
} from "$lib/timestamp-boundary";
import type {
  AdminResponse,
  ClientInfo,
  LogEntry,
  LogMode,
  MetricsMap,
  QKeyEntry,
  StatusData,
} from "$lib/types";

export type ValidationResult<T> =
  | { success: true; value: T }
  | { success: false; issue: string };

export interface RuntimeSchema<T> {
  readonly name: string;
  validate(value: unknown): ValidationResult<T>;
}

export interface AuthStatusData {
  user: string;
  requires_password_change: boolean;
}

export interface LogsData {
  lines: LogEntry[];
  cursor: number;
  mode: LogMode;
}

const MAX_MESSAGE_LENGTH = 8_192;
const MAX_CONFIG_LENGTH = 1_048_576;
const MAX_IDENTIFIER_LENGTH = 512;
const MAX_LOG_MESSAGE_LENGTH = 65_536;
const MAX_COLLECTION_LENGTH = 65_536;

function valid<T>(value: T): ValidationResult<T> {
  return { success: true, value };
}

function invalid<T>(issue: string): ValidationResult<T> {
  return { success: false, issue };
}

function defineSchema<T>(
  name: string,
  validate: (value: unknown) => ValidationResult<T>,
): RuntimeSchema<T> {
  return { name, validate };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(
  value: unknown,
  path: string,
  maxLength: number,
  allowEmpty = false,
): ValidationResult<string> {
  if (typeof value !== "string") return invalid(`${path} must be a string`);
  if (!allowEmpty && value.trim().length === 0) return invalid(`${path} must not be empty`);
  if (value.length > maxLength) return invalid(`${path} exceeds ${maxLength} characters`);
  return valid(value);
}

function optionalString(
  value: unknown,
  path: string,
  maxLength: number,
): ValidationResult<string | null | undefined> {
  if (value === undefined) return valid(undefined);
  if (value === null) return valid(null);
  return requiredString(value, path, maxLength, true);
}

function nonNegativeInteger(value: unknown, path: string): ValidationResult<number> {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return invalid(`${path} must be a non-negative safe integer`);
  }
  return valid(value);
}

function optionalNonNegativeInteger(
  value: unknown,
  path: string,
): ValidationResult<number | null | undefined> {
  if (value === undefined) return valid(undefined);
  if (value === null) return valid(null);
  return nonNegativeInteger(value, path);
}

function parseLogMode(value: unknown, path: string): ValidationResult<LogMode> {
  if (value === "verbose" || value === "normal" || value === "minimal" || value === "no-log") {
    return valid(value);
  }
  return invalid(`${path} must be verbose, normal, minimal, or no-log`);
}

function parseAdminResponse<T>(
  raw: unknown,
  parseData: ((value: unknown) => ValidationResult<T>) | null,
  requireSuccessData: boolean,
): ValidationResult<AdminResponse<T>> {
  if (!isRecord(raw)) return invalid("response must be an object");
  if (typeof raw.success !== "boolean") return invalid("success must be a boolean");

  const parsedMessage = optionalString(raw.message, "message", MAX_MESSAGE_LENGTH);
  if (!parsedMessage.success) return parsedMessage;

  if (parseData === null) {
    return valid({ success: raw.success, message: parsedMessage.value, data: null });
  }
  if (raw.data === undefined || raw.data === null) {
    if (raw.success && requireSuccessData) return invalid("data is required for a successful response");
    return valid({ success: raw.success, message: parsedMessage.value, data: null });
  }

  const parsedData = parseData(raw.data);
  if (!parsedData.success) return invalid(`data.${parsedData.issue}`);
  return valid({ success: raw.success, message: parsedMessage.value, data: parsedData.value });
}

function dataSchema<T>(
  name: string,
  parseData: (value: unknown) => ValidationResult<T>,
): RuntimeSchema<AdminResponse<T>> {
  return defineSchema(name, (raw) => parseAdminResponse(raw, parseData, true));
}

function actionSchema(name: string): RuntimeSchema<AdminResponse<null>> {
  return defineSchema(name, (raw) => parseAdminResponse<null>(raw, null, false));
}

function parseAuthStatus(value: unknown): ValidationResult<AuthStatusData> {
  if (!isRecord(value)) return invalid("must be an object");
  const user = requiredString(value.user, "user", 64);
  if (!user.success) return user;
  if (typeof value.requires_password_change !== "boolean") {
    return invalid("requires_password_change must be a boolean");
  }
  return valid({ user: user.value, requires_password_change: value.requires_password_change });
}

function parseConfig(value: unknown): ValidationResult<{ config: string }> {
  if (!isRecord(value)) return invalid("must be an object");
  const config = requiredString(value.config, "config", MAX_CONFIG_LENGTH, true);
  return config.success ? valid({ config: config.value }) : config;
}

function parseStatus(value: unknown): ValidationResult<StatusData> {
  if (!isRecord(value)) return invalid("must be an object");
  const version = requiredString(value.version, "version", 128);
  if (!version.success) return version;
  const uptime = nonNegativeInteger(value.uptime_secs, "uptime_secs");
  if (!uptime.success) return uptime;
  const clientsActive = nonNegativeInteger(value.clients_active, "clients_active");
  if (!clientsActive.success) return clientsActive;
  const bytesIn = nonNegativeInteger(value.bytes_in, "bytes_in");
  if (!bytesIn.success) return bytesIn;
  const bytesOut = nonNegativeInteger(value.bytes_out, "bytes_out");
  if (!bytesOut.success) return bytesOut;
  const listen = requiredString(value.listen, "listen", MAX_IDENTIFIER_LENGTH);
  if (!listen.success) return listen;
  const clientsTotal = optionalNonNegativeInteger(value.clients_total, "clients_total");
  if (!clientsTotal.success) return clientsTotal;
  if (value.config_writable !== undefined && value.config_writable !== null && typeof value.config_writable !== "boolean") {
    return invalid("config_writable must be a boolean or null");
  }

  const status: StatusData = {
    version: version.value,
    uptime_secs: uptime.value,
    clients_active: clientsActive.value,
    bytes_in: bytesIn.value,
    bytes_out: bytesOut.value,
    listen: listen.value,
  };
  if (clientsTotal.value !== undefined && clientsTotal.value !== null) {
    status.clients_total = clientsTotal.value;
  }
  if (value.config_writable === null || typeof value.config_writable === "boolean") {
    status.config_writable = value.config_writable;
  }
  return valid(status);
}

function parseClient(value: unknown, index: number): ValidationResult<ClientInfo> {
  const path = `clients[${index}]`;
  if (!isRecord(value)) return invalid(`${path} must be an object`);
  const id = requiredString(value.id, `${path}.id`, MAX_IDENTIFIER_LENGTH);
  if (!id.success) return id;
  const ip = requiredString(value.ip, `${path}.ip`, 128);
  if (!ip.success) return ip;
  const bytesIn = nonNegativeInteger(value.bytes_in, `${path}.bytes_in`);
  if (!bytesIn.success) return bytesIn;
  const bytesOut = nonNegativeInteger(value.bytes_out, `${path}.bytes_out`);
  if (!bytesOut.success) return bytesOut;
  const connected = optionalNonNegativeInteger(value.connected_secs, `${path}.connected_secs`);
  if (!connected.success) return connected;
  const stealth = optionalString(value.stealth_mode, `${path}.stealth_mode`, 128);
  if (!stealth.success) return stealth;
  return valid({
    id: id.value,
    ip: ip.value,
    bytes_in: bytesIn.value,
    bytes_out: bytesOut.value,
    connected_secs: connected.value ?? null,
    stealth_mode: stealth.value ?? null,
  });
}

function parseClients(value: unknown): ValidationResult<ClientInfo[]> {
  if (!Array.isArray(value)) return invalid("must be an array");
  if (value.length > MAX_COLLECTION_LENGTH) return invalid("exceeds the client limit");
  const clients: ClientInfo[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const client = parseClient(value[index], index);
    if (!client.success) return client;
    clients.push(client.value);
  }
  return valid(clients);
}

const REQUIRED_METRICS = [
  "quicfuscate_connections_rejected",
  "quicfuscate_bytes_in_total",
  "quicfuscate_bytes_out_total",
];

function parseMetrics(value: unknown): ValidationResult<{ metrics: MetricsMap }> {
  if (!isRecord(value) || !isRecord(value.metrics)) return invalid("metrics must be an object");
  for (const name of REQUIRED_METRICS) {
    const metric = nonNegativeInteger(value.metrics[name], `metrics.${name}`);
    if (!metric.success) return metric;
  }
  const metrics: MetricsMap = {};
  for (const [name, metric] of Object.entries(value.metrics)) {
    if (typeof metric === "number" && Number.isSafeInteger(metric) && metric >= 0) metrics[name] = metric;
  }
  return valid({ metrics });
}

function parseBlockedIps(value: unknown): ValidationResult<{ ips: string[] }> {
  if (!isRecord(value) || !Array.isArray(value.ips)) return invalid("ips must be an array");
  if (value.ips.length > MAX_COLLECTION_LENGTH) return invalid("ips exceeds the blocked-IP limit");
  const ips: string[] = [];
  for (let index = 0; index < value.ips.length; index += 1) {
    const ip = requiredString(value.ips[index], `ips[${index}]`, 128);
    if (!ip.success) return ip;
    ips.push(ip.value);
  }
  return valid({ ips });
}

function parseLoggingConfig(value: unknown): ValidationResult<{ mode: LogMode }> {
  if (!isRecord(value)) return invalid("must be an object");
  const mode = parseLogMode(value.mode, "mode");
  return mode.success ? valid({ mode: mode.value }) : mode;
}

function validateLogLine(value: unknown, index: number): ValidationResult<null> {
  const path = `lines[${index}]`;
  if (!isRecord(value)) return invalid(`${path} must be an object`);
  const timestamp = nonNegativeInteger(value.ts, `${path}.ts`);
  if (!timestamp.success) return timestamp;
  if (typeof value.timestamp_valid !== "boolean") {
    return invalid(`${path}.timestamp_valid must be a boolean`);
  }
  const timestampError = optionalString(
    value.timestamp_error,
    `${path}.timestamp_error`,
    MAX_MESSAGE_LENGTH,
  );
  if (!timestampError.success) return timestampError;
  const level = requiredString(value.level, `${path}.level`, 32);
  if (!level.success) return level;
  const message = requiredString(value.msg, `${path}.msg`, MAX_LOG_MESSAGE_LENGTH, true);
  if (!message.success) return message;
  return valid(null);
}

function parseLogs(value: unknown): ValidationResult<LogsData> {
  if (!isRecord(value) || !Array.isArray(value.lines)) return invalid("lines must be an array");
  if (value.lines.length > 2_000) return invalid("lines exceeds the log batch limit");
  for (let index = 0; index < value.lines.length; index += 1) {
    const line = validateLogLine(value.lines[index], index);
    if (!line.success) return line;
  }
  const cursor = nonNegativeInteger(value.cursor, "cursor");
  if (!cursor.success) return cursor;
  const mode = parseLogMode(value.mode, "mode");
  if (!mode.success) return mode;
  return valid({ lines: parseAdminLogEntries(value.lines), cursor: cursor.value, mode: mode.value });
}

function validateQKeyEntry(value: unknown, index: number): ValidationResult<null> {
  const path = `keys[${index}]`;
  if (!isRecord(value)) return invalid(`${path} must be an object`);
  const id = requiredString(value.id, `${path}.id`, MAX_IDENTIFIER_LENGTH);
  if (!id.success) return id;
  if (id.value !== id.value.trim()) return invalid(`${path}.id must be canonical`);
  const created = nonNegativeInteger(value.created_at, `${path}.created_at`);
  if (!created.success) return created;
  const expires = optionalNonNegativeInteger(value.expires_at, `${path}.expires_at`);
  if (!expires.success) return expires;
  for (const field of ["name", "stealth", "fec"]) {
    const optional = optionalString(value[field], `${path}.${field}`, MAX_IDENTIFIER_LENGTH);
    if (!optional.success) return optional;
  }
  if (value.qkey !== undefined && value.qkey !== null) {
    return invalid(`${path}.qkey must not be exposed by the list endpoint`);
  }
  return valid(null);
}

function parseQKeyList(value: unknown): ValidationResult<{ keys: QKeyEntry[] }> {
  if (!isRecord(value) || !Array.isArray(value.keys)) return invalid("keys must be an array");
  if (value.keys.length > 200) return invalid("keys exceeds the registry limit");
  for (let index = 0; index < value.keys.length; index += 1) {
    const entry = validateQKeyEntry(value.keys[index], index);
    if (!entry.success) return entry;
  }
  return valid({ keys: parseAdminQKeyEntries(value.keys) });
}

function parseQKeyCreate(value: unknown): ValidationResult<ParsedQKeyCreateResponse> {
  if (!isRecord(value)) return invalid("must be an object");
  const qkey = requiredString(value.qkey, "qkey", 65_536);
  if (!qkey.success) return qkey;
  const created = nonNegativeInteger(value.created_at, "created_at");
  if (!created.success) return created;
  const expires = optionalNonNegativeInteger(value.expires_at, "expires_at");
  if (!expires.success) return expires;
  const parsed = parseAdminQKeyCreateResponse(value);
  return parsed === null ? invalid("could not parse QKey metadata") : valid(parsed);
}

export const adminApiSchemas = {
  login: dataSchema("POST /api/login", parseAuthStatus),
  logout: actionSchema("POST /api/logout"),
  adminAuthRead: dataSchema("GET /api/admin/auth", parseAuthStatus),
  adminAuthUpdate: actionSchema("POST /api/admin/auth"),
  configRead: dataSchema("GET /api/config", parseConfig),
  configWrite: actionSchema("POST /api/config"),
  status: dataSchema("GET /api/status", parseStatus),
  clients: dataSchema("GET /api/clients", parseClients),
  metrics: dataSchema("GET /api/metrics/json", parseMetrics),
  blockedIps: dataSchema("GET /api/blocked", parseBlockedIps),
  blockIp: actionSchema("POST /api/block"),
  unblockIp: actionSchema("POST /api/unblock"),
  loggingRead: dataSchema("GET /api/config/logging", parseLoggingConfig),
  loggingWrite: actionSchema("POST /api/config/logging"),
  logs: dataSchema("GET /api/logs", parseLogs),
  logsClear: actionSchema("POST /api/logs/clear"),
  qkeyList: dataSchema("GET /api/qkeys", parseQKeyList),
  qkeyCreate: dataSchema("POST /api/qkey", parseQKeyCreate),
  qkeyRevoke: actionSchema("POST /api/qkeys/revoke"),
};
