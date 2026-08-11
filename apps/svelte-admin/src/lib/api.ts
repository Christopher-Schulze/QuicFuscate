import type { RuntimeSchema } from "$lib/admin-api-contracts";

export class ApiError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

const SERVER_ERROR_PATTERN = /\b500\b|\bHTTP\s*500\b|\bInternal Server Error\b|\btemporarily unavailable\b/i;
const GENERIC_FAILURE_PATTERN = /\b(?:request\s+failed|could not|failed|no status)\b/i;
const NOT_FOUND_PATTERN = /\bnot\s+found\b/i;

function isServerError(status: number | undefined): boolean {
  return typeof status === "number" && status >= 500 && status < 600;
}

function normalizeApiErrorMessage(status: number, message: string | null): string {
  if (isServerError(status)) return "";
  return message ?? "";
}

export function isAuthError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

export function sanitizeErrorMessage(message: unknown, fallback = "Request failed"): string {
  const apiStatus = message instanceof ApiError ? message.status : undefined;
  const raw = typeof message === "string"
    ? message.trim()
    : message instanceof Error
      ? message.message.trim()
      : "";
  const fallbackText = String(fallback).trim();

  if (isServerError(apiStatus)) return "";
  if (SERVER_ERROR_PATTERN.test(raw)) return "";
  if (NOT_FOUND_PATTERN.test(raw)) return "";
  if (GENERIC_FAILURE_PATTERN.test(raw)) return "";
  if (!raw) {
    if (GENERIC_FAILURE_PATTERN.test(fallbackText)) return "";
    return fallbackText;
  }
  return raw;
}

function truncateUtf8Like(text: string, maxChars: number): string {
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}...`;
}

interface ApiErrorResponse {
  message?: unknown;
  error?: unknown;
  success?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function nonEmptyString(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

const CSRF_TOKEN_HEADER = "X-CSRF-Token";
const CSRF_NONCE_HEADER = "X-CSRF-Nonce";
const CSRF_STORAGE_KEY = "qf_admin_csrf_token";

export type CsrfNonceResult =
  | { ok: true; value: string }
  | { ok: false; reason: "secure-randomness-unavailable" };

function readPersistedCsrfToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.sessionStorage.getItem(CSRF_STORAGE_KEY);
    if (!raw) return null;
    const trimmed = raw.trim();
    return trimmed || null;
  } catch {
    return null;
  }
}

function persistCsrfToken(token: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (token && token.trim()) {
      window.sessionStorage.setItem(CSRF_STORAGE_KEY, token.trim());
    } else {
      window.sessionStorage.removeItem(CSRF_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors
  }
}

let csrfToken: string | null = readPersistedCsrfToken();
let csrfNonceSequence = 0;

function encodeNonceBytes(bytes: Uint8Array): string {
  let encoded = "";
  for (const byte of bytes) encoded += byte.toString(16).padStart(2, "0");
  return encoded;
}

function createSecureNoncePart(): string | null {
  if (typeof globalThis.crypto === "undefined") return null;

  try {
    if (typeof globalThis.crypto.randomUUID === "function") {
      const value = globalThis.crypto.randomUUID().trim();
      if (value) return value;
    }
  } catch {
    // Try the byte-oriented secure source below.
  }

  try {
    if (typeof globalThis.crypto.getRandomValues === "function") {
      const bytes = new Uint8Array(32);
      globalThis.crypto.getRandomValues(bytes);
      return encodeNonceBytes(bytes);
    }
  } catch {
    // Report the unavailable secure source to the request owner.
  }

  return null;
}

export function createCsrfNonce(): CsrfNonceResult {
  const securePart = createSecureNoncePart();
  if (!securePart) return { ok: false, reason: "secure-randomness-unavailable" };

  const sequence = csrfNonceSequence;
  csrfNonceSequence += 1;
  return { ok: true, value: `qf-csrf-${sequence.toString(36)}-${securePart}` };
}

function isCsrfError(status: number | undefined, message: string | null): boolean {
  if (status !== 403) return false;
  const msg = (message ?? "").toLowerCase();
  return msg.includes("csrf");
}

async function ensureCsrfToken(forceRefresh = false): Promise<void> {
  if (!forceRefresh && csrfToken) return;
  try {
    const resp = await fetch("/api/csrf", {
      method: "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    const token = resp.headers.get(CSRF_TOKEN_HEADER);
    if (token) {
      csrfToken = token;
      persistCsrfToken(token);
      return;
    }
    if (resp.status === 401) {
      csrfToken = null;
      persistCsrfToken(null);
    }
  } catch {
    // Network issues handled by actual request path
  }
}

export function parseErrorMessageBody(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) return null;

  if (trimmed.startsWith("{") || trimmed.startsWith("[") || trimmed.startsWith('"')) {
    try {
      const data: unknown = JSON.parse(trimmed);
      const direct = nonEmptyString(data);
      if (direct) return direct;
      if (isRecord(data)) {
        const parsed = data as ApiErrorResponse;
        const message = nonEmptyString(parsed.message);
        if (message) return message;
        const error = nonEmptyString(parsed.error);
        if (error) return error;
      }
    } catch {
      // fall through
    }
  }

  return truncateUtf8Like(trimmed, 240);
}

async function extractErrorMessage(resp: Response): Promise<string | null> {
  let text = "";
  try {
    text = await resp.text();
  } catch {
    return null;
  }
  return parseErrorMessageBody(text);
}

// Event for password-change-required lock
export const PASSWORD_CHANGE_EVENT = "qf:admin-password-change-required";

async function request(path: string, init: RequestInit): Promise<Response> {
  const method = (init.method ?? "GET").toUpperCase();
  if (method === "POST" && !csrfToken) {
    await ensureCsrfToken(false);
  }

  const send = async (): Promise<Response> => {
    const headers = new Headers(init.headers ?? undefined);
    headers.set("Content-Type", "application/json");
    if (csrfToken) {
      headers.set(CSRF_TOKEN_HEADER, csrfToken);
      if (method === "POST") {
        const nonce = createCsrfNonce();
        if (!nonce.ok) throw new ApiError("CSRF nonce unavailable");
        headers.set(CSRF_NONCE_HEADER, nonce.value);
      }
    }
    const resp = await fetch(path, {
      ...init,
      method,
      credentials: "same-origin",
      headers,
    });
    const nextCsrfToken = resp.headers.get(CSRF_TOKEN_HEADER);
    if (nextCsrfToken) {
      csrfToken = nextCsrfToken;
      persistCsrfToken(nextCsrfToken);
    }
    return resp;
  };

  let resp = await send();
  let msg: string | null = null;

  if (!resp.ok) {
    msg = await extractErrorMessage(resp);
    if (method === "POST" && isCsrfError(resp.status, msg)) {
      await ensureCsrfToken(true);
      resp = await send();
      if (!resp.ok) {
        msg = await extractErrorMessage(resp);
      } else {
        return resp;
      }
    }
  }

  if (!resp.ok) {
    if (resp.status === 401) {
      csrfToken = null;
      persistCsrfToken(null);
    }
    if (resp.status === 423) {
      if (typeof window !== "undefined") {
        window.dispatchEvent(new CustomEvent(PASSWORD_CHANGE_EVENT));
      }
    }
    throw new ApiError(
      sanitizeErrorMessage(normalizeApiErrorMessage(resp.status, msg), ""),
      resp.status,
    );
  }
  return resp;
}

async function readValidatedJson<T>(
  resp: Response,
  path: string,
  schema: RuntimeSchema<T>,
): Promise<T> {
  let raw: unknown;
  try {
    raw = await resp.json();
  } catch {
    throw new ApiError(`Invalid JSON response from ${path} [${schema.name}]`, resp.status);
  }
  const result = schema.validate(raw);
  if (!result.success) {
    throw new ApiError(`Invalid response from ${path}: ${result.issue}`, resp.status);
  }
  return result.value;
}

export async function getJson<T>(path: string, schema: RuntimeSchema<T>): Promise<T> {
  const resp = await request(path, { method: "GET" });
  return await readValidatedJson(resp, path, schema);
}

export async function getText(path: string): Promise<string> {
  const resp = await request(path, { method: "GET" });
  return await resp.text();
}

export async function postJson<T, B>(path: string, body: B, schema: RuntimeSchema<T>): Promise<T> {
  const resp = await request(path, { method: "POST", body: JSON.stringify(body) });
  return await readValidatedJson(resp, path, schema);
}
