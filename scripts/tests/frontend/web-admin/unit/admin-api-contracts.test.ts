import { afterEach, describe, expect, test, vi } from "vitest";

import {
  adminApiSchemas,
  type RuntimeSchema,
} from "../../../../../apps/svelte-admin/src/lib/admin-api-contracts";
import {
  getJson,
  postJson,
} from "../../../../../apps/svelte-admin/src/lib/api";

interface EndpointCase {
  name: string;
  method: "GET" | "POST";
  path: string;
  schema: RuntimeSchema<unknown>;
  valid: unknown;
  missing: unknown;
  wrongType: unknown;
}

const ACTION_VALID = { success: true, message: "ok" };
const ACTION_MISSING = { message: "ok" };
const ACTION_WRONG_TYPE = { success: "yes", message: "ok" };
const AUTH_VALID = {
  success: true,
  data: { user: "admin", requires_password_change: false },
};
const STATUS_VALID = {
  success: true,
  data: {
    version: "0.2.0",
    uptime_secs: 100,
    clients_active: 2,
    clients_total: 4,
    bytes_in: 1_024,
    bytes_out: 2_048,
    listen: "0.0.0.0:4433",
    config_writable: true,
  },
};

function actionCase(
  name: string,
  path: string,
  schema: RuntimeSchema<unknown>,
): EndpointCase {
  return {
    name,
    method: "POST",
    path,
    schema,
    valid: ACTION_VALID,
    missing: ACTION_MISSING,
    wrongType: ACTION_WRONG_TYPE,
  };
}

const ENDPOINT_CASES: EndpointCase[] = [
  {
    name: "login",
    method: "POST",
    path: "/api/login",
    schema: adminApiSchemas.login,
    valid: AUTH_VALID,
    missing: { success: true, data: { requires_password_change: false } },
    wrongType: { success: true, data: { user: "admin", requires_password_change: "no" } },
  },
  actionCase("logout", "/api/logout", adminApiSchemas.logout),
  {
    name: "admin auth read",
    method: "GET",
    path: "/api/admin/auth",
    schema: adminApiSchemas.adminAuthRead,
    valid: AUTH_VALID,
    missing: { success: true, data: { user: "admin" } },
    wrongType: { success: true, data: { user: 4, requires_password_change: false } },
  },
  actionCase("admin auth update", "/api/admin/auth", adminApiSchemas.adminAuthUpdate),
  {
    name: "config read",
    method: "GET",
    path: "/api/config",
    schema: adminApiSchemas.configRead,
    valid: { success: true, data: { config: "[transport]\nmtu = 1400\n" } },
    missing: { success: true, data: {} },
    wrongType: { success: true, data: { config: 1400 } },
  },
  actionCase("config write", "/api/config", adminApiSchemas.configWrite),
  {
    name: "status",
    method: "GET",
    path: "/api/status",
    schema: adminApiSchemas.status,
    valid: STATUS_VALID,
    missing: { success: true, data: { ...STATUS_VALID.data, version: undefined } },
    wrongType: { success: true, data: { ...STATUS_VALID.data, bytes_in: "1024" } },
  },
  {
    name: "clients",
    method: "GET",
    path: "/api/clients",
    schema: adminApiSchemas.clients,
    valid: {
      success: true,
      data: [{ id: "session:1", ip: "10.0.0.2", bytes_in: 100, bytes_out: 200 }],
    },
    missing: {
      success: true,
      data: [{ ip: "10.0.0.2", bytes_in: 100, bytes_out: 200 }],
    },
    wrongType: {
      success: true,
      data: [{ id: "session:1", ip: "10.0.0.2", bytes_in: "100", bytes_out: 200 }],
    },
  },
  {
    name: "metrics",
    method: "GET",
    path: "/api/metrics/json",
    schema: adminApiSchemas.metrics,
    valid: {
      success: true,
      data: {
        metrics: {
          quicfuscate_connections_rejected: 0,
          quicfuscate_bytes_in_total: 100,
          quicfuscate_bytes_out_total: 200,
          quicfuscate_lifecycle_phase: "running",
        },
      },
    },
    missing: {
      success: true,
      data: {
        metrics: {
          quicfuscate_connections_rejected: 0,
          quicfuscate_bytes_in_total: 100,
        },
      },
    },
    wrongType: {
      success: true,
      data: {
        metrics: {
          quicfuscate_connections_rejected: "0",
          quicfuscate_bytes_in_total: 100,
          quicfuscate_bytes_out_total: 200,
        },
      },
    },
  },
  {
    name: "blocked IPs",
    method: "GET",
    path: "/api/blocked",
    schema: adminApiSchemas.blockedIps,
    valid: { success: true, data: { ips: ["192.0.2.1"] } },
    missing: { success: true, data: {} },
    wrongType: { success: true, data: { ips: "192.0.2.1" } },
  },
  actionCase("block IP", "/api/block", adminApiSchemas.blockIp),
  actionCase("unblock IP", "/api/unblock", adminApiSchemas.unblockIp),
  {
    name: "logging read",
    method: "GET",
    path: "/api/config/logging",
    schema: adminApiSchemas.loggingRead,
    valid: { success: true, data: { mode: "normal" } },
    missing: { success: true, data: {} },
    wrongType: { success: true, data: { mode: 4 } },
  },
  actionCase("logging write", "/api/config/logging", adminApiSchemas.loggingWrite),
  {
    name: "logs",
    method: "GET",
    path: "/api/logs?cursor=0",
    schema: adminApiSchemas.logs,
    valid: {
      success: true,
      data: {
        lines: [{
          ts: 1_710_000_000_000,
          timestamp_valid: true,
          timestamp_error: null,
          level: "info",
          msg: "ready",
        }],
        cursor: 1,
        mode: "normal",
      },
    },
    missing: { success: true, data: { lines: [], mode: "normal" } },
    wrongType: { success: true, data: { lines: "ready", cursor: 1, mode: "normal" } },
  },
  actionCase("logs clear", "/api/logs/clear", adminApiSchemas.logsClear),
  {
    name: "QKey list",
    method: "GET",
    path: "/api/qkeys",
    schema: adminApiSchemas.qkeyList,
    valid: {
      success: true,
      data: { keys: [{ id: "abc123", created_at: 1_710_000_000, expires_at: null }] },
    },
    missing: { success: true, data: { keys: [{ id: "abc123" }] } },
    wrongType: {
      success: true,
      data: { keys: [{ id: "abc123", created_at: "1710000000" }] },
    },
  },
  {
    name: "QKey create",
    method: "POST",
    path: "/api/qkey",
    schema: adminApiSchemas.qkeyCreate,
    valid: {
      success: true,
      data: { qkey: "QKey-REAL", created_at: 1_710_000_000, expires_at: null },
    },
    missing: { success: true, data: { created_at: 1_710_000_000 } },
    wrongType: {
      success: true,
      data: { qkey: 4, created_at: 1_710_000_000, expires_at: null },
    },
  },
  actionCase("QKey revoke", "/api/qkeys/revoke", adminApiSchemas.qkeyRevoke),
];

function stubResponse(body: string, contentType = "application/json"): void {
  const fetchMock = vi.fn(async (input: unknown) => {
    if (input === "/api/csrf") {
      return new Response("{}", {
        status: 200,
        headers: { "X-CSRF-Token": "a".repeat(32), "Content-Type": "application/json" },
      });
    }
    return new Response(body, { status: 200, headers: { "Content-Type": contentType } });
  });
  vi.stubGlobal("fetch", fetchMock);
}

function invokeEndpoint(endpoint: EndpointCase): Promise<unknown> {
  if (endpoint.method === "GET") return getJson(endpoint.path, endpoint.schema);
  return postJson(endpoint.path, {}, endpoint.schema);
}

describe("admin API runtime contracts", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  test.each(ENDPOINT_CASES)("accepts a valid $name response", async (endpoint) => {
    stubResponse(JSON.stringify(endpoint.valid));
    await expect(invokeEndpoint(endpoint)).resolves.toMatchObject({ success: true });
  });

  test.each(ENDPOINT_CASES)("rejects a missing required field for $name", async (endpoint) => {
    stubResponse(JSON.stringify(endpoint.missing));
    await expect(invokeEndpoint(endpoint)).rejects.toMatchObject({
      message: expect.stringContaining(endpoint.path),
    });
  });

  test.each(ENDPOINT_CASES)("rejects a wrong field type for $name", async (endpoint) => {
    stubResponse(JSON.stringify(endpoint.wrongType));
    await expect(invokeEndpoint(endpoint)).rejects.toMatchObject({
      message: expect.stringContaining(endpoint.path),
    });
  });

  test.each(ENDPOINT_CASES)("rejects a non-JSON body for $name", async (endpoint) => {
    stubResponse("<html>proxy error</html>", "text/html");
    await expect(invokeEndpoint(endpoint)).rejects.toMatchObject({
      message: expect.stringContaining(endpoint.path),
    });
  });
});
