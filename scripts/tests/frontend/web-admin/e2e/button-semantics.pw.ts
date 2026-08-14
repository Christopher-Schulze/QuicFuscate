import { expect, test, type Page } from "@playwright/test";

type StubState = {
  serverConfig: string;
  serverLogMode: "verbose" | "normal" | "minimal" | "no-log";
  logs: Array<{ ts: number; level: "info" | "warn" | "error" | "debug"; msg: string }>;
  logCursor: number;
};

const CONFIG_TOML = [
  "[stealth]",
  "mode = \"manual\"",
  "enable_domain_fronting = true",
  "enable_http3_masquerading = true",
  "use_tls_cover = true",
  "use_qpack_headers = true",
  "enable_traffic_padding = false",
  "enable_timing_obfuscation = false",
  "enable_protocol_mimicry = true",
  "enable_doh = true",
  "",
  "[fec]",
  "initial_mode = \"normal\"",
  "",
  "[transport]",
  "cc_algorithm = \"bbr3\"",
  "mtu = 1400",
  "",
].join("\n");
const BASE_LOG_TIMESTAMP_MS = 1_710_000_000_000;

function bump(counters: Map<string, number>, key: string) {
  counters.set(key, (counters.get(key) ?? 0) + 1);
}

function count(counters: Map<string, number>, key: string): number {
  return counters.get(key) ?? 0;
}

async function selectLogMode(page: Page, modeLabel: "Verbose" | "Normal" | "Minimal" | "No-Log"): Promise<void> {
  const modeKey = modeLabel.toLowerCase().replace(/[^a-z]+/g, "-");
  await page.getByTestId(`log-mode-${modeKey}`).click();
}

async function stubApi(page: Page, state: StubState, counters: Map<string, number>): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const url = new URL(req.url());
    const path = url.pathname;
    const key = `${method} ${path}`;

    if (path.startsWith("/api/logs")) {
      bump(counters, "GET /api/logs");
    } else {
      bump(counters, key);
    }

    if (path === "/api/status") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: {
            version: "0.0.0-e2e",
            listen: "127.0.0.1:4433",
            uptime_secs: 123,
            clients_active: 2,
            bytes_in: 3072,
            bytes_out: 4096,
          },
        }),
      });
      return;
    }

    if (path === "/api/admin/auth") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: { user: "admin", requires_password_change: false },
        }),
      });
      return;
    }

    if (path === "/api/config" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { config: state.serverConfig } }),
      });
      return;
    }

    if (path === "/api/config" && method === "POST") {
      const body = req.postDataJSON() as { config?: unknown };
      if (typeof body?.config === "string" && body.config.trim()) {
        state.serverConfig = body.config;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    if (path === "/api/config/logging") {
      if (method === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { mode: state.serverLogMode } }),
        });
        return;
      }
      const body = req.postDataJSON() as { mode?: unknown };
      if (
        body?.mode === "verbose" ||
        body?.mode === "normal" ||
        body?.mode === "minimal" ||
        body?.mode === "no-log"
      ) {
        state.serverLogMode = body.mode;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    if (path === "/api/qkeys") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { keys: [] } }),
      });
      return;
    }

    if (path === "/api/logs/clear" && method === "POST") {
      state.logs = [];
      state.logCursor = 0;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, message: "Logs cleared" }),
      });
      return;
    }

    if (path.startsWith("/api/logs")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: {
            lines: state.logs,
            cursor: state.logCursor,
          },
        }),
      });
      return;
    }

    if (path === "/api/clients") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: [{ ip: "203.0.113.42" }, { ip: "198.51.100.27" }],
        }),
      });
      return;
    }

    if (path === "/api/blocked") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { ips: ["45.83.64.11"] } }),
      });
      return;
    }

    if (path === "/api/metrics/json") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: {
            metrics: {
              quicfuscate_up: 1,
              quicfuscate_uptime_seconds: 123,
              quicfuscate_clients_active: 2,
              quicfuscate_connections_rejected: 5,
              quicfuscate_bytes_in_total: 123456,
              quicfuscate_bytes_out_total: 654321,
            },
          },
        }),
      });
      return;
    }

    if (path === "/api/metrics") {
      await route.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "# metrics\n",
      });
      return;
    }

    if (path === "/api/csrf") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: { "X-CSRF-Token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ success: true, data: {} }),
    });
  });
}

test.describe("Button Semantics", () => {
  let state: StubState;
  let counters: Map<string, number>;

  test.beforeEach(async ({ page }) => {
    state = {
      serverConfig: CONFIG_TOML,
      serverLogMode: "normal",
      logs: [
        { ts: BASE_LOG_TIMESTAMP_MS - 2_000, level: "info", msg: "client connected" },
        { ts: BASE_LOG_TIMESTAMP_MS - 1_000, level: "warn", msg: "latency spike" },
      ],
      logCursor: 2,
    };
    counters = new Map();
    await stubApi(page, state, counters);
    await page.goto("/");
  });

  test("global refresh/save and container clear semantics stay consistent", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });

    await expect(page.getByRole("main").getByText("Dashboard", { exact: true })).toBeVisible();
    const dashboardRefresh = page.locator("main button.action-refresh-btn").first();
    const dashboardBase = {
      status: count(counters, "GET /api/status"),
      clients: count(counters, "GET /api/clients"),
      metrics: count(counters, "GET /api/metrics/json"),
      blocked: count(counters, "GET /api/blocked"),
    };
    await dashboardRefresh.click();
    await expect(page.getByTestId("toast-message").first()).toContainText("Refreshed");
    await expect.poll(() => count(counters, "GET /api/status")).toBeGreaterThan(dashboardBase.status);
    await expect.poll(() => count(counters, "GET /api/clients")).toBeGreaterThan(dashboardBase.clients);
    await expect.poll(() => count(counters, "GET /api/metrics/json")).toBeGreaterThan(dashboardBase.metrics);
    await expect.poll(() => count(counters, "GET /api/blocked")).toBeGreaterThan(dashboardBase.blocked);

    const serverSection = page.locator("section").filter({ has: page.getByText("Server", { exact: true }) }).first();
    await expect(serverSection).toContainText("127.0.0.1:4433");
    await expect(page.getByText("203.0.113.42")).toBeVisible();
    await serverSection.getByRole("button", { name: "Clear" }).click();
    await expect(serverSection).not.toContainText("127.0.0.1:4433");
    await expect(serverSection).toContainText("-");

    await nav.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
    const configRefresh = page.locator("main button.action-refresh-btn").first();
    const configBase = {
      status: count(counters, "GET /api/status"),
      config: count(counters, "GET /api/config"),
      auth: count(counters, "GET /api/admin/auth"),
    };
    await configRefresh.click();
    await expect(page.getByTestId("toast-message").first()).toContainText("Refreshed");
    await expect.poll(() => count(counters, "GET /api/status")).toBeGreaterThan(configBase.status);
    await expect.poll(() => count(counters, "GET /api/config")).toBeGreaterThan(configBase.config);
    await expect.poll(() => count(counters, "GET /api/admin/auth")).toBeGreaterThan(configBase.auth);

    const configSaveBase = count(counters, "POST /api/config");
    await page.locator("main [role='switch']").first().click();
    const configSave = page.locator("main button.action-save-btn:has-text('Save')").first();
    await expect(configSave).toBeEnabled();
    await configSave.click();
    await expect(page.getByTestId("toast-message").first()).toContainText("Changes saved");
    await expect.poll(() => count(counters, "POST /api/config")).toBeGreaterThan(configSaveBase);

    await nav.getByRole("button", { name: "Logs" }).click();
    await expect(page.getByRole("main").getByText("Logs", { exact: true })).toBeVisible();
    await expect(page.getByText("client connected", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Clear" }).first()).toBeEnabled();
    const logsBase = {
      mode: count(counters, "GET /api/config/logging"),
      status: count(counters, "GET /api/status"),
      logs: count(counters, "GET /api/logs"),
    };
    await page.locator("main button.action-refresh-btn").first().click();
    await expect(page.getByTestId("toast-message").first()).toContainText("Refreshed");
    await expect.poll(() => count(counters, "GET /api/config/logging")).toBeGreaterThan(logsBase.mode);
    await expect.poll(() => count(counters, "GET /api/status")).toBeGreaterThan(logsBase.status);
    await expect.poll(() => count(counters, "GET /api/logs")).toBeGreaterThan(logsBase.logs);

    const logsSaveBase = count(counters, "POST /api/config/logging");
    await selectLogMode(page, "Verbose");
    await page.locator("main button.action-save-btn:has-text('Save')").first().click();
    await expect(page.getByTestId("toast-message").first()).toContainText("Changes saved");
    await expect.poll(() => count(counters, "POST /api/config/logging")).toBeGreaterThan(logsSaveBase);

    await expect(page.getByText("client connected").first()).toBeVisible();
    const liveSection = page.locator("section").filter({ has: page.getByText("Live Output", { exact: true }) }).first();
    await liveSection.getByRole("button", { name: "Clear" }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByRole("button", { name: "Clear" }).click();
    await expect(page.getByText("Waiting for log entries...")).toBeVisible();
  });
});
