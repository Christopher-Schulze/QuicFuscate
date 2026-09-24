import { test, expect, type Page } from "@playwright/test";

const POSITION_TOLERANCE_PX = 6.0;

type StubState = {
  serverConfig: string;
  serverLogMode: "verbose" | "normal" | "minimal" | "no-log";
  failConfigSave: boolean;
};

const CONFIG_TOML = [
  "[stealth]",
  "mode = \"manual\"",
  "reality_cover_targets = [\"cdn.cloudflare.com\", \"cloudfront.net\"]",
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

async function stubAdminApi(page: Page, state: StubState): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const url = new URL(req.url());
    const path = url.pathname;

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
            clients_active: 0,
            bytes_in: 0,
            bytes_out: 0,
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
      if (state.failConfigSave) {
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Save failed" }),
        });
        return;
      }
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

    if (path.startsWith("/api/logs")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { lines: [], cursor: 0 } }),
      });
      return;
    }

    if (path === "/api/clients") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: [] }),
      });
      return;
    }

    if (path === "/api/blocked") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { ips: [] } }),
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
              quicfuscate_clients_active: 0,
              quicfuscate_connections_rejected: 0,
              quicfuscate_bytes_in_total: 0,
              quicfuscate_bytes_out_total: 0,
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

type OverlayMeasure = {
  mainCenterX: number;
  rowCenterY: number;
  toastCenterX: number;
  toastCenterY: number;
  dx: number;
  dy: number;
  color: string;
  borderColor: string;
  backgroundImage: string;
  radius: string;
  height: string;
};

async function clickAndMeasureOverlay(
  page: Page,
  trigger: ReturnType<Page["locator"]>,
  expectedMessage?: string,
): Promise<OverlayMeasure> {
  const main = page.locator("main").first();
  const triggerRect = await trigger.evaluate((el) => {
    const r = el.getBoundingClientRect();
    return { top: r.top, height: r.height };
  });
  const mainRect = await main.evaluate((el) => {
    const r = el.getBoundingClientRect();
    return { left: r.left, width: r.width };
  });
  await trigger.click();
  const toast = page.getByTestId("toast").first();
  await expect(toast).toBeVisible();
  if (expectedMessage) {
    await expect(page.getByTestId("toast-message").first()).toContainText(expectedMessage);
  }
  await page.waitForTimeout(260);

  const toastData = await toast.evaluate((el) => {
    const card = el.querySelector("[data-testid='toast-message']")?.parentElement as HTMLElement | null;
    const msg = el.querySelector("[data-testid='toast-message']") as HTMLElement | null;
    const r = el.getBoundingClientRect();
    const csCard = card ? getComputedStyle(card) : null;
    const csMsg = msg ? getComputedStyle(msg) : null;
    return {
      left: r.left,
      width: r.width,
      top: r.top,
      height: r.height,
      color: csMsg?.color ?? "",
      borderColor: csCard?.borderColor ?? "",
      backgroundImage: csCard?.backgroundImage ?? "",
      radius: csCard?.borderRadius ?? "",
      cssHeight: csCard?.height ?? "",
    };
  });

  const mainCenterX = mainRect.left + mainRect.width / 2;
  const rowCenterY = triggerRect.top + triggerRect.height / 2;
  const toastCenterX = toastData.left + toastData.width / 2;
  const toastCenterY = toastData.top + toastData.height / 2;

  return {
    mainCenterX,
    rowCenterY,
    toastCenterX,
    toastCenterY,
    dx: toastCenterX - mainCenterX,
    dy: toastCenterY - rowCenterY,
    color: toastData.color,
    borderColor: toastData.borderColor,
    backgroundImage: toastData.backgroundImage,
    radius: toastData.radius,
    height: toastData.cssHeight,
  };
}

test.describe("Overlay Notification Anchor", () => {
  let state: StubState;

  test.beforeEach(async ({ page }) => {
    state = {
      serverConfig: CONFIG_TOML,
      serverLogMode: "normal",
      failConfigSave: false,
    };
    await stubAdminApi(page, state);
    await page.goto("/");
  });

  test("stays exactly centered in content area and aligned to header-action row across views", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });

    await expect(page.getByRole("main").getByText("Dashboard", { exact: true })).toBeVisible();
    const dashboardRefresh = page.locator("main button.action-refresh-btn").first();
    const infoMeasureDashboard = await clickAndMeasureOverlay(page, dashboardRefresh, "Refreshed");
    expect(Math.abs(infoMeasureDashboard.dx)).toBeLessThanOrEqual(1.0);
    expect(Math.abs(infoMeasureDashboard.dy)).toBeLessThanOrEqual(POSITION_TOLERANCE_PX);

    await nav.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

    const configRefresh = page.locator("main button.action-refresh-btn").first();
    const infoMeasureConfig = await clickAndMeasureOverlay(page, configRefresh, "Refreshed");
    expect(Math.abs(infoMeasureConfig.dx)).toBeLessThanOrEqual(1.0);
    expect(Math.abs(infoMeasureConfig.dy)).toBeLessThanOrEqual(POSITION_TOLERANCE_PX);

    await nav.getByRole("button", { name: "Logs" }).click();
    await expect(page.getByRole("main").getByText("Logs", { exact: true })).toBeVisible();
    const logsRefresh = page.locator("main button.action-refresh-btn").first();
    const infoMeasureLogs = await clickAndMeasureOverlay(page, logsRefresh, "Refreshed");
    expect(Math.abs(infoMeasureLogs.dx)).toBeLessThanOrEqual(1.0);
    expect(Math.abs(infoMeasureLogs.dy)).toBeLessThanOrEqual(POSITION_TOLERANCE_PX);

    await nav.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

    const toggle = page.locator("main [role='switch']").first();
    await toggle.click();
    const saveButton = page.locator("main button.action-save-btn:has-text('Save')").first();
    const successMeasure = await clickAndMeasureOverlay(page, saveButton, "Changes saved");
    expect(Math.abs(successMeasure.dx)).toBeLessThanOrEqual(1.0);

    await toggle.click();
    state.failConfigSave = true;
    const errorMeasure = await clickAndMeasureOverlay(page, saveButton, "Failed to save configuration");
    expect(Math.abs(errorMeasure.dx)).toBeLessThanOrEqual(1.0);

    // Consecutive notifications must keep the same geometric center point.
    expect(Math.abs(successMeasure.toastCenterX - infoMeasureConfig.toastCenterX)).toBeLessThanOrEqual(1.0);
    expect(Math.abs(successMeasure.toastCenterY - infoMeasureConfig.toastCenterY)).toBeLessThanOrEqual(POSITION_TOLERANCE_PX);
    expect(Math.abs(errorMeasure.toastCenterX - infoMeasureConfig.toastCenterX)).toBeLessThanOrEqual(1.0);
    expect(Math.abs(errorMeasure.toastCenterY - infoMeasureConfig.toastCenterY)).toBeLessThanOrEqual(POSITION_TOLERANCE_PX);

    // Unified shell style must be identical across tones.
    expect(infoMeasureConfig.radius).toBe(successMeasure.radius);
    expect(infoMeasureConfig.radius).toBe(errorMeasure.radius);
    expect(infoMeasureConfig.height).toBe(successMeasure.height);
    expect(infoMeasureConfig.height).toBe(errorMeasure.height);

    // Tones must actually differ [blue / green / red].
    expect(infoMeasureConfig.color).not.toBe(successMeasure.color);
    expect(infoMeasureConfig.color).not.toBe(errorMeasure.color);
    expect(successMeasure.color).not.toBe(errorMeasure.color);
    expect(infoMeasureConfig.borderColor).not.toBe(successMeasure.borderColor);
    expect(successMeasure.borderColor).not.toBe(errorMeasure.borderColor);
    expect(infoMeasureConfig.backgroundImage).not.toBe(successMeasure.backgroundImage);
  });
});
