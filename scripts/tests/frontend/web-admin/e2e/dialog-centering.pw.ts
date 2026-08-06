import { expect, test, type Page, type TestInfo } from "@playwright/test";

type StubOptions = {
  auth401?: boolean;
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
const QKEY_CREATED_AT_SECONDS = 1_710_000_000;
const ADMIN_LOG_TIMESTAMP_MS = 1_710_000_000_000;

async function selectLogMode(page: Page, modeLabel: "Verbose" | "Normal" | "Minimal" | "No-Log"): Promise<void> {
  const modeKey = modeLabel.toLowerCase().replace(/[^a-z]+/g, "-");
  await page.getByTestId(`log-mode-${modeKey}`).click();
}

async function stubAdminApi(page: Page, opts: StubOptions = {}) {
  const auth401 = Boolean(opts.auth401);

  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method().toUpperCase();

    if (path === "/api/status") {
      if (auth401) {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: {
            version: "0.0.0-e2e",
            listen: "127.0.0.1:4433",
            uptime_secs: 321,
            clients_active: 0,
            bytes_in: 0,
            bytes_out: 0,
          },
        }),
      });
      return;
    }

    if (path === "/api/admin/auth") {
      if (auth401) {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
        return;
      }
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

    if (path === "/api/metrics") {
      await route.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "# mocked metrics\n",
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

    if (path === "/api/config" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { config: CONFIG_TOML } }),
      });
      return;
    }

    if (path === "/api/config" && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    if (path === "/api/config/logging" && method === "GET") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { mode: "normal" } }),
      });
      return;
    }

    if (path === "/api/config/logging" && method === "POST") {
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

    if (path === "/api/qkey" && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: { qkey: "QKey-CENTER-TEST", created_at: QKEY_CREATED_AT_SECONDS },
        }),
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
            lines: [
              {
                ts: ADMIN_LOG_TIMESTAMP_MS,
                level: "info",
                msg: "admin init",
              },
            ],
            cursor: 1,
          },
        }),
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

async function assertDialogCenteredInStage(page: Page, testInfo: TestInfo, label: string) {
  const stage = page.locator("#qf-app-stage");
  const dialog = page.getByRole("dialog").first();

  await expect(stage).toBeVisible();
  await expect(dialog).toBeVisible();

  const stageBox = await stage.boundingBox();
  const dialogBox = await dialog.boundingBox();
  expect(stageBox).not.toBeNull();
  expect(dialogBox).not.toBeNull();
  if (!stageBox || !dialogBox) return;

  const stageCenterX = stageBox.x + stageBox.width / 2;
  const stageCenterY = stageBox.y + stageBox.height / 2;
  const dialogCenterX = dialogBox.x + dialogBox.width / 2;
  const dialogCenterY = dialogBox.y + dialogBox.height / 2;
  const dx = dialogCenterX - stageCenterX;
  const dy = dialogCenterY - stageCenterY;

  console.log(
    `[dialog-center][web] ${label}: dx=${dx.toFixed(2)}px dy=${dy.toFixed(2)}px ` +
      `stage=${stageBox.width.toFixed(0)}x${stageBox.height.toFixed(0)} dialog=${dialogBox.width.toFixed(0)}x${dialogBox.height.toFixed(0)}`,
  );

  await page.screenshot({
    path: testInfo.outputPath(`web-${label.replace(/\s+/g, "-").toLowerCase()}.png`),
    fullPage: true,
  });

  expect(Math.abs(dx)).toBeLessThanOrEqual(2);
  expect(Math.abs(dy)).toBeLessThanOrEqual(2);
}

test.describe("Dialog Centering [Web-Admin]", () => {
  test("login dialog is centered in stage", async ({ page }, testInfo) => {
    await stubAdminApi(page, { auth401: true });
    await page.goto("/");
    await assertDialogCenteredInStage(page, testInfo, "login");
  });

  test("generate qkey dialog is centered in stage", async ({ page }, testInfo) => {
    await stubAdminApi(page);
    await page.goto("/");
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Configuration" }).click();
    await page.locator("button.action-save-btn:has-text('Generate')").first().click();
    await expect(page.getByText("Generate QKey", { exact: true })).toBeVisible();
    await assertDialogCenteredInStage(page, testInfo, "generate-qkey");
  });

  test("change password dialog is centered in stage", async ({ page }, testInfo) => {
    await stubAdminApi(page);
    await page.goto("/");
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Configuration" }).click();
    await page.locator("button.action-save-btn:has-text('Change Password')").first().click();
    await expect(page.getByRole("dialog", { name: "Change Password" })).toBeVisible();
    await assertDialogCenteredInStage(page, testInfo, "change-password");
  });

  test("clear logs dialog is centered in stage", async ({ page }, testInfo) => {
    await stubAdminApi(page);
    await page.goto("/");
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Logs" }).click();
    await page.getByRole("button", { name: "Clear" }).first().click();
    await expect(page.getByText("Clear Live Output", { exact: true })).toBeVisible();
    await assertDialogCenteredInStage(page, testInfo, "clear-live-output");
  });

  test("unsaved confirm dialog is centered in stage", async ({ page }, testInfo) => {
    await stubAdminApi(page);
    await page.goto("/");
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Logs" }).click();
    await selectLogMode(page, "Verbose");
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Dashboard" }).click();
    await expect(page.getByRole("dialog", { name: "Unsaved Changes" })).toBeVisible();
    await assertDialogCenteredInStage(page, testInfo, "unsaved-confirm");
  });
});
