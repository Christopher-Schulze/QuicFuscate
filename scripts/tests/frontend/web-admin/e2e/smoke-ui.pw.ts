import { test, expect, type Page } from "@playwright/test";

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

async function stubAdminApi(page: Page): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method().toUpperCase();

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
          data: { qkey: "QKey-SMOKE-TEST", created_at: QKEY_CREATED_AT_SECONDS },
        }),
      });
      return;
    }

    if (path === "/api/config/logging") {
      if (method === "GET") {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { mode: "normal" } }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
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

    if (path === "/api/logout") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
      return;
    }

    if (path === "/api/login" && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { user: "admin", requires_password_change: false } }),
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

async function readSwitchState(locator: ReturnType<Page["locator"]>): Promise<boolean> {
  return locator.evaluate((el) => {
    if (el instanceof HTMLInputElement) {
      return el.checked;
    }
    const ariaChecked = el.getAttribute("aria-checked");
    if (ariaChecked === "true") return true;
    if (ariaChecked === "false") return false;
    const selected = el.getAttribute("data-selected");
    if (selected === "true") return true;
    if (selected === "false") return false;
    return false;
  });
}

test.describe("Web Admin UI Smoke", () => {
  test.beforeEach(async ({ page }) => {
    await stubAdminApi(page);
    await page.goto("/");
    const loginDialog = page.getByRole("dialog").first();
    if (await loginDialog.isVisible().catch(() => false)) {
      await loginDialog.getByRole("button", { name: "Login" }).click();
      await expect(loginDialog).toBeHidden({ timeout: 10_000 });
    }
  });

  test("full interaction smoke [navigation, controls, modal validation, switch, typography]", async ({ page }) => {
    page.on("dialog", (dialog) => dialog.accept().catch(() => {}));

    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav.getByRole("button", { name: "Dashboard" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Configuration" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Logs" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "About" })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Logout" })).toBeVisible();

    await nav.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

    const topSave = page.locator("button.action-save-btn:has-text('Save')").first();
    const changePassword = page.locator("button.action-save-btn:has-text('Change Password')").first();
    const createQkey = page.locator("button.action-save-btn:has-text('Generate')").first();

    await expect(topSave).toBeVisible();
    await expect(changePassword).toBeVisible();
    await expect(createQkey).toBeVisible();

    await expect(topSave).toHaveCSS("color", "rgb(255, 255, 255)");
    await expect(changePassword).toHaveCSS("color", "rgb(255, 255, 255)");
    await expect(createQkey).toHaveCSS("color", "rgb(255, 255, 255)");

    const switchInput = page.locator("[role='switch']").first();
    await expect(switchInput).toBeVisible();
    await switchInput.focus();
    const beforeChecked = await readSwitchState(switchInput);
    await switchInput.press("Space");
    await page.waitForTimeout(120);
    const afterChecked = await readSwitchState(switchInput);
    expect(afterChecked).toBe(!beforeChecked);

    await topSave.click();

    await createQkey.click();
    const dialog = page.getByRole("dialog").first();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("Generate QKey", { exact: true })).toBeVisible();
    await expect(dialog.getByText("Port [optional]", { exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("Port [1-65535]", { exact: true })).toBeVisible();

    const dialogGenerate = dialog.locator("button.action-save-btn:has-text('Generate')").first();
    await expect(dialogGenerate).toBeVisible();

    await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Smoke Key");
    await dialog.getByLabel("Port [1-65535]", { exact: true }).fill("4433");
    await expect(dialogGenerate).toBeEnabled();

    const sniSelectButton = dialog.getByRole("button", { name: "Domain Fronting mode", exact: true });
    await expect(sniSelectButton).toBeVisible();
    await expect(sniSelectButton).toContainText("Auto [Rotating]");
    await dialog.getByRole("button", { name: "Cancel" }).click();

    await nav.getByRole("button", { name: "Logs" }).click();
    const unsavedDialog = page.getByRole("dialog", { name: "Unsaved Changes" });
    if (await unsavedDialog.isVisible().catch(() => false)) {
      await unsavedDialog.getByRole("button", { name: "Leave" }).click();
    }
    await expect(page.getByRole("main").getByText("Logs", { exact: true })).toBeVisible();
    const logsSave = page.locator("button.action-save-btn:has-text('Save')").first();
    const logsCopy = page.locator("button.action-copy-btn").first();
    await expect(logsSave).toBeVisible();
    await expect(logsCopy).toBeVisible();
    await expect(logsSave).toHaveCSS("color", "rgb(255, 255, 255)");
    await expect(logsCopy).toHaveCSS("color", "rgb(255, 255, 255)");

    const sideFont = await nav
      .getByRole("button", { name: "Configuration" })
      .locator("span")
      .first()
      .evaluate((el) => getComputedStyle(el).fontFamily);

    await nav.getByRole("button", { name: "Logout" }).click();
    const loginDialog = page.getByRole("dialog").first();
    await expect(loginDialog).toBeVisible();
    const loginFont = await loginDialog.getByText("Admin Login", { exact: true }).evaluate((el) => getComputedStyle(el).fontFamily);
    expect(loginFont).toBe(sideFont);
  });
});
