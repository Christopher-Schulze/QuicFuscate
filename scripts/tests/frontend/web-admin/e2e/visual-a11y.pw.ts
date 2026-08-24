import { test, expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

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

async function stubAdminApi(page: Page): Promise<void> {
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
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
    if (path === "/api/config") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { config: CONFIG_TOML } }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ success: true, data: [] }),
    });
  });
}

async function waitForHydration(page: Page) {
  await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
}

test.describe("Admin visual + a11y gates", () => {
  test.beforeEach(async ({ page }) => {
    await stubAdminApi(page);
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    await waitForHydration(page);
  });

  test("dashboard shell screenshot", async ({ page }) => {
    await expect(page.getByText("Dashboard", { exact: true }).first()).toBeVisible();
    await expect(page.locator("#qf-app-stage")).toHaveScreenshot("admin-dashboard.png", {
      maxDiffPixelRatio: 0.02,
      animations: "disabled",
    });
  });

  test("axe has no serious or critical violations on the dashboard shell", async ({ page }) => {
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();
    const blocking = results.violations.filter((violation) =>
      violation.impact === "serious" || violation.impact === "critical"
    );
    expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
  });
});
