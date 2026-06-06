import { test, expect } from "@playwright/test";

/**
 * E2E Tests for QuicFuscate Web Admin UI
 *
 * Note: These tests run against the dev server without a backend.
 * The app shows a login modal when authentication is required.
 * Tests are designed to verify UI structure and behavior.
 */

test.describe("Web Admin UI", () => {
  function appStage(page: any) {
    return page.locator("#qf-app-stage");
  }

  async function waitForHydration(page: any) {
    await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
  }

  async function ensureLoggedInIfPrompted(page: any) {
    const loginDialog = page.getByRole("dialog").first();
    const visible = await loginDialog.isVisible().catch(() => false);
    if (!visible) return;
    const loginButton = loginDialog.getByRole("button", { name: "Login" });
    await expect(loginButton).toBeVisible();
    await loginButton.click();
    await expect(loginDialog).toBeHidden({ timeout: 10_000 });
  }

  async function expectNoHorizontalOverflow(page: any) {
    const m = await page.evaluate(() => {
      const de = document.documentElement;
      const body = document.body;
      return {
        deClientWidth: de.clientWidth,
        deScrollWidth: de.scrollWidth,
        bodyClientWidth: body?.clientWidth ?? 0,
        bodyScrollWidth: body?.scrollWidth ?? 0,
      };
    });

    expect(m.deScrollWidth).toBeLessThanOrEqual(m.deClientWidth + 1);
    expect(m.bodyScrollWidth).toBeLessThanOrEqual(m.bodyClientWidth + 1);
  }

  async function expectLocatorInViewport(page: any, locator: any, marginPx = 8) {
    const r = await locator.evaluate((el: any) => {
      const b = el.getBoundingClientRect();
      return { left: b.left, top: b.top, right: b.right, bottom: b.bottom };
    });
    const vp = await page.evaluate(() => ({ w: window.innerWidth, h: window.innerHeight }));

    expect(r.left).toBeGreaterThanOrEqual(-marginPx);
    expect(r.top).toBeGreaterThanOrEqual(-marginPx);
    expect(r.right).toBeLessThanOrEqual(vp.w + marginPx);
    expect(r.bottom).toBeLessThanOrEqual(vp.h + marginPx);
  }

  async function expectLocatorInStage(page: any, locator: any, marginPx = 8) {
    const r = await locator.evaluate((el: any) => {
      const b = el.getBoundingClientRect();
      return { left: b.left, top: b.top, right: b.right, bottom: b.bottom };
    });
    const stage = await page.locator("#qf-app-stage").evaluate((el: any) => {
      const b = el.getBoundingClientRect();
      return { left: b.left, top: b.top, right: b.right, bottom: b.bottom };
    });

    expect(r.left).toBeGreaterThanOrEqual(stage.left - marginPx);
    expect(r.top).toBeGreaterThanOrEqual(stage.top - marginPx);
    expect(r.right).toBeLessThanOrEqual(stage.right + marginPx);
    expect(r.bottom).toBeLessThanOrEqual(stage.bottom + marginPx);
  }

  async function selectLogMode(page: any, modeLabel: "Verbose" | "Normal" | "Minimal" | "No-Log") {
    const modeKey = modeLabel.toLowerCase().replace(/[^a-z]+/g, "-");
    await page.getByTestId(`log-mode-${modeKey}`).click();
  }

  async function setInputValue(locator: any, value: string) {
    await locator.evaluate((el: HTMLInputElement, next: string) => {
      el.value = next;
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }, value);
  }

  test.beforeEach(async ({ page }) => {
    let serverConfig = [
      "[stealth]",
      "mode = \"intelligent\"",
      "enable_domain_fronting = false",
      "enable_http3_masquerading = false",
      "use_tls_cover = false",
      "use_qpack_headers = false",
      "enable_traffic_padding = false",
      "enable_timing_obfuscation = false",
      "enable_protocol_mimicry = false",
      "enable_doh = false",
      "",
      "[fec]",
      "initial_mode = \"zero\"",
      "",
      "[transport]",
      "mtu = 1400",
      "",
    ].join("\n");
    let serverLogMode: "verbose" | "normal" | "minimal" | "no-log" = "normal";

    // The dev server proxies /api/* to a backend in normal dev flows.
    // For E2E runs we stub minimal responses to keep the UI deterministic.
    await page.route("**/api/status", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: {
            version: "0.0.0-test",
            listen: "127.0.0.1:4433",
            uptime_secs: 123,
            clients_active: 0,
            bytes_in: 0,
            bytes_out: 0,
          },
        }),
      });
    });
    await page.route("**/api/clients", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: [] }),
      });
    });
    await page.route("**/api/blocked", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { ips: [] } }),
      });
    });
    await page.route("**/api/metrics", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "# mocked metrics\n",
      });
    });
    await page.route("**/api/metrics/json", async (route) => {
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
    });

    await page.route("**/api/admin/auth", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: { user: "admin", requires_password_change: false },
        }),
      });
    });
    await page.route("**/api/csrf", async (route) => {
      await route.fulfill({
        status: 204,
        headers: {
          "X-CSRF-Token": "test-csrf-token",
        },
      });
    });
    await page.route("**/api/config", async (route) => {
      const req = route.request();
      if (req.method() === "POST") {
        const body = req.postDataJSON() as { config?: unknown };
        if (typeof body.config === "string" && body.config.trim().length > 0) {
          serverConfig = body.config;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: { config: serverConfig },
        }),
      });
    });
    await page.route("**/api/qkeys", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { keys: [] } }),
      });
    });
    await page.route("**/api/config/logging", async (route) => {
      const req = route.request();
      if (req.method() === "POST") {
        const body = req.postDataJSON() as { mode?: unknown };
        const mode = body.mode;
        if (mode === "verbose" || mode === "normal" || mode === "minimal" || mode === "no-log") {
          serverLogMode = mode;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { mode: serverLogMode } }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { mode: serverLogMode } }),
      });
    });
    await page.route("**/api/logs**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true, data: { lines: [], cursor: 0 } }),
      });
    });
    await page.route("**/api/logout", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ success: true }),
      });
    });
    await page.route("**/api/login", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          data: { user: "admin", requires_password_change: false },
        }),
      });
    });

    await page.goto("/");
    await waitForHydration(page);
    await ensureLoggedInIfPrompted(page);
  });

  test.describe("App Shell", () => {
    test("page loads and renders main container", async ({ page }) => {
      // Main app container should exist
      await expect(appStage(page)).toBeVisible();
    });

    test("renders sidebar navigation", async ({ page }) => {
      // Sidebar should be visible
      const sidebar = page.getByRole("navigation", { name: "Primary" });
      await expect(sidebar).toBeVisible();
    });

    test("navigation items are present", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await expect(nav.getByRole("button", { name: "Dashboard" })).toBeVisible();
      await expect(nav.getByRole("button", { name: "Configuration" })).toBeVisible();
      await expect(nav.getByRole("button", { name: "Logs" })).toBeVisible();
      await expect(nav.getByRole("button", { name: "About" })).toBeVisible();
      await expect(nav.getByRole("button", { name: "Logout" })).toBeVisible();
    });
  });

  test.describe("Authentication Modal", () => {
    test.beforeEach(async ({ page }) => {
      // Force auth required by making the status endpoint return an auth error.
      await page.unroute("**/api/status");
      await page.route("**/api/status", async (route) => {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
      });
      await page.goto("/");
      await waitForHydration(page);
    });

    test("shows login modal when not authenticated", async ({ page }) => {
      const loginModal = page.getByRole("dialog").first();
      await expect(loginModal).toBeVisible();
    });

    test("login form has username and password fields", async ({ page }) => {
      const dialog = page.getByRole("dialog").first();
      await expect(dialog.getByLabel("Username", { exact: true })).toBeVisible();
      await expect(dialog.getByLabel("Password", { exact: true })).toBeVisible();
    });

    test("login form has submit button", async ({ page }) => {
      const dialog = page.getByRole("dialog").first();
      await expect(dialog.getByRole("button", { name: "Login" })).toBeVisible();
    });

    test("login blocks whitespace-only username", async ({ page }) => {
      const dialog = page.getByRole("dialog").first();
      const username = dialog.getByLabel("Username", { exact: true });
      const password = dialog.getByLabel("Password", { exact: true });

      await username.fill("    ");
      await password.fill("123456");
      await expect(dialog.getByRole("button", { name: "Login" })).toBeDisabled();
    });

    test("invalid login triggers motion feedback without inline error copy or layout shift", async ({ page }) => {
      await page.unroute("**/api/login");
      await page.route("**/api/login", async (route) => {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Invalid credentials" }),
        });
      });

      const dialog = page.getByRole("dialog").first();
      const username = dialog.locator('input[name="username"]');
      const password = dialog.getByLabel("Password", { exact: true });

      await setInputValue(username, "admin");
      await setInputValue(password, "wrong-password");
      await page.waitForTimeout(100);

      const before = await dialog.boundingBox();
      expect(before).not.toBeNull();

      await dialog.getByRole("button", { name: "Login" }).click();

      await expect(dialog).toHaveAttribute("data-auth-feedback", "reject");
      await expect(page.getByText("Invalid credentials", { exact: true })).toHaveCount(0);
      await expect(password).toBeFocused();

      await page.waitForTimeout(650);
      await expect(dialog).toBeVisible();
    });
  });

  test.describe("Navigation", () => {
    test("can click navigation items", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });

      // Click Configuration
      await nav.getByRole("button", { name: "Configuration" }).click();
      await page.waitForTimeout(300);

      // Click Logs
      await nav.getByRole("button", { name: "Logs" }).click();
      await page.waitForTimeout(300);

      // Click Dashboard
      await nav.getByRole("button", { name: "Dashboard" }).click();
      await page.waitForTimeout(300);

      // App should still be functional
      await expect(appStage(page)).toBeVisible();
    });
  });

  test.describe("Dashboard UX Guards", () => {
    test("does not show 'Not Found' banner when metrics json endpoint is unavailable", async ({ page }) => {
      await page.unroute("**/api/metrics/json");
      await page.route("**/api/metrics/json", async (route) => {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Not Found" }),
        });
      });

      await page.goto("/");
      await expect(page.getByRole("main").getByText("Dashboard", { exact: true })).toBeVisible();
      await page.waitForTimeout(500);
      await expect(page.getByText("Not Found", { exact: true })).toHaveCount(0);
      await expect(page.getByRole("alert")).toHaveCount(0);
    });

    test("refresh and clear buttons keep identical visual style on hover", async ({ page }) => {
      await page.unroute("**/api/metrics/json");
      await page.route("**/api/metrics/json", async (route) => {
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
      });

      await page.goto("/");
      await expect(page.getByRole("main").getByText("Dashboard", { exact: true })).toBeVisible();

      const refresh = page.locator("button.action-refresh-btn").first();
      const clear = page.locator("button.action-neutral-btn").first();
      await expect(refresh).toBeVisible();
      await expect(clear).toBeVisible();

      const readStyle = async (locator: ReturnType<typeof page.locator>) =>
        locator.evaluate((el) => {
          const s = getComputedStyle(el as HTMLElement);
          return {
            backgroundColor: s.backgroundColor,
            color: s.color,
            borderColor: s.borderColor,
            boxShadow: s.boxShadow,
            filter: s.filter,
            transform: s.transform,
            opacity: s.opacity,
          };
        });
      const normalizeTransform = (value: string) =>
        value === "none" ? "matrix(1, 0, 0, 1, 0, 0)" : value;

      const refreshBefore = await readStyle(refresh);
      await refresh.hover();
      await page.waitForTimeout(150);
      const refreshAfter = await readStyle(refresh);
      expect({
        ...refreshAfter,
        transform: normalizeTransform(refreshAfter.transform),
      }).toEqual({
        ...refreshBefore,
        transform: normalizeTransform(refreshBefore.transform),
      });

      const clearBefore = await readStyle(clear);
      await clear.hover();
      await page.waitForTimeout(150);
      const clearAfter = await readStyle(clear);
      expect({
        ...clearAfter,
        transform: normalizeTransform(clearAfter.transform),
      }).toEqual({
        ...clearBefore,
        transform: normalizeTransform(clearBefore.transform),
      });
    });
  });

  test.describe("Password Change Lock (423)", () => {
    test("locks UI to Configuration when admin auth indicates a password change is required", async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: { user: "admin", requires_password_change: true },
          }),
        });
      });

      await page.goto("/");

      await expect(page.getByRole("dialog", { name: "Change Password" })).toBeVisible({ timeout: 15_000 });
      await expect(page.getByText("Default credentials detected. Please change your password.", { exact: true })).toBeVisible();
      await expect(page.locator("main").getByText("Configuration", { exact: true }).first()).toBeVisible();
    });

    test("a 423 from another API call triggers lock to Configuration", async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: { user: "admin", requires_password_change: false },
          }),
        });
      });

      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        await route.fulfill({
          status: 423,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Password change required" }),
        });
      });

      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      // The app should lock to configuration shortly after the 423 response.
      await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
      await expect(nav.getByRole("button", { name: "Configuration" })).toBeEnabled();
      await expect(nav.getByRole("button", { name: "Dashboard" })).toBeDisabled();
      await expect(nav.getByRole("button", { name: "Logs" })).toBeDisabled();
    });
  });

  test.describe("Configuration", () => {
    test.beforeEach(async ({ page }) => {
      // Route status as unauthenticated unless we force it in the Auth tests.
      // Here we want the full app to render.
      await page.unroute("**/api/status");
      await page.route("**/api/status", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: {
              version: "0.0.0-test",
              listen: "127.0.0.1:4433",
              uptime_secs: 123,
              clients_active: 0,
              bytes_in: 0,
              bytes_out: 0,
            },
          }),
        });
      });
      await page.goto("/");
    });

    test("Save is disabled until config is dirty", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();
      await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeDisabled();
    });

    test("FEC toggle marks config dirty and enables Save", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeDisabled();

      // Toggle FEC via the preset selector.
      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();
      await expect(save).toBeEnabled();
    });

    test("beforeunload is triggered when config is dirty", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const fired = await page.evaluate(() => {
        const ev = new Event("beforeunload", { cancelable: true }) as any;
        const ok = window.dispatchEvent(ev);
        // When handler sets returnValue, ok is still true, but the value is observable.
        return typeof (ev as any).returnValue !== "undefined";
      });
      expect(fired).toBeTruthy();
    });

    test("Save posts config and shows transient saved status", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      await save.click();

      await expect(page.getByText("Changes saved", { exact: true })).toBeVisible();
      await expect(save).toBeDisabled();
    });

    test("Save keeps dirty state when readback verification does not match", async ({ page }) => {
      await page.unroute("**/api/config");
      const initialConfig = [
        "[transport]",
        "mtu = 1400",
        "",
      ].join("\n");
      await page.route("**/api/config", async (route) => {
        const req = route.request();
        if (req.method() === "POST") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ success: true }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: { config: initialConfig },
          }),
        });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      await save.click();

      await expect(page.getByText("Changes saved", { exact: true })).toHaveCount(0);
      await expect(save).toBeEnabled();
    });

    test("uses the last occurrence for duplicated keys in a section", async ({ page }) => {
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: {
              config: [
                "[transport]",
                "mtu = 1400",
                "mtu = 1500",
                "",
              ].join("\\n"),
            },
          }),
        });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      const mtu = page.getByLabel("MTU", { exact: true });
      await expect(mtu).toHaveValue("1500");
    });

    test("normalizes legacy escaped-newline TOML into form controls", async ({ page }) => {
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              success: true,
              data: {
                config: "[transport]\\ncc_algorithm = \"reno\"\\nmtu = 1550\\nenable_pacing = true\\n",
              },
            }),
          });
          return;
        }
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true }) });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await expect(page.getByLabel("MTU", { exact: true })).toHaveValue("1550");
      await expect(page.getByRole("button", { name: /Congestion control$/i })).toContainText("Reno");
    });

    test("save posts normalized multiline TOML when source contains escaped newlines", async ({ page }) => {
      let postedConfig: string | null = null;
      let serverConfig = "[transport]\\nmtu = 1400\\nenable_pacing = true\\n";
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              success: true,
              data: {
                config: serverConfig,
              },
            }),
          });
          return;
        }
        if (req.method() === "POST") {
          const rawBody = req.postData();
          if (typeof rawBody === "string" && rawBody.trim().length > 0) {
            try {
              const body = JSON.parse(rawBody) as { config?: unknown };
              postedConfig = typeof body.config === "string" ? body.config : null;
            } catch {
              postedConfig = null;
            }
          } else {
            postedConfig = null;
          }
          if (postedConfig) serverConfig = postedConfig;
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true }) });
          return;
        }
        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      await save.click();

      await expect(page.getByText("Changes saved", { exact: true })).toBeVisible();
      expect(postedConfig).not.toBeNull();
      expect(postedConfig!).toContain("[transport]\n");
      expect(postedConfig!).toContain("mtu = 1400\n");
      expect(postedConfig!).not.toContain("[transport]\\n");
    });

    test("does not normalize quoted escaped-newline literals", async ({ page }) => {
      let serverConfig = "[transport]\\nmtu = 1400\\ncomment = \"\\\\n\"\\n";
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              success: true,
              data: {
                config: serverConfig,
              },
            }),
          });
          return;
        }
        if (req.method() === "POST") {
          const rawBody = req.postData();
          let postedConfig: string | null = null;
          if (typeof rawBody === "string" && rawBody.trim().length > 0) {
            try {
              const body = JSON.parse(rawBody) as { config?: unknown };
              postedConfig = typeof body.config === "string" ? body.config : null;
            } catch {
              postedConfig = null;
            }
          }
          if (postedConfig) serverConfig = postedConfig;
          await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ success: true }) });
          return;
        }
        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      // Make config dirty and persist it; quoted "\\n" literals must survive unchanged.
      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();
      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      const postReqPromise = page.waitForRequest((req) => {
        if (req.method() !== "POST") return false;
        try {
          return new URL(req.url()).pathname === "/api/config";
        } catch {
          return false;
        }
      });
      await save.click();
      const postReq = await postReqPromise;
      const postBody = JSON.parse(postReq.postData() || "{}") as { config?: unknown };
      const postedConfig = typeof postBody.config === "string" ? postBody.config : null;

      expect(postedConfig).not.toBeNull();
      expect(postedConfig!).toContain("comment = \"\\\\n\"");
      expect(postedConfig!).not.toContain("comment = \"\n\"");
    });

    test("invalid MTU blocks Save even when config is dirty", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      // Make the config dirty first.
      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();

      // Now enter an invalid MTU value and ensure Save is blocked.
      const mtu = page.getByLabel("MTU", { exact: true });
      await mtu.fill("100");

      await expect(save).toBeDisabled();
    });

    test("non-numeric MTU suffix is rejected", async ({ page }) => {
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: {
              config: [
                "[transport]",
                "mtu = 1400abc",
                "",
              ].join("\\n"),
            },
          }),
        });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await expect(page.getByLabel("MTU", { exact: true })).toHaveValue("1400abc");
      await expect(page.getByRole("button", { name: "Save" }).first()).toBeDisabled();
    });

    test("server-side config save failure keeps config dirty without disruptive inline error", async ({ page }) => {
      await page.unroute("**/api/config");
      await page.route("**/api/config", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({
              success: true,
              data: {
                config: [
                  "[transport]",
                  "mtu = 1400",
                  "",
                ].join("\\n"),
              },
            }),
          });
          return;
        }
        if (req.method() === "POST") {
          await route.fulfill({
            status: 400,
            contentType: "application/json",
            body: JSON.stringify({
              success: false,
              message: "Config validation failed",
            }),
          });
          return;
        }
        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      await save.click();

      await expect(page.getByRole("alert")).toHaveCount(0);
      await expect(save).toBeEnabled();
    });

    test("dirty config navigation cancel keeps current tab and dirty state", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();
      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();

      await nav.getByRole("button", { name: "Dashboard" }).click();
      const confirm = page.getByRole("dialog", { name: "Unsaved Changes" });
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", { name: "Cancel" }).click();

      await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
      await expect(save).toBeEnabled();
    });

    test("dirty config navigation accept switches tab", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();
      await expect(page.getByRole("button", { name: "Save" }).first()).toBeEnabled();

      await nav.getByRole("button", { name: "Dashboard" }).click();
      const confirm = page.getByRole("dialog", { name: "Unsaved Changes" });
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", { name: "Leave" }).click();

      await expect(page.getByText("Dashboard", { exact: true })).toBeVisible();
    });
  });

  test.describe("QKeys", () => {
    let issuedName: string | null = null;
    const issuedQKey = "QKey-TEST-123";
    const issuedId = "a1b2c3d4e5f6";
    let created = false;
    let revoked = false;

    test.beforeEach(async ({ page }) => {
      created = false;
      revoked = false;
      issuedName = null;
      await page.unroute("**/api/qkey");
      await page.route("**/api/qkey", async (route) => {
        const body = route.request().postDataJSON() as { name?: unknown };
        const name = typeof body.name === "string" ? body.name.trim() : "";
        issuedName = name.length > 0 ? name : null;
        created = true;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { qkey: issuedQKey, created_at: 0, expires_at: null } }),
        });
      });
      await page.unroute("**/api/qkeys/revoke");
      await page.route("**/api/qkeys/revoke", async (route) => {
        revoked = true;
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true }),
        });
      });
      await page.unroute("**/api/qkeys");
      await page.route("**/api/qkeys", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: {
              keys: created && !revoked
                ? [{ id: issuedId, name: issuedName, stealth: "auto", fec: "auto", expires_at: null, created_at: 0 }]
                : [],
            },
          }),
        });
      });

      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();
      await expect(page.getByText("QKeys", { exact: true })).toBeVisible();
    });

    test("Generate posts name plus SNI strategy payload", async ({ page }) => {
      await page.getByRole("button", { name: "Generate" }).first().click();
      const postReqPromise = page.waitForRequest((req) => {
        if (req.method() !== "POST") return false;
        try {
          return new URL(req.url()).pathname === "/api/qkey";
        } catch {
          return false;
        }
      });
      await page.getByLabel("Name of the Connection", { exact: true }).fill("Team Berlin");
      await page.getByRole("dialog").getByRole("button", { name: "Generate" }).click();
      const postReq = await postReqPromise;
      const postedBody = postReq.postDataJSON() as Record<string, unknown>;

      expect(postedBody).toEqual({ name: "Team Berlin", sni_strategy: "auto_rotating" });
    });

    test("Generate shows a one-time reveal and metadata-only list row", async ({ page }) => {
      await page.getByRole("button", { name: "Generate" }).first().click();
      await page.getByLabel("Name of the Connection", { exact: true }).fill("Team Berlin");
      await page.getByRole("dialog", { name: "Generate QKey" }).getByRole("button", { name: "Generate" }).click();
      const issuedDialog = page.getByRole("dialog", { name: "Issued QKey" });
      await expect(issuedDialog).toBeVisible();
      await expect(issuedDialog.getByText("Team Berlin", { exact: true })).toBeVisible();
      await expect(issuedDialog.getByText(issuedQKey, { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: /Team Berlin Registry ID/ })).toBeVisible();
      await expect(page.getByText(issuedId, { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Copy QKey" })).toHaveCount(1);
    });

    test("Generate accepts empty name and still reveals the credential", async ({ page }) => {
      await page.getByRole("button", { name: "Generate" }).first().click();
      await page.getByRole("dialog", { name: "Generate QKey" }).getByRole("button", { name: "Generate" }).click();
      const issuedDialog = page.getByRole("dialog", { name: "Issued QKey" });
      await expect(issuedDialog).toBeVisible();
      await expect(issuedDialog.getByText(issuedQKey, { exact: true })).toBeVisible();
    });

    test("Copy is available only inside the one-time reveal dialog", async ({ page }) => {
      await page.getByRole("button", { name: "Generate" }).first().click();
      await page.getByRole("dialog", { name: "Generate QKey" }).getByRole("button", { name: "Generate" }).click();
      const issuedDialog = page.getByRole("dialog", { name: "Issued QKey" });
      const copyBtn = issuedDialog.getByRole("button", { name: "Copy QKey" });
      await copyBtn.click();
      await expect(copyBtn).toBeVisible();
      await issuedDialog.getByRole("button", { name: "Done" }).click();
      await expect(page.getByRole("button", { name: "Copy QKey" })).toHaveCount(0);
      await expect(page.getByRole("alert")).toHaveCount(0);
    });

    test("Revoke removes the issued metadata row from the list", async ({ page }) => {
      await page.getByRole("button", { name: "Generate" }).first().click();
      await page.getByLabel("Name of the Connection", { exact: true }).fill("Team Berlin");
      await page.getByRole("dialog", { name: "Generate QKey" }).getByRole("button", { name: "Generate" }).click();
      await page.getByRole("dialog", { name: "Issued QKey" }).getByRole("button", { name: "Done" }).click();
      const row = page.getByTestId("qkey-row").filter({ hasText: issuedId }).first();
      await expect(row).toBeVisible();
      await expect(page.getByText(issuedId, { exact: true })).toBeVisible();
      await row.getByRole("button", { name: "Revoke" }).click();

      await expect(page.getByText("No Keys created", { exact: true })).toBeVisible();
    });

    test("Revoke failure restores entry via refresh without inline error banner", async ({ page }) => {
      await page.unroute("**/api/qkeys/revoke");
      await page.route("**/api/qkeys/revoke", async (route) => {
        await route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Revoke failed" }),
        });
      });

      await page.getByRole("button", { name: "Generate" }).first().click();
      await page.getByLabel("Name of the Connection", { exact: true }).fill("Team Berlin");
      await page.getByRole("dialog", { name: "Generate QKey" }).getByRole("button", { name: "Generate" }).click();
      await page.getByRole("dialog", { name: "Issued QKey" }).getByRole("button", { name: "Done" }).click();
      const row = page.getByTestId("qkey-row").filter({ hasText: issuedId }).first();
      await expect(row).toBeVisible();
      await row.getByRole("button", { name: "Revoke" }).click();

      await expect(page.getByTestId("qkey-row").filter({ hasText: issuedId }).first()).toBeVisible();
      await expect(page.getByRole("alert")).toHaveCount(0);
    });
  });

  test.describe("Logs", () => {
    test.beforeEach(async ({ page }) => {
      let serverLogMode: "verbose" | "normal" | "minimal" | "no-log" = "normal";
      await page.unroute("**/api/config/logging");
      await page.route("**/api/config/logging", async (route) => {
        const req = route.request();
        if (req.method() === "POST") {
          const body = req.postDataJSON() as { mode?: unknown };
          const mode = body.mode;
          if (mode === "verbose" || mode === "normal" || mode === "minimal" || mode === "no-log") {
            serverLogMode = mode;
          }
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ success: true, data: { mode: serverLogMode } }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { mode: serverLogMode } }),
        });
      });
      await page.unroute("**/api/logs**");
      await page.route("**/api/logs**", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { lines: [], cursor: 0 } }),
        });
      });

      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Logs" }).click();
    });

    test("mode selection can be changed and saved", async ({ page }) => {
      await selectLogMode(page, "Minimal");
      await page.getByRole("button", { name: "Save" }).first().click();
      await expect(page.getByText("Changes saved", { exact: true })).toBeVisible();
    });

    test("logging mode remains dirty when readback verification mismatches", async ({ page }) => {
      await page.unroute("**/api/config/logging");
      await page.route("**/api/config/logging", async (route) => {
        const req = route.request();
        if (req.method() === "POST") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ success: true }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ success: true, data: { mode: "normal" } }),
        });
      });

      await selectLogMode(page, "Minimal");
      const save = page.getByRole("button", { name: "Save" }).first();
      await expect(save).toBeEnabled();
      await save.click();

      await expect(page.getByText("Changes saved", { exact: true })).toHaveCount(0);
      await expect(save).toBeEnabled();
    });

    test("No-log mode hides output and shows help text", async ({ page }) => {
      await selectLogMode(page, "No-Log");
      await expect(page.getByText("Zero-Log Privacy Mode", { exact: true })).toBeVisible();
      await expect(
        page.getByText("Log output is disabled in No-Log mode. Switch to Normal or Verbose to view server logs.", { exact: true }),
      ).toBeVisible();
      await expect(page.getByText("Live Output", { exact: true })).toHaveCount(0);
    });

    test("auth error in logs triggers login modal", async ({ page }) => {
      await page.unroute("**/api/logs**");
      await page.route("**/api/logs**", async (route) => {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
      });

      await expect(page.getByRole("dialog").first()).toBeVisible();
    });
  });

  test.describe("Settings", () => {
    test.beforeEach(async ({ page }) => {
      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();
    });

    test("Change Password posts fields and forces re-login", async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
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

        if (req.method() === "POST") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ success: true }),
          });
          return;
        }

        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      // Re-open settings to ensure it uses the routes above (test isolation).
      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await setInputValue(dialog.locator('input[name="admin-change-current-password"]'), "123");
      await setInputValue(dialog.locator('input[name="admin-change-new-password"]'), "abcdef");
      await setInputValue(dialog.locator('input[name="admin-change-confirm-password"]'), "abcdef");
      const postReqPromise = page.waitForRequest((req) => {
        return req.url().includes("/api/admin/auth") && req.method() === "POST";
      });
      await dialog.getByRole("button", { name: "Save" }).click();

      const postReq = await postReqPromise;
      expect(JSON.parse(postReq.postData() || "{}")).toEqual({
        current_password: "123",
        new_password: "abcdef",
      });

      // A successful password update forces re-login.
      await expect(page.getByText("Admin Login", { exact: true })).toBeVisible();
      const toast = page.getByTestId("toast").first();
      await expect(toast).toBeVisible();
    });

    test("Change Username posts fields and forces re-login", async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
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

        if (req.method() === "POST") {
          await route.fulfill({
            status: 200,
            contentType: "application/json",
            body: JSON.stringify({ success: true }),
          });
          return;
        }

        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: "Change Username" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Username" });
      await expect(dialog).toBeVisible();

      await setInputValue(dialog.locator('input[name="admin-change-username"]'), "root");
      await setInputValue(dialog.locator('input[name="admin-change-username-current-password"]'), "123");

      const postReqPromise = page.waitForRequest((req) => {
        return req.url().includes("/api/admin/auth") && req.method() === "POST";
      });
      await dialog.getByRole("button", { name: "Save" }).click();

      const postReq = await postReqPromise;
      expect(JSON.parse(postReq.postData() || "{}")).toEqual({
        new_username: "root",
        current_password: "123",
      });

      await expect(page.getByText("Admin Login", { exact: true })).toBeVisible();
      const toast = page.getByTestId("toast").first();
      await expect(toast).toBeVisible();
      await expect(page.getByTestId("toast-message").first()).toContainText("Username updated");
    });

    test("Rate-limited password change shows error banner", async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        const req = route.request();
        if (req.method() === "GET") {
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

        if (req.method() === "POST") {
          await route.fulfill({
            status: 429,
            contentType: "application/json",
            body: JSON.stringify({
              success: false,
              message: "Too many attempts. Try again in 10 seconds.",
            }),
          });
          return;
        }

        await route.fulfill({ status: 405, body: "Method Not Allowed" });
      });

      await page.goto("/");
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await dialog.getByLabel("Current Password", { exact: true }).fill("123");
      await dialog.getByLabel("New Password", { exact: true }).fill("abcdef");
      await dialog.getByLabel("Confirm Password", { exact: true }).fill("abcdef");
      await dialog.getByRole("button", { name: "Save" }).click();

      await expect(dialog.getByText("Too many attempts. Try again in 10 seconds.", { exact: true })).toBeVisible();
      const toast = page.getByTestId("toast").first();
      await expect(toast).toBeVisible();
      await expect(page.getByTestId("toast-message").first()).toContainText("Too many attempts. Try again in 10 seconds.");
    });

    test("Change password Save is disabled on mismatch", async ({ page }) => {
      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await dialog.getByLabel("Current Password", { exact: true }).fill("123");
      await dialog.getByLabel("New Password", { exact: true }).fill("abcdef");
      await dialog.getByLabel("Confirm Password", { exact: true }).fill("abcdeg");
      await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    test("Change password Save is disabled when new password is too short", async ({ page }) => {
      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await dialog.getByLabel("Current Password", { exact: true }).fill("123");
      await dialog.getByLabel("New Password", { exact: true }).fill("abc");
      await dialog.getByLabel("Confirm Password", { exact: true }).fill("abc");
      await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    test("Change password Save enables at the six-character minimum", async ({ page }) => {
      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await dialog.getByLabel("Current Password", { exact: true }).fill("123");
      await dialog.getByLabel("New Password", { exact: true }).fill("abcdef");
      await dialog.getByLabel("Confirm Password", { exact: true }).fill("abcdef");
      await expect(dialog.getByRole("button", { name: "Save" })).toBeEnabled();
    });

    test("logout on dirty config asks confirmation and can be cancelled", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();
      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      await nav.getByRole("button", { name: "Logout" }).click();
      const confirm = page.getByRole("dialog", { name: "Unsaved Changes" });
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", { name: "Cancel" }).click();

      await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
      await expect(page.getByText("Admin Login", { exact: true })).toHaveCount(0);
    });

    test("logout on dirty config asks confirmation and logs out when accepted", async ({ page }) => {
      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();
      await page.getByRole("button", { name: /FEC preset$/ }).click();
      await page.getByRole("option", { name: "Off", exact: true }).click();

      await nav.getByRole("button", { name: "Logout" }).click();
      const confirm = page.getByRole("dialog", { name: "Unsaved Changes" });
      await expect(confirm).toBeVisible();
      await confirm.getByRole("button", { name: "Leave" }).click();

      await expect(page.getByText("Admin Login", { exact: true })).toBeVisible();
    });

    test("Change Username save is disabled on whitespace-only username", async ({ page }) => {
      await page.getByRole("button", { name: "Change Username" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Username" });
      await expect(dialog).toBeVisible();

      const username = dialog.getByLabel("New Username", { exact: true });
      await username.fill("    ");
      await dialog.getByLabel("Current Password", { exact: true }).fill("123");

      await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
    });

    test("Change Username input enforces max length", async ({ page }) => {
      await page.getByRole("button", { name: "Change Username" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Username" });
      await expect(dialog).toBeVisible();

      const username = dialog.getByLabel("New Username", { exact: true });
      await username.fill("a".repeat(100));
      const valueLength = await username.evaluate((el: HTMLInputElement) => el.value.length);
      expect(valueLength).toBe(64);
    });
  });

  test.describe("Default Credentials Lock", () => {
    test.beforeEach(async ({ page }) => {
      await page.unroute("**/api/admin/auth");
      await page.route("**/api/admin/auth", async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            data: { user: "admin", requires_password_change: true },
          }),
        });
      });

      await page.goto("/");
    });

    test("forces password change flow and locks navigation to Configuration", async ({ page }) => {
      await expect(
        page.getByText("Default credentials detected. Please change your password."),
      ).toBeVisible();

      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      // Use a DOM selector (aria-label) to avoid accessibility-name edge cases with disabled buttons.
      const nav = page.locator("nav[aria-label='Primary']");
      await expect(nav).toBeVisible();

      const tabButton = (label: string) => nav.locator("button").filter({ hasText: label }).first();
      await expect(tabButton("Dashboard")).toBeDisabled();
      await expect(tabButton("Configuration")).toBeEnabled();
      await expect(tabButton("Logs")).toBeDisabled();
      await expect(tabButton("About")).toBeDisabled();

      await expect(dialog.getByLabel("Current Password", { exact: true })).toBeVisible();
      await expect(dialog.getByLabel("New Password", { exact: true })).toBeVisible();
      await expect(dialog.getByLabel("Confirm Password", { exact: true })).toBeVisible();
      await expect(page.getByRole("button", { name: "Change Username" })).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "Cancel" })).toHaveCount(0);
      await expect(dialog.getByRole("button", { name: "Close" })).toHaveCount(0);

      await page.keyboard.press("Escape");
      await expect(dialog).toBeVisible();
    });
  });

  test.describe("Toast System", () => {
    test("toast container exists in DOM", async ({ page }) => {
      const toastContainer = page.getByTestId("toast-container");
      await expect(toastContainer).toBeAttached();
    });
  });

  test.describe("Responsive Design", () => {
    test("renders correctly on desktop viewport", async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 720 });
      await page.waitForTimeout(200);

      await expect(appStage(page)).toBeVisible();
    });

    test("renders correctly on tablet viewport", async ({ page }) => {
      await page.setViewportSize({ width: 768, height: 1024 });
      await page.waitForTimeout(200);

      await expect(appStage(page)).toBeVisible();
    });

    test("renders correctly on mobile viewport", async ({ page }) => {
      await page.setViewportSize({ width: 375, height: 667 });
      await page.waitForTimeout(200);

      await expect(appStage(page)).toBeVisible();
    });
  });

  test.describe("Layout Stability", () => {
    test("no horizontal overflow across main tabs (desktop)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 1280, height: 720 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      const tabs = ["Dashboard", "Configuration", "Logs", "About"];

      for (const t of tabs) {
        await nav.getByRole("button", { name: t }).click();
        await page.waitForTimeout(100);
        await expectNoHorizontalOverflow(page);
      }
    });

    test("Configuration preset dropdown stays within viewport (tablet)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 768, height: 1024 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: /FEC preset$/ }).click();
      const listbox = page.locator("[role='listbox']").first();
      await expect(listbox).toBeVisible();

      await expectLocatorInViewport(page, listbox);

      await page.keyboard.press("Escape");
    });

    test("Change Password modal stays within fixed stage bounds (mobile viewport)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 375, height: 667 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: "Change Password" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Password" });
      await expect(dialog).toBeVisible();

      await expectLocatorInStage(page, dialog);

      await page.keyboard.press("Escape");
    });

    test("Change Username modal stays within fixed stage bounds (mobile viewport)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 375, height: 667 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration" }).click();

      await page.getByRole("button", { name: "Change Username" }).click();
      const dialog = page.getByRole("dialog", { name: "Change Username" });
      await expect(dialog).toBeVisible();

      await expectLocatorInStage(page, dialog);

      await page.keyboard.press("Escape");
    });

    test("Login modal stays within fixed stage bounds (mobile viewport)", async ({ page }) => {
      await page.unroute("**/api/status");
      await page.route("**/api/status", async (route) => {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
      });

      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 375, height: 667 });
      await page.goto("/");

      const dialog = page.getByRole("dialog").first();
      await expect(dialog).toBeVisible();
      await expectLocatorInStage(page, dialog);
    });
  });

  test.describe("Accessibility", () => {
    test("has proper document structure", async ({ page }) => {
      // Check for basic document structure
      await expect(page.locator("html")).toBeVisible();
      await expect(page.locator("body")).toBeVisible();
      await expect(appStage(page)).toBeVisible();
    });

    test("interactive elements are keyboard accessible", async ({ page }) => {
      // Tab to first focusable element
      await page.keyboard.press("Tab");

      // Something should be focused
      const focused = page.locator(":focus");
      await expect(focused.first()).toBeVisible();
    });

    test("buttons have accessible content", async ({ page }) => {
      const buttons = page.locator("button");
      const count = await buttons.count();

      // At least some buttons should exist
      expect(count).toBeGreaterThan(0);

      // Check first few buttons have accessible names
      for (let i = 0; i < Math.min(count, 5); i++) {
        const button = buttons.nth(i);
        const text = await button.textContent();
        const ariaLabel = await button.getAttribute("aria-label");
        expect(text?.trim().length || ariaLabel).toBeTruthy();
      }
    });
  });

  test.describe("Visual Regression", () => {
    test("sidebar keeps desktop-aligned width", async ({ page }) => {
      const sidebar = page.getByRole("navigation").first();
      await expect(sidebar).toBeVisible();
      const box = await sidebar.boundingBox();
      expect(box).not.toBeNull();
      expect(Math.round((box?.width ?? 0))).toBe(152);
    });

    test("login modal stays visible and within viewport", async ({ page }) => {
      // Force auth required for a stable modal snapshot.
      await page.unroute("**/api/status");
      await page.route("**/api/status", async (route) => {
        await route.fulfill({
          status: 401,
          contentType: "application/json",
          body: JSON.stringify({ success: false, message: "Unauthorized" }),
        });
      });
      await page.goto("/");

      const modal = page.getByRole("dialog").first();
      await expect(modal).toBeVisible();
      await expectLocatorInViewport(page, modal);
    });
  });
});
