import { test, expect } from "@playwright/test";

test.describe("Desktop UI (Browser Mode)", () => {
  async function waitForHydration(page: any) {
    await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
  }

  function createButton(page: any) {
    return page.getByRole("button", { name: "Open tunnel composer", exact: true });
  }

  function importQkeyButton(page: any) {
    return page.getByRole("button", { name: "Open QKey vault", exact: true });
  }

  async function expectNoHorizontalOverflow(page: any) {
    const m = await page.evaluate(() => {
      const shell = document.querySelector("#qf-app-stage");
      return {
        shellClientWidth: (shell as HTMLElement | null)?.clientWidth ?? 0,
        shellScrollWidth: (shell as HTMLElement | null)?.scrollWidth ?? 0,
      };
    });

    expect(m.shellScrollWidth).toBeLessThanOrEqual(m.shellClientWidth + 1);
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

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForHydration(page);
  });

  test("app shell renders and primary navigation is accessible", async ({ page }) => {
    await expect(page.getByAltText("QuicFuscate logo")).toBeVisible();

    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav).toBeVisible();
    await expect(nav.getByRole("button", { name: "Tunnels", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Configuration", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Logs", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "About", exact: true })).toBeVisible();
  });

  test("tunnels view shows create + import actions and a stable content area", async ({ page }) => {
    await expect(createButton(page)).toBeVisible();
    await expect(importQkeyButton(page)).toBeVisible();
    const openConfigButtons = page.getByRole("button", { name: "Open configuration", exact: true });
    if ((await openConfigButtons.count()) > 0) {
      await expect(openConfigButtons.first()).toBeVisible();
    } else {
      await expect(page.locator("main").getByText("0", { exact: true }).first()).toBeVisible();
      await expect(page.locator("main").getByText("Tunnels", { exact: true }).first()).toBeVisible();
    }
  });

  test("create tunnel validates remote and creates a tunnel shell", async ({ page }) => {
    await createButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Create Tunnel" });
    await expect(dialog).toBeVisible();

    await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Frankfurt DE");
    await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("not a remote");
    await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();
    await expect(dialog).toBeVisible();
    await expect(page.locator("main").getByText("Frankfurt DE", { exact: true })).toHaveCount(0);

    // Valid IPv6 (defaults port to 4433 if missing)
    await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("[::1]");
    await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();

    // Tunnel appears in list and is selected
    await expect(page.getByText("Frankfurt DE", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("[::1]:4433", { exact: true }).first()).toBeVisible();

    // Detail panel connect action stays disabled until a QKey exists.
    const connectWithoutQKey = page.getByRole("button", { name: "Set QKey" }).filter({ hasText: "Connect" }).first();
    await expect(connectWithoutQKey).toBeVisible();
    await expect(connectWithoutQKey).toBeDisabled();
  });

  test("country code renders flag and can delete tunnels", async ({ page }) => {
    await createButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Create Tunnel" });
    await expect(dialog).toBeVisible();
    await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Berlin");
    await dialog.getByRole("button", { name: "-", exact: true }).click();
    const germanyOption = page.locator('[role="listbox"]').locator('[data-option]').filter({ hasText: "Germany" }).first();
    await germanyOption.scrollIntoViewIfNeeded();
    await expect(germanyOption).toBeVisible();
    await germanyOption.click();
    await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("vpn.example.com:4433");
    await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();

    // Flag should be visible for DE.
    await expect(page.getByText("Berlin", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("DE", { exact: true }).first()).toBeVisible();

    // Toolbar should appear once we have tunnels.
    await expect(createButton(page)).toBeVisible();
    await expect(importQkeyButton(page)).toBeVisible();

    // Remove the tunnel through the configuration flow and confirm the destructive action.
    const berlinCard = page.locator("[data-tunnel-card]").filter({ hasText: "Berlin" }).first();
    const configBtn = berlinCard.getByRole("button", { name: "Open configuration", exact: true });
    await expect(configBtn).toBeVisible();
    await configBtn.click();
    const configDialog = page.getByRole("dialog", { name: "Tunnel Configuration" });
    await expect(configDialog).toBeVisible();
    await configDialog.getByRole("button", { name: "Delete", exact: true }).click();
    const deleteDialog = page.getByRole("dialog", { name: "Delete Tunnel" });
    await expect(deleteDialog).toBeVisible();
    await deleteDialog.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(deleteDialog).toBeHidden();
    await expect(page.locator("main").getByText("Berlin", { exact: true })).toHaveCount(0);
  });

  test("without QKey the connect control stays disabled and import flow is available", async ({ page }) => {
    await createButton(page).click();
    const dialog = page.getByRole("dialog", { name: "Create Tunnel" });
    await expect(dialog).toBeVisible();
    await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Test");
    await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("vpn.example.com:4433");
    await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();

    const connectWithoutQKey = page.getByRole("button", { name: "Set QKey" }).filter({ hasText: "Connect" }).first();
    await expect(connectWithoutQKey).toBeVisible();
    await expect(connectWithoutQKey).toBeDisabled();

    await importQkeyButton(page).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await expect(page.getByLabel("QKey String", { exact: true })).toBeVisible();
  });

  test("import qkey is disabled in browser mode and warns clearly", async ({ page }) => {
    await importQkeyButton(page).click();
    await expect(page.getByLabel("QKey String", { exact: true })).toBeVisible();

    await page.getByRole("textbox", { name: "QKey String" }).fill("QKey-TESTONLY");
    const importBtn = page.getByRole("button", { name: "Import", exact: true });
    await expect(importBtn).toBeDisabled();
  });

  test("configuration view shows logging/startup/updates controls", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });
    await nav.getByRole("button", { name: "Configuration", exact: true }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

    await expect(page.getByText("Logging", { exact: true })).toBeVisible();
    await expect(page.getByText("Log Level", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Log level info", exact: true })).toBeVisible();
    await expect(page.getByText("Startup", { exact: true })).toBeVisible();
    await expect(page.getByText("Updates", { exact: true })).toBeVisible();
  });

  test("logs view renders empty state and skeleton", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });
    await nav.getByRole("button", { name: "Logs", exact: true }).click();
    await expect(page.getByText("Live Output", { exact: true })).toBeVisible();
    await expect(page.getByText("Waiting for engine output...")).toBeVisible();
  });

  test("about view renders specs and does not crash without runtime", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });
    await nav.getByRole("button", { name: "About", exact: true }).click();
    await expect(page.getByText("Open-source obfuscated QUIC tunnel")).toBeVisible();
    await expect(page.getByText("Engine")).toBeVisible();
    await expect(page.getByText("Rust + Tokio")).toBeVisible();
  });

  test.describe("Layout Stability", () => {
    test("no horizontal overflow across main tabs (desktop)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 1280, height: 720 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      const tabs = ["Tunnels", "Configuration", "Logs", "About"];

      for (const t of tabs) {
        await nav.getByRole("button", { name: t, exact: true }).click();
        await page.waitForTimeout(80);
        await expectNoHorizontalOverflow(page);
      }
    });

    test("Create Tunnel dialog stays within viewport (small window)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 900, height: 600 });

      await createButton(page).click();
      const dialog = page.getByRole("dialog").first();
      await expect(dialog).toBeVisible();

      await expectLocatorInViewport(page, dialog, 8);

      // Regression check: labels must not overlap previous fields.
      const nameInput = dialog.getByLabel("Name of the Connection", { exact: true });
      const remoteLabel = dialog.locator("label").filter({ hasText: "Remote [IP-Address:Port]" }).first();
      const nameBox = await nameInput.boundingBox();
      const remoteLabelBox = await remoteLabel.boundingBox();
      if (nameBox && remoteLabelBox) {
        // Keep a small epsilon for browser sub-pixel layout differences.
        expect(remoteLabelBox.y).toBeGreaterThanOrEqual(nameBox.y + nameBox.height - 0.5);
      }

      await page.keyboard.press("Escape");
    });

    test("Create Tunnel field labels do not overlap controls in fixed desktop viewport", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 900, height: 600 });

      await createButton(page).click();
      const dialog = page.getByRole("dialog").first();
      await expect(dialog).toBeVisible();

      const nameInput = dialog.getByLabel("Name of the Connection", { exact: true });
      const remoteLabel = dialog.locator("label").filter({ hasText: "Remote [IP-Address:Port]" }).first();
      const remoteInput = dialog.getByLabel("Remote [IP-Address:Port]", { exact: true });

      const nameBox = await nameInput.boundingBox();
      const remoteLabelBox = await remoteLabel.boundingBox();
      const remoteBox = await remoteInput.boundingBox();
      expect(nameBox).not.toBeNull();
      expect(remoteLabelBox).not.toBeNull();
      expect(remoteBox).not.toBeNull();
      if (nameBox && remoteLabelBox && remoteBox) {
        // Keep a positive gap so the label does not touch the previous input border.
        expect(remoteLabelBox.y).toBeGreaterThan(nameBox.y + nameBox.height + 1);
        // Label must stay above its own input.
        expect(remoteLabelBox.y + remoteLabelBox.height).toBeLessThanOrEqual(remoteBox.y - 1);
      }

      await page.keyboard.press("Escape");
    });

    test("Import QKey dialog stays within viewport (small window)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 900, height: 600 });

      await importQkeyButton(page).click();
      const dialog = page.getByRole("dialog").first();
      await expect(dialog).toBeVisible();

      await expectLocatorInViewport(page, dialog, 8);

      await page.keyboard.press("Escape");
    });

    test("connect control stays stable without QKey (small window)", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 900, height: 600 });

      await createButton(page).click();
      const dialog = page.getByRole("dialog", { name: "Create Tunnel" });
      await expect(dialog).toBeVisible();
      await dialog.getByLabel("Name of the Connection", { exact: true }).fill("Viewport");
      await dialog.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("vpn.example.com:4433");
      await dialog.getByRole("button", { name: "Create Tunnel", exact: true }).click();

      const connectWithoutQKey = page.getByRole("button", { name: "Set QKey" }).filter({ hasText: "Connect" }).first();
      await expect(connectWithoutQKey).toBeVisible();
      await expect(connectWithoutQKey).toBeDisabled();
      await expectLocatorInViewport(page, connectWithoutQKey, 8);
    });

    test("configuration view stays stable in fixed viewport", async ({ page }) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.setViewportSize({ width: 900, height: 600 });

      const nav = page.getByRole("navigation", { name: "Primary" });
      await nav.getByRole("button", { name: "Configuration", exact: true }).click();
      await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
      await expectNoHorizontalOverflow(page);
    });
  });
});
