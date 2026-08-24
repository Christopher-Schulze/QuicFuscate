import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

async function waitForHydration(page: import("@playwright/test").Page) {
  await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
}

test.describe("Desktop visual + a11y gates", () => {
  test.beforeEach(async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/");
    await waitForHydration(page);
  });

  test("tunnels shell screenshot", async ({ page }) => {
    await expect(page.locator("#qf-app-stage")).toHaveScreenshot("desktop-tunnels.png", {
      maxDiffPixelRatio: 0.02,
      animations: "disabled",
    });
  });

  test("configuration shell screenshot", async ({ page }) => {
    await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: "Configuration", exact: true }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();
    await expect(page.locator("#qf-app-stage")).toHaveScreenshot("desktop-configuration.png", {
      maxDiffPixelRatio: 0.02,
      animations: "disabled",
    });
  });

  test("axe has no serious or critical violations on the tunnels shell", async ({ page }) => {
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();
    const blocking = results.violations.filter((violation) =>
      violation.impact === "serious" || violation.impact === "critical"
    );
    expect(blocking, JSON.stringify(blocking, null, 2)).toEqual([]);
  });
});
