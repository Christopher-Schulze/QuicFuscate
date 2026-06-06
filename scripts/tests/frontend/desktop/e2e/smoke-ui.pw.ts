import { test, expect } from "@playwright/test";

async function waitForHydration(page: any) {
  await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
}

test.describe("Desktop UI Smoke", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForHydration(page);
  });

  test("full interaction smoke [navigation, toggles, dropdowns, pages]", async ({ page }) => {
    const nav = page.getByRole("navigation", { name: "Primary" });
    await expect(nav.getByRole("button", { name: "Tunnels", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Configuration", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "Logs", exact: true })).toBeVisible();
    await expect(nav.getByRole("button", { name: "About", exact: true })).toBeVisible();

    await nav.getByRole("button", { name: "Tunnels", exact: true }).click();
    await expect(page.getByRole("button", { name: "Open tunnel composer", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Open QKey vault", exact: true })).toBeVisible();

    await nav.getByRole("button", { name: "Configuration", exact: true }).click();
    await expect(page.getByRole("main").getByText("Configuration", { exact: true })).toBeVisible();

    const switches = page.locator("[role='switch']");
    await expect(switches).toHaveCount(3);
    const firstSwitch = switches.first();
    const before = await firstSwitch.getAttribute("aria-checked");
    await firstSwitch.click();
    await page.waitForTimeout(120);
    const after = await firstSwitch.getAttribute("aria-checked");
    expect(after).not.toBe(before);

    const logLevel = page.getByRole("button", { name: /^Log level / });
    await logLevel.click();
    await page.waitForTimeout(120);
    await page.getByRole("option", { name: /^debug$/ }).click();
    await expect(logLevel).toContainText("debug");

    await nav.getByRole("button", { name: "Logs", exact: true }).click();
    await expect(page.getByText("Live Output", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Copy" }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Clear" }).first()).toBeVisible();

    await nav.getByRole("button", { name: "About", exact: true }).click();
    await expect(page.getByText("Open-source obfuscated QUIC tunnel")).toBeVisible();
    await expect(page.getByText("Rust + Tokio")).toBeVisible();
  });
});
