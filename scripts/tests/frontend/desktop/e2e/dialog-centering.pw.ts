import { expect, test, type Page, type TestInfo } from "@playwright/test";

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
    `[dialog-center][desktop] ${label}: dx=${dx.toFixed(2)}px dy=${dy.toFixed(2)}px ` +
      `stage=${stageBox.width.toFixed(0)}x${stageBox.height.toFixed(0)} dialog=${dialogBox.width.toFixed(0)}x${dialogBox.height.toFixed(0)}`,
  );

  await page.screenshot({
    path: testInfo.outputPath(`desktop-${label.replace(/\s+/g, "-").toLowerCase()}.png`),
    fullPage: true,
  });

  expect(Math.abs(dx)).toBeLessThanOrEqual(2);
  expect(Math.abs(dy)).toBeLessThanOrEqual(2);
}

async function createTunnelShell(page: Page, name: string) {
  await page.getByRole("button", { name: "Open tunnel composer", exact: true }).click();
  await page.getByLabel("Name of the Connection", { exact: true }).fill(name);
  await page.getByLabel("Remote [IP-Address:Port]", { exact: true }).fill("203.0.113.11:4433");
  await page.getByRole("button", { name: "Create Tunnel", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByText(name, { exact: true }).first()).toBeVisible();
}

async function waitForHydration(page: Page) {
  await expect(page.locator('#qf-app-stage[data-hydrated="true"]')).toBeVisible();
}

test.describe("Dialog Centering [Desktop Browser Mode]", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForHydration(page);
  });

  test("create dialog is centered in stage", async ({ page }, testInfo) => {
    await page.getByRole("button", { name: "Open tunnel composer", exact: true }).click();
    await assertDialogCenteredInStage(page, testInfo, "create-tunnel");
  });

  test("import qkey dialog is centered in stage", async ({ page }, testInfo) => {
    await page.getByRole("button", { name: "Open QKey vault", exact: true }).click();
    await assertDialogCenteredInStage(page, testInfo, "import-qkey");
  });

  test("delete confirm dialog is centered in stage", async ({ page }, testInfo) => {
    await createTunnelShell(page, "Center Delete");
    const card = page.locator("[data-tunnel-card]").filter({ hasText: "Center Delete" }).first();
    await expect(card).toBeVisible();
    await card.getByRole("button", { name: "Open configuration", exact: true }).click();
    const configDialog = page.getByRole("dialog", { name: "Tunnel Configuration" });
    await expect(configDialog).toBeVisible();
    await configDialog.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Delete Tunnel" })).toBeVisible();
    await assertDialogCenteredInStage(page, testInfo, "delete-confirm");
  });
});
