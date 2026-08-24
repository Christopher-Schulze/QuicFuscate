import { defineConfig, devices } from "@playwright/test";

const isCI = !!process.env.CI;
const wantHtmlReport = process.env.PW_HTML === "1";
const reuseExistingServer = process.env.PW_REUSE_SERVER === "1";

export default defineConfig({
  testDir: "../../scripts/tests/frontend/desktop/e2e",
  testMatch: "**/*.pw.ts",
  // Screenshot baselines are not in the repo yet. Missing snapshots fail CI
  // closed; keep the functional E2E on the hosted runner.
  testIgnore: isCI ? ["**/visual-a11y.pw.ts"] : [],
  fullyParallel: false,
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  timeout: isCI ? 60_000 : 30_000,
  workers: 1,
  reporter: wantHtmlReport ? [["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: "http://localhost:4173",
    channel: "chromium",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command:
      "env -u NO_COLOR -u FORCE_COLOR bun run build && env -u NO_COLOR -u FORCE_COLOR bun run preview -- --port 4173 --strictPort --host 127.0.0.1",
    env: { E2E: "1" },
    url: "http://localhost:4173",
    reuseExistingServer,
    timeout: 300 * 1000,
  },
});
