import { resolve } from "node:path";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { svelteTesting } from "@testing-library/svelte/vite";
import { configDefaults, defineConfig } from "vitest/config";

const workspaceRoot = resolve(__dirname, "../..");
const sharedUiTestRoot = resolve(workspaceRoot, "scripts/tests/frontend/shared-ui/unit");

export default defineConfig({
  plugins: [svelte({ hot: false }), svelteTesting()],
  resolve: {
    conditions: ["browser"],
    alias: {
      "@testing-library/svelte": resolve(__dirname, "node_modules/@testing-library/svelte"),
      "@testing-library/jest-dom": resolve(__dirname, "node_modules/@testing-library/jest-dom"),
      "@testing-library/jest-dom/vitest": resolve(
        __dirname,
        "node_modules/@testing-library/jest-dom/vitest.js",
      ),
    },
  },
  server: {
    fs: {
      allow: [workspaceRoot],
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: [resolve(sharedUiTestRoot, "setup.ts")],
    include: [resolve(sharedUiTestRoot, "**/*.{test,spec}.ts")],
    css: true,
    exclude: [...configDefaults.exclude],
  },
});
