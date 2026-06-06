import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sveltekit } from "@sveltejs/kit/vite";
import { svelteTesting } from "@testing-library/svelte/vite";
import { configDefaults, defineConfig } from "vitest/config";

const workspaceRoot = resolve(__dirname, "../..");
const adminUnitTestRoot = resolve(workspaceRoot, "scripts/tests/frontend/web-admin/unit");
const jestDomVitestPath = fileURLToPath(import.meta.resolve("@testing-library/jest-dom/vitest"));
const testingLibrarySveltePath = fileURLToPath(import.meta.resolve("@testing-library/svelte"));
const lucideSveltePath = fileURLToPath(import.meta.resolve("@lucide/svelte"));

export default defineConfig({
  plugins: [sveltekit(), svelteTesting()],
  resolve: {
    conditions: ["browser"],
    alias: {
      "@testing-library/svelte": testingLibrarySveltePath,
      "@testing-library/jest-dom": resolve(__dirname, "node_modules/@testing-library/jest-dom"),
      "@testing-library/jest-dom/vitest": jestDomVitestPath,
      "@lucide/svelte": lucideSveltePath,
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
    setupFiles: [
      jestDomVitestPath,
      resolve(adminUnitTestRoot, "setup.ts"),
    ],
    include: [resolve(adminUnitTestRoot, "**/*.{test,spec}.{ts,tsx}")],
    css: true,
    exclude: [...configDefaults.exclude, "e2e/**", "dist/**"],
  },
});
