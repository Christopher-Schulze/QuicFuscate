import { resolve } from "node:path";
import { sveltekit } from "@sveltejs/kit/vite";
import { svelteTesting } from "@testing-library/svelte/vite";
import { configDefaults, defineConfig } from "vitest/config";

const workspaceRoot = resolve(__dirname, "../..");
const adminUnitTestRoot = resolve(workspaceRoot, "scripts/tests/frontend/web-admin/unit");

export default defineConfig({
  plugins: [sveltekit(), svelteTesting()],
  resolve: {
    conditions: ["browser"],
    alias: {
      "@testing-library/svelte": resolve(__dirname, "node_modules/@testing-library/svelte"),
      "@testing-library/jest-dom": resolve(__dirname, "node_modules/@testing-library/jest-dom"),
      "@testing-library/jest-dom/vitest": resolve(
        __dirname,
        "node_modules/@testing-library/jest-dom/vitest.js",
      ),
      // @lucide/svelte is a peer dep of @quicfuscate/ui (packages/ui).
      // packages/ui has no local node_modules for it, so Vite cannot resolve it
      // when transforming Select.svelte from the workspace root. Pin it to the
      // copy installed here so the transform does not fail.
      "@lucide/svelte": resolve(__dirname, "node_modules/@lucide/svelte"),
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
    setupFiles: [resolve(adminUnitTestRoot, "setup.ts")],
    include: [resolve(adminUnitTestRoot, "**/*.{test,spec}.{ts,tsx}")],
    css: true,
    exclude: [...configDefaults.exclude, "e2e/**", "dist/**"],
  },
});
