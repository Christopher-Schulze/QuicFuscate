import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sveltekit } from "@sveltejs/kit/vite";
import { svelteTesting } from "@testing-library/svelte/vite";
import { configDefaults, defineConfig } from "vitest/config";

const workspaceRoot = resolve(__dirname, "../..");
const desktopUnitTestRoot = resolve(workspaceRoot, "scripts/tests/frontend/desktop/unit");
const jestDomVitestPath = fileURLToPath(import.meta.resolve("@testing-library/jest-dom/vitest"));
const testingLibrarySveltePath = fileURLToPath(import.meta.resolve("@testing-library/svelte"));
const lucideSveltePath = fileURLToPath(import.meta.resolve("@lucide/svelte"));

// Mirror the single release-version owner used by vite.config.ts. Components read the
// injected `__RELEASE_VERSION__`, so without this define every test that renders one
// fails with a ReferenceError rather than a real assertion.
function releaseVersion(): string {
  const manifest = resolve(workspaceRoot, "Cargo.toml");
  const source = readFileSync(manifest, "utf8");
  const workspace = source.split(/^\[workspace\.package\]\s*$/m)[1];
  const found = workspace?.match(/^\s*version\s*=\s*"([^"]+)"/m)?.[1];
  if (!found) {
    throw new Error(`cannot read the release version from ${manifest}`);
  }
  return found;
}

export default defineConfig({
  define: {
    __RELEASE_VERSION__: JSON.stringify(releaseVersion()),
  },
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
    pool: "threads",
    fileParallelism: false,
    maxWorkers: 1,
    testTimeout: 15_000,
    setupFiles: [
      jestDomVitestPath,
      resolve(desktopUnitTestRoot, "setup.ts"),
    ],
    include: [resolve(desktopUnitTestRoot, "src/**/*.{test,spec}.{ts,tsx}")],
    css: true,
    exclude: [...configDefaults.exclude, "e2e/**", "dist/**"],
  },
});
