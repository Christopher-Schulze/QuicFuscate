import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import { defineConfig } from "vite";

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// The release version has exactly one owner: the workspace package version in the root
// Cargo.toml. Reading it here means the About surface cannot drift from what is built and
// shipped, which is how it ended up displaying v0.2.0 while the product was 0.4.4.
// scripts/audits/verify-release-version.sh enforces that every other manifest agrees.
function releaseVersion(): string {
  const manifest = fileURLToPath(new URL("../../Cargo.toml", import.meta.url));
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
  plugins: [tailwindcss(), sveltekit()],
  server: {
    proxy: {
      "/api": {
        target: "http://127.0.0.1:9000",
      },
    },
  },
});
