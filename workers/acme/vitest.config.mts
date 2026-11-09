import { readFile } from "node:fs/promises";
import { defineConfig } from "vitest/config";

export default defineConfig({
  // Match Wrangler's HTML text-module imports in the Node test environment.
  plugins: [{
    name: "html-text",
    async load(id) {
      if (id.endsWith(".html")) {
        return `export default ${JSON.stringify(await readFile(id, "utf8"))};`;
      }
    },
  }],
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["./test/setup.ts"],
  },
});
