import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [{
    name: "llhttp-wasm-test-module",
    enforce: "pre",
    resolveId(id) {
      if (id.endsWith("/llhttp.wasm")) return "\0llhttp-compiled-test";
    },
    load(id) {
      if (id === "\0llhttp-compiled-test") {
        return `export default new WebAssembly.Module(Uint8Array.from(${JSON.stringify([...readFileSync(new URL("./cas/llhttp.wasm", import.meta.url))])}));`;
      }
    },
  }],
  test: {
    globals: true,
    environment: "node",
    setupFiles: ["./test/setup.ts"],
  },
});
