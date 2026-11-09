import fs from "node:fs";
import path from "node:path";
import { vi } from "vitest";

/** Replace only the requested bundled certificate; all other files stay real. */
export function mockCaCertificate(pem: string, certFile = "generic-intermediate.pem") {
  const readFileSync = fs.readFileSync.bind(fs);
  const localFile = path.resolve("generated/cas", certFile);
  const bundleFile = path.posix.join("/bundle", certFile);
  const fixture = { pem };
  vi.spyOn(fs, "readFileSync").mockImplementation((...args: Parameters<typeof fs.readFileSync>) => {
    const file = String(args[0]);
    if (file === bundleFile || path.resolve(file) === localFile) return fixture.pem;
    return readFileSync(...args);
  });
  return fixture;
}
