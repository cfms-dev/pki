import "reflect-metadata";
import { afterEach, beforeEach, vi } from "vitest";
import { CONFIG } from "../src/config";

vi.mock("../src/config", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/config")>();
  // Keep the helpers and their closed-over CONFIG on the same test-local instance.
  return { ...actual };
});

const originalConfig = structuredClone(CONFIG);
beforeEach(() => Object.assign(CONFIG, structuredClone(originalConfig)));
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  Object.assign(CONFIG, structuredClone(originalConfig));
});
