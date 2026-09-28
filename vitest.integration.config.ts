import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { alias: { "@": path.resolve(import.meta.dirname, "src") } },
  test: { include: ["tests/integration/**/*.test.ts"], environment: "node", testTimeout: 30_000, setupFiles: ["tests/integration/setup.ts"], fileParallelism: false },
});
