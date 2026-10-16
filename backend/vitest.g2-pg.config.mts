import path from "node:path";
import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    globals: true,
    include: ["test-isolated/g2-postgres.integration.test.ts"],
    maxWorkers: 1,
    fileParallelism: false,
    testTimeout: 30000,
    hookTimeout: 180000
  },
  resolve: { alias: { "@app": path.resolve(import.meta.dirname, "src") } }
});
