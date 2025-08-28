import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 30_000,
    maxConcurrency: 2,
    isolate: false,
    exclude: ["**/node_modules/**", "**/.git/**", "dist"],
  },
})
