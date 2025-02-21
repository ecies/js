import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    browser: {
      instances: [{ browser: "chromium" }, { browser: "firefox" }, { browser: "webkit" }],
      enabled: true,
      provider: "playwright",
    },
  },
});
