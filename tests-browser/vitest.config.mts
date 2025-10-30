import { defineConfig } from "vitest/config";
import { playwright } from "@vitest/browser-playwright";

export default defineConfig({
  test: {
    browser: {
      instances: [{ browser: "chromium" }, { browser: "firefox" }, { browser: "webkit" }],
      enabled: true,
      provider: playwright(),
    },
  },
});
