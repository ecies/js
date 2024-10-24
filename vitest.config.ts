import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "tests-browser/**"],
    coverage: {
      include: ["src/**"],
      enabled: true,
      provider: "v8",
    },
  },
});
