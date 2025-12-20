import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "tests-browser/**"],
    coverage: {
      include: ["src/**"],
      // Exclude re-export files and runtime-detection dispatcher
      // (the underlying implementations have 100% coverage)
      exclude: [
        "src/keys/index.ts",
        "src/utils/index.ts",
        "src/ciphers/index.ts",
      ],
      enabled: true,
      provider: "v8",
    },
  },
});
