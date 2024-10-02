import { defineConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: [],
      globals: {
        Buffer: true,
        global: false,
        process: false,
      },
    }),
  ],
});
