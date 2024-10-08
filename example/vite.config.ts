import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("@noble")) {
            return "noble";
          } else if (id.includes("buffer")) {
            return "buffer";
          }
        },
      },
    },
  },
});
