import { defineConfig } from "vite";

// `npm run dev` proxies the API to a vouch started with `./vouch` on :8080.
export default defineConfig({
  build: {
    outDir: "dist",
    // The build script recreates dist/.gitkeep, which lets the Go embed compile before the
    // web build has run.
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  server: {
    proxy: { "/api": "http://127.0.0.1:8080" },
  },
});
