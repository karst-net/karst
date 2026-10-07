// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:4010" } },
  // maplibre-gl constructs its worker from a relative `new URL(..., import.meta.url)`
  // at module-evaluation time; Vite's dev-time dependency pre-bundling moves the
  // module to node_modules/.vite/deps/, which resolves that URL to a location the
  // worker chunk was never copied to ("Worker failed to load"). Excluding it from
  // pre-bundling serves it as the package's own untouched ESM, where the relative
  // URL is correct. Production builds are unaffected -- that bug is dev-server-only.
  optimizeDeps: { exclude: ["maplibre-gl"] },
  // silent-renew.html is a second real entry point, not a route the SPA
  // handles client-side — the hidden iframe automaticSilentRenew navigates to
  // it needs its own minimal bundle (src/silent-renew.ts), not the full app.
  build: { rollupOptions: { input: { main: resolve(import.meta.dirname, "index.html"), silentRenew: resolve(import.meta.dirname, "silent-renew.html") } } },
});
