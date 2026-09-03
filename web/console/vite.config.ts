// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:4010" } },
  // silent-renew.html is a second real entry point, not a route the SPA
  // handles client-side — the hidden iframe automaticSilentRenew navigates to
  // it needs its own minimal bundle (src/silent-renew.ts), not the full app.
  build: { rollupOptions: { input: { main: resolve(import.meta.dirname, "index.html"), silentRenew: resolve(import.meta.dirname, "silent-renew.html") } } },
});
