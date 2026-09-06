// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig({ plugins: [react()], build: { rollupOptions: { input: { main: resolve(import.meta.dirname, "index.html"), silentRenew: resolve(import.meta.dirname, "silent-renew.html") } } }, server: { proxy: { "/api": "http://127.0.0.1:4010", "/releases": "http://127.0.0.1:4010" } } });
