// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// VITE_BASE lets a sub-path deployment (e.g. GETTING-STARTED.md §7.2's
// single-origin layout, which serves this app from /portal/) produce asset
// URLs that resolve there instead of at the site root — see #252: built with
// the default base, the single-origin Caddy example's /portal/* route never
// matches this app's own root-relative asset requests.
export default defineConfig({ base: process.env.VITE_BASE || "/", plugins: [react()], build: { rollupOptions: { input: { main: resolve(import.meta.dirname, "index.html"), silentRenew: resolve(import.meta.dirname, "silent-renew.html") } } }, server: { proxy: { "/api": "http://127.0.0.1:4010", "/releases": "http://127.0.0.1:4010" } } });
