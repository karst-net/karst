// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: { proxy: { "/api": "http://127.0.0.1:4010" } },
});
