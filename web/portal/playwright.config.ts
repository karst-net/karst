// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { defineConfig } from "@playwright/test";
export default defineConfig({ testDir: "./e2e", use: { baseURL: "http://127.0.0.1:4174" }, webServer: [{ command: "node ../tools/karst-api-mock.mjs", url: "http://127.0.0.1:4010/api/karst/v1/nodes", reuseExistingServer: !process.env.CI }, { command: "corepack pnpm dev --host 127.0.0.1 --port 4174", url: "http://127.0.0.1:4174", reuseExistingServer: !process.env.CI }] });
