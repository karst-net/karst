// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { defineConfig } from "@playwright/test";

const apiPort = process.env.KARST_API_MOCK_PORT ?? "4010";
const webPort = process.env.KARST_CONSOLE_TEST_PORT ?? "4173";

export default defineConfig({
  testDir: "./e2e",
  use: { baseURL: `http://127.0.0.1:${webPort}` },
  webServer: [
    { command: "node ../tools/karst-api-mock.mjs", url: `http://127.0.0.1:${apiPort}/api/karst/v1/nodes`, reuseExistingServer: !process.env.CI },
    { command: `corepack pnpm dev --host 127.0.0.1 --port ${webPort}`, url: `http://127.0.0.1:${webPort}`, reuseExistingServer: !process.env.CI },
  ],
});
