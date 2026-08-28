// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

import { defineConfig } from "vitest/config";

export default defineConfig({ test: { environment: "node", include: ["src/**/*.test.{ts,tsx}"] } });
