// SPDX-License-Identifier: AGPL-3.0-or-later
import { createAuth } from "@karst-net/auth";
export type { AuthConfig, AuthState } from "@karst-net/auth";
export const { loadConfig, accessToken, bootstrap, login, logout, renewOnce, silentCallback } = createAuth("/");
