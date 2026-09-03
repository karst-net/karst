// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

// Loaded in the hidden iframe `automaticSilentRenew` navigates to. Its only
// job is handing the authorization response back to the parent window's
// UserManager — see src/auth.ts's header for why the token itself never
// touches storage here or anywhere else.
import { UserManager } from "oidc-client-ts";
import { loadConfig } from "./auth";

async function run() {
  const config = await loadConfig();
  await new UserManager({ authority: config.oidcAuthority, client_id: config.oidcClientId, redirect_uri: `${location.origin}/oidc/callback`}).signinSilentCallback();
}

void run().catch((error: unknown) => { console.error("karst: silent renew callback failed", error); });
