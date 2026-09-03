// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright the Karst contributors.

/**
 * OIDC Authorization Code + PKCE, per plans/phase-5/04-admin-console.md §4.
 * The access token lives only in this module's memory — never `localStorage`,
 * never `sessionStorage` — so a page reload always re-establishes it via a
 * silent renew against the IdP's own session (a hidden iframe navigated to
 * `silent-renew.html`), the same mechanism `automaticSilentRenew` uses ahead
 * of expiry. An XSS that can read this module's state can also just call the
 * API directly, so this buys nothing beyond crash-resilience over an
 * explicitly persisted token — the point is not leaving one sitting in
 * storage for an unrelated bug to find later.
 */
import { UserManager, type User } from "oidc-client-ts";

export type AuthConfig = { oidcAuthority: string; oidcClientId: string };

let configPromise: Promise<AuthConfig> | undefined;

/** Memoized: every caller (main.tsx, api.ts, the silent-renew page) shares one fetch. */
export function loadConfig(): Promise<AuthConfig> {
  configPromise ??= fetch("/config.json")
    .then((response) => (response.ok ? (response.json() as Promise<AuthConfig>) : { oidcAuthority: "", oidcClientId: "" }))
    .catch(() => ({ oidcAuthority: "", oidcClientId: "" }));
  return configPromise;
}

let manager: UserManager | undefined;
let currentUser: User | undefined;

function getManager(config: AuthConfig): UserManager {
  if (manager) return manager;
  manager = new UserManager({
    authority: config.oidcAuthority,
    client_id: config.oidcClientId,
    redirect_uri: `${location.origin}/oidc/callback`,
    silent_redirect_uri: `${location.origin}/silent-renew.html`,
    response_type: "code",
    scope: "openid profile email",
    automaticSilentRenew: true,
  });
  manager.events.addUserLoaded((user) => { currentUser = user; });
  manager.events.addUserUnloaded(() => { currentUser = undefined; });
  manager.events.addSilentRenewError((error) => { console.error("karst: silent renew failed", error); });
  return manager;
}

export function accessToken(): string | undefined {
  return currentUser?.expired === false ? currentUser.access_token : undefined;
}

const postLoginHashKey = "karst.postLoginHash";

export type AuthState = "authenticated" | "anonymous" | "disabled";

/** Call once at startup. Handles the redirect-callback path itself. */
export async function bootstrap(config: AuthConfig): Promise<AuthState> {
  if (!config.oidcAuthority || !config.oidcClientId) return "disabled";
  const userManager = getManager(config);

  if (location.pathname === "/oidc/callback") {
    currentUser = await userManager.signinRedirectCallback();
    const hash = sessionStorage.getItem(postLoginHashKey) ?? "";
    sessionStorage.removeItem(postLoginHashKey);
    history.replaceState(null, "", "/" + hash);
    return "authenticated";
  }

  try {
    currentUser = (await userManager.signinSilent()) ?? undefined;
  } catch {
    currentUser = undefined;
  }
  return currentUser ? "authenticated" : "anonymous";
}

export function login(config: AuthConfig): void {
  sessionStorage.setItem(postLoginHashKey, location.hash);
  void getManager(config).signinRedirect();
}

export function logout(config: AuthConfig): void {
  currentUser = undefined;
  void getManager(config).signoutRedirect();
}

/** One retry after a fresh silent renew; the caller treats a second 401 as real. */
export async function renewOnce(config: AuthConfig): Promise<boolean> {
  try {
    currentUser = (await getManager(config).signinSilent()) ?? undefined;
  } catch {
    currentUser = undefined;
  }
  return currentUser !== undefined;
}
